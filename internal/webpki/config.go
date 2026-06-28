package webpki

import (
	"errors"
	"fmt"
	"net/http"

	"github.com/go-acme/lego/v4/challenge"
	"github.com/go-acme/lego/v4/lego"
	"github.com/go-acme/lego/v4/providers/dns/cloudflare"
	"github.com/go-acme/lego/v4/providers/dns/exec"
)

// Account is the ACME account: the CA endpoint and the credentials that bind a
// deployment to it. One account drives issuance for every managed domain; the
// DNS-01 provider (which differs per domain) is supplied separately to New, so a
// deployment can host domains across different DNS providers under one account.
type Account struct {
	// Email is the ACME account contact.
	Email string `yaml:"email,omitempty"`
	// DirectoryURL is an explicit ACME directory; when set it overrides
	// Production (used for ZeroSSL or a private ACME/pebble in tests).
	DirectoryURL string `yaml:"directory_url,omitempty"`
	// Production selects the Let's Encrypt production directory when
	// DirectoryURL is empty. Default (false) uses the staging directory, so a
	// misconfigured or test deployment can never burn the production
	// rate-limit bucket.
	Production bool `yaml:"production,omitempty"`
	// EAB carries external-account-binding credentials for CAs that require
	// them (e.g. ZeroSSL). Nil for Let's Encrypt.
	EAB *EABConfig `yaml:"eab,omitempty"`
	// AccountKeyPEM is the persisted ACME account key. The caller generates it
	// once (GenerateAccountKey) and stores it; it binds the deployment to its
	// ACME account.
	AccountKeyPEM []byte `yaml:"-"`
	// httpClient optionally overrides the ACME HTTP client (e.g. a custom CA
	// bundle for a private/test ACME server). nil uses a default-timeout client.
	httpClient *http.Client
}

// EABConfig is RFC 8555 external account binding (HMAC base64url-encoded).
type EABConfig struct {
	KID  string `yaml:"kid,omitempty"`
	HMAC string `yaml:"hmac,omitempty"`
}

// DNS01Config selects the DNS-01 provider for one managed domain. Only the
// selected provider's sub-struct is read; only its lego subpackage is imported,
// so the controller binary does not pull a provider's cloud SDK until that provider
// ships.
type DNS01Config struct {
	Provider   string           `yaml:"provider,omitempty"` // "" | "cloudflare" | "exec"
	Cloudflare CloudflareConfig `yaml:"cloudflare,omitempty"`
	Exec       ExecConfig       `yaml:"exec,omitempty"`
}

// ExecConfig drives the generic "exec" provider: a script the issuer runs to
// publish/remove the DNS-01 TXT record. lego invokes it as
// `program present|cleanup <fqdn> <value>`. It lets a self-hosted operator wire
// any DNS API (and lets tests drive a local mock DNS) without a built-in plugin.
type ExecConfig struct {
	Program string `yaml:"program,omitempty"`
}

// CloudflareConfig authenticates to the Cloudflare DNS API. Prefer a token
// scoped to the delegated managed zone with DNS:Edit only — never an
// account-wide token (a compromised controller must not be able to touch other
// zones). ZoneToken may scope zone reads separately from the edit token.
type CloudflareConfig struct {
	APIToken  string `yaml:"api_token,omitempty"`
	ZoneToken string `yaml:"zone_token,omitempty"`
	// BaseURL overrides the Cloudflare API endpoint (default
	// https://api.cloudflare.com/client/v4) — for a CF-compatible API or tests.
	BaseURL string `yaml:"base_url,omitempty"`
}

func (a Account) directory() string {
	if a.DirectoryURL != "" {
		return a.DirectoryURL
	}
	if a.Production {
		return lego.LEDirectoryProduction
	}
	return lego.LEDirectoryStaging
}

// Validate checks the account is usable before any network call.
func (a Account) Validate() error {
	if a.Email == "" {
		return errors.New("webpki: account email is required")
	}
	if len(a.AccountKeyPEM) == 0 {
		return errors.New("webpki: account key is required")
	}
	if a.EAB != nil && (a.EAB.KID == "" || a.EAB.HMAC == "") {
		return errors.New("webpki: eab requires both kid and hmac")
	}
	return nil
}

// Validate checks the DNS-01 provider is configured. It does not need the
// account key, so config loading can validate providers before the key exists.
func (d DNS01Config) Validate() error {
	switch d.Provider {
	case "cloudflare":
		if d.Cloudflare.APIToken == "" {
			return errors.New("webpki: dns01.cloudflare requires api_token")
		}
		return nil
	case "exec":
		if d.Exec.Program == "" {
			return errors.New("webpki: dns01.exec requires program")
		}
		return nil
	case "":
		return errors.New("webpki: dns01.provider is required")
	default:
		return fmt.Errorf("webpki: unknown dns01 provider %q (want cloudflare or exec)", d.Provider)
	}
}

func (d DNS01Config) provider() (challenge.Provider, error) {
	if err := d.Validate(); err != nil {
		return nil, err
	}
	switch d.Provider {
	case "cloudflare":
		cf := cloudflare.NewDefaultConfig()
		cf.AuthToken = d.Cloudflare.APIToken
		cf.ZoneToken = d.Cloudflare.ZoneToken
		if d.Cloudflare.BaseURL != "" {
			cf.BaseURL = d.Cloudflare.BaseURL
		}
		return cloudflare.NewDNSProviderConfig(cf)
	case "exec":
		ec := exec.NewDefaultConfig()
		ec.Program = d.Exec.Program
		return exec.NewDNSProviderConfig(ec)
	default:
		return nil, fmt.Errorf("webpki: unknown dns01 provider %q", d.Provider)
	}
}
