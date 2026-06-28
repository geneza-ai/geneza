// Package webpki obtains publicly-trusted TLS certificates for Geneza's managed
// domain. It wraps an ACME client (lego) driving the DNS-01 challenge through a
// pluggable DNS provider, so the controller can mint a wildcard certificate per
// workspace and narrow leaf certificates for funnel hostnames without running a
// CA or exposing any host to the public internet.
//
// This package only issues. It holds no storage, no scheduling, and no knowledge
// of workspaces — the controller owns the renewal loop, the certificate store, and
// the sealed distribution to agents and relays. Keeping issuance pure makes the
// ACME path testable in isolation against a staging directory or pebble.
package webpki

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"net/http"
	"sync"
	"time"

	"github.com/go-acme/lego/v4/certificate"
	"github.com/go-acme/lego/v4/challenge"
	"github.com/go-acme/lego/v4/challenge/dns01"
	"github.com/go-acme/lego/v4/lego"
	"github.com/go-acme/lego/v4/registration"
)

// Cert is a freshly issued certificate: the PEM chain (leaf first, issuer
// appended), the PEM private key, and the leaf's validity window. The caller
// persists and distributes it; webpki keeps no copy.
type Cert struct {
	Names     []string
	ChainPEM  []byte
	KeyPEM    []byte
	NotBefore time.Time
	NotAfter  time.Time
}

// Issuer obtains certificates for a set of DNS names. names is typically the
// workspace wildcard plus its apex (["*.w-x.example.app", "w-x.example.app"]),
// or a single funnel hostname.
type Issuer interface {
	Issue(ctx context.Context, names []string) (*Cert, error)
}

// acmeUser adapts a persisted account key to lego's registration.User.
type acmeUser struct {
	email string
	key   crypto.PrivateKey
	reg   *registration.Resource
}

func (u *acmeUser) GetEmail() string                        { return u.email }
func (u *acmeUser) GetRegistration() *registration.Resource { return u.reg }
func (u *acmeUser) GetPrivateKey() crypto.PrivateKey        { return u.key }

// acmeIssuer is the lego-backed Issuer. The lego client is built once; account
// registration is performed lazily on the first Issue (it needs the network),
// so New stays offline-cheap and unit-testable.
type acmeIssuer struct {
	acct   Account
	user   *acmeUser
	client *lego.Client

	mu         sync.Mutex
	registered bool
}

// New builds an Issuer for one DNS-01 provider under the given account. It parses
// the account key and constructs the ACME client and DNS-01 solver, but does not
// contact the CA — registration is deferred to the first Issue. A deployment
// hosting several domains across different DNS providers builds one Issuer per
// provider, all sharing the same account.
func New(acct Account, dns01 DNS01Config) (Issuer, error) {
	provider, err := dns01.provider()
	if err != nil {
		return nil, err
	}
	return newWithProvider(acct, provider)
}

// newWithProvider builds an Issuer against an already-constructed DNS-01 solver.
// New wraps it for the config-driven providers; tests use it directly to drive a
// local ACME server (pebble), and it is the seam a future custom provider hooks.
// opts tune the lego DNS-01 self-check (recursive nameservers / propagation
// gating) — empty in production, set by the pebble test to point at its mock DNS.
func newWithProvider(acct Account, provider challenge.Provider, opts ...dns01.ChallengeOption) (Issuer, error) {
	if err := acct.Validate(); err != nil {
		return nil, err
	}
	key, err := parsePrivateKey(acct.AccountKeyPEM)
	if err != nil {
		return nil, fmt.Errorf("account key: %w", err)
	}
	user := &acmeUser{email: acct.Email, key: key}

	lc := lego.NewConfig(user)
	lc.CADirURL = acct.directory()
	lc.UserAgent = "geneza-webpki"
	lc.HTTPClient = acct.httpClient
	if lc.HTTPClient == nil {
		lc.HTTPClient = &http.Client{Timeout: 2 * time.Minute}
	}

	client, err := lego.NewClient(lc)
	if err != nil {
		return nil, fmt.Errorf("acme client: %w", err)
	}
	if err := client.Challenge.SetDNS01Provider(provider, opts...); err != nil {
		return nil, fmt.Errorf("dns-01 solver: %w", err)
	}
	return &acmeIssuer{acct: acct, user: user, client: client}, nil
}

func (a *acmeIssuer) ensureRegistered() error {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.registered {
		return nil
	}
	var (
		reg *registration.Resource
		err error
	)
	if a.acct.EAB != nil {
		reg, err = a.client.Registration.RegisterWithExternalAccountBinding(registration.RegisterEABOptions{
			TermsOfServiceAgreed: true,
			Kid:                  a.acct.EAB.KID,
			HmacEncoded:          a.acct.EAB.HMAC,
		})
	} else {
		reg, err = a.client.Registration.Register(registration.RegisterOptions{TermsOfServiceAgreed: true})
	}
	if err != nil {
		return fmt.Errorf("acme account: %w", err)
	}
	a.user.reg = reg
	a.registered = true
	return nil
}

func (a *acmeIssuer) Issue(ctx context.Context, names []string) (*Cert, error) {
	if len(names) == 0 {
		return nil, errors.New("webpki: no names to issue")
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if err := a.ensureRegistered(); err != nil {
		return nil, err
	}
	res, err := a.client.Certificate.Obtain(certificate.ObtainRequest{
		Domains: names,
		Bundle:  true,
	})
	if err != nil {
		return nil, fmt.Errorf("obtain %v: %w", names, err)
	}
	leaf, err := parseLeaf(res.Certificate)
	if err != nil {
		return nil, err
	}
	return &Cert{
		Names:     names,
		ChainPEM:  res.Certificate,
		KeyPEM:    res.PrivateKey,
		NotBefore: leaf.NotBefore,
		NotAfter:  leaf.NotAfter,
	}, nil
}

// GenerateAccountKey returns a PEM-encoded ECDSA P-256 key the caller persists
// as the deployment's stable ACME account key. Re-registering the same key with
// the CA returns the existing account, so the key — not a saved registration
// URL — is what binds the deployment to its ACME account across restarts.
func GenerateAccountKey() ([]byte, error) {
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	der, err := x509.MarshalPKCS8PrivateKey(k)
	if err != nil {
		return nil, err
	}
	return pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}), nil
}

func parsePrivateKey(pemBytes []byte) (crypto.PrivateKey, error) {
	if len(pemBytes) == 0 {
		return nil, errors.New("empty key")
	}
	blk, _ := pem.Decode(pemBytes)
	if blk == nil {
		return nil, errors.New("not PEM")
	}
	if k, err := x509.ParsePKCS8PrivateKey(blk.Bytes); err == nil {
		return k, nil
	}
	if k, err := x509.ParseECPrivateKey(blk.Bytes); err == nil {
		return k, nil
	}
	if k, err := x509.ParsePKCS1PrivateKey(blk.Bytes); err == nil {
		return k, nil
	}
	return nil, errors.New("unsupported key format")
}

func parseLeaf(chainPEM []byte) (*x509.Certificate, error) {
	blk, _ := pem.Decode(chainPEM)
	if blk == nil {
		return nil, errors.New("certificate chain is not PEM")
	}
	return x509.ParseCertificate(blk.Bytes)
}
