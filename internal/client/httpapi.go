package client

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"

	"osie.cloud/geneza/internal/ca"
)

// AuthConfig is the gateway's GET /v1/auth-config document, normalized for the
// CLI. The gateway emits {"oidc":{"issuer","client_id"}|null,"local_enabled":bool};
// UnmarshalJSON maps that onto a flat providers list the login flow consumes.
type AuthConfig struct {
	Providers    []string // subset of {"oidc","local"}
	OIDCIssuer   string
	OIDCClientID string
}

func (a *AuthConfig) UnmarshalJSON(b []byte) error {
	var wire struct {
		OIDC *struct {
			Issuer   string `json:"issuer"`
			ClientID string `json:"client_id"`
		} `json:"oidc"`
		LocalEnabled bool `json:"local_enabled"`
	}
	if err := json.Unmarshal(b, &wire); err != nil {
		return err
	}
	a.Providers = a.Providers[:0]
	if wire.OIDC != nil {
		a.Providers = append(a.Providers, "oidc")
		a.OIDCIssuer = wire.OIDC.Issuer
		a.OIDCClientID = wire.OIDC.ClientID
	}
	if wire.LocalEnabled {
		a.Providers = append(a.Providers, "local")
	}
	return nil
}

const maxHTTPBody = 1 << 20

func httpGet(ctx context.Context, c *http.Client, url string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	resp, err := c.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxHTTPBody))
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("GET %s: %s: %s", url, resp.Status, truncate(string(body), 200))
	}
	return body, nil
}

func truncate(s string, n int) string {
	if len(s) > n {
		return s[:n] + "..."
	}
	return s
}

// FetchCARootsTOFU fetches the gateway's CA bundle WITHOUT verifying the
// server certificate (we do not have a trust anchor yet — that is what we are
// fetching). This is trust-on-first-use: the caller MUST show the returned
// fingerprint to the operator, and the bundle is pinned in the profile so any
// later swap fails closed.
func FetchCARootsTOFU(ctx context.Context, gatewayHTTP string) (pemBytes []byte, fingerprint string, err error) {
	c := &http.Client{
		Timeout: 15 * time.Second,
		Transport: &http.Transport{
			// TOFU bootstrap only; every subsequent request verifies against
			// the pinned bundle.
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true, MinVersion: tls.VersionTLS12},
		},
	}
	body, err := httpGet(ctx, c, gatewayHTTP+"/v1/ca-roots")
	if err != nil {
		return nil, "", fmt.Errorf("fetch CA roots: %w", err)
	}
	if _, err := ca.PoolFromPEM(body); err != nil {
		return nil, "", fmt.Errorf("gateway returned an invalid CA bundle: %w", err)
	}
	return body, CAFingerprint(body), nil
}

// VerifiedHTTPClient returns an HTTP client that only trusts the given pool
// (the pinned geneza CA) — used for all gateway HTTPS after the TOFU step.
func VerifiedHTTPClient(pool *x509.CertPool) *http.Client {
	return &http.Client{
		Timeout: 30 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12},
		},
	}
}

// FetchAuthConfig retrieves /v1/auth-config over a CA-verified connection.
func FetchAuthConfig(ctx context.Context, gatewayHTTP string, pool *x509.CertPool) (*AuthConfig, error) {
	body, err := httpGet(ctx, VerifiedHTTPClient(pool), gatewayHTTP+"/v1/auth-config")
	if err != nil {
		return nil, fmt.Errorf("fetch auth config: %w", err)
	}
	var ac AuthConfig
	if err := json.Unmarshal(body, &ac); err != nil {
		return nil, fmt.Errorf("auth config: %w", err)
	}
	return &ac, nil
}
