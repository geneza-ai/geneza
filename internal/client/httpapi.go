package client

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"net/http"
	"time"

	"geneza.io/internal/ca"
)

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

// FetchCARootsTOFU fetches the controller's CA bundle WITHOUT verifying the
// server certificate (we do not have a trust anchor yet — that is what we are
// fetching). This is trust-on-first-use: the caller MUST show the returned
// fingerprint to the operator, and the bundle is pinned in the profile so any
// later swap fails closed.
func FetchCARootsTOFU(ctx context.Context, controllerHTTP string) (pemBytes []byte, fingerprint string, err error) {
	c := &http.Client{
		Timeout: 15 * time.Second,
		Transport: &http.Transport{
			// TOFU bootstrap only; every subsequent request verifies against
			// the pinned bundle.
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true, MinVersion: tls.VersionTLS12},
		},
	}
	body, err := httpGet(ctx, c, controllerHTTP+"/v1/ca-roots")
	if err != nil {
		return nil, "", fmt.Errorf("fetch CA roots: %w", err)
	}
	if _, err := ca.PoolFromPEM(body); err != nil {
		return nil, "", fmt.Errorf("controller returned an invalid CA bundle: %w", err)
	}
	return body, CAFingerprint(body), nil
}

// VerifiedHTTPClient returns an HTTP client that only trusts the given pool
// (the pinned geneza CA) — used for all controller HTTPS after the TOFU step.
func VerifiedHTTPClient(pool *x509.CertPool) *http.Client {
	return &http.Client{
		Timeout: 30 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12},
		},
	}
}

// MutualTLSHTTPClient trusts the pinned pool AND presents the user's client cert,
// so it can reach the controller's cert-authed :7402 endpoints (the same mount
// the desktop app uses) — e.g. the CycloneDX SBOM / OpenVEX exports.
func MutualTLSHTTPClient(pool *x509.CertPool, cert *tls.Certificate) *http.Client {
	return &http.Client{
		Timeout: 60 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				RootCAs:      pool,
				Certificates: []tls.Certificate{*cert},
				MinVersion:   tls.VersionTLS12,
			},
		},
	}
}
