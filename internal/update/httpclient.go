package update

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"strings"

	"geneza.io/internal/types"
)

// DesiredPath is the controller HTTP endpoint the bootstrap polls
// (reconcile-loop desired state, ARCHITECTURE.md §9 "staged rollout").
const DesiredPath = "/v1/updates/desired"

// NewHTTPClient builds the client used for desired-version polls and
// artifact downloads. When caRootsFile is set, the controller's TLS chain is
// verified against it; when it is not, TLS verification is DISABLED and a
// loud warning is logged. That is acceptable only because binary trust does
// not come from TLS at all — every artifact is verified against the pinned
// offline signing key — but it still leaves polls observable/tamperable on
// path, so production nodes should always configure ca_roots_file.
func NewHTTPClient(caRootsFile string, log *slog.Logger) (*http.Client, error) {
	tlsCfg := &tls.Config{MinVersion: tls.VersionTLS12}
	if caRootsFile != "" {
		pem, err := os.ReadFile(caRootsFile)
		if err != nil {
			// Fail closed: the operator asked for pinned roots; running
			// without them silently would downgrade the configuration.
			return nil, fmt.Errorf("ca_roots_file: %w", err)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(pem) {
			return nil, fmt.Errorf("ca_roots_file %s: no usable certificates", caRootsFile)
		}
		tlsCfg.RootCAs = pool
	} else {
		tlsCfg.InsecureSkipVerify = true
		if log != nil {
			log.Warn("SECURITY: no ca_roots_file configured — controller TLS is UNVERIFIED; " +
				"artifact integrity rests solely on the pinned signing key")
		}
	}
	return &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: tlsCfg,
			Proxy:           http.ProxyFromEnvironment,
		},
		// No global timeout: artifact downloads may be large. Callers bound
		// every request with a context deadline instead.
	}, nil
}

// FetchDesired polls the controller for this node's desired worker version.
// Returns (nil, nil) when the controller has nothing for us (204, empty body,
// or empty version) — the caller treats that as "converged, do nothing".
// product selects the rollout ring: "" (or "geneza-agent") is the agent ring
// and keeps the historical query string; "geneza-relay" drives the relay ring.
func FetchDesired(ctx context.Context, c *http.Client, controllerURL, node, current, product string) (*types.DesiredVersionResponse, error) {
	q := url.Values{}
	q.Set("node", node)
	q.Set("current", current)
	// Omit product for the agent so the agent request is byte-for-byte unchanged.
	if product != "" && product != "geneza-agent" {
		q.Set("product", product)
	}
	u := strings.TrimRight(controllerURL, "/") + DesiredPath + "?" + q.Encode()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return nil, err
	}
	resp, err := c.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	switch resp.StatusCode {
	case http.StatusNoContent:
		return nil, nil
	case http.StatusOK:
	default:
		return nil, fmt.Errorf("controller returned %s", resp.Status)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, err
	}
	if len(bytes.TrimSpace(body)) == 0 {
		return nil, nil
	}
	var d types.DesiredVersionResponse
	if err := json.Unmarshal(body, &d); err != nil {
		return nil, fmt.Errorf("decode desired-version response: %w", err)
	}
	if d.Version == "" {
		return nil, nil
	}
	return &d, nil
}
