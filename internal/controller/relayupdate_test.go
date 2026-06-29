package controller

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"reflect"
	"strings"
	"testing"
	"time"

	"geneza.io/internal/defaults"
	genezav1 "geneza.io/internal/pb/geneza/v1"
	"geneza.io/internal/types"
)

// publishTestManifest writes a signed manifest + its blob into the server's store
// exactly as PublishArtifact would, so the desired endpoint can serve it. The
// signing key is throwaway: the desired endpoint only decodes and forwards the
// stored envelope; the bootstrap is what verifies it against its pinned key.
func publishTestManifest(t *testing.T, srv *Server, product, version, osName, arch string) *types.Signed {
	t.Helper()
	blob := make([]byte, 256)
	if _, err := rand.Read(blob); err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(blob)
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	m := types.Manifest{
		Product: product, Version: version, OS: osName, Arch: arch,
		SHA256: hex.EncodeToString(sum[:]), Size: int64(len(blob)), CreatedAt: time.Now().UTC(),
	}
	signed, err := types.Sign(priv, types.KeyIDFor(pub), defaults.ContextManifest, &m)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := json.Marshal(signed)
	if err != nil {
		t.Fatal(err)
	}
	if err := srv.store.PutManifest(ManifestKey(product, osName, arch, version), raw); err != nil {
		t.Fatal(err)
	}
	return signed
}

// desiredResp does one GET /v1/updates/desired and returns the status and body.
func desiredResp(t *testing.T, base, node, product string) (int, []byte) {
	t.Helper()
	q := url.Values{}
	q.Set("node", node)
	if product != "" {
		q.Set("product", product)
	}
	resp, err := http.Get(base + "/v1/updates/desired?" + q.Encode())
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, body
}

func desiredStatus(t *testing.T, base, node, product string) int {
	t.Helper()
	code, _ := desiredResp(t, base, node, product)
	return code
}

func desiredVersion(t *testing.T, base, node, product string) string {
	t.Helper()
	code, body := desiredResp(t, base, node, product)
	if code != http.StatusOK {
		t.Fatalf("desired(%s) status = %d, body=%s", product, code, strings.TrimSpace(string(body)))
	}
	var d types.DesiredVersionResponse
	if err := json.Unmarshal(body, &d); err != nil {
		t.Fatalf("decode desired response: %v (body=%s)", err, body)
	}
	return d.Version
}

// relayRingRoundTrip exercises the relay rollout ring through the Store interface
// so one body covers bbolt and every configured SQL engine: the relay ring must
// be independent of the agent ring (setting one never disturbs the other) and
// survive a read-back.
func relayRingRoundTrip(t *testing.T, s Store) {
	t.Helper()

	// Empty store: every relay-ring getter is the zero value.
	if v, err := s.RelayStableVersion(); err != nil || v != "" {
		t.Fatalf("empty RelayStableVersion = %q, %v", v, err)
	}
	if v, err := s.RelayCanaryVersion(); err != nil || v != "" {
		t.Fatalf("empty RelayCanaryVersion = %q, %v", v, err)
	}
	if v, err := s.RelayCanaryNodes(); err != nil || len(v) != 0 {
		t.Fatalf("empty RelayCanaryNodes = %v, %v", v, err)
	}

	if err := s.SetRelayStableVersion("1.2.0"); err != nil {
		t.Fatal(err)
	}
	if err := s.SetRelayCanaryVersion("1.3.0"); err != nil {
		t.Fatal(err)
	}
	if err := s.SetRelayCanaryNodes([]string{"r-eu-1", "r-us-1"}); err != nil {
		t.Fatal(err)
	}

	if v, err := s.RelayStableVersion(); err != nil || v != "1.2.0" {
		t.Fatalf("RelayStableVersion = %q, %v", v, err)
	}
	if v, err := s.RelayCanaryVersion(); err != nil || v != "1.3.0" {
		t.Fatalf("RelayCanaryVersion = %q, %v", v, err)
	}
	if v, err := s.RelayCanaryNodes(); err != nil || !reflect.DeepEqual(v, []string{"r-eu-1", "r-us-1"}) {
		t.Fatalf("RelayCanaryNodes = %v, %v", v, err)
	}

	// The agent ring is a separate keyspace: writing the relay ring above must not
	// have touched it, and writing the agent ring now must not bleed back.
	if v, err := s.StableVersion(); err != nil || v != "" {
		t.Fatalf("agent StableVersion leaked from relay write: %q, %v", v, err)
	}
	if err := s.SetStableVersion("9.9.9"); err != nil {
		t.Fatal(err)
	}
	if v, err := s.RelayStableVersion(); err != nil || v != "1.2.0" {
		t.Fatalf("relay ring perturbed by agent write: %q, %v", v, err)
	}
}

func TestRelayRingRoundTrip(t *testing.T) {
	t.Run("bbolt", func(t *testing.T) {
		relayRingRoundTrip(t, testStore(t))
	})
	t.Run("sql", func(t *testing.T) {
		forEachSQLEngine(t, func(t *testing.T, s *sqlStore) {
			relayRingRoundTrip(t, s)
		})
	})
}

// TestDesiredEndpointProductParam proves the /v1/updates/desired product contract:
// the same call with product=geneza-relay returns the relay manifest while the call
// WITHOUT product returns the agent manifest unchanged (the regression guard). It
// also covers the empty-ring 204 and the unknown-product 400.
func TestDesiredEndpointProductParam(t *testing.T) {
	srv := newDataPlaneServer(t)

	// Seed both rings + a manifest for each product on linux/amd64.
	publishTestManifest(t, srv, "geneza-agent", "a-1.0.0", "linux", "amd64")
	publishTestManifest(t, srv, "geneza-relay", "r-2.0.0", "linux", "amd64")
	if err := srv.store.SetStableVersion("a-1.0.0"); err != nil {
		t.Fatal(err)
	}
	if err := srv.store.SetRelayStableVersion("r-2.0.0"); err != nil {
		t.Fatal(err)
	}

	ts := httptest.NewServer(srv.httpHandler())
	defer ts.Close()

	// Agent path (no product): unchanged, returns the agent manifest.
	if got := desiredVersion(t, ts.URL, "node-a", ""); got != "a-1.0.0" {
		t.Fatalf("agent desired = %q, want a-1.0.0", got)
	}
	// Explicit product=geneza-agent is identical.
	if got := desiredVersion(t, ts.URL, "node-a", "geneza-agent"); got != "a-1.0.0" {
		t.Fatalf("explicit agent desired = %q, want a-1.0.0", got)
	}
	// Relay path: same endpoint, product=geneza-relay, returns the relay manifest.
	if got := desiredVersion(t, ts.URL, "r-eu-1", "geneza-relay"); got != "r-2.0.0" {
		t.Fatalf("relay desired = %q, want r-2.0.0", got)
	}

	// An empty relay ring (after clearing) yields 204 for the relay product while the
	// agent ring still answers — independence proven over the wire too.
	if err := srv.store.SetRelayStableVersion(""); err != nil {
		t.Fatal(err)
	}
	if code := desiredStatus(t, ts.URL, "r-eu-1", "geneza-relay"); code != http.StatusNoContent {
		t.Fatalf("empty relay ring status = %d, want 204", code)
	}
	if got := desiredVersion(t, ts.URL, "node-a", ""); got != "a-1.0.0" {
		t.Fatalf("agent ring disturbed by relay clear: %q", got)
	}

	// Unknown product is a 400.
	if code := desiredStatus(t, ts.URL, "node-a", "geneza-bogus"); code != http.StatusBadRequest {
		t.Fatalf("unknown product status = %d, want 400", code)
	}
}

func seedRelay(t *testing.T, srv *Server, id, version string, lastSeen time.Time) {
	t.Helper()
	if err := srv.store.UpsertRelay(&RelayRecord{
		RelayNode:    types.RelayNode{RegionID: "eu", RelayID: id, Addrs: []string{id + ":7404"}},
		LastSeenUnix: lastSeen.Unix(),
		Version:      version,
	}); err != nil {
		t.Fatal(err)
	}
}

// TestRelayCanaryGate proves the relay-aware promotion gate: a stable promotion is
// blocked while a canary relay still reports the OLD version (or has aged out), and
// allowed once every canary relay reports the candidate freshly.
func TestRelayCanaryGate(t *testing.T) {
	srv := newDataPlaneServer(t)
	admin := &clusterAPIService{s: srv}
	ctx := context.Background()
	set := func(ring, version string, relays []string) error {
		_, err := admin.SetDesiredVersion(ctx, &genezav1.SetDesiredVersionRequest{
			Product: "geneza-relay", Ring: ring, Version: version, CanaryNodes: relays,
		})
		return err
	}

	// Put two relays in the relay canary ring, candidate r-2.0.0.
	if err := set("canary", "r-2.0.0", []string{"r-eu-1", "r-eu-2"}); err != nil {
		t.Fatalf("set relay canary: %v", err)
	}

	now := time.Now()
	// r-eu-1 already on the candidate + fresh; r-eu-2 still on the old version.
	seedRelay(t, srv, "r-eu-1", "r-2.0.0", now)
	seedRelay(t, srv, "r-eu-2", "r-1.0.0", now)

	// Promotion must be blocked by the lagging relay.
	if err := set("stable", "r-2.0.0", nil); err == nil {
		t.Fatal("expected relay-stable promotion to be blocked by the lagging canary relay")
	} else if !strings.Contains(err.Error(), "r-eu-2") {
		t.Fatalf("blocker should name r-eu-2, got: %v", err)
	}

	// A stale-but-on-version relay also blocks (aged out beyond the relay TTL).
	seedRelay(t, srv, "r-eu-2", "r-2.0.0", now.Add(-2*relayStaleTTL))
	if err := set("stable", "r-2.0.0", nil); err == nil || !strings.Contains(err.Error(), "stale") {
		t.Fatalf("expected stale-heartbeat block, got: %v", err)
	}

	// Both fresh + on the candidate: promotion succeeds and the relay stable ring
	// advances — while the AGENT stable ring stays untouched (independence).
	seedRelay(t, srv, "r-eu-2", "r-2.0.0", now)
	if err := set("stable", "r-2.0.0", nil); err != nil {
		t.Fatalf("promotion should pass once all canary relays are healthy: %v", err)
	}
	if v, _ := srv.store.RelayStableVersion(); v != "r-2.0.0" {
		t.Fatalf("relay stable = %q, want r-2.0.0", v)
	}
	if v, _ := srv.store.StableVersion(); v != "" {
		t.Fatalf("agent stable ring perturbed by relay promotion: %q", v)
	}
}
