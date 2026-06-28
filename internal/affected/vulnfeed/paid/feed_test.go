package paid

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"geneza.io/internal/affected/vulnfeed"
	"geneza.io/internal/types"
)

// memStore is an in-memory vulnfeed.AdvisoryStore so the feed test needs no DB.
type memStore struct {
	byID  map[string]vulnfeed.AdvisoryRecord
	byPkg map[string][]string // ecosystem\x00name -> ids
}

func newMemStore() *memStore {
	return &memStore{byID: map[string]vulnfeed.AdvisoryRecord{}, byPkg: map[string][]string{}}
}

func (m *memStore) PutAdvisories(recs []vulnfeed.AdvisoryRecord) error {
	for _, r := range recs {
		if _, ok := m.byID[r.ID]; !ok {
			k := r.Ecosystem + "\x00" + r.PackageName
			m.byPkg[k] = append(m.byPkg[k], r.ID)
		}
		m.byID[r.ID] = r
	}
	return nil
}

func (m *memStore) AdvisoriesForPackage(ecosystem, name string) ([]vulnfeed.AdvisoryRecord, error) {
	var out []vulnfeed.AdvisoryRecord
	for _, id := range m.byPkg[ecosystem+"\x00"+name] {
		out = append(out, m.byID[id])
	}
	return out, nil
}

// signBundle marshals a bundle, signs it under the bundle context with priv, and
// returns the encoded signed envelope — the bytes the fixture server hands the
// client.
func signBundle(t *testing.T, priv ed25519.PrivateKey, b Bundle) []byte {
	t.Helper()
	env, err := types.Sign(priv, "vendor", signContext, b)
	if err != nil {
		t.Fatalf("sign bundle: %v", err)
	}
	raw, err := env.Encode()
	if err != nil {
		t.Fatalf("encode envelope: %v", err)
	}
	return raw
}

// bundleServer serves a fixed envelope and records the Authorization header it saw,
// so a test asserts the license key reaches the server without any live network.
func bundleServer(t *testing.T, body []byte) (*httptest.Server, *string) {
	t.Helper()
	var gotAuth string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		_, _ = w.Write(body)
	}))
	t.Cleanup(srv.Close)
	return srv, &gotAuth
}

// sampleBundle is a small curated bundle: one Debian advisory affecting two
// packages plus npm, carrying curated enrichment, at the given version.
func sampleBundle(version int64) Bundle {
	return Bundle{
		Version: version,
		Advisories: []CuratedAdvisory{
			{
				Vuln: vulnfeed.Vulnerability{
					ID:       "GENEZA-1",
					Aliases:  []string{"CVE-2024-9"},
					Modified: time.Date(2024, 3, 1, 0, 0, 0, 0, time.UTC),
					Affected: []vulnfeed.Affected{
						{
							Package: vulnfeed.Package{Ecosystem: "Debian:12", Name: "openssl"},
							Ranges: []vulnfeed.Range{{Type: "ECOSYSTEM", Events: []vulnfeed.Event{
								{Introduced: "0"}, {Fixed: "1.1.1n-0+deb12u1"}}}},
						},
						{Package: vulnfeed.Package{Ecosystem: "Debian:12", Name: "libssl"}},
					},
				},
				Enrichment: vulnfeed.Enrichment{Severity: "critical", KEV: true, EPSS: 0.92},
			},
			{
				Vuln: vulnfeed.Vulnerability{
					ID:       "GENEZA-2",
					Aliases:  []string{"CVE-2024-10"},
					Modified: time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC),
					Affected: []vulnfeed.Affected{
						{Package: vulnfeed.Package{Ecosystem: "npm", Name: "lodash"}},
					},
				},
			},
		},
	}
}

func newFeed(t *testing.T, endpoint, license string, pub ed25519.PublicKey, st vulnfeed.AdvisoryStore, vs VersionStore, client httpDoer) *Feed {
	t.Helper()
	f, err := New(Options{
		Endpoint:     endpoint,
		LicenseKey:   license,
		VendorPubKey: pub,
		Store:        st,
		Versions:     vs,
		HTTP:         client,
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return f
}

// TestSyncVerifiesIngestsAndServes is the happy path: a signed, versioned bundle is
// verified against the pinned key, ingested through the store, and served by
// package; the curated enrichment is answered by CVE; the license key reaches the
// server.
func TestSyncVerifiesIngestsAndServes(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	srv, gotAuth := bundleServer(t, signBundle(t, priv, sampleBundle(1)))

	st := newMemStore()
	f := newFeed(t, srv.URL, "lic-abc", pub, st, &memVersionStore{}, srv.Client())
	if f.Name() != FeedName {
		t.Errorf("Name = %q, want %q", f.Name(), FeedName)
	}

	n, err := f.Sync(context.Background(), time.Time{})
	if err != nil {
		t.Fatalf("Sync: %v", err)
	}
	// GENEZA-1 affects openssl + libssl = 2 rows; GENEZA-2 affects lodash = 1 row.
	if n != 3 {
		t.Fatalf("Sync wrote %d rows, want 3", n)
	}
	if *gotAuth != "Bearer lic-abc" {
		t.Errorf("license key not sent: Authorization=%q", *gotAuth)
	}

	ossl, err := f.Advisories("Debian:12", "openssl")
	if err != nil || len(ossl) != 1 {
		t.Fatalf("Advisories openssl: err=%v len=%d", err, len(ossl))
	}
	if ossl[0].ID != "GENEZA-1" {
		t.Errorf("want GENEZA-1, got %q", ossl[0].ID)
	}
	if ossl[0].Affected[0].Ranges[0].Events[1].Fixed != "1.1.1n-0+deb12u1" {
		t.Errorf("range lost in round-trip: %+v", ossl[0].Affected)
	}
	if libssl, _ := f.Advisories("Debian:12", "libssl"); len(libssl) != 1 || libssl[0].ID != "GENEZA-1" {
		t.Errorf("libssl resolve wrong: %+v", libssl)
	}
	if lod, _ := f.Advisories("npm", "lodash"); len(lod) != 1 || lod[0].ID != "GENEZA-2" {
		t.Errorf("lodash resolve wrong: %+v", lod)
	}

	// Curated enrichment resolves by the advisory id AND the CVE alias.
	for _, key := range []string{"GENEZA-1", "CVE-2024-9"} {
		e, _ := f.Enrich(context.Background(), key)
		if !e.KEV || e.Severity != "critical" || e.EPSS != 0.92 {
			t.Errorf("Enrich(%q) = %+v, want curated critical/KEV/0.92", key, e)
		}
	}
	// A CVE the bundle has no curated signal for is a zero Enrichment, not an error.
	if e, _ := f.Enrich(context.Background(), "CVE-2024-10"); e != (vulnfeed.Enrichment{}) {
		t.Errorf("Enrich(uncurated) = %+v, want zero", e)
	}

	// Changed lists exactly the two advisory ids this sync wrote.
	if c := f.Changed(); len(c) != 2 || c[0].ID != "GENEZA-1" || c[1].ID != "GENEZA-2" {
		t.Fatalf("Changed = %+v, want [GENEZA-1 GENEZA-2]", c)
	}
}

// TestSyncRejectsForgedSignature proves a bundle whose signature does not verify
// against the pinned key is rejected and NOTHING is ingested — a MITM cannot inject
// a forged advisory.
func TestSyncRejectsForgedSignature(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)

	// Sign a valid bundle, then tamper one byte of the payload so the signature no
	// longer matches.
	raw := signBundle(t, priv, sampleBundle(1))
	var env types.Signed
	if err := json.Unmarshal(raw, &env); err != nil {
		t.Fatal(err)
	}
	env.Payload[len(env.Payload)/2] ^= 0xFF
	tampered, _ := env.Encode()

	srv, _ := bundleServer(t, tampered)
	st := newMemStore()
	f := newFeed(t, srv.URL, "", pub, st, &memVersionStore{}, srv.Client())

	if _, err := f.Sync(context.Background(), time.Time{}); err == nil {
		t.Fatal("expected a verify error for a tampered bundle")
	}
	if len(st.byID) != 0 {
		t.Fatalf("tampered bundle ingested %d advisories, want 0", len(st.byID))
	}
}

// TestSyncRejectsNonPinnedSigner proves a bundle signed by a DIFFERENT (valid) key
// than the pinned one is rejected — a MITM cannot substitute its own signing key.
func TestSyncRejectsNonPinnedSigner(t *testing.T) {
	pinnedPub, _, _ := ed25519.GenerateKey(rand.Reader)
	_, attackerPriv, _ := ed25519.GenerateKey(rand.Reader)

	// The server serves a perfectly-signed bundle, but by the attacker's key.
	srv, _ := bundleServer(t, signBundle(t, attackerPriv, sampleBundle(1)))
	st := newMemStore()
	f := newFeed(t, srv.URL, "", pinnedPub, st, &memVersionStore{}, srv.Client())

	if _, err := f.Sync(context.Background(), time.Time{}); err == nil {
		t.Fatal("expected a verify error for a non-pinned signer")
	}
	if len(st.byID) != 0 {
		t.Fatalf("non-pinned bundle ingested %d advisories, want 0", len(st.byID))
	}
}

// TestSyncRejectsRollback proves the monotonic version guard: after ingesting
// version 2, a re-served version 2 (replay) and an older version 1 (rollback) are
// both refused without writing, and the watermark stays at 2.
func TestSyncRejectsRollback(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	vs := &memVersionStore{}
	st := newMemStore()

	// Ingest version 2 first.
	srv2, _ := bundleServer(t, signBundle(t, priv, sampleBundle(2)))
	f2 := newFeed(t, srv2.URL, "", pub, st, vs, srv2.Client())
	if n, err := f2.Sync(context.Background(), time.Time{}); err != nil || n != 3 {
		t.Fatalf("ingest v2: n=%d err=%v", n, err)
	}
	if v, _ := vs.GetBundleVersion(); v != 2 {
		t.Fatalf("watermark after v2 = %d, want 2", v)
	}

	// A replay of the SAME version 2 is a no-op (zero rows, no error, no re-match).
	if n, err := f2.Sync(context.Background(), time.Time{}); err != nil || n != 0 {
		t.Fatalf("replay v2: n=%d err=%v, want 0/nil", n, err)
	}
	if len(f2.Changed()) != 0 {
		t.Errorf("replay re-matched %d advisories, want 0", len(f2.Changed()))
	}

	// A rollback to version 1 (a captured older bundle) is refused: zero rows, no
	// error, watermark unchanged. This is also how suppression-by-omission surfaces:
	// a MITM cannot serve an OLD bundle with an advisory dropped without tripping
	// this guard, and cannot forge a higher version without the pinned key.
	srv1, _ := bundleServer(t, signBundle(t, priv, sampleBundle(1)))
	f1 := newFeed(t, srv1.URL, "", pub, st, vs, srv1.Client())
	if n, err := f1.Sync(context.Background(), time.Time{}); err != nil || n != 0 {
		t.Fatalf("rollback v1: n=%d err=%v, want 0/nil", n, err)
	}
	if v, _ := vs.GetBundleVersion(); v != 2 {
		t.Fatalf("watermark after rollback = %d, want 2 (unchanged)", v)
	}
}

// TestSyncAcceptsMonotonicUpgrade proves a strictly-higher version IS ingested and
// advances the watermark — the legitimate update path the rollback guard protects.
func TestSyncAcceptsMonotonicUpgrade(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	vs := &memVersionStore{}
	st := newMemStore()

	srv2, _ := bundleServer(t, signBundle(t, priv, sampleBundle(2)))
	f := newFeed(t, srv2.URL, "", pub, st, vs, srv2.Client())
	if _, err := f.Sync(context.Background(), time.Time{}); err != nil {
		t.Fatalf("ingest v2: %v", err)
	}

	// Version 5 adds a new advisory; it must ingest and bump the watermark.
	b := sampleBundle(5)
	b.Advisories = append(b.Advisories, CuratedAdvisory{
		Vuln: vulnfeed.Vulnerability{
			ID:       "GENEZA-3",
			Affected: []vulnfeed.Affected{{Package: vulnfeed.Package{Ecosystem: "PyPI", Name: "requests"}}},
		},
	})
	srv5, _ := bundleServer(t, signBundle(t, priv, b))
	f5 := newFeed(t, srv5.URL, "", pub, st, vs, srv5.Client())
	if n, err := f5.Sync(context.Background(), time.Time{}); err != nil || n != 4 {
		t.Fatalf("upgrade v5: n=%d err=%v, want 4 rows", n, err)
	}
	if v, _ := vs.GetBundleVersion(); v != 5 {
		t.Fatalf("watermark after upgrade = %d, want 5", v)
	}
	if r, _ := f5.Advisories("PyPI", "requests"); len(r) != 1 || r[0].ID != "GENEZA-3" {
		t.Errorf("new advisory not served: %+v", r)
	}
}

// TestNewRejectsBadPinnedKey proves construction fails closed on a wrong-size pinned
// key rather than running the feed unpinned.
func TestNewRejectsBadPinnedKey(t *testing.T) {
	if _, err := New(Options{Endpoint: "http://x", VendorPubKey: []byte("short"), Store: newMemStore()}); err == nil {
		t.Fatal("expected New to reject a wrong-size pinned key")
	}
	if _, err := New(Options{Endpoint: "", VendorPubKey: make([]byte, ed25519.PublicKeySize), Store: newMemStore()}); err == nil {
		t.Fatal("expected New to reject an empty endpoint")
	}
}

// TestSyncRejectsAuthFailure proves a non-200 (e.g. a license rejection) fails the
// sync without ingesting.
func TestSyncRejectsAuthFailure(t *testing.T) {
	pub, _, _ := ed25519.GenerateKey(rand.Reader)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
	}))
	t.Cleanup(srv.Close)
	st := newMemStore()
	f := newFeed(t, srv.URL, "bad-license", pub, st, &memVersionStore{}, srv.Client())
	if _, err := f.Sync(context.Background(), time.Time{}); err == nil {
		t.Fatal("expected an error on a non-200 response")
	}
	if len(st.byID) != 0 {
		t.Fatalf("ingested %d advisories on auth failure, want 0", len(st.byID))
	}
}
