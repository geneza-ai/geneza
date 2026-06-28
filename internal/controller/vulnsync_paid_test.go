package controller

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"geneza.io/internal/affected/vulnfeed"
	"geneza.io/internal/affected/vulnfeed/paid"
	"geneza.io/internal/types"
)

// signPaidBundle signs a paid bundle the same way the vendor service would, so the
// fixture server hands the controller a verifiable, versioned envelope.
func signPaidBundle(t *testing.T, priv ed25519.PrivateKey, b paid.Bundle) []byte {
	t.Helper()
	env, err := types.Sign(priv, "vendor", "vulnfeed-bundle", b)
	if err != nil {
		t.Fatalf("sign bundle: %v", err)
	}
	raw, err := env.Encode()
	if err != nil {
		t.Fatalf("encode bundle: %v", err)
	}
	return raw
}

// paidVulnSyncSuite seeds inventory, points the controller's vuln-sync chore at a
// FIXTURE signed-bundle server (never a live endpoint), builds the PAID feed the
// same way the server does from config (so config selection + the settings-backed
// version watermark are exercised), runs one tick, and asserts the chore verified +
// ingested the curated bundle AND the engine matched it onto the affected node.
// It runs against any Store so bbolt and both SQL engines share the assertions.
func paidVulnSyncSuite(t *testing.T, s Store) {
	t.Helper()
	ctx := context.Background()
	const wsA = "wsA"

	if err := s.PutWorkspace(&WorkspaceRecord{ID: wsA, Name: "A"}); err != nil {
		t.Fatalf("PutWorkspace: %v", err)
	}
	if err := s.UpsertNodeComponents(wsA, "n1", []ComponentRecord{
		{Purl: "pkg:npm/ansi-regex@5.0.0", Source: "lang", Ecosystem: "npm", Name: "ansi-regex", Version: "5.0.0"},
	}); err != nil {
		t.Fatalf("seed n1: %v", err)
	}
	if err := s.UpsertNodeComponents(wsA, "n2", []ComponentRecord{
		{Purl: "pkg:npm/left-pad@1.0.0", Source: "lang", Ecosystem: "npm", Name: "left-pad", Version: "1.0.0"},
	}); err != nil {
		t.Fatalf("seed n2: %v", err)
	}

	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	bundle := paid.Bundle{
		Version: 7,
		Advisories: []paid.CuratedAdvisory{{
			Vuln: vulnfeed.Vulnerability{
				ID:       "GENEZA-ADV-1",
				Aliases:  []string{"CVE-2021-3807"},
				Modified: time.Date(2024, 6, 1, 0, 0, 0, 0, time.UTC),
				Affected: []vulnfeed.Affected{{
					Package: vulnfeed.Package{Ecosystem: "npm", Name: "ansi-regex"},
					Ranges: []vulnfeed.Range{{Type: "ECOSYSTEM", Events: []vulnfeed.Event{
						{Introduced: "0"}, {Fixed: "5.0.1"}}}},
				}},
			},
			Enrichment: vulnfeed.Enrichment{Severity: "high", KEV: true, EPSS: 0.7},
		}},
	}
	envBytes := signPaidBundle(t, priv, bundle)

	var gotAuth string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		_, _ = w.Write(envBytes)
	}))
	defer srv.Close()

	sv := &Server{store: s}
	sv.cfg = &Config{VulnFeed: VulnFeedConfig{
		Source:       "geneza-paid",
		PaidEndpoint: srv.URL,
		PaidLicense:  "lic-xyz",
		PaidPubKey:   base64.StdEncoding.EncodeToString(pub),
		SyncInterval: Duration(6 * time.Hour),
	}}
	// Build the feed exactly as the server would from config: this selects the paid
	// feed by source and binds it to a settings-backed version watermark.
	sv.inventoryFeed = sv.buildVulnFeed()
	if sv.inventoryFeed == nil {
		t.Fatal("buildVulnFeed returned nil for source=geneza-paid")
	}
	if sv.inventoryFeed.Name() != "geneza-vulnfeed" {
		t.Fatalf("selected feed = %q, want geneza-vulnfeed", sv.inventoryFeed.Name())
	}

	sv.vulnSyncTick(ctx)

	if gotAuth != "Bearer lic-xyz" {
		t.Fatalf("license key not sent to the bundle server: Authorization=%q", gotAuth)
	}

	// The engine matched the curated advisory onto n1.
	rows, err := s.NodesAffectedByCVE(wsA, "CVE-2021-3807")
	if err != nil {
		t.Fatalf("NodesAffectedByCVE: %v", err)
	}
	if len(rows) != 1 || rows[0].NodeID != "n1" || rows[0].Status != "affected" {
		t.Fatalf("after paid sync chore: want one affected row for n1, got %v", rows)
	}
	// n2 (unrelated package) was never touched.
	if n2cves, _ := s.CVEsForNode(wsA, "n2"); len(n2cves) != 0 {
		t.Fatalf("paid sync chore touched unrelated n2: %v", n2cves)
	}
	// The curated advisory doc was persisted under the paid source.
	advs, _ := s.AdvisoriesForPackage("npm", "ansi-regex")
	if len(advs) != 1 || advs[0].Source != "geneza-vulnfeed" {
		t.Fatalf("want one stored advisory from the paid source, got %v", advs)
	}

	// The version watermark advanced to the bundle version and persisted in settings.
	wmRaw, _ := s.GetSetting(settingPaidBundleVersion)
	if string(wmRaw) != "7" {
		t.Fatalf("paid bundle version watermark = %q, want 7", wmRaw)
	}

	// A second tick re-serves the SAME version 7: the rollback/replay guard makes it
	// a no-op, leaving the verdict set unchanged.
	sv.vulnSyncTick(ctx)
	if rows2, _ := s.NodesAffectedByCVE(wsA, "CVE-2021-3807"); len(rows2) != 1 {
		t.Fatalf("replay tick changed the verdict set: %v", rows2)
	}
}

func TestPaidVulnSyncChoreBbolt(t *testing.T) {
	paidVulnSyncSuite(t, testStore(t))
}

func TestPaidVulnSyncChoreSQL(t *testing.T) {
	forEachSQLEngine(t, func(t *testing.T, s *sqlStore) {
		paidVulnSyncSuite(t, s)
	})
}

// TestPaidConfigRejectsBadPinnedKey proves config validation fails closed on a
// missing/garbled pinned key, so a paid feed never runs unpinned.
func TestPaidConfigRejectsBadPinnedKey(t *testing.T) {
	base := func() *Config {
		c := &Config{
			DataDir:     "/var/lib/geneza",
			ClusterName: "test",
			PolicyFile:  "/etc/geneza/policy.yaml",
			RelayAddrs:  []string{"relay.example:7000"},
		}
		c.applyDefaults()
		c.VulnFeed = VulnFeedConfig{Source: "geneza-paid", PaidEndpoint: "https://feed.example"}
		return c
	}
	// No pinned key.
	if err := base().validateForServe(); err == nil {
		t.Fatal("expected validate to reject geneza-paid with no pinned key")
	}
	// Garbled base64.
	c := base()
	c.VulnFeed.PaidPubKey = "!!!not-base64!!!"
	if err := c.validateForServe(); err == nil {
		t.Fatal("expected validate to reject a non-base64 pinned key")
	}
	// Wrong length.
	c = base()
	c.VulnFeed.PaidPubKey = base64.StdEncoding.EncodeToString([]byte("too-short"))
	if err := c.validateForServe(); err == nil {
		t.Fatal("expected validate to reject a wrong-size pinned key")
	}
	// Missing endpoint.
	c = base()
	c.VulnFeed.PaidEndpoint = ""
	c.VulnFeed.PaidPubKey = base64.StdEncoding.EncodeToString(make([]byte, ed25519.PublicKeySize))
	if err := c.validateForServe(); err == nil {
		t.Fatal("expected validate to reject geneza-paid with no endpoint")
	}
	// A complete config validates.
	c = base()
	c.VulnFeed.PaidPubKey = base64.StdEncoding.EncodeToString(make([]byte, ed25519.PublicKeySize))
	if err := c.validateForServe(); err != nil {
		t.Fatalf("a complete geneza-paid config should validate: %v", err)
	}
}
