package agentd

import (
	"context"
	"log/slog"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/google/osv-scalibr/extractor"
	dpkgmeta "github.com/google/osv-scalibr/extractor/filesystem/os/dpkg/metadata"
	"github.com/google/osv-scalibr/purl"

	genezav1 "geneza.io/internal/pb/geneza/v1"
	"geneza.io/internal/sbom"
)

// TestComponentsFromInventory checks the scalibr-package -> flat-component mapping:
// a dpkg package yields the distro-scoped OSV ecosystem and the distro identifier
// the matcher needs, and a package with no PURL type is dropped.
func TestComponentsFromInventory(t *testing.T) {
	pkgs := []*extractor.Package{
		{
			Name:     "openssl",
			Version:  "1.1.1f-1ubuntu2.16",
			PURLType: purl.TypeDebian,
			Metadata: &dpkgmeta.Metadata{
				PackageName: "openssl", PackageVersion: "1.1.1f-1ubuntu2.16",
				OSID: "ubuntu", OSVersionID: "22.04", OSVersionCodename: "jammy",
			},
		},
		{Name: "nopurl", Version: "1.0"}, // no PURLType -> no PURL -> dropped
	}
	comps := componentsFromPackages(pkgs, "os")
	if len(comps) != 1 {
		t.Fatalf("want 1 component (the PURL-less one dropped), got %d (%+v)", len(comps), comps)
	}
	c := comps[0]
	if c.Name != "openssl" || c.Version != "1.1.1f-1ubuntu2.16" {
		t.Errorf("name/version wrong: %+v", c)
	}
	if c.Ecosystem != "Ubuntu:22.04" {
		t.Errorf("ecosystem: got %q want Ubuntu:22.04", c.Ecosystem)
	}
	if c.Distro != "ubuntu:22.04" {
		t.Errorf("distro: got %q want ubuntu:22.04", c.Distro)
	}
	if c.Source != "os" {
		t.Errorf("source: got %q want os", c.Source)
	}
	// And the component round-trips through the SBOM the controller parses.
	doc, err := sbom.Encode("n", comps)
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	back, err := sbom.Extract(doc)
	if err != nil || len(back) != 1 || back[0].Ecosystem != "Ubuntu:22.04" {
		t.Fatalf("round trip: err=%v comps=%+v", err, back)
	}
}

// TestInventoryReportOnChangeOnly proves the anti-bloat reporting: the module ships
// a FULL SBOM on first collection, NOTHING on an unchanged re-collection, and a
// DELTA (added/removed against the last hash, no full SBOM) on a small change. The
// host scan is stubbed so the test is deterministic and needs no package DB.
func TestInventoryReportOnChangeOnly(t *testing.T) {
	m := &inventoryModule{log: slog.New(slog.NewTextHandler(os.Stderr, nil)), forceFull: true}

	var mu sync.Mutex
	var reports []*genezav1.InventoryReport
	m.SetReporter(func(msg *genezav1.AgentMsg) {
		if r := msg.GetInventory(); r != nil {
			mu.Lock()
			reports = append(reports, r)
			mu.Unlock()
		}
	})

	current := []sbom.Component{
		{Purl: "pkg:npm/ansi-regex@5.0.0", Name: "ansi-regex", Version: "5.0.0", Ecosystem: "npm", Source: "lang"},
	}
	m.collect = func(ctx context.Context) ([]sbom.Component, error) { return current, nil }

	reportCount := func() int { mu.Lock(); defer mu.Unlock(); return len(reports) }
	lastReport := func() *genezav1.InventoryReport { mu.Lock(); defer mu.Unlock(); return reports[len(reports)-1] }

	// First collection -> one FULL report carrying the whole SBOM.
	m.reportOnce(context.Background())
	if reportCount() != 1 {
		t.Fatalf("first collection: want 1 report, got %d", reportCount())
	}
	first := lastReport()
	if !first.GetFull() || len(first.GetSbom()) == 0 {
		t.Fatalf("first report must be a full SBOM: full=%v sbom_len=%d", first.GetFull(), len(first.GetSbom()))
	}
	h1, ok := m.InventoryHash()
	if !ok || len(h1) != 32 {
		t.Fatalf("InventoryHash after first report: ok=%v len=%d", ok, len(h1))
	}

	// Unchanged re-collection -> NO new report (steady state, hash already on heartbeat).
	m.reportOnce(context.Background())
	if reportCount() != 1 {
		t.Fatalf("unchanged re-collection must be a no-op, got %d reports", reportCount())
	}

	// Small change -> a DELTA against the prior hash: one added component, no full SBOM.
	current = append(current, sbom.Component{Purl: "pkg:npm/left-pad@1.0.0", Name: "left-pad", Version: "1.0.0", Ecosystem: "npm", Source: "lang"})
	m.reportOnce(context.Background())
	if reportCount() != 2 {
		t.Fatalf("changed inventory: want 2 reports, got %d", reportCount())
	}
	delta := lastReport()
	if delta.GetFull() || len(delta.GetSbom()) != 0 {
		t.Fatalf("a small change must ship a delta, not a full SBOM: full=%v sbom_len=%d", delta.GetFull(), len(delta.GetSbom()))
	}
	if len(delta.GetAdded()) != 1 || len(delta.GetRemoved()) != 0 {
		t.Fatalf("delta wire shape: want 1 added 0 removed, got %d added %d removed", len(delta.GetAdded()), len(delta.GetRemoved()))
	}
	if delta.GetAdded()[0].GetPurl() != "pkg:npm/left-pad@1.0.0" {
		t.Errorf("delta added the wrong component: %q", delta.GetAdded()[0].GetPurl())
	}
	// The delta names the prior hash as its base, and the new content hash moves.
	if string(delta.GetBaseHash()) != string(h1) {
		t.Errorf("delta base_hash must be the prior content hash")
	}
	h2, _ := m.InventoryHash()
	if string(h1) == string(h2) {
		t.Fatal("inventory hash must change when the inventory changes")
	}
	if string(delta.GetContentHash()) != string(h2) {
		t.Errorf("delta content_hash must be the new whole-set hash")
	}

	// A forced full resend ships the whole SBOM again even with no content change.
	m.RequestFull()
	m.reportOnce(context.Background())
	if reportCount() != 3 {
		t.Fatalf("RequestFull must ship even on an unchanged set, got %d reports", reportCount())
	}
	full := lastReport()
	if !full.GetFull() || len(full.GetSbom()) == 0 {
		t.Fatalf("forced resend must be a full SBOM: full=%v sbom_len=%d", full.GetFull(), len(full.GetSbom()))
	}
	doc, err := sbom.Decompress(full.GetSbom())
	if err != nil {
		t.Fatalf("decompress full report: %v", err)
	}
	comps, err := sbom.Extract(doc)
	if err != nil || len(comps) != 2 {
		t.Fatalf("full sbom: err=%v comps=%d", err, len(comps))
	}
	sum := sbom.Hash(doc)
	if string(sum[:]) != string(full.GetContentHash()) {
		t.Fatal("full report content hash does not match shipped sbom")
	}
}

// TestCollectKernelFromRoot proves the kernel collector reads the release from a
// scan root's /proc/version and scopes it to the distro from that root's os-release,
// emitting a component the matcher can key on (carrying the distro OSV ecosystem so
// the release compares under that distro's version rules, not the uncomparable
// generic "Linux" one).
func TestCollectKernelFromRoot(t *testing.T) {
	root := t.TempDir()
	if err := os.MkdirAll(root+"/proc", 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(root+"/etc", 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(root+"/proc/version", []byte("Linux version 6.1.0-22-amd64 (debian@debian) (gcc ...) #1 SMP\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(root+"/etc/os-release", []byte("ID=debian\nVERSION_ID=\"12\"\nPRETTY_NAME=\"Debian GNU/Linux 12\"\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	k, ok := collectKernel(root)
	if !ok {
		t.Fatal("kernel collector returned no component")
	}
	if k.Version != "6.1.0-22-amd64" {
		t.Errorf("kernel version: got %q want 6.1.0-22-amd64", k.Version)
	}
	if k.Distro != "debian:12" {
		t.Errorf("kernel distro: got %q want debian:12", k.Distro)
	}
	if k.Ecosystem != "Debian:12" {
		t.Errorf("kernel ecosystem: got %q want Debian:12 (so the release compares under Debian rules)", k.Ecosystem)
	}
	if k.Source != "kernel" || k.Name != "linux-kernel" {
		t.Errorf("kernel identity wrong: %+v", k)
	}
	if k.Purl != "pkg:generic/linux-kernel@6.1.0-22-amd64" {
		t.Errorf("kernel purl: %q", k.Purl)
	}
	// A root with no proc/version yields no kernel component (rather than a bogus one).
	if _, ok := collectKernel(t.TempDir()); ok {
		t.Error("kernel collector must yield nothing when no version is readable")
	}
}

// TestCollectLanguagesFromFixtures proves the language collector walks a scan root,
// runs osv-scalibr's leaf extractors over real lockfiles, and emits the right PURLs
// and OSV ecosystems into the flat components the controller indexes — npm from a
// package-lock.json and PyPI from a requirements.txt, all tagged source "lang".
func TestCollectLanguagesFromFixtures(t *testing.T) {
	root := t.TempDir()
	if err := os.MkdirAll(root+"/app", 0o755); err != nil {
		t.Fatal(err)
	}
	lock := `{
	  "name": "app", "version": "1.0.0", "lockfileVersion": 3,
	  "packages": {
	    "node_modules/left-pad": {"version": "1.3.0"},
	    "node_modules/ansi-regex": {"version": "5.0.0"}
	  }
	}`
	if err := os.WriteFile(root+"/app/package-lock.json", []byte(lock), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(root+"/app/requirements.txt", []byte("django==4.2.1\nrequests==2.31.0\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	m := &inventoryModule{log: slog.New(slog.NewTextHandler(os.Stderr, nil))}
	comps, err := m.collectLanguages(context.Background(), []string{root})
	if err != nil {
		t.Fatalf("collectLanguages: %v", err)
	}
	byPurl := map[string]sbom.Component{}
	for _, c := range comps {
		byPurl[c.Purl] = c
		if c.Source != "lang" {
			t.Errorf("language component must be source=lang: %+v", c)
		}
	}
	want := map[string]string{
		"pkg:npm/left-pad@1.3.0":   "npm",
		"pkg:npm/ansi-regex@5.0.0": "npm",
		"pkg:pypi/django@4.2.1":    "PyPI",
		"pkg:pypi/requests@2.31.0": "PyPI",
	}
	for purl, eco := range want {
		c, ok := byPurl[purl]
		if !ok {
			t.Errorf("missing language component %q (got %v)", purl, keysOf(byPurl))
			continue
		}
		if c.Ecosystem != eco {
			t.Errorf("%s ecosystem: got %q want %q", purl, c.Ecosystem, eco)
		}
	}
	// And the components round-trip into the CycloneDX the controller extracts.
	doc, err := sbom.Encode("n", comps)
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	back, err := sbom.Extract(doc)
	if err != nil {
		t.Fatalf("extract: %v", err)
	}
	if len(back) < len(want) {
		t.Errorf("round trip dropped components: got %d want >= %d", len(back), len(want))
	}
}

func keysOf(m map[string]sbom.Component) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}

// TestInventoryGatherHostOSPackages collects the real host's OS packages and
// asserts the SBOM is non-empty with PURLs. Gated on an env var because a build
// host may lack a package DB (the SQL tests gate on a DSN the same way).
func TestInventoryGatherHostOSPackages(t *testing.T) {
	if os.Getenv("GENEZA_TEST_HOST_INVENTORY") == "" {
		t.Skip("set GENEZA_TEST_HOST_INVENTORY=1 to scan the build host's OS packages")
	}
	m, err := newInventoryModule(slog.New(slog.NewTextHandler(os.Stderr, nil)))
	if err != nil {
		t.Fatalf("new module: %v", err)
	}
	im := m.(*inventoryModule)
	im.scanRoot = "/"
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	comps, err := im.collectHost(ctx)
	if err != nil {
		t.Fatalf("collectHost: %v", err)
	}
	if len(comps) == 0 {
		t.Fatal("host scan returned no OS packages")
	}
	doc, err := sbom.Encode("host", comps)
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	parsed, err := sbom.Extract(doc)
	if err != nil {
		t.Fatalf("extract: %v", err)
	}
	withPurl := 0
	for _, c := range parsed {
		if c.Purl != "" {
			withPurl++
		}
	}
	if withPurl == 0 {
		t.Fatal("no component carried a PURL")
	}
	t.Logf("host inventory: %d packages, %d with PURLs", len(parsed), withPurl)
}
