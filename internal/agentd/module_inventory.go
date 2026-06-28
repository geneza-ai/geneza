package agentd

import (
	"context"
	"crypto/sha256"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	cpb "github.com/google/osv-scalibr/binary/proto/config_go_proto"
	"github.com/google/osv-scalibr/extractor"
	"github.com/google/osv-scalibr/extractor/filesystem"
	"github.com/google/osv-scalibr/extractor/filesystem/language/golang/gomod"
	"github.com/google/osv-scalibr/extractor/filesystem/language/javascript/packagejson"
	"github.com/google/osv-scalibr/extractor/filesystem/language/javascript/packagelockjson"
	"github.com/google/osv-scalibr/extractor/filesystem/language/python/requirements"
	"github.com/google/osv-scalibr/extractor/filesystem/language/python/wheelegg"
	"github.com/google/osv-scalibr/extractor/filesystem/language/ruby/gemfilelock"
	"github.com/google/osv-scalibr/extractor/filesystem/os/apk"
	apkmeta "github.com/google/osv-scalibr/extractor/filesystem/os/apk/metadata"
	"github.com/google/osv-scalibr/extractor/filesystem/os/dpkg"
	dpkgmeta "github.com/google/osv-scalibr/extractor/filesystem/os/dpkg/metadata"
	"github.com/google/osv-scalibr/extractor/filesystem/os/rpm"
	rpmmeta "github.com/google/osv-scalibr/extractor/filesystem/os/rpm/metadata"
	scalibrfs "github.com/google/osv-scalibr/fs"
	"github.com/google/osv-scalibr/stats"
	"golang.org/x/sys/unix"

	genezav1 "geneza.io/internal/pb/geneza/v1"
	"geneza.io/internal/sbom"
)

// inventoryModule collects the host's software inventory into a CycloneDX SBOM and
// reports it up the control stream when it changes. It reuses osv-scalibr's
// in-process extractors — the same library the controller matcher uses to compare
// versions — so the collected ecosystem strings and the matcher's expectations
// cannot drift, and the agent pulls in no separate SBOM toolchain: OS packages
// (dpkg/rpm/apk), language dependencies (npm/PyPI/Go/... from lockfiles + installed
// metadata), and the running kernel (uname/proc/version as a generic component).
//
// It does not produce Prometheus metrics: Gather returns nothing, and the module
// ships its own InventoryReport arm through the reporter hook, off the capped
// metrics path. Reporting is anti-bloat in two stages: every cycle re-collects, but
// nothing ships while the content hash is unchanged (the heartbeat already carries
// it); when the set DOES change, only the difference ships — a delta of the
// added/removed components against the last controller-acked hash — and the whole SBOM
// is sent only on the first report or when the controller lost the delta's base.
type inventoryModule struct {
	log     *slog.Logger
	collect func(ctx context.Context) ([]sbom.Component, error) // host scan; swappable in tests

	mu        sync.Mutex
	enqueue   func(*genezav1.AgentMsg)
	scanRoot  string
	langRoots []string
	// scanContainers gates the running-container image scan (off by default): with it
	// set the collector enumerates running containers and scans each unique image
	// digest once. run/lookPath are the exec seams the container path shells out
	// through (the runtime CLI, to enumerate containers and export their images),
	// swappable in tests; nil means the real os/exec.
	scanContainers bool
	run            commandRunner
	lookPath       func(string) (string, error)
	lastHash       [32]byte
	haveHash       bool
	// lastSet is the component set the controller holds under lastHash, kept so a small
	// change ships as a delta (the diff against this set) rather than the whole SBOM.
	lastSet []sbom.Component
	// forceFull makes the next report a FULL SBOM regardless of how small the change
	// is. It is set on the first cycle (no base yet) and whenever the controller could
	// not apply our last delta and asked for a resend.
	forceFull bool
}

func newInventoryModule(log *slog.Logger) (Module, error) {
	m := &inventoryModule{log: log.With("module", "inventory"), forceFull: true}
	m.collect = m.collectHost
	return m, nil
}

func (m *inventoryModule) Name() string { return "inventory" }

// SetReporter wires the control-stream enqueue so the module ships its SBOM itself.
func (m *inventoryModule) SetReporter(enqueue func(*genezav1.AgentMsg)) {
	m.mu.Lock()
	m.enqueue = enqueue
	m.mu.Unlock()
}

// Start records the scan roots and runs the collect-and-report loop: an immediate
// report so a freshly enabled module converges without waiting a full interval,
// then a re-collection every interval (a changed inventory ships, an unchanged one
// is a no-op). settings["scan_root"] overrides the OS-package + kernel root (the host
// fs by default; a test or a containerized agent can point it elsewhere);
// settings["lang_scan_roots"] is a comma-separated list of directories to walk for
// language dependencies (default none — language collection is opt-in because the
// trees worth scanning are deployment-specific, e.g. /opt or an app root);
// settings["scan_containers"] (off by default) turns on the running-container image
// scan — enumerate the running containers and scan each unique image digest once;
// settings["scan_interval_seconds"] overrides the cadence.
func (m *inventoryModule) Start(ctx context.Context, settings map[string]string) error {
	root := strings.TrimSpace(settings["scan_root"])
	if root == "" {
		root = "/"
	}
	m.mu.Lock()
	m.scanRoot = root
	m.langRoots = splitRoots(settings["lang_scan_roots"])
	m.scanContainers = boolSetting(settings["scan_containers"])
	m.mu.Unlock()
	go m.reportLoop(ctx, inventoryInterval(settings))
	return nil
}

// boolSetting reads a module setting as a boolean: "1"/"true"/"yes"/"on" enable it
// (case-insensitive), everything else (including empty) leaves it off. Off-by-default
// keeps a legacy node byte-for-byte until an operator opts in.
func boolSetting(v string) bool {
	switch strings.ToLower(strings.TrimSpace(v)) {
	case "1", "true", "yes", "on":
		return true
	}
	return false
}

// splitRoots parses a comma-separated list of scan roots, trimming blanks.
func splitRoots(v string) []string {
	var out []string
	for _, r := range strings.Split(v, ",") {
		if r = strings.TrimSpace(r); r != "" {
			out = append(out, r)
		}
	}
	return out
}

// inventoryInterval is the re-collection cadence: hours-scale by default (an SBOM
// rarely changes between package operations), overridable for tests/eventing.
func inventoryInterval(settings map[string]string) time.Duration {
	if v := strings.TrimSpace(settings["scan_interval_seconds"]); v != "" {
		if d, err := time.ParseDuration(v + "s"); err == nil && d >= time.Second {
			return d
		}
	}
	return 6 * time.Hour
}

// reportLoop reports immediately and then on each tick until the module ctx is
// cancelled.
func (m *inventoryModule) reportLoop(ctx context.Context, interval time.Duration) {
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		m.reportOnce(ctx)
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}

func (m *inventoryModule) Stop() {}

// InventoryHash is the content hash of the last collected SBOM, for the heartbeat.
// ok is false until the first collection succeeds.
func (m *inventoryModule) InventoryHash() ([]byte, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if !m.haveHash {
		return nil, false
	}
	h := m.lastHash
	return h[:], true
}

// Gather produces no Prometheus metrics: the inventory rides its own report arm.
func (m *inventoryModule) Gather() ([]byte, error) { return nil, nil }

// RequestFull arms the next report to ship a full SBOM. The worker calls this when
// the controller sends an InventoryControl asking for a resend, because it could not
// apply our last delta (it holds no SBOM for this node, or a base different from the
// one the delta named). The next cycle re-syncs both ends on a known-good full set.
func (m *inventoryModule) RequestFull() {
	m.mu.Lock()
	m.forceFull = true
	m.mu.Unlock()
}

// reportOnce collects the inventory and ships the change since the last successful
// report. Nothing ships while the content hash is unchanged (the heartbeat already
// carries it). On a change it sends a DELTA — only the added/removed components vs
// the last controller-acked set — unless this is the first report or the controller asked
// for a full resend, in which case it sends the whole SBOM. A delta is also widened
// to a full when its changed portion is no smaller than re-sending everything (a mass
// upgrade), so the wire never carries a delta bigger than the full it replaces. A
// collection error is logged and skipped — a transient scan failure must not wedge
// the module or drop a previously good inventory.
func (m *inventoryModule) reportOnce(ctx context.Context) {
	comps, err := m.collect(ctx)
	if err != nil {
		m.log.Warn("inventory collection failed", "err", err)
		return
	}
	doc, err := sbom.Encode(m.nodeRef(), comps)
	if err != nil {
		m.log.Warn("inventory encode failed", "err", err)
		return
	}
	hash := sha256.Sum256(doc)

	m.mu.Lock()
	full := m.forceFull || !m.haveHash
	// Steady state ships nothing: the heartbeat hash already reflects this set. A
	// forced full resend is the exception — the controller lost our base and asked for
	// the whole SBOM, so we re-ship even when the content did not change.
	unchanged := m.haveHash && hash == m.lastHash && !m.forceFull
	enqueue := m.enqueue
	base := m.lastHash
	baseSet := m.lastSet
	m.mu.Unlock()
	if unchanged {
		return
	}
	if enqueue == nil {
		// No control stream wired yet (module started before the reporter hook); the
		// next cycle re-collects and ships once it is.
		return
	}

	rep := &genezav1.InventoryReport{
		Format:        sbom.MediaType,
		ContentHash:   hash[:],
		CollectedUnix: time.Now().Unix(),
	}
	added, removed := sbom.Diff(baseSet, comps)
	// A delta only pays off when fewer components changed than the whole set carries;
	// otherwise (a near-total churn) sending the full SBOM is smaller and simpler.
	if full || len(added)+len(removed) >= len(comps) {
		blob, cerr := sbom.Compress(doc)
		if cerr != nil {
			m.log.Warn("inventory compress failed", "err", cerr)
			return
		}
		rep.Full = true
		rep.Sbom = blob
	} else {
		rep.BaseHash = base[:]
		rep.Added = inventoryComponentsProto(added)
		rep.Removed = inventoryComponentsProto(removed)
	}
	enqueue(&genezav1.AgentMsg{Msg: &genezav1.AgentMsg_Inventory{Inventory: rep}})

	m.mu.Lock()
	m.lastHash = hash
	m.haveHash = true
	m.lastSet = comps
	m.forceFull = false
	m.mu.Unlock()
	if rep.Full {
		m.log.Info("inventory reported (full)", "components", len(comps), "compressed_bytes", len(rep.GetSbom()))
	} else {
		m.log.Info("inventory reported (delta)", "components", len(comps), "added", len(added), "removed", len(removed))
	}
}

// inventoryComponentsProto maps the flat components into the delta's wire shape.
func inventoryComponentsProto(comps []sbom.Component) []*genezav1.InventoryComponent {
	out := make([]*genezav1.InventoryComponent, 0, len(comps))
	for _, c := range comps {
		out = append(out, &genezav1.InventoryComponent{
			Purl:      c.Purl,
			Name:      c.Name,
			Version:   c.Version,
			Ecosystem: c.Ecosystem,
			Distro:    c.Distro,
			Source:    c.Source,
		})
	}
	return out
}

// nodeRef is the subject name recorded in the SBOM metadata. The controller binds the
// stored SBOM to the authenticated node regardless, so this is descriptive only.
func (m *inventoryModule) nodeRef() string { return "node" }

// collectHost gathers the node's whole software inventory: OS packages (over the
// scan root), language dependencies (over the configured language roots), and the
// running kernel. Each source maps into the same flat component the controller indexes;
// the report path treats them uniformly, distinguished only by the component Source.
func (m *inventoryModule) collectHost(ctx context.Context) ([]sbom.Component, error) {
	m.mu.Lock()
	root := m.scanRoot
	langRoots := append([]string(nil), m.langRoots...)
	scanContainers := m.scanContainers
	m.mu.Unlock()

	comps, err := m.collectOSPackages(ctx, root)
	if err != nil {
		return nil, err
	}
	if len(langRoots) > 0 {
		lang, lerr := m.collectLanguages(ctx, langRoots)
		if lerr != nil {
			// A language-tree scan failure must not drop the OS inventory that already
			// collected; log and continue with what we have.
			m.log.Warn("language inventory collection failed", "err", lerr)
		} else {
			comps = append(comps, lang...)
		}
	}
	if k, ok := collectKernel(root); ok {
		comps = append(comps, k)
	}
	if scanContainers {
		images, ierr := m.collectContainers(ctx)
		if ierr != nil {
			// A container scan failure (no runtime, image-unpack error) must not drop the
			// host inventory that already collected; log and continue with what we have.
			m.log.Warn("container image inventory collection failed", "err", ierr)
		} else {
			comps = append(comps, images...)
		}
	}
	return comps, nil
}

// dirsToSkip is the set the host walk never descends into: kernel/synthetic
// filesystems with no packages, plus the runtime dir. Bounds a whole-host walk to
// real on-disk package metadata.
var dirsToSkip = []string{"/proc", "/sys", "/dev", "/run"}

// skipDirsUnder returns the subset of dirsToSkip that actually lives under root, so a
// language scan rooted at an app dir does not pass scalibr an absolute skip path
// outside the scan root (which it rejects). For the host root it returns them all.
func skipDirsUnder(root string) []string {
	root = filepath.Clean(root)
	if root == "/" {
		return dirsToSkip
	}
	var out []string
	for _, d := range dirsToSkip {
		if d == root || strings.HasPrefix(d, root+string(filepath.Separator)) {
			out = append(out, d)
		}
	}
	return out
}

// osPackageExtractors builds the OS-package extractor set (dpkg/rpm/apk) the host and
// image scans share — the distro-backport surface the matcher most needs. Keeping one
// builder means a Debian, RPM, or Alpine target is covered identically wherever the set
// is run, so the host SBOM and an image SBOM cannot drift on which package types they see.
func osPackageExtractors() ([]filesystem.Extractor, error) {
	cfg := &cpb.PluginConfig{}
	dpkgExtractor, err := dpkg.New(cfg)
	if err != nil {
		return nil, fmt.Errorf("dpkg extractor: %w", err)
	}
	rpmExtractor, err := rpm.New(cfg)
	if err != nil {
		return nil, fmt.Errorf("rpm extractor: %w", err)
	}
	apkExtractor, err := apk.New(cfg)
	if err != nil {
		return nil, fmt.Errorf("apk extractor: %w", err)
	}
	return []filesystem.Extractor{dpkgExtractor, rpmExtractor, apkExtractor}, nil
}

// collectOSPackages runs the dpkg/rpm/apk extractors over root — the distro-backport
// surface the matcher most needs.
func (m *inventoryModule) collectOSPackages(ctx context.Context, root string) ([]sbom.Component, error) {
	exts, err := osPackageExtractors()
	if err != nil {
		return nil, err
	}
	inv, _, err := filesystem.Run(ctx, &filesystem.Config{
		Extractors: exts,
		ScanRoots:  scalibrfs.RealFSScanRoots(root),
		// The walker requires a metric sink; we record none.
		Stats:      stats.NoopCollector{},
		DirsToSkip: dirsToSkip,
	})
	if err != nil {
		return nil, fmt.Errorf("scan os packages under %s: %w", root, err)
	}
	return componentsFromPackages(inv.Packages, "os"), nil
}

// languageExtractors are the osv-scalibr language extractors the language scan runs:
// lockfiles AND installed-package metadata for the common ecosystems (npm, PyPI, Go,
// Ruby). The agent reuses scalibr's extractors so the PURLs match the controller's OSV
// ecosystems rather than parsing any lockfile format itself. They are imported as
// individual leaf packages, NOT through scalibr's extractor catalog, which would drag
// in the container-image, qcow2, and Maven/deps.dev trees the inventory never needs.
func languageExtractors() ([]filesystem.Extractor, error) {
	cfg := &cpb.PluginConfig{}
	npmLock, err := packagelockjson.New(cfg)
	if err != nil {
		return nil, err
	}
	npmPkg, err := packagejson.New(cfg)
	if err != nil {
		return nil, err
	}
	pyReq, err := requirements.New(cfg)
	if err != nil {
		return nil, err
	}
	pyWheel, err := wheelegg.New(cfg)
	if err != nil {
		return nil, err
	}
	goMod, err := gomod.New(cfg)
	if err != nil {
		return nil, err
	}
	rubyGems, err := gemfilelock.New(cfg)
	if err != nil {
		return nil, err
	}
	return []filesystem.Extractor{npmLock, npmPkg, pyReq, pyWheel, goMod, rubyGems}, nil
}

// collectLanguages walks the configured roots with the language extractor set and
// maps the found dependencies into components. The walk is bounded by the same skip
// set as the OS scan, and only runs over the roots an operator opted into (an app
// dir, /opt, ...) rather than the whole host, since language trees are deployment-
// specific and a blind whole-host walk is expensive.
func (m *inventoryModule) collectLanguages(ctx context.Context, roots []string) ([]sbom.Component, error) {
	exts, err := languageExtractors()
	if err != nil {
		return nil, fmt.Errorf("build language extractors: %w", err)
	}
	var comps []sbom.Component
	for _, r := range roots {
		// Each root is scanned on its own so an absolute skip path (the synthetic
		// kernel filesystems) is expressed relative to that root, and a root that
		// happens to be the host root still skips them. scalibr rejects a DirsToSkip
		// entry that is not under the scan root, so the set is filtered per root.
		inv, _, err := filesystem.Run(ctx, &filesystem.Config{
			Extractors: exts,
			ScanRoots:  scalibrfs.RealFSScanRoots(r),
			Stats:      stats.NoopCollector{},
			DirsToSkip: skipDirsUnder(r),
		})
		if err != nil {
			return nil, fmt.Errorf("scan language deps under %s: %w", r, err)
		}
		comps = append(comps, componentsFromPackages(inv.Packages, "lang")...)
	}
	return comps, nil
}

// componentsFromPackages maps scalibr packages into the flat SBOM components,
// taking the OSV ecosystem and PURL from scalibr directly (so they match the
// matcher's expectations) and the distro from the package metadata. source records
// the collection origin ("os", "lang") so the controller keys two origins of the same
// purl apart.
func componentsFromPackages(pkgs []*extractor.Package, source string) []sbom.Component {
	out := make([]sbom.Component, 0, len(pkgs))
	for _, p := range pkgs {
		if p == nil {
			continue
		}
		pu := p.PURL()
		if pu == nil {
			continue
		}
		out = append(out, sbom.Component{
			Purl:      pu.String(),
			Name:      p.Name,
			Version:   p.Version,
			Ecosystem: p.Ecosystem().String(),
			Distro:    distroOf(p.Metadata),
			Source:    source,
		})
	}
	return out
}

// distroOf builds the distro identifier ("ubuntu:22.04") from a package's metadata.
// Each OS package type carries its own metadata shape, so it type-switches over the
// ones the OS extractors emit; an unknown shape yields no distro (the ecosystem
// already carries the distro-scoped family for matching).
func distroOf(meta any) string {
	switch md := meta.(type) {
	case *dpkgmeta.Metadata:
		return joinDistro(md.OSID, md.OSVersionID)
	case *rpmmeta.Metadata:
		return joinDistro(md.OSID, md.OSVersionID)
	case *apkmeta.Metadata:
		return joinDistro(md.OSID, md.OSVersionID)
	}
	return ""
}

func joinDistro(osID, versionID string) string {
	osID, versionID = strings.TrimSpace(osID), strings.TrimSpace(versionID)
	if osID == "" {
		return ""
	}
	if versionID == "" {
		return osID
	}
	return osID + ":" + versionID
}

// collectKernel emits a component for the RUNNING kernel so the engine can match
// kernel advisories. scalibr's kernel extractors read a boot image or module files,
// which need not be the kernel actually running; the running release is what an
// advisory applies to, and it comes from uname (or, when scanning a non-host root,
// that root's /proc/version). It rides as pkg:generic/linux-kernel@<release> but is
// tagged with the DISTRO's OSV ecosystem ("Debian:12", ...) so the matcher compares
// the release with that distro's native version rules and resolves the distro's
// backported kernel advisories — the running release (e.g. 6.1.0-22) is a distro
// version, not an upstream one, and the generic "Linux" ecosystem has no comparator.
// ok is false when no kernel version could be read (e.g. a non-Linux build host).
func collectKernel(root string) (sbom.Component, bool) {
	release := kernelRelease(root)
	if release == "" {
		return sbom.Component{}, false
	}
	distro := osReleaseDistro(root)
	return sbom.Component{
		Purl:      "pkg:generic/linux-kernel@" + release,
		Name:      "linux-kernel",
		Version:   release,
		Ecosystem: osvEcosystemForDistro(distro),
		Distro:    distro,
		Source:    "kernel",
	}, true
}

// osvEcosystemForDistro maps a distro identifier ("ubuntu:22.04") to its OSV
// ecosystem string ("Ubuntu:22.04"), so a kernel component compares under that
// distro's version rules. An unmapped or empty distro yields an empty ecosystem,
// which the controller then derives from the PURL (none here) — i.e. the kernel is
// recorded but unmatched, never mis-compared under a wrong ruleset.
func osvEcosystemForDistro(distro string) string {
	id, ver, _ := strings.Cut(distro, ":")
	family := map[string]string{
		"debian":    "Debian",
		"ubuntu":    "Ubuntu",
		"alpine":    "Alpine",
		"rhel":      "Red Hat",
		"rocky":     "Rocky Linux",
		"alma":      "AlmaLinux",
		"almalinux": "AlmaLinux",
		"suse":      "SUSE",
		"opensuse":  "openSUSE",
	}[strings.ToLower(strings.TrimSpace(id))]
	if family == "" {
		return ""
	}
	if ver = strings.TrimSpace(ver); ver == "" {
		return family
	}
	return family + ":" + ver
}

// kernelRelease returns the running kernel release string. For the host root it asks
// the kernel directly (uname); for a scan root pointed elsewhere it reads that root's
// /proc/version so a test or containerized scan is deterministic and hermetic.
func kernelRelease(root string) string {
	if root != "" && root != "/" {
		return releaseFromProcVersion(filepath.Join(root, "proc", "version"))
	}
	var uts unix.Utsname
	if err := unix.Uname(&uts); err != nil {
		return ""
	}
	return unix.ByteSliceToString(uts.Release[:])
}

// releaseFromProcVersion parses the kernel release (the third whitespace field) from
// a /proc/version file's contents, e.g. "Linux version 6.1.0-21-amd64 (...) ..." ->
// "6.1.0-21-amd64". Empty when the file is absent or unparseable.
func releaseFromProcVersion(path string) string {
	b, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	fields := strings.Fields(string(b))
	if len(fields) < 3 {
		return ""
	}
	return fields[2]
}

// osReleaseDistro reads "<id>:<version_id>" from a root's /etc/os-release so the
// kernel component carries the same distro scope the OS packages do. Empty when the
// file is absent or carries no ID.
func osReleaseDistro(root string) string {
	if root == "" {
		root = "/"
	}
	b, err := os.ReadFile(filepath.Join(root, "etc", "os-release"))
	if err != nil {
		return ""
	}
	var id, versionID string
	for _, line := range strings.Split(string(b), "\n") {
		k, v, ok := strings.Cut(strings.TrimSpace(line), "=")
		if !ok {
			continue
		}
		v = strings.Trim(v, `"'`)
		switch k {
		case "ID":
			id = v
		case "VERSION_ID":
			versionID = v
		}
	}
	return joinDistro(id, versionID)
}
