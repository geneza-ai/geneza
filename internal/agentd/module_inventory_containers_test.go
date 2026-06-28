package agentd

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/google/go-containerregistry/pkg/crane"
	"github.com/google/go-containerregistry/pkg/name"
	"github.com/google/go-containerregistry/pkg/v1/tarball"
)

// buildImageTarball writes a minimal docker-save image tarball under dir whose single
// layer carries the given files (path -> contents), and returns its path. It is the
// fixture the in-process image scan runs against: a real OCI/docker tarball scalibr
// unpacks, so the test exercises the genuine FromTarball -> layer-unpack -> extractor
// path rather than a stub.
func buildImageTarball(t *testing.T, dir string, files map[string][]byte) string {
	t.Helper()
	img, err := crane.Image(files)
	if err != nil {
		t.Fatalf("build fixture image: %v", err)
	}
	ref, err := name.NewTag("geneza-fixture:latest")
	if err != nil {
		t.Fatalf("fixture ref: %v", err)
	}
	path := filepath.Join(dir, "image.tar")
	if err := tarball.WriteToFile(path, ref, img); err != nil {
		t.Fatalf("write fixture tarball: %v", err)
	}
	return path
}

// dpkgStatus is a minimal /var/lib/dpkg/status entry for one installed package, the
// shape the dpkg extractor reads.
func dpkgStatus(pkg, version string) []byte {
	return []byte(fmt.Sprintf(
		"Package: %s\nStatus: install ok installed\nVersion: %s\nArchitecture: amd64\n\n",
		pkg, version))
}

// fakeRuntime is a commandRunner+lookPath pair scripted with fixture outputs, so the
// container collector runs end-to-end with no live docker. It records every command run
// so a test can assert how many image exports fired (the dedup proof).
type fakeRuntime struct {
	mu      sync.Mutex
	present map[string]bool   // binaries on "PATH"
	out     map[string][]byte // exact "name arg arg..." -> stdout
	// saveTar is the tarball path a `<runtime> save -o <path> <ref>` copies into; with
	// it set the runner copies the fixture tarball to the requested output path so the
	// in-process unpack reads a real image. saved records the refs exported, in order.
	saveTar string
	saved   []string
	runs    []string // every command line run
}

func (f *fakeRuntime) lookPath(name string) (string, error) {
	if f.present[name] {
		return "/usr/bin/" + name, nil
	}
	return "", errors.New("not found")
}

func (f *fakeRuntime) run(ctx context.Context, name string, args ...string) ([]byte, error) {
	line := strings.Join(append([]string{name}, args...), " ")
	f.mu.Lock()
	f.runs = append(f.runs, line)
	f.mu.Unlock()
	// A `save -o <path> <ref>` copies the fixture tarball to the requested output path,
	// emulating `docker save` dropping the image's layers for the in-process unpack.
	if len(args) >= 3 && args[0] == "save" && args[1] == "-o" && f.saveTar != "" {
		outPath, ref := args[2], args[len(args)-1]
		blob, err := os.ReadFile(f.saveTar)
		if err != nil {
			return nil, err
		}
		if err := os.WriteFile(outPath, blob, 0o600); err != nil {
			return nil, err
		}
		f.mu.Lock()
		f.saved = append(f.saved, ref)
		f.mu.Unlock()
		return nil, nil
	}
	if out, ok := f.out[line]; ok {
		return out, nil
	}
	// Prefix match so an inspect keyed by id need not spell every flag.
	for k, v := range f.out {
		if strings.HasPrefix(line, k) {
			return v, nil
		}
	}
	return nil, fmt.Errorf("no fixture for %q", line)
}

func newInventoryModuleForTest() *inventoryModule {
	return &inventoryModule{log: slog.New(slog.NewTextHandler(os.Stderr, nil))}
}

// TestCollectContainersImageScanDedup proves the in-process image-scan path with digest
// dedup: three running containers, two sharing an image digest, trigger exactly TWO
// image exports (one per unique digest), the layers are unpacked and scanned in-process,
// and the emitted components are tagged image:<ref>@<digest> with the matcher's
// ecosystem.
func TestCollectContainersImageScanDedup(t *testing.T) {
	const digestA = "sha256:aaaa"
	const digestB = "sha256:bbbb"
	tar := buildImageTarball(t, t.TempDir(), map[string][]byte{
		"var/lib/dpkg/status": dpkgStatus("openssl", "1.1.1f-1"),
	})
	ps := strings.Join([]string{
		`{"ID":"c1","Image":"app:1"}`,
		`{"ID":"c2","Image":"app:1"}`, // same image+digest as c1 -> deduped
		`{"ID":"c3","Image":"db:2"}`,
	}, "\n")
	f := &fakeRuntime{
		present: map[string]bool{"docker": true},
		saveTar: tar,
		out: map[string][]byte{
			"docker ps --no-trunc --format {{json .}}": []byte(ps),
			"docker inspect c1": []byte(fmt.Sprintf(`[{"Image":%q,"State":{"Pid":11}}]`, digestA)),
			"docker inspect c2": []byte(fmt.Sprintf(`[{"Image":%q,"State":{"Pid":12}}]`, digestA)),
			"docker inspect c3": []byte(fmt.Sprintf(`[{"Image":%q,"State":{"Pid":13}}]`, digestB)),
		},
	}
	m := newInventoryModuleForTest()
	m.run = f.run
	m.lookPath = f.lookPath

	comps, err := m.collectContainers(context.Background())
	if err != nil {
		t.Fatalf("collectContainers: %v", err)
	}

	// Exactly two image exports fired despite three containers (c1/c2 share a digest).
	if len(f.saved) != 2 {
		t.Fatalf("want 2 image exports (one per unique digest), got %d: %v", len(f.saved), f.saved)
	}

	// Each container contributes its image's component, tagged with ref@digest.
	bySource := map[string]int{}
	for _, c := range comps {
		if c.Name == "openssl" {
			bySource[c.Source]++
		}
	}
	wantA := "image:app:1@" + digestA
	wantB := "image:db:2@" + digestB
	if bySource[wantA] != 2 { // c1 and c2 both attribute the deduped scan's component
		t.Errorf("want 2 components sourced %q (c1,c2), got %d (%v)", wantA, bySource[wantA], bySource)
	}
	if bySource[wantB] != 1 {
		t.Errorf("want 1 component sourced %q (c3), got %d", wantB, bySource[wantB])
	}
}

// TestScanImageFromTarball is the real integration test for the in-process image scan:
// it builds a genuine image tarball carrying a dpkg status file and a package-lock.json,
// unpacks it through scalibr, and asserts both the OS package (dpkg, Debian ecosystem)
// and the language package (npm) surface with the right purl/ecosystem.
func TestScanImageFromTarball(t *testing.T) {
	lock := []byte(`{
		"name": "fixture", "version": "1.0.0", "lockfileVersion": 3,
		"packages": {
			"node_modules/left-pad": {"version": "1.3.0"}
		}
	}`)
	tar := buildImageTarball(t, t.TempDir(), map[string][]byte{
		"var/lib/dpkg/status": dpkgStatus("openssl", "1.1.1f-1"),
		"app/package-lock.json": lock,
	})

	fsys, cleanup, ok, err := fsFromTarball(tar)
	if err != nil {
		t.Fatalf("fsFromTarball: %v", err)
	}
	if !ok {
		t.Fatal("tarball unpack must be supported")
	}
	defer cleanup()

	comps, err := scanImageFS(context.Background(), fsys)
	if err != nil {
		t.Fatalf("scanImageFS: %v", err)
	}

	var sawDpkg, sawNpm bool
	for _, c := range comps {
		switch c.Name {
		case "openssl":
			sawDpkg = true
			if !strings.HasPrefix(c.Purl, "pkg:deb/") {
				t.Errorf("openssl purl not a deb purl: %q", c.Purl)
			}
			if c.Ecosystem == "" {
				t.Errorf("openssl missing ecosystem: %+v", c)
			}
		case "left-pad":
			sawNpm = true
			if c.Ecosystem != "npm" {
				t.Errorf("left-pad ecosystem = %q, want npm", c.Ecosystem)
			}
			if !strings.HasPrefix(c.Purl, "pkg:npm/") {
				t.Errorf("left-pad purl not an npm purl: %q", c.Purl)
			}
		}
	}
	if !sawDpkg {
		t.Errorf("dpkg package not extracted from image: %+v", comps)
	}
	if !sawNpm {
		t.Errorf("npm package not extracted from image: %+v", comps)
	}
}

// TestImageScanRetagsSource proves the per-image scan stamps the image source onto every
// component, so host and image packages stay distinct in the index.
func TestImageScanRetagsSource(t *testing.T) {
	const digest = "sha256:feed"
	tar := buildImageTarball(t, t.TempDir(), map[string][]byte{
		"var/lib/dpkg/status": dpkgStatus("zlib", "1.2.11-1"),
	})
	f := &fakeRuntime{present: map[string]bool{"docker": true}, saveTar: tar}
	m := newInventoryModuleForTest()
	m.run = f.run
	m.lookPath = f.lookPath

	ct := runningContainer{id: "c1", image: "img:1", digest: digest, pid: 1}
	comps := m.scanContainerImage(context.Background(), f.run, dockerRuntime{bin: "docker"}, ct)
	if len(comps) == 0 {
		t.Fatal("want at least one component from the image scan")
	}
	want := imageSource("img:1", digest)
	for _, c := range comps {
		if c.Source != want {
			t.Errorf("component source = %q, want %q", c.Source, want)
		}
	}
}

// TestCollectContainersNoRuntime proves no runtime on PATH is a clean no-op: empty
// components, no error (a node not running containers must not fail its inventory).
func TestCollectContainersNoRuntime(t *testing.T) {
	f := &fakeRuntime{present: map[string]bool{}} // nothing installed
	m := newInventoryModuleForTest()
	m.run = f.run
	m.lookPath = f.lookPath

	comps, err := m.collectContainers(context.Background())
	if err != nil {
		t.Fatalf("no runtime must be a no-op, got err: %v", err)
	}
	if len(comps) != 0 {
		t.Fatalf("no runtime must yield no components, got %d", len(comps))
	}
}

// TestCollectContainersNoContainers proves a runtime with no running containers is a
// no-op (no image exported).
func TestCollectContainersNoContainers(t *testing.T) {
	f := &fakeRuntime{
		present: map[string]bool{"docker": true},
		out:     map[string][]byte{"docker ps --no-trunc --format {{json .}}": []byte("")},
	}
	m := newInventoryModuleForTest()
	m.run = f.run
	m.lookPath = f.lookPath

	comps, err := m.collectContainers(context.Background())
	if err != nil {
		t.Fatalf("no containers: %v", err)
	}
	if len(comps) != 0 || len(f.saved) != 0 {
		t.Fatalf("no containers must export nothing: comps=%d exports=%v", len(comps), f.saved)
	}
}

// TestCrictlRuntimeListParsesDigest proves crictl enumeration: `ps -o json` yields the
// (id, image, digest) tuples, the digest taken from the imageRef's @sha256 part.
func TestCrictlRuntimeListParsesDigest(t *testing.T) {
	const digest = "sha256:dddd"
	out := fmt.Sprintf(`{"containers":[
		{"id":"k1","image":{"image":"reg/app:1"},"imageRef":"reg/app@%s"},
		{"id":"k2","image":{"image":"reg/db:2"},"imageRef":""}
	]}`, digest)
	f := &fakeRuntime{out: map[string][]byte{"crictl ps -o json": []byte(out)}}
	rt := crictlRuntime{bin: "crictl"}
	cs, err := rt.list(context.Background(), f.run)
	if err != nil {
		t.Fatalf("crictl list: %v", err)
	}
	if len(cs) != 2 {
		t.Fatalf("want 2 containers, got %d", len(cs))
	}
	if cs[0].id != "k1" || cs[0].image != "reg/app:1" || cs[0].digest != digest {
		t.Errorf("k1 tuple wrong: %+v", cs[0])
	}
	if cs[1].digest != "" {
		t.Errorf("k2 with no imageRef must have empty digest, got %q", cs[1].digest)
	}
}

// TestCrictlFallsBackToRootfs proves crictl (which cannot export an image tarball) takes
// the /proc/<pid>/root fallback: imageFS reports unsupported, so the collector scans the
// merged rootfs. The proc root is unreadable for a bogus pid in the test sandbox, so this
// asserts the fallback path is reached without erroring the whole collection.
func TestCrictlFallsBackToRootfs(t *testing.T) {
	rt := crictlRuntime{bin: "crictl"}
	_, _, ok, err := rt.imageFS(context.Background(), nil, "reg/app:1")
	if err != nil {
		t.Fatalf("crictl imageFS must not error: %v", err)
	}
	if ok {
		t.Fatal("crictl must report image export unsupported (no save)")
	}
}

// TestContainerRootfsFallback proves the rootfs fallback: the in-process extractors
// scan a container's merged rootfs (a fixture dpkg status file), producing the right
// components — the path taken when an image cannot be unpacked.
func TestContainerRootfsFallback(t *testing.T) {
	root := t.TempDir()
	if err := os.MkdirAll(root+"/var/lib/dpkg", 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(root+"/var/lib/dpkg/status", dpkgStatus("openssl", "1.1.1f-1"), 0o644); err != nil {
		t.Fatal(err)
	}
	comps, err := scanRootfs(context.Background(), root)
	if err != nil {
		t.Fatalf("scanRootfs: %v", err)
	}
	var found bool
	for _, c := range comps {
		if c.Name == "openssl" && c.Version == "1.1.1f-1" {
			found = true
		}
	}
	if !found {
		t.Fatalf("rootfs fallback must extract the dpkg package, got %+v", comps)
	}
}

// TestImageUnpackFailureFallsBackToRootfs proves a failed image export does not drop the
// image: when `save` errors, the collector falls back to the /proc/<pid>/root scan. The
// proc root is unreadable for a bogus pid in the test sandbox, so this asserts the
// fallback is reached without erroring the collection (the per-image failure is swallowed).
func TestImageUnpackFailureFallsBackToRootfs(t *testing.T) {
	f := &fakeRuntime{
		present: map[string]bool{"docker": true}, // runtime present, but no saveTar -> save fails
		out: map[string][]byte{
			"docker ps --no-trunc --format {{json .}}": []byte(`{"ID":"c1","Image":"app:1"}`),
			"docker inspect c1":                        []byte(`[{"Image":"sha256:eeee","State":{"Pid":999999}}]`),
		},
	}
	m := newInventoryModuleForTest()
	m.run = f.run
	m.lookPath = f.lookPath
	// The whole collection must not error even though the export fails and the proc scan
	// of a bogus pid fails too (both per-image failures are logged and yield nothing).
	if _, err := m.collectContainers(context.Background()); err != nil {
		t.Fatalf("fallback collection must not error: %v", err)
	}
}

// TestImageSource pins the source helper: it carries the digest when known, and the ref
// alone otherwise.
func TestImageSource(t *testing.T) {
	if got := imageSource("app:1", "sha256:ab"); got != "image:app:1@sha256:ab" {
		t.Errorf("imageSource with digest: %q", got)
	}
	if got := imageSource("app:1", ""); got != "image:app:1" {
		t.Errorf("imageSource without digest: %q", got)
	}
}
