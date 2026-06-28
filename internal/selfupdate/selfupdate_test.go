package selfupdate

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"geneza.io/internal/defaults"
	"geneza.io/internal/releasetrust"
	"geneza.io/internal/types"
)

// makeTarGz builds a geneza_<os>_<arch>.tar.gz containing geneza_<os>_<arch>/geneza
// (plus a sibling binary, to prove extraction picks the right one).
func makeTarGz(t *testing.T, goos, goarch string, clientContent []byte) []byte {
	t.Helper()
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)
	dir := fmt.Sprintf("geneza_%s_%s", goos, goarch)
	add := func(name string, content []byte) {
		if err := tw.WriteHeader(&tar.Header{Name: dir + "/" + name, Mode: 0o755, Size: int64(len(content)), Typeflag: tar.TypeReg}); err != nil {
			t.Fatal(err)
		}
		if _, err := tw.Write(content); err != nil {
			t.Fatal(err)
		}
	}
	add("geneza-controller", []byte("not the client")) // sibling must be ignored
	add("geneza", clientContent)
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := gz.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func sha256hex(b []byte) string {
	s := sha256.Sum256(b)
	return hex.EncodeToString(s[:])
}

// mockGitHub serves the release API and the asset downloads for one release.
func mockGitHub(t *testing.T, tag, goos, goarch string, archive []byte, corruptSums bool) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()
	srv := httptest.NewServer(mux)

	archName := archiveName(goos, goarch)
	sum := sha256hex(archive)
	if corruptSums {
		sum = strings.Repeat("0", 64)
	}
	sums := fmt.Sprintf("%s  %s\n%s  %s.sha256\n", sum, archName, sha256hex([]byte("x")), archName)

	mux.HandleFunc("/dl/"+archName, func(w http.ResponseWriter, _ *http.Request) { w.Write(archive) })
	mux.HandleFunc("/dl/"+checksumManifest, func(w http.ResponseWriter, _ *http.Request) { w.Write([]byte(sums)) })

	rel := Release{
		TagName: tag,
		Assets: []Asset{
			{Name: archName, URL: srv.URL + "/dl/" + archName},
			{Name: archName + ".sha256", URL: srv.URL + "/dl/ignored"},
			{Name: checksumManifest, URL: srv.URL + "/dl/" + checksumManifest},
		},
	}
	body, _ := json.Marshal(rel)
	mux.HandleFunc("/repos/"+RepoSlug+"/releases/latest", func(w http.ResponseWriter, _ *http.Request) { w.Write(body) })
	mux.HandleFunc("/repos/"+RepoSlug+"/releases/tags/"+tag, func(w http.ResponseWriter, _ *http.Request) { w.Write(body) })
	return srv
}

func withAPIBase(t *testing.T, base string) {
	t.Helper()
	old := apiBase
	apiBase = base
	t.Cleanup(func() { apiBase = old })
}

func TestApplyRoundTrip(t *testing.T) {
	const goos, goarch = "linux", "amd64"
	newContent := []byte("#!/genuine new geneza binary v0.2.0\n" + strings.Repeat("payload", 100))
	archive := makeTarGz(t, goos, goarch, newContent)
	srv := mockGitHub(t, "v0.2.0", goos, goarch, archive, false)
	defer srv.Close()
	withAPIBase(t, srv.URL)

	// Stand in a fake "installed" binary in a temp dir; Apply replaces it in place.
	dir := t.TempDir()
	exe := filepath.Join(dir, "geneza")
	if err := os.WriteFile(exe, []byte("OLD v0.1.0"), 0o755); err != nil {
		t.Fatal(err)
	}
	// installOver resolves os.Executable(); point Apply at our fake by overriding
	// the package's exe resolution via a symlink the test controls is overkill —
	// instead exercise installOver directly plus the network/verify path.
	rel, err := LatestRelease(context.Background())
	if err != nil {
		t.Fatalf("LatestRelease: %v", err)
	}
	if rel.TagName != "v0.2.0" {
		t.Fatalf("tag = %s", rel.TagName)
	}

	// Drive the download+verify+extract path, then the atomic install, against
	// our controlled exe path (Apply uses os.Executable, which in `go test` is
	// the test binary — so verify the pieces with the real archive bytes).
	sums, err := download(context.Background(), srv.Client(), rel.Assets[2].URL, 1<<20)
	if err != nil {
		t.Fatalf("download sums: %v", err)
	}
	want, err := lookupChecksum(sums, archiveName(goos, goarch))
	if err != nil {
		t.Fatalf("lookupChecksum: %v", err)
	}
	if err := verifySHA256(archive, want, archiveName(goos, goarch)); err != nil {
		t.Fatalf("verifySHA256: %v", err)
	}
	got, err := binaryFromTarGz(archive, "geneza_"+goos+"_"+goarch+"/"+clientBinary)
	if err != nil {
		t.Fatalf("extract: %v", err)
	}
	if !bytes.Equal(got, newContent) {
		t.Fatalf("extracted wrong binary (got %d bytes, want %d)", len(got), len(newContent))
	}
	if err := installOver(exe, got); err != nil {
		t.Fatalf("installOver: %v", err)
	}
	after, _ := os.ReadFile(exe)
	if !bytes.Equal(after, newContent) {
		t.Fatalf("exe not replaced with new content")
	}
	if info, _ := os.Stat(exe); info.Mode().Perm()&0o100 == 0 {
		t.Fatalf("replaced binary is not executable: %v", info.Mode())
	}
}

func TestApplyRejectsTamperedChecksum(t *testing.T) {
	const goos, goarch = "linux", "amd64"
	archive := makeTarGz(t, goos, goarch, []byte("payload"))
	srv := mockGitHub(t, "v0.2.0", goos, goarch, archive, true /* corrupt SHA256SUMS */)
	defer srv.Close()
	withAPIBase(t, srv.URL)

	rel, err := LatestRelease(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	// The full Apply path runs against os.Executable() (the test binary); we must
	// not let it actually replace that, so assert the verify gate trips first by
	// checking the digest directly with the corrupted manifest.
	sums, err := download(context.Background(), srv.Client(), rel.Assets[2].URL, 1<<20)
	if err != nil {
		t.Fatal(err)
	}
	want, err := lookupChecksum(sums, archiveName(goos, goarch))
	if err != nil {
		t.Fatal(err)
	}
	if err := verifySHA256(archive, want, archiveName(goos, goarch)); err == nil {
		t.Fatal("expected checksum mismatch to be rejected, got nil")
	}
}

func TestApplyMissingPlatformAsset(t *testing.T) {
	archive := makeTarGz(t, "linux", "amd64", []byte("x"))
	srv := mockGitHub(t, "v0.2.0", "linux", "amd64", archive, false)
	defer srv.Close()
	withAPIBase(t, srv.URL)
	rel, _ := LatestRelease(context.Background())
	// Ask for a platform the release doesn't carry.
	_, err := Apply(context.Background(), rel, Options{GOOS: "plan9", GOARCH: "mips"})
	if err == nil || !strings.Contains(err.Error(), "no build for plan9/mips") {
		t.Fatalf("err = %v, want missing-asset error", err)
	}
}

func TestLookupChecksumFailClosed(t *testing.T) {
	if _, err := lookupChecksum([]byte("deadbeef  someother.tar.gz\n"), "geneza_linux_amd64.tar.gz"); err == nil {
		t.Fatal("expected error when the manifest lacks our asset")
	}
}

func TestLookupChecksumRejectsMalformedDigest(t *testing.T) {
	// Right filename, but the digest is not 64 hex chars — fail closed.
	if _, err := lookupChecksum([]byte("notahash  geneza_linux_amd64.tar.gz\n"), "geneza_linux_amd64.tar.gz"); err == nil {
		t.Fatal("expected malformed-digest rejection")
	}
}

func TestExtractAnchorsCanonicalPath(t *testing.T) {
	// A regular file named "geneza" but NOT at geneza_<os>_<arch>/geneza must
	// not be accepted (no bare-basename-anywhere match).
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)
	body := []byte("evil")
	_ = tw.WriteHeader(&tar.Header{Name: "elsewhere/geneza", Mode: 0o755, Size: int64(len(body)), Typeflag: tar.TypeReg})
	tw.Write(body)
	tw.Close()
	gz.Close()
	if _, err := binaryFromTarGz(buf.Bytes(), "geneza_linux_amd64/geneza"); err == nil {
		t.Fatal("expected miss: geneza outside the canonical dir must not match")
	}
}

func TestExtractRejectsSymlinkEntry(t *testing.T) {
	// A symlink entry at the canonical path must be rejected, not followed.
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)
	_ = tw.WriteHeader(&tar.Header{Name: "geneza_linux_amd64/geneza", Mode: 0o777, Typeflag: tar.TypeSymlink, Linkname: "/etc/passwd"})
	tw.Close()
	gz.Close()
	if _, err := binaryFromTarGz(buf.Bytes(), "geneza_linux_amd64/geneza"); err == nil {
		t.Fatal("expected symlink entry to be rejected")
	}
}

func TestInstallOverLockBlocksConcurrent(t *testing.T) {
	dir := t.TempDir()
	exe := filepath.Join(dir, "geneza")
	if err := os.WriteFile(exe, []byte("old"), 0o755); err != nil {
		t.Fatal(err)
	}
	// Hold the lock, then a concurrent install must fail fast.
	rel, err := lockUpdate(exe)
	if err != nil {
		t.Fatalf("lockUpdate: %v", err)
	}
	defer rel()
	if err := installOver(exe, []byte("new")); err == nil || !strings.Contains(err.Error(), "in progress") {
		t.Fatalf("concurrent install err = %v, want in-progress", err)
	}
}

func TestVersionLogic(t *testing.T) {
	cases := []struct {
		name            string
		latest, current string
		upToDate, newer bool
	}{
		{"equal", "v0.2.0", "0.2.0", true, false},
		{"equal-with-v", "v0.2.0", "v0.2.0", true, false},
		{"patch-newer", "v0.2.1", "0.2.0", false, true},
		{"minor-newer", "v0.3.0", "0.2.9", false, true},
		{"older", "v0.1.0", "0.2.0", false, false},
		{"dev-build-current", "v0.2.0", "0.1.0-dev", false, true},
		{"wip-build-current", "v0.2.0", "0.0.0-wip+abc123", false, true},
		{"prerelease-latest", "v0.2.0-rc1", "0.1.0", false, true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := IsUpToDate(c.current, c.latest); got != c.upToDate {
				t.Errorf("IsUpToDate(%q,%q) = %v, want %v", c.current, c.latest, got, c.upToDate)
			}
			if got := IsNewer(c.latest, c.current); got != c.newer {
				t.Errorf("IsNewer(%q,%q) = %v, want %v", c.latest, c.current, got, c.newer)
			}
		})
	}
}

func TestBrewPrefixDetection(t *testing.T) {
	if p := brewPrefixOf("/opt/homebrew/Cellar/geneza/0.1.0/bin/geneza"); p != "/opt/homebrew" {
		t.Fatalf("brew prefix = %q", p)
	}
	if p := brewPrefixOf("/usr/local/bin/geneza"); p != "" {
		t.Fatalf("non-Cellar path flagged as brew: %q", p)
	}
}

func TestNoReleaseFound(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/repos/"+RepoSlug+"/releases/latest", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()
	withAPIBase(t, srv.URL)
	if _, err := LatestRelease(context.Background()); err == nil || !strings.Contains(err.Error(), "no release found") {
		t.Fatalf("err = %v, want friendly no-release error", err)
	}
}

// TestVerifiedSumsPinned: when a root is pinned, VerifiedSums verifies the full
// chain (root-keys.json + SHA256SUMS.sig), binds to the release tag, enforces the
// rollback floor, and fails closed on missing signature assets.
func TestVerifiedSumsPinned(t *testing.T) {
	rootPub, rootPriv, rootID, _ := types.GenerateSigningKey()
	signerPub, signerPriv, _, _ := types.GenerateSigningKey()

	old := releasetrust.RootPub
	releasetrust.RootPub = rootPub // pin a test root
	t.Cleanup(func() { releasetrust.RootPub = old })

	const tag = "v1.0.0"
	sums := []byte("abc123  geneza_linux_amd64.tar.gz\n")
	rk := types.RootKeys{Version: 1, ExpiresAt: time.Now().Add(24 * time.Hour),
		Keys: []types.ArtifactKey{{KeyID: types.KeyIDFor(signerPub), PublicKey: signerPub}}}
	signedRK, _ := types.Sign(rootPriv, rootID, defaults.ContextRootKeys, &rk)
	rkJSON, _ := signedRK.Encode()
	signedSums, _ := releasetrust.SignSums(signerPriv, tag, sums)
	sigBytes, _ := signedSums.Encode()

	mux := http.NewServeMux()
	srv := httptest.NewServer(mux)
	defer srv.Close()
	mux.HandleFunc("/sums", func(w http.ResponseWriter, _ *http.Request) { w.Write(sums) })
	mux.HandleFunc("/rk", func(w http.ResponseWriter, _ *http.Request) { w.Write(rkJSON) })
	mux.HandleFunc("/sig", func(w http.ResponseWriter, _ *http.Request) { w.Write(sigBytes) })
	rel := &Release{TagName: tag, Assets: []Asset{
		{Name: checksumManifest, URL: srv.URL + "/sums"},
		{Name: rootKeysAsset, URL: srv.URL + "/rk"},
		{Name: sumsSigAsset, URL: srv.URL + "/sig"},
	}}
	dl := newClient(10 * time.Second)

	gotSums, ver, err := VerifiedSums(context.Background(), dl, rel, 0)
	if err != nil || ver != 1 || !bytes.Equal(gotSums, sums) {
		t.Fatalf("valid signed release: ver=%d err=%v", ver, err)
	}
	if _, _, err := VerifiedSums(context.Background(), dl, rel, 2); err == nil {
		t.Fatal("rolled-back root-keys (floor above doc version) accepted")
	}
	relWrongTag := &Release{TagName: "v2.0.0", Assets: rel.Assets}
	if _, _, err := VerifiedSums(context.Background(), dl, relWrongTag, 0); err == nil {
		t.Fatal("signature bound to a different release tag accepted")
	}
	relBare := &Release{TagName: tag, Assets: []Asset{{Name: checksumManifest, URL: srv.URL + "/sums"}}}
	if _, _, err := VerifiedSums(context.Background(), dl, relBare, 0); err == nil {
		t.Fatal("pinned build accepted a release missing the signature assets")
	}
}
