// Package selfupdate implements `geneza update`: the client replaces its own
// binary with the latest (or a chosen) GitHub release, on any OS. It pulls the
// release archive and the SHA256SUMS manifest, verifies the archive digest,
// extracts the client binary, and atomically swaps it over the running
// executable. This is the user-facing CLI updater; the managed-fleet worker has
// its own controller-driven, offline-signed update path in internal/update.
//
// Trust model: the SHA-256 in SHA256SUMS proves the download matches what the
// release publisher chose — it is integrity, not authenticity. Anyone who can
// publish a geneza-ai/geneza release is trusted, exactly like `brew`/`curl|sh`.
// A signature over SHA256SUMS (geneza-sign) would add publisher authenticity;
// that is tracked separately and would slot into verifyManifest below.
package selfupdate

import (
	"archive/tar"
	"archive/zip"
	"bufio"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"time"

	"geneza.io/internal/releasetrust"
)

const (
	// RepoSlug is the GitHub repository self-update pulls releases from.
	RepoSlug = "geneza-ai/geneza"
	// checksumManifest is the aggregate digest file the release workflow
	// publishes (see .github/workflows/binaries.yml). Standard sha256sum
	// format: "<hex>  <filename>".
	checksumManifest = "SHA256SUMS"
	// rootKeysAsset and sumsSigAsset carry the offline-signed release trust
	// chain: root-keys.json (root authorizes the signer set) and the signer's
	// detached signature over checksumManifest.
	rootKeysAsset = "root-keys.json"
	sumsSigAsset  = "SHA256SUMS.sig"
	// clientBinary is the binary inside the per-platform archive that this
	// command replaces — the operator CLI, not the bundled server binaries.
	clientBinary = "geneza"
	// maxBinarySize caps a single extracted file so a malformed or hostile
	// archive can't exhaust memory during extraction.
	maxBinarySize = 256 << 20
	// maxArchiveSize bounds the archive download (all of a platform's bundled
	// binaries; well under this today).
	maxArchiveSize = 512 << 20

	// DefaultTimeout bounds the archive + manifest download.
	DefaultTimeout = 120 * time.Second
)

// Asset is one downloadable file attached to a release.
type Asset struct {
	Name string `json:"name"`
	URL  string `json:"browser_download_url"`
}

// Release is the subset of the GitHub release API we use.
type Release struct {
	TagName string  `json:"tag_name"`
	HTMLURL string  `json:"html_url"`
	Assets  []Asset `json:"assets"`
}

// httpsOnlyRedirect refuses any redirect that is not https, so a man-in-the-
// middle 302 cannot downgrade an asset fetch to cleartext. GitHub's CDN handoff
// (api.github.com → objects.githubusercontent.com) stays https, so this keeps
// the legitimate redirect while blocking a scheme downgrade.
func httpsOnlyRedirect(req *http.Request, via []*http.Request) error {
	if len(via) >= 10 {
		return errors.New("stopped after 10 redirects")
	}
	if req.URL.Scheme != "https" {
		return fmt.Errorf("refusing non-https redirect to %s", req.URL.Redacted())
	}
	return nil
}

func newClient(timeout time.Duration) *http.Client {
	return &http.Client{Timeout: timeout, CheckRedirect: httpsOnlyRedirect}
}

func assertHTTPS(rawURL string) error {
	if strings.HasPrefix(rawURL, "https://") {
		return nil
	}
	// Permit plain http only to loopback — used by tests, and never a network
	// MITM surface. GitHub asset/API URLs are always https, so this never
	// loosens the real path.
	if u, err := url.Parse(rawURL); err == nil && u.Scheme == "http" {
		switch u.Hostname() {
		case "localhost", "127.0.0.1", "::1":
			return nil
		}
	}
	return fmt.Errorf("refusing non-https URL %q", rawURL)
}

// apiBase is overridable in tests to point at an httptest server (http).
var apiBase = "https://api.github.com"

func githubGet(ctx context.Context, url string) (*http.Response, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/vnd.github+json")
	if tok := firstEnv("GENEZA_GITHUB_TOKEN", "GITHUB_TOKEN", "GH_TOKEN"); tok != "" {
		req.Header.Set("Authorization", "Bearer "+tok)
	}
	return newClient(15 * time.Second).Do(req)
}

func firstEnv(keys ...string) string {
	for _, k := range keys {
		if v := os.Getenv(k); v != "" {
			return v
		}
	}
	return ""
}

// LatestRelease returns the repository's latest published release.
func LatestRelease(ctx context.Context) (*Release, error) {
	return fetchRelease(ctx, apiBase+"/repos/"+RepoSlug+"/releases/latest")
}

// ReleaseByTag returns the release for an exact tag (e.g. "v0.1.0").
func ReleaseByTag(ctx context.Context, tag string) (*Release, error) {
	return fetchRelease(ctx, apiBase+"/repos/"+RepoSlug+"/releases/tags/"+normalizeTag(tag))
}

func fetchRelease(ctx context.Context, url string) (*Release, error) {
	resp, err := githubGet(ctx, url)
	if err != nil {
		return nil, fmt.Errorf("contact GitHub: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNotFound {
		return nil, fmt.Errorf("no release found (have any %s releases been published yet?)", RepoSlug)
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("GitHub API returned %d", resp.StatusCode)
	}
	var r Release
	if err := json.NewDecoder(io.LimitReader(resp.Body, 8<<20)).Decode(&r); err != nil {
		return nil, fmt.Errorf("decode release: %w", err)
	}
	return &r, nil
}

func normalizeTag(v string) string {
	t := strings.TrimSpace(v)
	if t != "" && !strings.HasPrefix(t, "v") {
		t = "v" + t
	}
	return t
}

// archiveName is the per-platform archive asset name the release workflow
// publishes for goos/goarch (e.g. geneza_darwin_arm64.tar.gz).
func archiveName(goos, goarch string) string {
	ext := "tar.gz"
	if goos == "windows" {
		ext = "zip"
	}
	return fmt.Sprintf("geneza_%s_%s.%s", goos, goarch, ext)
}

// IsUpToDate reports whether the running version already matches the release's
// tag (both compared with any leading "v" stripped).
func IsUpToDate(current, tag string) bool {
	return strings.TrimPrefix(strings.TrimSpace(current), "v") == strings.TrimPrefix(strings.TrimSpace(tag), "v")
}

// IsNewer reports whether tag is a strictly newer release than current. A
// version that can't be parsed as N.N.N (a dev build like "0.1.0-dev" or
// "0.0.0-wip+abc") is treated as older, so a manual `geneza update` from a dev
// build still moves to the latest release. Returns false when tag itself is
// unparseable.
func IsNewer(tag, current string) bool {
	l, ok := parseSemver(tag)
	if !ok {
		return false
	}
	c, ok := parseSemver(current)
	if !ok {
		return true // current is a dev/unparseable build; any real release is "newer"
	}
	for i := 0; i < 3; i++ {
		if l[i] != c[i] {
			return l[i] > c[i]
		}
	}
	return false
}

// parseSemver extracts the three leading numeric components of v, ignoring a
// pre-release / build suffix on the patch (so "1.2.3-rc1" parses as 1.2.3).
func parseSemver(v string) ([3]int, bool) {
	s := strings.TrimPrefix(strings.TrimSpace(v), "v")
	if s == "" {
		return [3]int{}, false
	}
	parts := strings.SplitN(s, ".", 3)
	if len(parts) != 3 {
		return [3]int{}, false
	}
	var out [3]int
	for i, p := range parts {
		if i == 2 { // patch may carry a -suffix / +build
			p = strings.FieldsFunc(p, func(r rune) bool { return r == '-' || r == '+' })[0]
		}
		n, err := strconv.Atoi(p)
		if err != nil {
			return [3]int{}, false
		}
		out[i] = n
	}
	return out, true
}

// Options tunes a self-update.
type Options struct {
	Timeout time.Duration
	GOOS    string // defaults to runtime.GOOS
	GOARCH  string // defaults to runtime.GOARCH
}

// Apply downloads the client binary from rel for this platform, verifies it
// against the release's SHA256SUMS, and atomically replaces the running
// executable. It returns a human-readable summary on success. The new binary is
// written locally (not "downloaded" by a quarantine-aware app), so on macOS it
// carries no com.apple.quarantine xattr and runs without a Gatekeeper prompt.
func Apply(ctx context.Context, rel *Release, opt Options) (string, error) {
	goos, goarch := opt.GOOS, opt.GOARCH
	if goos == "" {
		goos = runtime.GOOS
	}
	if goarch == "" {
		goarch = runtime.GOARCH
	}
	timeout := opt.Timeout
	if timeout <= 0 {
		timeout = DefaultTimeout
	}

	exePath, err := resolveSelf()
	if err != nil {
		return "", err
	}
	if prefix := brewPrefixOf(exePath); prefix != "" {
		return "", fmt.Errorf("this geneza is managed by Homebrew (%s); upgrade it with `brew upgrade`, not `geneza update`", prefix)
	}

	wantName := archiveName(goos, goarch)
	archiveAsset := findAsset(rel.Assets, wantName)
	if archiveAsset == nil {
		return "", fmt.Errorf("release %s has no build for %s/%s (expected asset %s)", rel.TagName, goos, goarch, wantName)
	}
	if err := assertHTTPS(archiveAsset.URL); err != nil {
		return "", err
	}
	dl := newClient(timeout)
	// Verify SHA256SUMS — and its signature chain when this build pins a release
	// root, so a compromised GitHub release alone can't ship a malicious binary —
	// before spending bandwidth on the archive. Unpinned (dev) builds fall back
	// to the bare digest (integrity only).
	floorPath := releaseFloorPath()
	floor := releasetrust.LoadVersionFloor(floorPath)
	sums, rkVersion, err := VerifiedSums(ctx, dl, rel, floor)
	if err != nil {
		return "", err
	}
	wantSum, err := lookupChecksum(sums, wantName)
	if err != nil {
		return "", err
	}
	archive, err := download(ctx, dl, archiveAsset.URL, maxArchiveSize)
	if err != nil {
		return "", fmt.Errorf("download %s: %w", wantName, err)
	}
	// Verify the FULL archive before a single byte is extracted or written.
	if err := verifySHA256(archive, wantSum, wantName); err != nil {
		return "", err
	}

	binName := clientBinary
	if goos == "windows" {
		binName = clientBinary + ".exe"
	}
	// Anchor to the canonical inner path geneza_<os>_<arch>/<binName>, accept
	// only a regular file, and fail closed on duplicates.
	wantPath := fmt.Sprintf("geneza_%s_%s/%s", goos, goarch, binName)
	var newBin []byte
	if goos == "windows" {
		newBin, err = binaryFromZip(archive, wantPath)
	} else {
		newBin, err = binaryFromTarGz(archive, wantPath)
	}
	if err != nil {
		return "", fmt.Errorf("extract %s: %w", binName, err)
	}
	if len(newBin) == 0 {
		return "", fmt.Errorf("extracted %s is empty", binName)
	}

	if err := installOver(exePath, newBin); err != nil {
		return "", err
	}
	// Raise the anti-rollback floor only after a successful install (best-effort).
	if rkVersion > 0 {
		_ = releasetrust.SaveVersionFloor(floorPath, rkVersion)
	}
	return fmt.Sprintf("updated %s to %s", exePath, rel.TagName), nil
}

// resolveSelf returns the absolute, symlink-resolved path of the running binary,
// refusing to proceed if it is an unresolvable symlink (overwriting the link
// with a regular file would silently break the install).
func resolveSelf() (string, error) {
	exePath, err := os.Executable()
	if err != nil {
		return "", fmt.Errorf("resolve executable path: %w", err)
	}
	resolved, evalErr := filepath.EvalSymlinks(exePath)
	if evalErr != nil {
		if fi, lerr := os.Lstat(exePath); lerr == nil && fi.Mode()&os.ModeSymlink != 0 {
			return "", fmt.Errorf("refusing to update: %s is a symlink that can't be resolved: %v", exePath, evalErr)
		}
	} else {
		exePath = resolved
	}
	abs, err := filepath.Abs(exePath)
	if err != nil {
		return "", fmt.Errorf("absolute path of %s: %w", exePath, err)
	}
	return abs, nil
}

func findAsset(assets []Asset, name string) *Asset {
	for i := range assets {
		if assets[i].Name == name {
			return &assets[i]
		}
	}
	return nil
}

func download(ctx context.Context, c *http.Client, url string, limit int64) ([]byte, error) {
	if err := assertHTTPS(url); err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	resp, err := c.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	// Read one byte past the cap so an oversized body is rejected, not truncated.
	b, err := io.ReadAll(io.LimitReader(resp.Body, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(b)) > limit {
		return nil, fmt.Errorf("response exceeded %d bytes", limit)
	}
	return b, nil
}

// lookupChecksum returns the lowercase hex digest for name from a sha256sum-style
// manifest ("<hex>  <name>"), or an error if absent or malformed (fail closed).
func lookupChecksum(manifest []byte, name string) (string, error) {
	sc := bufio.NewScanner(bytes.NewReader(manifest))
	for sc.Scan() {
		f := strings.Fields(strings.TrimSpace(sc.Text()))
		if len(f) >= 2 && f[len(f)-1] == name {
			sum := strings.ToLower(f[0])
			if !isSHA256Hex(sum) {
				return "", fmt.Errorf("malformed %s entry for %s", checksumManifest, name)
			}
			return sum, nil
		}
	}
	if err := sc.Err(); err != nil {
		return "", fmt.Errorf("read %s: %w", checksumManifest, err)
	}
	return "", fmt.Errorf("%s has no entry for %s", checksumManifest, name)
}

func isSHA256Hex(s string) bool {
	if len(s) != 64 {
		return false
	}
	_, err := hex.DecodeString(s)
	return err == nil
}

// releaseFloorPath is where the client persists the highest root-keys version it
// has accepted (anti-rollback against signer revival). Empty if no user config
// dir is available, in which case the expiry window is the only backstop.
func releaseFloorPath() string {
	dir, err := os.UserConfigDir()
	if err != nil {
		return ""
	}
	return filepath.Join(dir, "geneza", "release-rootkeys-version")
}

// --- reusable release primitives (shared with the controller agent-pull) ---

// NewHTTPClient returns the hardened download client (https-only redirects).
func NewHTTPClient(timeout time.Duration) *http.Client { return newClient(timeout) }

// FindAsset returns the named release asset, or nil.
func FindAsset(rel *Release, name string) *Asset { return findAsset(rel.Assets, name) }

// Fetch downloads url with the hardened client (https-pinned, capped at limit).
func Fetch(ctx context.Context, dl *http.Client, url string, limit int64) ([]byte, error) {
	return download(ctx, dl, url, limit)
}

// VerifiedSums downloads rel's SHA256SUMS and, when this build pins a release
// root, verifies its signature chain (binding the signature to rel.TagName and
// rejecting a root-keys version below floor). It returns the trusted manifest
// bytes and the accepted root-keys version (0 for an unpinned/dev build) for the
// caller to persist as the new floor; callers then look up a per-asset digest
// with ExpectedDigest. Shared by the client self-update and the controller pull.
func VerifiedSums(ctx context.Context, dl *http.Client, rel *Release, floor int64) ([]byte, int64, error) {
	sumsAsset := findAsset(rel.Assets, checksumManifest)
	if sumsAsset == nil {
		return nil, 0, fmt.Errorf("release %s has no %s; refusing unverified binaries", rel.TagName, checksumManifest)
	}
	if err := assertHTTPS(sumsAsset.URL); err != nil {
		return nil, 0, err
	}
	sums, err := download(ctx, dl, sumsAsset.URL, 1<<20)
	if err != nil {
		return nil, 0, fmt.Errorf("download %s: %w", checksumManifest, err)
	}
	if releasetrust.RootPub == nil {
		return sums, 0, nil // dev build: no pinned root, integrity-only
	}
	rkAsset := findAsset(rel.Assets, rootKeysAsset)
	sigAsset := findAsset(rel.Assets, sumsSigAsset)
	if rkAsset == nil || sigAsset == nil {
		return nil, 0, fmt.Errorf("release %s lacks %s/%s but this build requires a signed release", rel.TagName, rootKeysAsset, sumsSigAsset)
	}
	if err := assertHTTPS(rkAsset.URL); err != nil {
		return nil, 0, err
	}
	if err := assertHTTPS(sigAsset.URL); err != nil {
		return nil, 0, err
	}
	rootKeys, err := download(ctx, dl, rkAsset.URL, 1<<20)
	if err != nil {
		return nil, 0, fmt.Errorf("download %s: %w", rootKeysAsset, err)
	}
	sig, err := download(ctx, dl, sigAsset.URL, 1<<20)
	if err != nil {
		return nil, 0, fmt.Errorf("download %s: %w", sumsSigAsset, err)
	}
	ver, err := releasetrust.VerifySums(rootKeys, sums, sig, rel.TagName, floor, time.Now())
	if err != nil {
		return nil, 0, fmt.Errorf("release signature: %w", err)
	}
	return sums, ver, nil
}

// ExpectedDigest returns the hex sha256 for assetName from a SHA256SUMS manifest.
func ExpectedDigest(sums []byte, assetName string) (string, error) {
	return lookupChecksum(sums, assetName)
}

// VerifyDigest checks data's sha256 against the expected hex.
func VerifyDigest(data []byte, wantHex, name string) error {
	return verifySHA256(data, wantHex, name)
}

// ExtractTarGzFile returns the regular-file entry at the exact innerPath of a
// .tar.gz (e.g. "geneza-node_linux_amd64/geneza-agent").
func ExtractTarGzFile(archive []byte, innerPath string) ([]byte, error) {
	return binaryFromTarGz(archive, innerPath)
}

func verifySHA256(data []byte, wantHex, name string) error {
	sum := sha256.Sum256(data)
	got := hex.EncodeToString(sum[:])
	if !strings.EqualFold(got, wantHex) {
		return fmt.Errorf("checksum mismatch for %s: want %s, got %s", name, wantHex, got)
	}
	return nil
}

// binaryFromTarGz returns the contents of the regular-file entry at exactly
// wantPath (archive paths use '/'), erroring on absent, non-regular, or
// duplicate matches.
func binaryFromTarGz(archive []byte, wantPath string) ([]byte, error) {
	gz, err := gzip.NewReader(bytes.NewReader(archive))
	if err != nil {
		return nil, fmt.Errorf("gzip: %w", err)
	}
	defer gz.Close()
	tr := tar.NewReader(gz)
	var found []byte
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, err
		}
		if path.Clean(hdr.Name) != wantPath {
			continue
		}
		if hdr.Typeflag != tar.TypeReg {
			return nil, fmt.Errorf("%s is not a regular file (type %d)", wantPath, hdr.Typeflag)
		}
		if found != nil {
			return nil, fmt.Errorf("multiple %s entries in archive", wantPath)
		}
		found, err = readCapped(tr)
		if err != nil {
			return nil, err
		}
	}
	if found == nil {
		return nil, fmt.Errorf("%s not in archive", wantPath)
	}
	return found, nil
}

func binaryFromZip(archive []byte, wantPath string) ([]byte, error) {
	zr, err := zip.NewReader(bytes.NewReader(archive), int64(len(archive)))
	if err != nil {
		return nil, fmt.Errorf("zip: %w", err)
	}
	var found []byte
	for _, f := range zr.File {
		if path.Clean(f.Name) != wantPath {
			continue
		}
		if !f.Mode().IsRegular() { // rejects symlink / dir / device entries
			return nil, fmt.Errorf("%s is not a regular file (%v)", wantPath, f.Mode())
		}
		if found != nil {
			return nil, fmt.Errorf("multiple %s entries in archive", wantPath)
		}
		rc, err := f.Open()
		if err != nil {
			return nil, err
		}
		found, err = readCapped(rc)
		rc.Close()
		if err != nil {
			return nil, err
		}
	}
	if found == nil {
		return nil, fmt.Errorf("%s not in archive", wantPath)
	}
	return found, nil
}

// readCapped reads up to maxBinarySize+1 and errors if the entry is larger, so a
// decompression bomb can't blow past the cap.
func readCapped(r io.Reader) ([]byte, error) {
	b, err := io.ReadAll(io.LimitReader(r, maxBinarySize+1))
	if err != nil {
		return nil, err
	}
	if int64(len(b)) > maxBinarySize {
		return nil, fmt.Errorf("binary exceeds %d bytes", maxBinarySize)
	}
	return b, nil
}

// installOver writes newBin next to exePath and atomically swaps it in,
// preserving the original file mode. A lockfile beside the target serializes
// concurrent updates so two runs can't tear each other's swap. The temp file
// shares exePath's directory so the rename stays on one filesystem.
func installOver(exePath string, newBin []byte) error {
	dir := filepath.Dir(exePath)
	unlock, err := lockUpdate(exePath)
	if err != nil {
		return err
	}
	defer unlock()

	tmp, err := os.CreateTemp(dir, ".geneza-update-*")
	if err != nil {
		return writableHint(dir, err)
	}
	tmpPath := tmp.Name()
	cleanup := func() { _ = os.Remove(tmpPath) }

	if _, err := tmp.Write(newBin); err != nil {
		tmp.Close()
		cleanup()
		return fmt.Errorf("write temp binary: %w", err)
	}
	if err := tmp.Close(); err != nil {
		cleanup()
		return fmt.Errorf("close temp binary: %w", err)
	}
	mode := os.FileMode(0o755)
	if info, err := os.Stat(exePath); err == nil {
		mode = info.Mode().Perm()
	}
	if err := os.Chmod(tmpPath, mode); err != nil {
		cleanup()
		return fmt.Errorf("chmod temp binary: %w", err)
	}
	if err := replaceBinary(tmpPath, exePath); err != nil {
		cleanup()
		return fmt.Errorf("replace %s: %w", exePath, writableHint(dir, err))
	}
	return nil
}

// lockUpdate takes an exclusive lockfile next to the target binary. It returns a
// release func; a second concurrent updater gets a clear "in progress" error
// rather than racing the temp/rename.
func lockUpdate(exePath string) (func(), error) {
	lockPath := exePath + ".update-lock"
	f, err := os.OpenFile(lockPath, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o644)
	if err != nil {
		if os.IsExist(err) {
			return nil, fmt.Errorf("another geneza update is in progress (delete %s if it's stale)", lockPath)
		}
		return nil, writableHint(filepath.Dir(exePath), err)
	}
	return func() { f.Close(); _ = os.Remove(lockPath) }, nil
}

// writableHint turns a bare permission error into an actionable one (system
// installs need elevation), and passes other errors through.
func writableHint(dir string, err error) error {
	if errors.Is(err, os.ErrPermission) {
		return fmt.Errorf("%s is not writable — re-run with sudo (or as Administrator), or install geneza somewhere you own: %w", dir, err)
	}
	return err
}

// brewPrefixOf returns the Homebrew prefix that owns path, else "". Self-update
// must not clobber a Homebrew-managed binary (it desyncs the formula); the
// caller redirects those users to `brew upgrade`. Matches the Cellar and opt/
// dirs, which are brew-exclusive — a manual binary in /usr/local/bin is NOT
// brew, so it is intentionally not matched. resolveSelf has already followed the
// bin/ symlink to its Cellar target (and refuses an unresolvable symlink), so
// this sees the real path of a brew install.
func brewPrefixOf(p string) string {
	for _, prefix := range []string{"/opt/homebrew", "/usr/local", "/home/linuxbrew/.linuxbrew"} {
		if strings.HasPrefix(p, prefix+"/Cellar/") || strings.HasPrefix(p, prefix+"/opt/") {
			return prefix
		}
	}
	return ""
}
