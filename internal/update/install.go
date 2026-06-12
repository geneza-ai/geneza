package update

import (
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"osie.cloud/geneza/internal/defaults"
	"osie.cloud/geneza/internal/types"
)

// Installer downloads and installs one worker artifact described by an
// offline-signed manifest. The order of operations is the whole point:
// verify the manifest signature against the pinned key FIRST, download to a
// hidden temp file, verify the blob hash+size against the verified manifest,
// and only then atomically rename() into place. The running binary's path is
// never written to; a crash at any step leaves at worst a stale temp file.
type Installer struct {
	Client     *http.Client // built by NewHTTPClient; required
	GatewayURL string       // base URL, e.g. https://gw.example:7402
	Pub        ed25519.PublicKey
	KeyID      string // optional key-id pin; "" accepts any id (signature must still verify with Pub)

	// Trusted is the root-anchored set of release-SIGNING keys (derived from a
	// verified RootKeys doc). When non-empty it takes precedence over the single
	// pinned Pub: a manifest is accepted if signed by ANY trusted key, which is
	// what enables key rotation (root authorizes a new key set; nodes pick it up)
	// without re-touching the pinned root. Empty falls back to the single Pub.
	Trusted map[string]ed25519.PublicKey

	// Required-match fields: a manifest for another product/platform is
	// rejected even with a valid signature (prevents cross-product or
	// cross-arch confusion attacks via a replayed valid manifest).
	Product string
	OS      string
	Arch    string

	VersionsDir string
	Log         *slog.Logger

	// MinCreatedAt is the anti-rollback floor: Install rejects any manifest
	// built before this instant (the highest CreatedAt ever committed). Zero
	// disables the check (fresh node with no committed history).
	MinCreatedAt time.Time
}

// Install verifies sm, downloads the blob, and installs it as
// <VersionsDir>/<version>/geneza-agent. Returns the installed binary path
// and the verified manifest. Every failure is fail-closed: nothing is left
// at the final path unless every check passed.
func (ins *Installer) Install(ctx context.Context, sm *types.Signed) (string, *types.Manifest, error) {
	if ins.Client == nil {
		return "", nil, fmt.Errorf("installer: no http client")
	}

	// Trust set: the root-anchored signing keys if provided (rotation-friendly),
	// else the single pinned key for backward compatibility. A manifest verifies
	// if signed by any trusted key under the artifact-manifest context.
	trusted := ins.Trusted
	if len(trusted) == 0 {
		if len(ins.Pub) != ed25519.PublicKeySize {
			return "", nil, fmt.Errorf("installer: no trusted artifact keys")
		}
		trusted = map[string]ed25519.PublicKey{types.KeyIDFor(ins.Pub): ins.Pub}
	}
	var m types.Manifest
	if _, err := types.Verify(trusted, defaults.ContextManifest, sm, &m); err != nil {
		return "", nil, fmt.Errorf("manifest signature: %w", err)
	}
	if m.Product != ins.Product {
		return "", nil, fmt.Errorf("manifest product %q != expected %q", m.Product, ins.Product)
	}
	if m.OS != ins.OS || m.Arch != ins.Arch {
		return "", nil, fmt.Errorf("manifest platform %s/%s != expected %s/%s", m.OS, m.Arch, ins.OS, ins.Arch)
	}
	if err := validVersion(m.Version); err != nil {
		return "", nil, fmt.Errorf("manifest version: %w", err)
	}
	// Anti-rollback: reject a manifest built before the highest version we have
	// ever committed. CreatedAt is inside the offline-signed payload, so a
	// compromised gateway replaying an old signed manifest cannot forge a newer
	// timestamp. A small skew tolerance avoids tripping on clock jitter.
	if !ins.MinCreatedAt.IsZero() && m.CreatedAt.Before(ins.MinCreatedAt.Add(-2*time.Minute)) {
		return "", nil, fmt.Errorf("manifest for %q is older (%s) than the rollback floor (%s): refusing downgrade",
			m.Version, m.CreatedAt.UTC().Format(time.RFC3339), ins.MinCreatedAt.UTC().Format(time.RFC3339))
	}
	if err := validSHA256(m.SHA256); err != nil {
		return "", nil, fmt.Errorf("manifest sha256: %w", err)
	}
	if m.Size <= 0 {
		return "", nil, fmt.Errorf("manifest size %d invalid", m.Size)
	}

	dir := filepath.Join(ins.VersionsDir, m.Version)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return "", nil, err
	}
	tmp := filepath.Join(dir, ".geneza-agent.tmp")
	if err := ins.download(ctx, &m, tmp); err != nil {
		os.Remove(tmp)
		return "", nil, fmt.Errorf("download %s: %w", m.SHA256, err)
	}
	// Re-read the temp file from disk for hash verification so the bytes
	// that get executed are the bytes that were verified.
	f, err := os.Open(tmp)
	if err != nil {
		os.Remove(tmp)
		return "", nil, err
	}
	verr := m.VerifyBlob(f)
	f.Close()
	if verr != nil {
		os.Remove(tmp)
		return "", nil, fmt.Errorf("blob verification: %w", verr)
	}
	if err := os.Chmod(tmp, 0o755); err != nil {
		os.Remove(tmp)
		return "", nil, err
	}
	final := filepath.Join(dir, "geneza-agent")
	if err := os.Rename(tmp, final); err != nil {
		os.Remove(tmp)
		return "", nil, err
	}
	if ins.Log != nil {
		ins.Log.Info("artifact installed",
			"product", m.Product, "version", m.Version,
			"sha256", m.SHA256, "size", m.Size, "path", final)
	}
	return final, &m, nil
}

func (ins *Installer) download(ctx context.Context, m *types.Manifest, tmp string) error {
	url := strings.TrimRight(ins.GatewayURL, "/") + m.BlobPath()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return err
	}
	resp, err := ins.Client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("gateway returned %s", resp.Status)
	}
	f, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
	if err != nil {
		return err
	}
	// Cap the read at size+1 so a hostile gateway cannot fill the disk;
	// any overrun then shows up as a size mismatch below.
	n, cerr := io.Copy(f, io.LimitReader(resp.Body, m.Size+1))
	serr := f.Sync()
	if err := f.Close(); cerr == nil {
		cerr = err
	}
	if cerr != nil {
		return cerr
	}
	if serr != nil {
		return serr
	}
	if n != m.Size {
		return fmt.Errorf("downloaded %d bytes, manifest says %d", n, m.Size)
	}
	return nil
}

// validVersion constrains the version string to a safe single path
// component: the version comes from a signed manifest, but defense in depth
// — a key compromise must not also become a path traversal.
func validVersion(v string) error {
	if v == "" || len(v) > 100 {
		return fmt.Errorf("empty or oversized version string")
	}
	for i, r := range v {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9':
		case i > 0 && (r == '.' || r == '_' || r == '+' || r == '-'):
		default:
			return fmt.Errorf("version %q contains disallowed character", v)
		}
	}
	return nil
}

// validSHA256 requires exactly 64 lowercase hex chars: it is interpolated
// into the artifact URL and string-compared by Manifest.VerifyBlob.
func validSHA256(s string) error {
	if len(s) != 64 {
		return fmt.Errorf("want 64 hex chars, got %d", len(s))
	}
	b, err := hex.DecodeString(s)
	if err != nil {
		return err
	}
	if hex.EncodeToString(b) != s {
		return fmt.Errorf("sha256 must be lowercase hex")
	}
	return nil
}
