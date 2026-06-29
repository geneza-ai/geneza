// Package releasetrust pins the offline ROOT public key into the client and
// controller and verifies the release trust chain over a GitHub release's
// SHA256SUMS manifest:
//
//	pinned root  --signs-->  RootKeys (root-keys.json)  --authorizes-->  signerN
//	signerN  --signs-->  ReleaseSums{sha256(SHA256SUMS)}  (SHA256SUMS.sig)
//
// A verified signature transfers trust to every per-asset digest the manifest
// lists, so the downloader can trust the archive digest without trusting GitHub.
// This is integrity AND publisher authenticity: a compromised release publisher
// cannot forge a signerN signature, and a leaked signerN is rotated out by
// re-signing root-keys.json with the OFFLINE root — no client/controller rebuild.
//
// The root public key is injected at release-build time via -ldflags -X (see
// deploy/release/build-archive.sh); dev/test builds carry none, so VerifySums
// returns ErrNotPinned and the caller falls back to integrity-only (bare
// SHA256SUMS). The key is public — it is committed at deploy/release/root.pub.
package releasetrust

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"geneza.io/internal/types"
)

// rootPubB64 is the base64 of the offline release ROOT public key (PEM),
// injected at release-build time via:
//
//	-ldflags "-X geneza.io/internal/releasetrust.rootPubB64=<base64>"
//
// Empty in dev/test builds, so RootPub stays nil and updates fall back to
// integrity-only.
var rootPubB64 string

// RootPub is the pinned offline root public key, or nil when this build injected
// none (dev/test).
var RootPub ed25519.PublicKey

// RootPubPEM is the PEM the root public key was injected as (the bytes a deploy
// serves at /v1/root-pubkey so the curl|bash installer can pin it). Nil in an
// uninjected dev/test build.
var RootPubPEM []byte

func init() {
	if rootPubB64 == "" {
		return
	}
	// A build that injected a root MUST parse it — a malformed pin is a build
	// misconfiguration, not a reason to silently ship an unverified (unpinned)
	// release binary. Fail loudly rather than fail open.
	pemBytes, err := base64.StdEncoding.DecodeString(rootPubB64)
	if err != nil {
		panic("releasetrust: injected rootPubB64 is not valid base64: " + err.Error())
	}
	k, err := types.ParsePublicKeyPEM(pemBytes)
	if err != nil {
		panic("releasetrust: injected rootPubB64 is not a valid public key: " + err.Error())
	}
	RootPub = k
	RootPubPEM = pemBytes
}

// contextReleaseSums domain-separates the SHA256SUMS signature from every other
// ed25519 signature in the system (grants, manifests, root-keys).
const contextReleaseSums = "release-sums"

// ReleaseSums is the signed payload binding a release to its SHA256SUMS file.
// Tag pins the signature to a specific release so a validly-signed older
// release's chain can't be replayed onto a different (e.g. "latest") fetch.
type ReleaseSums struct {
	SHA256 string `json:"sha256"`        // hex sha256 of the SHA256SUMS bytes
	Tag    string `json:"tag,omitempty"` // the release tag these sums belong to
}

// ErrNotPinned means this build embeds no root key, so release signatures cannot
// be verified; the caller decides whether to fall back to integrity-only.
var ErrNotPinned = errors.New("release signing not pinned in this build")

func sha256hex(b []byte) string {
	s := sha256.Sum256(b)
	return hex.EncodeToString(s[:])
}

// SignSums signs the SHA256SUMS bytes for release tag with a release signing
// key. It is the body of `geneza-sign sign-file`; the result is published as
// SHA256SUMS.sig.
func SignSums(priv ed25519.PrivateKey, tag string, sums []byte) (*types.Signed, error) {
	pub, ok := priv.Public().(ed25519.PublicKey)
	if !ok {
		return nil, errors.New("not an ed25519 key")
	}
	return types.Sign(priv, types.KeyIDFor(pub), contextReleaseSums, ReleaseSums{SHA256: sha256hex(sums), Tag: tag})
}

// VerifySums walks the release trust chain and returns the accepted root-keys
// version (for the caller to persist as the new anti-rollback floor) iff: the
// pinned root signed rootKeysJSON at version >= minVersion and unexpired, an
// authorized signer signed sig, the signed hash matches sums, and (when
// expectedTag is non-empty) the signature was made for that release tag. Returns
// ErrNotPinned when no root is pinned.
func VerifySums(rootKeysJSON, sums, sig []byte, expectedTag string, minVersion int64, now time.Time) (int64, error) {
	return verifySumsWith(RootPub, rootKeysJSON, sums, sig, expectedTag, minVersion, now)
}

func verifySumsWith(rootPub ed25519.PublicKey, rootKeysJSON, sums, sig []byte, expectedTag string, minVersion int64, now time.Time) (int64, error) {
	if rootPub == nil {
		return 0, ErrNotPinned
	}
	signedRK, err := types.DecodeSigned(rootKeysJSON)
	if err != nil {
		return 0, fmt.Errorf("root-keys: %w", err)
	}
	// Reuse the agent path's verifier: it binds the root key id, enforces
	// version monotonicity (anti-rollback / signer-revival) against minVersion,
	// and checks expiry.
	rootTrusted := map[string]ed25519.PublicKey{types.KeyIDFor(rootPub): rootPub}
	rk, err := types.VerifyRootKeys(rootTrusted, signedRK, minVersion, now)
	if err != nil {
		return 0, fmt.Errorf("root-keys: %w", err)
	}
	trusted, err := rk.SigningKeys()
	if err != nil {
		return 0, fmt.Errorf("root-keys signing set: %w", err)
	}
	if len(trusted) == 0 {
		return 0, errors.New("root-keys authorizes no signing keys")
	}
	signedSums, err := types.DecodeSigned(sig)
	if err != nil {
		return 0, fmt.Errorf("sums sig: %w", err)
	}
	var rs ReleaseSums
	if _, err := types.Verify(trusted, contextReleaseSums, signedSums, &rs); err != nil {
		return 0, fmt.Errorf("sums signature: %w", err)
	}
	if got := sha256hex(sums); !strings.EqualFold(got, rs.SHA256) {
		return 0, fmt.Errorf("SHA256SUMS hash mismatch: signed %s, got %s", rs.SHA256, got)
	}
	if expectedTag != "" && rs.Tag != expectedTag {
		return 0, fmt.Errorf("release tag mismatch: signed for %q, installing %q", rs.Tag, expectedTag)
	}
	return rk.Version, nil
}

// LoadVersionFloor returns the highest root-keys version recorded at path, or 0
// when absent/unreadable (first run).
func LoadVersionFloor(path string) int64 {
	b, err := os.ReadFile(path)
	if err != nil {
		return 0
	}
	n, err := strconv.ParseInt(strings.TrimSpace(string(b)), 10, 64)
	if err != nil || n < 0 {
		return 0
	}
	return n
}

// SaveVersionFloor atomically records v at path if it advances the floor.
// Best-effort: a write failure degrades anti-rollback to the expiry backstop,
// it does not break verification.
func SaveVersionFloor(path string, v int64) error {
	if path == "" || v <= LoadVersionFloor(path) {
		return nil
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, []byte(strconv.FormatInt(v, 10)+"\n"), 0o644); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}
