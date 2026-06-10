package types

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"time"
)

// Manifest describes one published agent (worker) binary. It is signed
// OFFLINE by the artifact signing key — never by the gateway — and verified
// by the bootstrap against a public key pinned in its own config/build.
// A compromised gateway can therefore serve stale manifests at worst, never
// forged ones.
type Manifest struct {
	Product   string    `json:"product"` // "geneza-agent"
	Version   string    `json:"version"`
	OS        string    `json:"os"`
	Arch      string    `json:"arch"`
	SHA256    string    `json:"sha256"` // hex of the binary blob
	Size      int64     `json:"size"`
	CreatedAt time.Time `json:"created_at"`
}

func (m *Manifest) BlobPath() string {
	return "/v1/artifacts/" + m.SHA256
}

// VerifyBlob checks a downloaded blob against the manifest hash/size.
func (m *Manifest) VerifyBlob(r io.Reader) error {
	h := sha256.New()
	n, err := io.Copy(h, r)
	if err != nil {
		return fmt.Errorf("hashing blob: %w", err)
	}
	if n != m.Size {
		return fmt.Errorf("blob size %d != manifest size %d", n, m.Size)
	}
	got := hex.EncodeToString(h.Sum(nil))
	if got != m.SHA256 {
		return fmt.Errorf("blob sha256 %s != manifest %s", got, m.SHA256)
	}
	return nil
}

// DesiredVersionResponse is returned by the gateway's HTTP desired-version
// endpoint, polled by bootstraps (reconcile loop, not push).
type DesiredVersionResponse struct {
	Version        string  `json:"version"`         // desired worker version for this node
	SignedManifest *Signed `json:"signed_manifest"` // wraps Manifest; absent if no artifact
}
