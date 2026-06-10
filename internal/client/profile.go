// Package client implements the operator-side ("geneza" CLI) plumbing:
// profile state on disk, the key store, gateway HTTP/gRPC access, the OIDC
// login flows, and the native end-to-end tunnel + attach-channel pumps.
package client

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
)

// Profile is the persisted per-profile configuration (profile.json).
type Profile struct {
	GatewayGRPC string `json:"gateway_grpc"` // host:7401
	GatewayHTTP string `json:"gateway_http"` // https://host:7402
	User        string `json:"user,omitempty"`
	Provider    string `json:"provider,omitempty"`
	// CASHA256 pins the SHA-256 (hex) of the ca.pem bundle accepted at login
	// (TOFU or --ca-file). Every later load fails closed on a mismatch.
	CASHA256 string `json:"ca_sha256,omitempty"`
}

// Store is the on-disk profile directory: ($GENEZA_HOME|~/.geneza)/<profile>.
type Store struct {
	dir string
}

// NewStore resolves (and creates) the profile directory.
func NewStore(profile string) (*Store, error) {
	if profile == "" {
		profile = "default"
	}
	// Profile names become path components; refuse anything that escapes.
	if profile != filepath.Base(profile) || profile == "." || profile == ".." {
		return nil, fmt.Errorf("invalid profile name %q", profile)
	}
	home := os.Getenv("GENEZA_HOME")
	if home == "" {
		uh, err := os.UserHomeDir()
		if err != nil {
			return nil, fmt.Errorf("resolve home dir: %w", err)
		}
		home = filepath.Join(uh, ".geneza")
	}
	dir := filepath.Join(home, profile)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	return &Store{dir: dir}, nil
}

func (s *Store) Dir() string         { return s.dir }
func (s *Store) ProfilePath() string { return filepath.Join(s.dir, "profile.json") }
func (s *Store) CAPath() string      { return filepath.Join(s.dir, "ca.pem") }
func (s *Store) KeyPath() string     { return filepath.Join(s.dir, "user.key") }
func (s *Store) CertPath() string    { return filepath.Join(s.dir, "user.crt") }

// ErrNoProfile means login has never been run for this profile.
var ErrNoProfile = errors.New("no profile found (run 'geneza login')")

func (s *Store) LoadProfile() (*Profile, error) {
	b, err := os.ReadFile(s.ProfilePath())
	if errors.Is(err, os.ErrNotExist) {
		return nil, ErrNoProfile
	}
	if err != nil {
		return nil, err
	}
	var p Profile
	if err := json.Unmarshal(b, &p); err != nil {
		return nil, fmt.Errorf("%s: %w", s.ProfilePath(), err)
	}
	return &p, nil
}

func (s *Store) SaveProfile(p *Profile) error {
	b, err := json.MarshalIndent(p, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(s.ProfilePath(), append(b, '\n'), 0o600)
}

// SaveCA writes the trust bundle and returns its pin (hex SHA-256).
func (s *Store) SaveCA(pemBytes []byte) (string, error) {
	if err := os.WriteFile(s.CAPath(), pemBytes, 0o644); err != nil {
		return "", err
	}
	return CAFingerprint(pemBytes), nil
}

// LoadCA reads ca.pem and, when pin is non-empty, fails closed on mismatch.
func (s *Store) LoadCA(pin string) ([]byte, error) {
	b, err := os.ReadFile(s.CAPath())
	if errors.Is(err, os.ErrNotExist) {
		return nil, fmt.Errorf("no CA bundle for this profile (run 'geneza login')")
	}
	if err != nil {
		return nil, err
	}
	if pin != "" {
		if got := CAFingerprint(b); got != pin {
			return nil, fmt.Errorf("CA pin mismatch for %s: have %s, pinned %s — possible tampering; remove the profile dir to re-establish trust", s.CAPath(), got, pin)
		}
	}
	return b, nil
}

// CAFingerprint is the pin format: lowercase hex SHA-256 of the PEM bundle.
func CAFingerprint(pemBytes []byte) string {
	h := sha256.Sum256(pemBytes)
	return hex.EncodeToString(h[:])
}
