package controller

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"testing"
)

// TestEd25519PublicKeyRejectsNonEd25519 pins the load-bearing guard: the grant key
// must be Ed25519. A non-Ed25519 signer (an ECDSA token key is the realistic case,
// since it is the one that opens on an HSM) is rejected before it can sign a config
// that the Ed25519-only verifier would later reject.
func TestEd25519PublicKeyRejectsNonEd25519(t *testing.T) {
	_, ed, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	pub, err := ed25519PublicKey(ed)
	if err != nil || !pub.Equal(ed.Public().(ed25519.PublicKey)) {
		t.Fatalf("ed25519 signer: got (%v, %v), want its public key", pub, err)
	}
	ec, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ed25519PublicKey(ec); err == nil {
		t.Fatal("an ECDSA grant signer must be rejected, got nil error")
	}
}

// A key-source block defaults to the on-disk key (file backend) and may opt into
// a pkcs11 token. A pkcs11 block must be complete — a missing module, token
// selector, or key selector fails loudly at config load rather than at startup.
func TestKeySourceValidation(t *testing.T) {
	base := func() *Config {
		c := &Config{
			DataDir:     "/var/lib/geneza",
			ClusterName: "test",
			PolicyFile:  "/etc/geneza/policy.yaml",
		}
		c.applyDefaults() // synthesizes the required "default" workspace
		return c
	}
	full := KeySourceConfig{
		Backend:    "pkcs11",
		Module:     "/usr/lib/softhsm/libsofthsm2.so",
		TokenLabel: "geneza",
		PIN:        "1234",
		KeyLabel:   "geneza-ca",
	}
	cases := []struct {
		name   string
		src    KeySourceConfig
		wantOK bool
	}{
		{"empty is file default", KeySourceConfig{}, true},
		{"explicit file", KeySourceConfig{Backend: "file"}, true},
		{"complete pkcs11", full, true},
		{"unknown backend", KeySourceConfig{Backend: "vault"}, false},
		{"pkcs11 missing module", KeySourceConfig{Backend: "pkcs11", TokenLabel: "t", KeyLabel: "k"}, false},
		{"pkcs11 missing token selector", KeySourceConfig{Backend: "pkcs11", Module: "/m.so", KeyLabel: "k"}, false},
		{"pkcs11 missing key selector", KeySourceConfig{Backend: "pkcs11", Module: "/m.so", TokenLabel: "t"}, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			cfg := base()
			cfg.CAKeySource = c.src
			err := cfg.validate()
			if c.wantOK && err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if !c.wantOK && err == nil {
				t.Fatal("expected a validation error")
			}
		})
	}
}

// The default (unset) key-source resolves to the on-disk key paths under data_dir
// — the byte-for-byte behavior a deployment with no key-source config gets.
func TestKeySourceDefaultPaths(t *testing.T) {
	cfg := &Config{DataDir: "/var/lib/geneza"}
	if got := cfg.caKeySource().Path; got != "/var/lib/geneza/ca/issuing-ca.key" {
		t.Errorf("ca path = %q", got)
	}
	if cfg.caKeySource().Backend != "" {
		t.Errorf("ca backend = %q, want file default", cfg.caKeySource().Backend)
	}
	if got := cfg.grantKeySource().Path; got != "/var/lib/geneza/grant.key" {
		t.Errorf("grant path = %q", got)
	}
}
