package update

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"testing"
	"time"

	"osie.cloud/geneza/internal/defaults"
	"osie.cloud/geneza/internal/types"
)

func TestRaiseFloor(t *testing.T) {
	s := &State{}
	if !s.RaiseFloor(100) || s.FloorUnix != 100 {
		t.Fatalf("floor should rise to 100, got %d", s.FloorUnix)
	}
	if s.RaiseFloor(50) || s.FloorUnix != 100 {
		t.Fatalf("floor must not lower; got %d", s.FloorUnix)
	}
	if !s.RaiseFloor(200) || s.FloorUnix != 200 {
		t.Fatalf("floor should rise to 200, got %d", s.FloorUnix)
	}
}

// Install must refuse a validly-signed manifest built before the anti-rollback
// floor, BEFORE any download — defeating a replayed old manifest (downgrade).
func TestInstallRefusesRollback(t *testing.T) {
	pub, priv, keyID, err := types.GenerateSigningKey()
	if err != nil {
		t.Fatal(err)
	}
	blob := []byte("#!/bin/sh\necho old\n")
	sum := sha256.Sum256(blob)
	old := &types.Manifest{
		Product: "geneza-agent", Version: "0.9.0", OS: "linux", Arch: "amd64",
		SHA256: hex.EncodeToString(sum[:]), Size: int64(len(blob)),
		CreatedAt: time.Unix(1000, 0),
	}
	sm, err := types.Sign(priv, keyID, defaults.ContextManifest, old)
	if err != nil {
		t.Fatal(err)
	}
	ins := &Installer{
		Client: http.DefaultClient, GatewayURL: "https://unused", Pub: pub,
		Product: "geneza-agent", OS: "linux", Arch: "amd64",
		VersionsDir:  t.TempDir(),
		MinCreatedAt: time.Unix(5000, 0), // floor is newer than the manifest
	}
	_, _, err = ins.Install(context.Background(), sm)
	if err == nil {
		t.Fatal("expected anti-rollback rejection")
	}
	// It must fail on the rollback check, not on a network error (i.e. before download).
	if got := err.Error(); !contains(got, "rollback floor") && !contains(got, "refusing downgrade") {
		t.Fatalf("expected rollback rejection, got: %v", err)
	}
}

func contains(s, sub string) bool {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}
