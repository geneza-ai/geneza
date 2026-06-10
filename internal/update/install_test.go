package update

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"osie.cloud/geneza/internal/defaults"
	"osie.cloud/geneza/internal/types"
)

func testLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

func makeBlob(t *testing.T, size int) []byte {
	t.Helper()
	b := make([]byte, size)
	if _, err := rand.Read(b); err != nil {
		t.Fatal(err)
	}
	return b
}

func manifestFor(blob []byte, version string) *types.Manifest {
	sum := sha256.Sum256(blob)
	return &types.Manifest{
		Product:   "geneza-agent",
		Version:   version,
		OS:        "linux",
		Arch:      "amd64",
		SHA256:    hex.EncodeToString(sum[:]),
		Size:      int64(len(blob)),
		CreatedAt: time.Now().UTC(),
	}
}

func signManifest(t *testing.T, priv ed25519.PrivateKey, keyID string, m *types.Manifest) *types.Signed {
	t.Helper()
	s, err := types.Sign(priv, keyID, defaults.ContextManifest, m)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

// TestManifestSignVerifyRoundTripAndTamper covers the offline-signing trust
// core: a valid manifest verifies; any flipped byte — in the signed payload
// or in the binary blob — must fail closed.
func TestManifestSignVerifyRoundTripAndTamper(t *testing.T) {
	pub, priv, keyID, err := types.GenerateSigningKey()
	if err != nil {
		t.Fatal(err)
	}
	blob := makeBlob(t, 4096)
	m := manifestFor(blob, "1.2.3")
	signed := signManifest(t, priv, keyID, m)

	var got types.Manifest
	if err := types.VerifyOne(pub, "", defaults.ContextManifest, signed, &got); err != nil {
		t.Fatalf("VerifyOne(valid): %v", err)
	}
	if got.SHA256 != m.SHA256 || got.Version != "1.2.3" {
		t.Fatalf("verified manifest mismatch: %+v", got)
	}
	if err := got.VerifyBlob(bytes.NewReader(blob)); err != nil {
		t.Fatalf("VerifyBlob(valid): %v", err)
	}

	// Tampered payload byte: signature must fail.
	bad := *signed
	bad.Payload = bytes.Clone(signed.Payload)
	bad.Payload[len(bad.Payload)/2] ^= 0x01
	if err := types.VerifyOne(pub, "", defaults.ContextManifest, &bad, nil); err == nil {
		t.Fatal("tampered payload verified — MUST fail")
	}

	// Tampered signature byte.
	bad2 := *signed
	bad2.Sig = bytes.Clone(signed.Sig)
	bad2.Sig[0] ^= 0x01
	if err := types.VerifyOne(pub, "", defaults.ContextManifest, &bad2, nil); err == nil {
		t.Fatal("tampered signature verified — MUST fail")
	}

	// Wrong verification context (domain separation).
	if err := types.VerifyOne(pub, "", defaults.ContextGrant, signed, nil); err == nil {
		t.Fatal("cross-context verification succeeded — MUST fail")
	}

	// Tampered blob byte: hash check must fail.
	blob2 := bytes.Clone(blob)
	blob2[10] ^= 0x01
	if err := got.VerifyBlob(bytes.NewReader(blob2)); err == nil {
		t.Fatal("tampered blob verified — MUST fail")
	}
	// Truncated blob: size check must fail.
	if err := got.VerifyBlob(bytes.NewReader(blob[:len(blob)-1])); err == nil {
		t.Fatal("truncated blob verified — MUST fail")
	}
}

func newArtifactServer(t *testing.T, blobs map[string][]byte) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		const prefix = "/v1/artifacts/"
		if len(r.URL.Path) <= len(prefix) || r.URL.Path[:len(prefix)] != prefix {
			http.NotFound(w, r)
			return
		}
		b, ok := blobs[r.URL.Path[len(prefix):]]
		if !ok {
			http.NotFound(w, r)
			return
		}
		w.Write(b)
	}))
	t.Cleanup(srv.Close)
	return srv
}

func newTestInstaller(t *testing.T, srvURL string, pub ed25519.PublicKey) *Installer {
	t.Helper()
	return &Installer{
		Client:      http.DefaultClient,
		GatewayURL:  srvURL,
		Pub:         pub,
		Product:     "geneza-agent",
		OS:          "linux",
		Arch:        "amd64",
		VersionsDir: t.TempDir(),
		Log:         testLogger(),
	}
}

func TestInstallerHappyPath(t *testing.T) {
	pub, priv, keyID, err := types.GenerateSigningKey()
	if err != nil {
		t.Fatal(err)
	}
	blob := makeBlob(t, 8192)
	m := manifestFor(blob, "2.0.0")
	signed := signManifest(t, priv, keyID, m)
	srv := newArtifactServer(t, map[string][]byte{m.SHA256: blob})
	ins := newTestInstaller(t, srv.URL, pub)

	path, gotM, err := ins.Install(context.Background(), signed)
	if err != nil {
		t.Fatalf("Install: %v", err)
	}
	want := filepath.Join(ins.VersionsDir, "2.0.0", "geneza-agent")
	if path != want {
		t.Fatalf("installed path %q, want %q", path, want)
	}
	if gotM.Version != "2.0.0" {
		t.Fatalf("manifest version %q", gotM.Version)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(data, blob) {
		t.Fatal("installed binary differs from blob")
	}
	fi, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode().Perm() != 0o755 {
		t.Fatalf("installed mode %v, want 0755", fi.Mode().Perm())
	}
	// No temp file may remain.
	if _, err := os.Stat(filepath.Join(ins.VersionsDir, "2.0.0", ".geneza-agent.tmp")); !os.IsNotExist(err) {
		t.Fatal("temp file left behind")
	}
}

func TestInstallerRejectsTamperedManifest(t *testing.T) {
	pub, priv, keyID, _ := types.GenerateSigningKey()
	blob := makeBlob(t, 1024)
	signed := signManifest(t, priv, keyID, manifestFor(blob, "2.0.0"))
	signed.Payload = bytes.Clone(signed.Payload)
	signed.Payload[5] ^= 0x01

	srv := newArtifactServer(t, nil)
	ins := newTestInstaller(t, srv.URL, pub)
	if _, _, err := ins.Install(context.Background(), signed); err == nil {
		t.Fatal("tampered manifest installed — MUST fail")
	}
}

func TestInstallerRejectsWrongKey(t *testing.T) {
	// Signed with a different key than the pinned one: the gateway-
	// compromise scenario. Must fail regardless of TLS.
	pinnedPub, _, _, _ := types.GenerateSigningKey()
	_, otherPriv, otherID, _ := types.GenerateSigningKey()
	blob := makeBlob(t, 1024)
	m := manifestFor(blob, "2.0.0")
	signed := signManifest(t, otherPriv, otherID, m)

	srv := newArtifactServer(t, map[string][]byte{m.SHA256: blob})
	ins := newTestInstaller(t, srv.URL, pinnedPub)
	if _, _, err := ins.Install(context.Background(), signed); err == nil {
		t.Fatal("manifest signed by non-pinned key installed — MUST fail")
	}
}

func TestInstallerRejectsMismatchedPlatformAndProduct(t *testing.T) {
	pub, priv, keyID, _ := types.GenerateSigningKey()
	blob := makeBlob(t, 1024)
	srv := newArtifactServer(t, nil)
	ins := newTestInstaller(t, srv.URL, pub)

	for _, mutate := range []func(*types.Manifest){
		func(m *types.Manifest) { m.Product = "geneza-gateway" },
		func(m *types.Manifest) { m.OS = "darwin" },
		func(m *types.Manifest) { m.Arch = "arm64" },
		func(m *types.Manifest) { m.Version = "../escape" },
		func(m *types.Manifest) { m.SHA256 = "abc" },
		func(m *types.Manifest) { m.Size = 0 },
	} {
		m := manifestFor(blob, "2.0.0")
		mutate(m)
		signed := signManifest(t, priv, keyID, m)
		if _, _, err := ins.Install(context.Background(), signed); err == nil {
			t.Fatalf("manifest %+v installed — MUST fail", m)
		}
	}
}

func TestInstallerRejectsWrongBlob(t *testing.T) {
	pub, priv, keyID, _ := types.GenerateSigningKey()
	blob := makeBlob(t, 2048)
	m := manifestFor(blob, "2.0.0")
	signed := signManifest(t, priv, keyID, m)

	// Server returns different bytes under the manifest's hash (hostile or
	// corrupted gateway storage).
	evil := makeBlob(t, 2048)
	srv := newArtifactServer(t, map[string][]byte{m.SHA256: evil})
	ins := newTestInstaller(t, srv.URL, pub)

	if _, _, err := ins.Install(context.Background(), signed); err == nil {
		t.Fatal("blob with wrong hash installed — MUST fail")
	}
	// Nothing may exist at the final path, and no temp residue.
	dir := filepath.Join(ins.VersionsDir, "2.0.0")
	if _, err := os.Stat(filepath.Join(dir, "geneza-agent")); !os.IsNotExist(err) {
		t.Fatal("final binary present after failed verification")
	}
	if _, err := os.Stat(filepath.Join(dir, ".geneza-agent.tmp")); !os.IsNotExist(err) {
		t.Fatal("temp file left behind after failed verification")
	}
}

func TestFetchDesired(t *testing.T) {
	var gotNode, gotCurrent string
	mode := "json"
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != DesiredPath {
			http.NotFound(w, r)
			return
		}
		gotNode = r.URL.Query().Get("node")
		gotCurrent = r.URL.Query().Get("current")
		switch mode {
		case "nocontent":
			w.WriteHeader(http.StatusNoContent)
		case "empty":
			w.WriteHeader(http.StatusOK)
		default:
			w.Write([]byte(`{"version":"3.0.0"}`))
		}
	}))
	defer srv.Close()

	d, err := FetchDesired(context.Background(), http.DefaultClient, srv.URL, "node-a", "2.0.0")
	if err != nil || d == nil || d.Version != "3.0.0" {
		t.Fatalf("FetchDesired(json) = %+v, %v", d, err)
	}
	if gotNode != "node-a" || gotCurrent != "2.0.0" {
		t.Fatalf("query params node=%q current=%q", gotNode, gotCurrent)
	}

	mode = "nocontent"
	if d, err = FetchDesired(context.Background(), http.DefaultClient, srv.URL, "n", "c"); err != nil || d != nil {
		t.Fatalf("FetchDesired(204) = %+v, %v", d, err)
	}
	mode = "empty"
	if d, err = FetchDesired(context.Background(), http.DefaultClient, srv.URL, "n", "c"); err != nil || d != nil {
		t.Fatalf("FetchDesired(empty) = %+v, %v", d, err)
	}
}
