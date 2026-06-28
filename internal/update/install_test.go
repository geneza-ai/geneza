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
	"strings"
	"testing"
	"time"

	"geneza.io/internal/defaults"
	"geneza.io/internal/types"
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
		ControllerURL:  srvURL,
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

// manifestForProduct builds a manifest for an arbitrary product (the helper
// manifestFor is agent-only), used to exercise the relay install path and the
// cross-product rejection.
func manifestForProduct(blob []byte, product, version string) *types.Manifest {
	sum := sha256.Sum256(blob)
	return &types.Manifest{
		Product:   product,
		Version:   version,
		OS:        "linux",
		Arch:      "amd64",
		SHA256:    hex.EncodeToString(sum[:]),
		Size:      int64(len(blob)),
		CreatedAt: time.Now().UTC(),
	}
}

// TestInstallerRelayProduct: a geneza-relay manifest installs under a relay
// installer, and the on-disk binary is named for the product (geneza-relay), so
// the same install machinery serves the relay worker.
func TestInstallerRelayProduct(t *testing.T) {
	pub, priv, keyID, err := types.GenerateSigningKey()
	if err != nil {
		t.Fatal(err)
	}
	blob := makeBlob(t, 4096)
	m := manifestForProduct(blob, "geneza-relay", "1.5.0")
	signed := signManifest(t, priv, keyID, m)
	srv := newArtifactServer(t, map[string][]byte{m.SHA256: blob})
	ins := newTestInstaller(t, srv.URL, pub)
	ins.Product = "geneza-relay"

	path, gotM, err := ins.Install(context.Background(), signed)
	if err != nil {
		t.Fatalf("relay Install: %v", err)
	}
	want := filepath.Join(ins.VersionsDir, "1.5.0", "geneza-relay")
	if path != want {
		t.Fatalf("installed path %q, want %q", path, want)
	}
	if gotM.Product != "geneza-relay" {
		t.Fatalf("manifest product %q", gotM.Product)
	}
	if _, err := os.Stat(want); err != nil {
		t.Fatalf("relay binary not at %q: %v", want, err)
	}
	// The temp file is product-named too and must be gone.
	if _, err := os.Stat(filepath.Join(ins.VersionsDir, "1.5.0", ".geneza-relay.tmp")); !os.IsNotExist(err) {
		t.Fatal("relay temp file left behind")
	}
}

// TestInstallerRejectsCrossProduct: an installer for one product must refuse a
// manifest for the other — a replayed valid relay manifest cannot install as the
// agent, and vice-versa.
func TestInstallerRejectsCrossProduct(t *testing.T) {
	pub, priv, keyID, err := types.GenerateSigningKey()
	if err != nil {
		t.Fatal(err)
	}
	blob := makeBlob(t, 2048)

	// A geneza-relay manifest handed to an agent installer is rejected.
	relayM := manifestForProduct(blob, "geneza-relay", "1.0.0")
	relaySigned := signManifest(t, priv, keyID, relayM)
	srv := newArtifactServer(t, map[string][]byte{relayM.SHA256: blob})
	agentIns := newTestInstaller(t, srv.URL, pub) // Product=geneza-agent
	if _, _, err := agentIns.Install(context.Background(), relaySigned); err == nil {
		t.Fatal("agent installer accepted a geneza-relay manifest — MUST reject")
	} else if !strings.Contains(err.Error(), "product") {
		t.Fatalf("rejection should cite product mismatch, got: %v", err)
	}

	// The mirror: an agent manifest handed to a relay installer is rejected.
	agentM := manifestForProduct(blob, "geneza-agent", "1.0.0")
	agentSigned := signManifest(t, priv, keyID, agentM)
	relayIns := newTestInstaller(t, srv.URL, pub)
	relayIns.Product = "geneza-relay"
	if _, _, err := relayIns.Install(context.Background(), agentSigned); err == nil {
		t.Fatal("relay installer accepted a geneza-agent manifest — MUST reject")
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
	// Signed with a different key than the pinned one: the controller-
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
		func(m *types.Manifest) { m.Product = "geneza-controller" },
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
	// corrupted controller storage).
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
	var gotNode, gotCurrent, gotProduct string
	mode := "json"
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != DesiredPath {
			http.NotFound(w, r)
			return
		}
		gotNode = r.URL.Query().Get("node")
		gotCurrent = r.URL.Query().Get("current")
		gotProduct = r.URL.Query().Get("product")
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

	// The agent path must NOT set ?product (byte-for-byte back-compat).
	d, err := FetchDesired(context.Background(), http.DefaultClient, srv.URL, "node-a", "2.0.0", "geneza-agent")
	if err != nil || d == nil || d.Version != "3.0.0" {
		t.Fatalf("FetchDesired(json) = %+v, %v", d, err)
	}
	if gotNode != "node-a" || gotCurrent != "2.0.0" {
		t.Fatalf("query params node=%q current=%q", gotNode, gotCurrent)
	}
	if gotProduct != "" {
		t.Fatalf("agent path set product=%q, want empty", gotProduct)
	}
	// An empty product is the agent default and likewise omits ?product.
	if _, err := FetchDesired(context.Background(), http.DefaultClient, srv.URL, "n", "c", ""); err != nil {
		t.Fatalf("FetchDesired(empty product) err = %v", err)
	}
	if gotProduct != "" {
		t.Fatalf("empty product set product=%q, want empty", gotProduct)
	}
	// The relay path carries ?product=geneza-relay.
	if _, err := FetchDesired(context.Background(), http.DefaultClient, srv.URL, "r-1", "1.0.0", "geneza-relay"); err != nil {
		t.Fatalf("FetchDesired(relay) err = %v", err)
	}
	if gotProduct != "geneza-relay" {
		t.Fatalf("relay path product=%q, want geneza-relay", gotProduct)
	}

	mode = "nocontent"
	if d, err = FetchDesired(context.Background(), http.DefaultClient, srv.URL, "n", "c", ""); err != nil || d != nil {
		t.Fatalf("FetchDesired(204) = %+v, %v", d, err)
	}
	mode = "empty"
	if d, err = FetchDesired(context.Background(), http.DefaultClient, srv.URL, "n", "c", ""); err != nil || d != nil {
		t.Fatalf("FetchDesired(empty) = %+v, %v", d, err)
	}
}
