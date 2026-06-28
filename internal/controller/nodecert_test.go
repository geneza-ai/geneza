package controller

import (
	"bytes"
	"crypto/rand"
	"testing"

	"golang.org/x/crypto/curve25519"

	"geneza.io/internal/nodeseal"
)

func gwNodeKeypair(t *testing.T) (priv, pub []byte) {
	t.Helper()
	priv = make([]byte, 32)
	if _, err := rand.Read(priv); err != nil {
		t.Fatal(err)
	}
	pub, err := curve25519.X25519(priv, curve25519.Basepoint)
	if err != nil {
		t.Fatal(err)
	}
	return priv, pub
}

func writeBlob(t *testing.T, s *Server, name string, data []byte) string {
	t.Helper()
	ref := s.recordingBlobs.newRef(name)
	w, err := s.recordingBlobs.create(ref)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := w.Write(data); err != nil {
		t.Fatal(err)
	}
	if err := w.Commit(); err != nil {
		t.Fatal(err)
	}
	return ref
}

func TestBuildNodeCertBundle(t *testing.T) {
	srv := newReplayServer(t)
	ws := defaultWorkspace
	priv, pub := gwNodeKeypair(t)
	node := &NodeRecord{ID: "n1", WorkspaceID: ws, NoisePub: pub, Approved: true}
	if err := srv.store.PutNode(ws, node); err != nil {
		t.Fatal(err)
	}

	// A managed cert for this workspace, bundle stored in the blob store.
	bundle := []byte("-----BEGIN PRIVATE KEY-----\nk\n-----END PRIVATE KEY-----\n-----BEGIN CERTIFICATE-----\nc\n-----END CERTIFICATE-----\n")
	ref := writeBlob(t, srv, "mc-acme.pem", bundle)
	if err := srv.store.PutManagedCert(&ManagedCertRecord{
		ID: reservationCertID("geneza.app", "acme"), WorkspaceID: ws,
		Domain: "geneza.app", Label: "acme", Kind: KindWorkspaceWildcard, Ref: ref, Epoch: 1,
		Names: []string{"*.acme.geneza.app", "acme.geneza.app"},
	}); err != nil {
		t.Fatal(err)
	}
	// A cert in a DIFFERENT workspace must not be included.
	ref2 := writeBlob(t, srv, "mc-other.pem", []byte("other-bundle"))
	if err := srv.store.PutManagedCert(&ManagedCertRecord{
		ID: "sub-x", WorkspaceID: "wsOther", Domain: "geneza.app", Label: "x", Kind: KindWorkspaceWildcard, Ref: ref2, Epoch: 1,
	}); err != nil {
		t.Fatal(err)
	}

	cb, err := srv.buildNodeCertBundle(ws, node)
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	if len(cb.GetCerts()) != 1 {
		t.Fatalf("want 1 workspace-scoped cert, got %d", len(cb.GetCerts()))
	}
	sc := cb.GetCerts()[0]
	if sc.GetZone() != "acme.geneza.app" || sc.GetEpoch() != 1 {
		t.Fatalf("unexpected sealed cert: zone=%q epoch=%d", sc.GetZone(), sc.GetEpoch())
	}
	// The target node can unseal it back to the original bundle; no one else can.
	got, err := nodeseal.Open(sc.GetSealed(), priv)
	if err != nil {
		t.Fatalf("node open: %v", err)
	}
	if !bytes.Equal(got, bundle) {
		t.Fatalf("round-trip mismatch")
	}
	otherPriv, _ := gwNodeKeypair(t)
	if _, err := nodeseal.Open(sc.GetSealed(), otherPriv); err == nil {
		t.Fatal("a different node must not be able to unseal")
	}
}

func TestBuildNodeCertBundleNoNoiseKey(t *testing.T) {
	srv := newReplayServer(t)
	node := &NodeRecord{ID: "n2", WorkspaceID: defaultWorkspace, Approved: true} // no NoisePub
	if _, err := srv.buildNodeCertBundle(defaultWorkspace, node); err == nil {
		t.Fatal("a node with no noise key cannot receive sealed certs")
	}
}
