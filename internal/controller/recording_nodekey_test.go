package controller

import (
	"crypto/ecdsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"testing"

	"geneza.io/internal/types"
)

// The node's signature was stored and served from the very first release, but the
// key that produced it was not — and node certs live 24 hours. So the signature
// was an unverifiable blob: no client could check it, and the console had to fall
// back to claiming only that a sha256 matched a digest served in the same
// response by the same party.
//
// This asserts the fix end-to-end: the upload captures the signing key, and the
// signature re-verifies against the STORED key afterwards, which is exactly what
// the browser does with the X-Geneza-Recording-Node-Key header.
func TestUploadRetainsTheKeyThatMakesTheSignatureVerifiable(t *testing.T) {
	run := func(t *testing.T, srv *Server) {
		srv.setClusterConfig(2, signedConfigWithAudit(t, srv, 2, testAuditRecipient))
		nc := newNodeCert(t)
		const ws, node, sid = defaultWorkspace, "n1", "s-bbbbbbbbbbbb"
		seedSession(t, srv, ws, node, sid)

		cipher := []byte("ciphertext-blob")
		if err := uploadRecording(t, srv, ws, node, nc, sid, cipher, ""); err != nil {
			t.Fatalf("upload: %v", err)
		}
		rec, err := srv.store.GetRecording(ws, sid)
		if err != nil {
			t.Fatalf("get recording: %v", err)
		}
		if len(rec.NodeSPKI) == 0 {
			t.Fatal("no node key stored: the signature can never be verified again")
		}

		// Re-verify exactly as an auditor would, from the STORED key alone —
		// nothing from the live node, whose cert has since rotated.
		pub, err := x509.ParsePKIXPublicKey(rec.NodeSPKI)
		if err != nil {
			t.Fatalf("stored key does not parse as SPKI: %v", err)
		}
		ecPub, ok := pub.(*ecdsa.PublicKey)
		if !ok {
			t.Fatalf("stored key is %T, want *ecdsa.PublicKey", pub)
		}
		sum := sha256.Sum256(cipher)
		digest := types.RecordingManifestDigest(sid, hex.EncodeToString(sum[:]), int64(len(cipher)), 1700)
		if !ecdsa.VerifyASN1(ecPub, digest, rec.NodeSig) {
			t.Fatal("the stored signature does not verify against the stored key")
		}

		// The signature must be bound to THIS recording: a manifest describing
		// different bytes must not verify under the same key.
		other := sha256.Sum256([]byte("some other blob"))
		tampered := types.RecordingManifestDigest(sid, hex.EncodeToString(other[:]), int64(len(cipher)), 1700)
		if ecdsa.VerifyASN1(ecPub, tampered, rec.NodeSig) {
			t.Fatal("the signature verifies over a substituted blob, so it attests nothing")
		}

		// And it must be the UPLOADING node's key, not some other node's.
		if string(rec.NodeSPKI) != string(nc.cert.RawSubjectPublicKeyInfo) {
			t.Fatal("stored key is not the key of the cert that authenticated the upload")
		}
	}

	t.Run("bbolt", func(t *testing.T) { run(t, newReplayServer(t)) })
	t.Run("sql", func(t *testing.T) {
		forEachSQLEngine(t, func(t *testing.T, sqls *sqlStore) {
			run(t, newReplayServerWithStore(t, sqls))
		})
	})
}
