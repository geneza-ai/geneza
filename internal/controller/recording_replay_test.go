package controller

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"geneza.io/internal/ca"
	"geneza.io/internal/defaults"
	genezav1 "geneza.io/internal/pb/geneza/v1"
	"geneza.io/internal/types"
)

// fakeUploadStream feeds a fixed set of RecordingChunks into UploadRecording and
// captures the final ack, standing in for the gRPC client-streaming transport.
type fakeUploadStream struct {
	grpc.ServerStream
	ctx    context.Context
	chunks []*genezav1.RecordingChunk
	i      int
	ack    *genezav1.UploadAck
}

func (f *fakeUploadStream) Context() context.Context { return f.ctx }
func (f *fakeUploadStream) Recv() (*genezav1.RecordingChunk, error) {
	if f.i >= len(f.chunks) {
		return nil, context.Canceled
	}
	c := f.chunks[f.i]
	f.i++
	return c, nil
}
func (f *fakeUploadStream) SendAndClose(ack *genezav1.UploadAck) error { f.ack = ack; return nil }

// fakeBlobStream collects the RecordingBlobChunks GetRecording streams out. A
// non-zero failAfter makes Send fail once that many chunks have been delivered, to
// model a client that drops the connection mid-cast.
type fakeBlobStream struct {
	grpc.ServerStream
	ctx       context.Context
	chunks    []*genezav1.RecordingBlobChunk
	failAfter int
}

func (f *fakeBlobStream) Context() context.Context { return f.ctx }
func (f *fakeBlobStream) Send(c *genezav1.RecordingBlobChunk) error {
	f.chunks = append(f.chunks, c)
	if f.failAfter > 0 && len(f.chunks) >= f.failAfter {
		return errors.New("stream cancelled")
	}
	return nil
}

// nodeCertCtx wraps a node identity plus the cert that authenticated it (the
// upload path verifies the manifest signature against this cert).
func nodeCertCtx(ws, name string, cert *certWithKey) context.Context {
	pi := &peerInfo{identity: &ca.Identity{Kind: ca.KindNode, Workspace: ws, Name: name}, leaf: cert.cert}
	return context.WithValue(context.Background(), peerInfoKey{}, pi)
}

// userCtx builds a user identity context with the given roles.
func userCtx(ws, name string, roles ...string) context.Context {
	pi := &peerInfo{identity: &ca.Identity{Kind: ca.KindUser, Workspace: ws, Name: name, Roles: roles}}
	return context.WithValue(context.Background(), peerInfoKey{}, pi)
}

type certWithKey struct {
	key  *ecdsa.PrivateKey
	cert *x509.Certificate
}

// newNodeCert mints an ECDSA key and a self-signed cert wrapping its public key,
// the node leaf the upload path verifies the manifest signature against.
func newNodeCert(t *testing.T) *certWithKey {
	t.Helper()
	key := mustECDSA(t)
	return &certWithKey{key: key, cert: certFor(t, &key.PublicKey)}
}

// signedConfigWithAudit returns the encoded signed cluster config carrying the
// given audit recipient, using the server's own grant key so setClusterConfig can
// decode it.
func signedConfigWithAudit(t *testing.T, srv *Server, version int64, recipient string) []byte {
	t.Helper()
	cc := types.ClusterConfig{ConfigVersion: version, AuditRecipient: recipient}
	signed, err := types.Sign(srv.grantKey, srv.grantKeyID, defaults.ContextClusterConfig, cc)
	if err != nil {
		t.Fatalf("sign config: %v", err)
	}
	b, err := signed.Encode()
	if err != nil {
		t.Fatalf("encode config: %v", err)
	}
	return b
}

// uploadRecording drives a full recording upload for sessionID with the given
// ciphertext, signing the manifest with nodeKey and claiming claimedAuditKeyID in
// the manifest (which the controller must ignore).
func uploadRecording(t *testing.T, srv *Server, ws, node string, nc *certWithKey, sessionID string, cipher []byte, claimedAuditKeyID string) error {
	t.Helper()
	sum := sha256.Sum256(cipher)
	size := int64(len(cipher))
	const ended = int64(1700)
	digest := types.RecordingManifestDigest(sessionID, hex.EncodeToString(sum[:]), size, ended)
	sig, err := ecdsa.SignASN1(rand.Reader, nc.key, digest)
	if err != nil {
		t.Fatal(err)
	}
	man := &genezav1.RecordingManifest{
		Sha256: sum[:], SizeBytes: size, NodeSig: sig, EndedUnix: ended,
		AuditKeyId: claimedAuditKeyID, StartedUnix: 1600, Principal: "node-claimed",
	}
	stream := &fakeUploadStream{
		ctx: nodeCertCtx(ws, node, nc),
		chunks: []*genezav1.RecordingChunk{
			{SessionId: sessionID, Data: cipher, Eof: true, Manifest: man},
		},
	}
	n := &nodeControlService{s: srv}
	return n.UploadRecording(stream)
}

// seedSession records a minimal active session UploadRecording will accept.
func seedSession(t *testing.T, srv *Server, ws, node, id string) {
	t.Helper()
	if err := srv.store.PutSession(ws, &SessionRecord{
		ID: id, NodeID: node, User: "alice", Action: "shell",
		State: SessionActive, StartedUnix: 1600,
	}); err != nil {
		t.Fatalf("seed session: %v", err)
	}
}

const testAuditRecipient = "age1ql3z7hjy54pw3hyww5ayyfg7zqgvc7w3j2elw8zmrj2kg5sfn9aqmcac8p"

// TestUploadRecordingAuthoritativeAuditKeyID proves the stored audit_key_id is
// derived from the workspace's configured recipient, never from the node-supplied
// manifest — so a compromised node cannot mislabel which key decrypts its blob.
func TestUploadRecordingAuthoritativeAuditKeyID(t *testing.T) {
	run := func(t *testing.T, srv *Server) {
		srv.setClusterConfig(2, signedConfigWithAudit(t, srv, 2, testAuditRecipient))
		nc := newNodeCert(t)
		const ws, node, sid = defaultWorkspace, "n1", "s-aaaaaaaaaaaa"
		seedSession(t, srv, ws, node, sid)

		// The node lies about the audit key in its manifest.
		if err := uploadRecording(t, srv, ws, node, nc, sid, []byte("ciphertext-blob"), "attacker-controlled-key"); err != nil {
			t.Fatalf("upload: %v", err)
		}
		rec, err := srv.store.GetRecording(ws, sid)
		if err != nil {
			t.Fatalf("get recording: %v", err)
		}
		want := auditKeyIDFor(testAuditRecipient)
		if rec.AuditKeyID != want {
			t.Fatalf("audit_key_id = %q, want the configured key %q (not the manifest claim)", rec.AuditKeyID, want)
		}
		if rec.AuditKeyID == "attacker-controlled-key" {
			t.Fatalf("audit_key_id took the node's manifest claim")
		}
	}

	t.Run("bbolt", func(t *testing.T) { run(t, newReplayServer(t)) })
	t.Run("sql", func(t *testing.T) {
		forEachSQLEngine(t, func(t *testing.T, sqls *sqlStore) {
			run(t, newReplayServerWithStore(t, sqls))
		})
	})
}

// newReplayServer is a full bbolt-backed server (real audit + blob store + config).
func newReplayServer(t *testing.T) *Server {
	t.Helper()
	cfg := testServerConfig(t)
	if err := InitDataDir(cfg); err != nil {
		t.Fatalf("init: %v", err)
	}
	srv, err := New(cfg)
	if err != nil {
		t.Fatalf("new server: %v", err)
	}
	t.Cleanup(srv.Close)
	return srv
}

// newReplayServerWithStore swaps a SQL store under an otherwise-real server, so the
// audit-key assertion runs against Postgres and MariaDB while keeping the live
// audit, blob store and signed-config machinery.
func newReplayServerWithStore(t *testing.T, sqls *sqlStore) *Server {
	t.Helper()
	srv := newReplayServer(t)
	srv.store = sqls
	if err := sqls.PutWorkspace(&WorkspaceRecord{ID: defaultWorkspace, Name: "default", OverlayCIDR: "100.64.0.0/24"}); err != nil {
		t.Fatalf("seed workspace: %v", err)
	}
	return srv
}

// TestRecordingReplayAuthz proves the capability gate and the auditor-is-audited
// property: list/fetch are denied without the replay capability and allowed with
// it, and a fetch emits a recording_fetched audit event.
func TestRecordingReplayAuthz(t *testing.T) {
	srv := newReplayServer(t)
	srv.setClusterConfig(2, signedConfigWithAudit(t, srv, 2, testAuditRecipient))
	nc := newNodeCert(t)
	const ws, node, sid = defaultWorkspace, "n1", "s-bbbbbbbbbbbb"
	seedSession(t, srv, ws, node, sid)
	cipher := []byte("opaque-age-ciphertext-payload")
	if err := uploadRecording(t, srv, ws, node, nc, sid, cipher, "ignored"); err != nil {
		t.Fatalf("upload: %v", err)
	}

	u := &userAPIService{s: srv}

	// Denied: an ordinary operator (ws-member) cannot list or fetch.
	opCtx := userCtx(ws, "bob", "ws-member")
	if _, err := u.ListRecordings(opCtx, &genezav1.ListRecordingsRequest{}); status.Code(err) != codes.PermissionDenied {
		t.Fatalf("list without capability: want PermissionDenied, got %v", err)
	}
	if err := u.GetRecording(&genezav1.GetRecordingRequest{SessionId: sid},
		&fakeBlobStream{ctx: opCtx}); status.Code(err) != codes.PermissionDenied {
		t.Fatalf("get without capability: want PermissionDenied, got %v", err)
	}

	// Allowed: the ws-auditor capability lists and fetches.
	audCtx := userCtx(ws, "carol", "ws-auditor")
	lr, err := u.ListRecordings(audCtx, &genezav1.ListRecordingsRequest{})
	if err != nil {
		t.Fatalf("list with capability: %v", err)
	}
	if len(lr.GetRecordings()) != 1 || lr.GetRecordings()[0].GetSessionId() != sid {
		t.Fatalf("list returned %d rows, want the one recording", len(lr.GetRecordings()))
	}

	blob := &fakeBlobStream{ctx: audCtx}
	if err := u.GetRecording(&genezav1.GetRecordingRequest{SessionId: sid}, blob); err != nil {
		t.Fatalf("get with capability: %v", err)
	}
	got := collectBlob(blob)
	if !bytes.Equal(got, cipher) {
		t.Fatalf("served bytes != stored ciphertext")
	}

	// The auditor is audited.
	detail, ok := lastAudit(t, srv, "recording_fetched")
	if !ok {
		t.Fatalf("no recording_fetched audit event emitted")
	}
	if detail["audit_key_id"] != auditKeyIDFor(testAuditRecipient) {
		t.Fatalf("audit event missing the authoritative audit_key_id: %+v", detail)
	}

	// A denied fetch attempt and a successful list are both on the ledger — the
	// premise is that every access to recordings is auditable, not just full fetches.
	if _, ok := lastAudit(t, srv, "recording_fetch_denied"); !ok {
		t.Fatal("a denied fetch attempt must be audited")
	}
	if _, ok := lastAudit(t, srv, "recording_listed"); !ok {
		t.Fatal("a successful list must be audited")
	}
}

// TestGetRecordingAuditsPartialFetch proves the auditor is audited even when the
// fetch is cut off mid-cast: the access is recorded at grant time, before the
// stream, so a client that drops after the first chunk cannot escape the ledger.
func TestGetRecordingAuditsPartialFetch(t *testing.T) {
	srv := newReplayServer(t)
	srv.setClusterConfig(2, signedConfigWithAudit(t, srv, 2, testAuditRecipient))
	nc := newNodeCert(t)
	const ws, node, sid = defaultWorkspace, "n1", "s-eeeeeeeeeeee"
	seedSession(t, srv, ws, node, sid)
	// Multiple chunks so the stream has somewhere to fail mid-way.
	cipher := bytes.Repeat([]byte("x"), recordingChunkBytes*3)
	if err := uploadRecording(t, srv, ws, node, nc, sid, cipher, ""); err != nil {
		t.Fatalf("upload: %v", err)
	}

	audCtx := userCtx(ws, "carol", "ws-auditor")
	blob := &fakeBlobStream{ctx: audCtx, failAfter: 1} // drop after the first chunk
	if err := u(srv).GetRecording(&genezav1.GetRecordingRequest{SessionId: sid}, blob); err == nil {
		t.Fatal("a mid-stream send failure must surface")
	}
	if _, ok := lastAudit(t, srv, "recording_fetched"); !ok {
		t.Fatal("a partial fetch must still be audited (the auditor is audited)")
	}
}

// TestRecordingReplayCrossWorkspaceIsolation proves a fully-privileged auditor of one
// workspace cannot reach another workspace's recording: the workspace is taken from
// the authenticated cert, and the request carries no workspace field, so the bypass
// is unreachable even when the caller holds the replay capability.
func TestRecordingReplayCrossWorkspaceIsolation(t *testing.T) {
	srv := newReplayServer(t)
	const sid = "s-dddddddddddd"
	sum := sha256.Sum256([]byte("ciphertext"))
	if err := srv.store.PutRecording("wsB", &RecordingRecord{
		SessionID: sid, NodeID: "n9", Principal: "user:eve",
		BlobRef: "local:" + sid + ".cast.age", SHA256: hex.EncodeToString(sum[:]), StoredUnix: 1700,
	}); err != nil {
		t.Fatalf("seed wsB recording: %v", err)
	}

	aCtx := userCtx("wsA", "carol", "ws-auditor") // privileged, but in workspace A
	if err := u(srv).GetRecording(&genezav1.GetRecordingRequest{SessionId: sid},
		&fakeBlobStream{ctx: aCtx}); status.Code(err) != codes.NotFound {
		t.Fatalf("cross-workspace fetch: want NotFound, got %v", err)
	}
	lr, err := u(srv).ListRecordings(aCtx, &genezav1.ListRecordingsRequest{})
	if err != nil || len(lr.GetRecordings()) != 0 {
		t.Fatalf("cross-workspace list: want empty, got %d rows err=%v", len(lr.GetRecordings()), err)
	}
}

// collectBlob concatenates a fake blob stream's chunks back into the ciphertext.
func collectBlob(b *fakeBlobStream) []byte {
	var out []byte
	for _, c := range b.chunks {
		out = append(out, c.GetData()...)
	}
	return out
}

// TestGetRecordingDetectsCorruption proves the at-rest integrity check: mutating one
// byte on disk makes GetRecording fail rather than serve a silently-bad cast.
func TestGetRecordingDetectsCorruption(t *testing.T) {
	srv := newReplayServer(t)
	srv.setClusterConfig(2, signedConfigWithAudit(t, srv, 2, testAuditRecipient))
	nc := newNodeCert(t)
	const ws, node, sid = defaultWorkspace, "n1", "s-cccccccccccc"
	seedSession(t, srv, ws, node, sid)
	if err := uploadRecording(t, srv, ws, node, nc, sid, []byte("ciphertext-to-be-corrupted"), ""); err != nil {
		t.Fatalf("upload: %v", err)
	}

	// Flip a byte in the on-disk blob.
	blobPath := filepath.Join(srv.cfg.RecordingsDir(), sid+".cast")
	raw, err := os.ReadFile(blobPath)
	if err != nil {
		t.Fatalf("read blob: %v", err)
	}
	raw[len(raw)-1] ^= 0x01
	if err := os.WriteFile(blobPath, raw, 0o600); err != nil {
		t.Fatalf("rewrite blob: %v", err)
	}

	audCtx := userCtx(ws, "carol", "ws-auditor")
	blob := &fakeBlobStream{ctx: audCtx}
	err = u(srv).GetRecording(&genezav1.GetRecordingRequest{SessionId: sid}, blob)
	if status.Code(err) != codes.DataLoss {
		t.Fatalf("corrupted blob: want DataLoss, got %v", err)
	}
	if len(blob.chunks) != 0 {
		t.Fatalf("corrupted blob streamed %d chunks (should serve nothing)", len(blob.chunks))
	}
}

func u(srv *Server) *userAPIService { return &userAPIService{s: srv} }
