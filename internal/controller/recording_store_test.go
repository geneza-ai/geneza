package controller

import (
	"errors"
	"testing"
)

// recordingStoreSuite exercises the recordings index across any Store impl, so
// the bbolt and both SQL engines run the identical assertions.
func recordingStoreSuite(t *testing.T, s Store) {
	t.Helper()
	const ws = "default"

	if _, err := s.GetRecording(ws, "s-000000000000"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("get missing: want ErrNotFound, got %v", err)
	}
	if list, err := s.ListRecordings(ws); err != nil || len(list) != 0 {
		t.Fatalf("list empty: err=%v len=%d", err, len(list))
	}
	if err := s.DeleteRecording(ws, "s-000000000000"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("delete missing: want ErrNotFound, got %v", err)
	}

	rec := &RecordingRecord{
		SessionID:   "s-aaaaaaaaaaaa",
		NodeID:      "n-1",
		Principal:   "keystone:ks-uid-7",
		Action:      "shell",
		StartedUnix: 100,
		EndedUnix:   160,
		SizeBytes:   4096,
		SHA256:      "deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef",
		NodeSig:     []byte{0x01, 0x02, 0x03, 0x04},
		AuditKeyID:  "age1auditkey",
		BlobRef:     "local:s-aaaaaaaaaaaa.cast.age",
		Truncated:   true,
		StoredUnix:  200,
	}
	if err := s.PutRecording(ws, rec); err != nil {
		t.Fatalf("put: %v", err)
	}

	got, err := s.GetRecording(ws, rec.SessionID)
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if got.WorkspaceID != ws {
		t.Errorf("workspace not stamped: %q", got.WorkspaceID)
	}
	if got.NodeID != rec.NodeID || got.Principal != rec.Principal || got.Action != rec.Action {
		t.Errorf("identity fields round-trip wrong: %+v", got)
	}
	if got.StartedUnix != rec.StartedUnix || got.EndedUnix != rec.EndedUnix || got.SizeBytes != rec.SizeBytes {
		t.Errorf("numeric fields round-trip wrong: %+v", got)
	}
	if got.SHA256 != rec.SHA256 || got.AuditKeyID != rec.AuditKeyID || got.BlobRef != rec.BlobRef {
		t.Errorf("string fields round-trip wrong: %+v", got)
	}
	if string(got.NodeSig) != string(rec.NodeSig) {
		t.Errorf("node_sig round-trip wrong: %x", got.NodeSig)
	}
	if !got.Truncated || got.StoredUnix != rec.StoredUnix {
		t.Errorf("flags round-trip wrong: %+v", got)
	}

	// A second recording orders after the first by started_unix.
	rec2 := &RecordingRecord{SessionID: "s-bbbbbbbbbbbb", NodeID: "n-2", Action: "exec", StartedUnix: 50}
	if err := s.PutRecording(ws, rec2); err != nil {
		t.Fatalf("put 2: %v", err)
	}
	list, err := s.ListRecordings(ws)
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(list) != 2 {
		t.Fatalf("list len: want 2 got %d", len(list))
	}
	if list[0].SessionID != rec2.SessionID || list[1].SessionID != rec.SessionID {
		t.Errorf("list not ordered by started_unix: %q then %q", list[0].SessionID, list[1].SessionID)
	}

	// Foreign-workspace isolation: a different workspace sees none of these rows.
	if other, err := s.ListRecordings("other-ws"); err != nil || len(other) != 0 {
		t.Fatalf("foreign workspace leak: err=%v len=%d", err, len(other))
	}

	if err := s.DeleteRecording(ws, rec.SessionID); err != nil {
		t.Fatalf("delete: %v", err)
	}
	if _, err := s.GetRecording(ws, rec.SessionID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("get after delete: want ErrNotFound, got %v", err)
	}
	if list, err := s.ListRecordings(ws); err != nil || len(list) != 1 {
		t.Fatalf("list after delete: err=%v len=%d", err, len(list))
	}
}

func TestRecordingStoreBbolt(t *testing.T) {
	recordingStoreSuite(t, testStore(t))
}

func TestRecordingStoreSQL(t *testing.T) {
	forEachSQLEngine(t, func(t *testing.T, s *sqlStore) {
		recordingStoreSuite(t, s)
	})
}
