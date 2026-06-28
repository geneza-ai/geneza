package controller

import (
	"errors"
	"io"
	"strings"
	"testing"
)

// recordingBackend records which refs hit each method, to assert routing.
type recordingBackend struct {
	scheme  string
	created []string
	opened  []string
	removed []string
}

func (b *recordingBackend) newRef(name string) string { return b.scheme + ":" + name }
func (b *recordingBackend) create(ref string) (blobWriter, error) {
	b.created = append(b.created, ref)
	return nil, nil
}
func (b *recordingBackend) open(ref string) (io.ReadCloser, error) {
	b.opened = append(b.opened, ref)
	return io.NopCloser(strings.NewReader("")), nil
}
func (b *recordingBackend) remove(ref string) error {
	b.removed = append(b.removed, ref)
	return nil
}

func TestMultiBlobStoreRoutesByScheme(t *testing.T) {
	local := &recordingBackend{scheme: "local"}
	s3 := &recordingBackend{scheme: "s3"}
	m := &multiBlobStore{
		backends: map[string]blobStore{"local": local, "s3": s3},
		primary:  "s3",
	}
	// newRef mints under the primary.
	if got := m.newRef("x.cast"); got != "s3:x.cast" {
		t.Fatalf("newRef under primary = %q, want s3:x.cast", got)
	}
	// open/remove route by the ref's scheme — old local refs still reach local.
	_, _ = m.open("local:old.cast")
	_ = m.remove("local:old.cast")
	_, _ = m.create("s3:new.cast")
	if len(local.opened) != 1 || len(local.removed) != 1 {
		t.Fatalf("local backend not used for local: ref (opened=%v removed=%v)", local.opened, local.removed)
	}
	if len(s3.created) != 1 {
		t.Fatalf("s3 backend not used for s3: ref (created=%v)", s3.created)
	}
	// Unknown scheme is an error, not a silent misroute.
	if _, err := m.open("ftp:nope"); err == nil {
		t.Fatal("unknown scheme must error")
	}
}

func TestNewBlobStoreConfig(t *testing.T) {
	// Default (empty) backend is local, and a round-trip works through it.
	bs, err := newBlobStore(StorageConfig{}, t.TempDir())
	if err != nil {
		t.Fatalf("default storage: %v", err)
	}
	ref := bs.newRef("s-test.cast")
	if !strings.HasPrefix(ref, "local:") {
		t.Fatalf("default primary not local: %q", ref)
	}
	w, err := bs.create(ref)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := io.WriteString(w, "hello-cast"); err != nil {
		t.Fatal(err)
	}
	if err := w.Commit(); err != nil {
		t.Fatal(err)
	}
	rc, err := bs.open(ref)
	if err != nil {
		t.Fatal(err)
	}
	got, _ := io.ReadAll(rc)
	rc.Close()
	if string(got) != "hello-cast" {
		t.Fatalf("round-trip = %q", got)
	}
	if err := bs.remove(ref); err != nil {
		t.Fatal(err)
	}
	if _, err := bs.open(ref); !errors.Is(err, ErrNotFound) {
		t.Fatalf("after remove, open = %v, want ErrNotFound", err)
	}

	// s3 requires endpoint + bucket.
	if _, err := newBlobStore(StorageConfig{Backend: "s3"}, t.TempDir()); err == nil {
		t.Error("s3 backend without endpoint/bucket must error")
	}
	// s3 with the minimum builds (no network until a call) and is the primary.
	bs3, err := newBlobStore(StorageConfig{Backend: "s3", S3: S3StorageConfig{
		Endpoint: "https://s3.example:9000", Bucket: "geneza", Prefix: "recordings/",
	}}, t.TempDir())
	if err != nil {
		t.Fatalf("s3 construct: %v", err)
	}
	if got := bs3.newRef("s-x.cast"); got != "s3:recordings/s-x.cast" {
		t.Fatalf("s3 newRef = %q, want s3:recordings/s-x.cast", got)
	}
	// Unknown backend errors.
	if _, err := newBlobStore(StorageConfig{Backend: "swift"}, t.TempDir()); err == nil {
		t.Error("unknown backend must error")
	}
}

func TestS3RefKey(t *testing.T) {
	s := &s3BlobStore{bucket: "b", prefix: "recordings/"}
	if got := s.newRef("s-x.cast"); got != "s3:recordings/s-x.cast" {
		t.Fatalf("newRef = %q", got)
	}
	if key, err := s.key("s3:recordings/s-x.cast"); err != nil || key != "recordings/s-x.cast" {
		t.Fatalf("key = %q, %v", key, err)
	}
	if _, err := s.key("local:s-x.cast"); err == nil {
		t.Error("key on a non-s3 ref must error")
	}
}
