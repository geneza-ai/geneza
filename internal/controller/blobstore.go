package controller

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

// blobStore is the controller's general-purpose, write-once blob store. Recordings
// are its first user; other per-node artifacts can reuse it later. Blobs are
// opaque bytes keyed by a scheme-tagged ref ("local:<name>" | "s3:<key>"); the
// store does not interpret the contents (so encryption, if any, is the caller's
// concern). Backends: a local directory or an S3-compatible object store, chosen
// by the operator via the storage config; a multiBlobStore routes by ref scheme
// so a deployment that switched to S3 can still read blobs written to local disk.
type blobStore interface {
	// newRef mints a ref for a logical name under the store's PRIMARY backend
	// (the one the operator configured for new writes), e.g. "local:<name>" or
	// "s3:<prefix><name>". The caller persists the returned ref.
	newRef(name string) string
	// create opens a write-once writer for ref. It returns errBlobExists if a
	// committed blob already exists for ref (the write-once guard). The caller
	// streams bytes, then calls Commit to atomically publish or Abort to
	// discard a partial upload.
	create(ref string) (blobWriter, error)
	// open returns a reader over a committed blob, or ErrNotFound.
	open(ref string) (io.ReadCloser, error)
	// remove deletes a committed blob (retention GC); a missing blob is not an error.
	remove(ref string) error
}

// blobWriter accumulates a blob and publishes it atomically on Commit. Abort
// discards any partial bytes; it is safe to call after Commit (a no-op).
type blobWriter interface {
	io.Writer
	Commit() error
	Abort()
}

var errBlobExists = errors.New("recording blob already exists")

// localBlobStore stores each blob as a file under dir. The ref is "local:<name>";
// the name is constrained to a safe basename so a ref can never escape dir.
type localBlobStore struct {
	dir string
}

func newLocalBlobStore(dir string) *localBlobStore { return &localBlobStore{dir: dir} }

func (l *localBlobStore) newRef(name string) string { return "local:" + name }

// blobRefName extracts and validates the on-disk basename from a "local:<name>"
// ref. It rejects any name with path separators or traversal so a ref is confined
// to the recordings directory.
func blobRefName(ref string) (string, error) {
	name, ok := strings.CutPrefix(ref, "local:")
	if !ok {
		return "", fmt.Errorf("not a local blob ref: %q", ref)
	}
	if name == "" || name != filepath.Base(name) || strings.ContainsAny(name, `/\`) || name == "." || name == ".." {
		return "", fmt.Errorf("unsafe blob ref: %q", ref)
	}
	return name, nil
}

func (l *localBlobStore) path(ref string) (string, error) {
	name, err := blobRefName(ref)
	if err != nil {
		return "", err
	}
	return filepath.Join(l.dir, name), nil
}

func (l *localBlobStore) create(ref string) (blobWriter, error) {
	path, err := l.path(ref)
	if err != nil {
		return nil, err
	}
	if err := os.MkdirAll(l.dir, 0o700); err != nil {
		return nil, fmt.Errorf("recordings dir: %w", err)
	}
	// Fast-path reject if a committed blob already exists; the real write-once
	// fence is the atomic hard-link at Commit (the stat alone would be a TOCTOU).
	if _, err := os.Stat(path); err == nil {
		return nil, errBlobExists
	}
	// A unique temp file per upload, so two concurrent streams for the same id can
	// never share a buffer and interleave their ciphertext into one file.
	f, err := os.CreateTemp(l.dir, filepath.Base(path)+".*.uploading")
	if err != nil {
		return nil, fmt.Errorf("open recording: %w", err)
	}
	return &localBlobWriter{f: f, tmp: f.Name(), final: path}, nil
}

func (l *localBlobStore) open(ref string) (io.ReadCloser, error) {
	path, err := l.path(ref)
	if err != nil {
		return nil, err
	}
	f, err := os.Open(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil, ErrNotFound
	}
	return f, err
}

func (l *localBlobStore) remove(ref string) error {
	path, err := l.path(ref)
	if err != nil {
		return err
	}
	if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return nil
}

type localBlobWriter struct {
	f         *os.File
	tmp       string
	final     string
	committed bool
}

func (w *localBlobWriter) Write(p []byte) (int, error) { return w.f.Write(p) }

func (w *localBlobWriter) Commit() error {
	if err := w.f.Sync(); err != nil {
		w.f.Close()
		return fmt.Errorf("sync recording: %w", err)
	}
	if err := w.f.Close(); err != nil {
		return fmt.Errorf("close recording: %w", err)
	}
	// Claim the committed name atomically: a hard link fails if the name already
	// exists, so a concurrent or repeat upload of the same id cannot replace an
	// already-stored recording (Rename would silently overwrite). The temp is
	// unlinked either way — its bytes survive under final on success.
	if err := os.Link(w.tmp, w.final); err != nil {
		os.Remove(w.tmp)
		if os.IsExist(err) {
			return errBlobExists
		}
		return fmt.Errorf("commit recording: %w", err)
	}
	os.Remove(w.tmp)
	w.committed = true
	return nil
}

func (w *localBlobWriter) Abort() {
	if w.committed {
		return
	}
	w.f.Close()
	os.Remove(w.tmp)
}

// multiBlobStore routes a ref to the backend named by its scheme, and mints new
// refs under the configured primary backend. The local backend is always present
// (so blobs written before a switch to S3 stay readable); the S3 backend is added
// only when configured. This is what makes the storage choice an operator setting
// without orphaning existing data.
type multiBlobStore struct {
	backends map[string]blobStore // scheme ("local" | "s3") -> backend
	primary  string               // the scheme newRef writes under
}

func refScheme(ref string) string {
	if i := strings.IndexByte(ref, ':'); i >= 0 {
		return ref[:i]
	}
	return ""
}

func (m *multiBlobStore) backendFor(ref string) (blobStore, error) {
	b, ok := m.backends[refScheme(ref)]
	if !ok {
		return nil, fmt.Errorf("no blob backend for ref %q", ref)
	}
	return b, nil
}

func (m *multiBlobStore) newRef(name string) string { return m.backends[m.primary].newRef(name) }

func (m *multiBlobStore) create(ref string) (blobWriter, error) {
	b, err := m.backendFor(ref)
	if err != nil {
		return nil, err
	}
	return b.create(ref)
}

func (m *multiBlobStore) open(ref string) (io.ReadCloser, error) {
	b, err := m.backendFor(ref)
	if err != nil {
		return nil, err
	}
	return b.open(ref)
}

func (m *multiBlobStore) remove(ref string) error {
	b, err := m.backendFor(ref)
	if err != nil {
		return err
	}
	return b.remove(ref)
}

// StorageConfig selects the blob-store backend (controller.yaml `storage:`).
type StorageConfig struct {
	Backend string          `yaml:"backend,omitempty"` // "" | "fs" | "s3"
	FS      FSStorageConfig `yaml:"fs,omitempty"`
	S3      S3StorageConfig `yaml:"s3,omitempty"`
}

type FSStorageConfig struct {
	// Dir overrides the local blob directory; empty uses the controller default
	// (<data_dir>/recordings), so existing deployments are unchanged.
	Dir string `yaml:"dir,omitempty"`
}

type S3StorageConfig struct {
	Endpoint        string `yaml:"endpoint,omitempty"` // host[:port] or http(s)://host (S3, Ceph RGW, MinIO…)
	Region          string `yaml:"region,omitempty"`
	Bucket          string `yaml:"bucket,omitempty"`
	Prefix          string `yaml:"prefix,omitempty"` // object-key prefix, e.g. "recordings/"
	AccessKeyID     string `yaml:"access_key_id,omitempty"`
	SecretAccessKey string `yaml:"secret_access_key,omitempty"`
	UsePathStyle    bool   `yaml:"use_path_style,omitempty"`
}

// newBlobStore builds the configured store. The local backend always backs the
// "local:" scheme (so blobs written before a switch to S3 stay readable); when
// backend is "s3" the S3 backend is added and becomes the primary for new writes.
func newBlobStore(cfg StorageConfig, defaultLocalDir string) (blobStore, error) {
	localDir := defaultLocalDir
	if cfg.FS.Dir != "" {
		localDir = cfg.FS.Dir
	}
	m := &multiBlobStore{
		backends: map[string]blobStore{"local": newLocalBlobStore(localDir)},
		primary:  "local",
	}
	switch cfg.Backend {
	case "", "fs", "local":
		// local primary (default)
	case "s3":
		if cfg.S3.Endpoint == "" || cfg.S3.Bucket == "" {
			return nil, fmt.Errorf("storage.s3 requires endpoint and bucket")
		}
		s3, err := newS3BlobStore(cfg.S3)
		if err != nil {
			return nil, err
		}
		m.backends["s3"] = s3
		m.primary = "s3"
	default:
		return nil, fmt.Errorf("unknown storage backend %q (want fs or s3)", cfg.Backend)
	}
	return m, nil
}
