package controller

import (
	"context"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/minio/minio-go/v7"
	"github.com/minio/minio-go/v7/pkg/credentials"
)

// s3BlobStore is the S3-compatible backend for blobStore: AWS S3, Ceph RGW,
// MinIO, or any endpoint speaking the S3 API. Refs are "s3:<key>"; the configured
// prefix is baked into the key at newRef time so a later prefix change does not
// re-point existing refs.
type s3BlobStore struct {
	client *minio.Client
	bucket string
	prefix string
}

func newS3BlobStore(cfg S3StorageConfig) (*s3BlobStore, error) {
	ep := cfg.Endpoint
	secure := !strings.HasPrefix(ep, "http://")
	ep = strings.TrimSuffix(strings.TrimPrefix(strings.TrimPrefix(ep, "https://"), "http://"), "/")
	opts := &minio.Options{
		Creds:  credentials.NewStaticV4(cfg.AccessKeyID, cfg.SecretAccessKey, ""),
		Secure: secure,
		Region: cfg.Region,
	}
	// Non-AWS endpoints (Ceph RGW, MinIO, on-prem) usually need path-style addressing.
	if cfg.UsePathStyle {
		opts.BucketLookup = minio.BucketLookupPath
	}
	cl, err := minio.New(ep, opts)
	if err != nil {
		return nil, fmt.Errorf("s3 client: %w", err)
	}
	return &s3BlobStore{client: cl, bucket: cfg.Bucket, prefix: cfg.Prefix}, nil
}

func (s *s3BlobStore) newRef(name string) string { return "s3:" + s.prefix + name }

func (s *s3BlobStore) key(ref string) (string, error) {
	key, ok := strings.CutPrefix(ref, "s3:")
	if !ok || key == "" {
		return "", fmt.Errorf("not an s3 blob ref: %q", ref)
	}
	return key, nil
}

func (s *s3BlobStore) create(ref string) (blobWriter, error) {
	key, err := s.key(ref)
	if err != nil {
		return nil, err
	}
	// Write-once guard. S3 has no cheap atomic create-exclusive across all
	// implementations, so this is a best-effort pre-check (a rare concurrent
	// duplicate upload of the same key could still overwrite); session ids are
	// unique, so duplicates are not expected on the recording path.
	if _, err := s.client.StatObject(context.Background(), s.bucket, key, minio.StatObjectOptions{}); err == nil {
		return nil, errBlobExists
	} else if code := minio.ToErrorResponse(err).Code; code != "" && code != "NoSuchKey" {
		return nil, fmt.Errorf("stat object: %w", err)
	}
	// Buffer to a temp file so PutObject streams with a known size (and we never
	// hold a whole blob in memory). The blob is published atomically by PutObject.
	tmp, err := os.CreateTemp("", "geneza-s3blob-*.tmp")
	if err != nil {
		return nil, fmt.Errorf("s3 staging file: %w", err)
	}
	return &s3BlobWriter{store: s, key: key, tmp: tmp}, nil
}

func (s *s3BlobStore) open(ref string) (io.ReadCloser, error) {
	key, err := s.key(ref)
	if err != nil {
		return nil, err
	}
	// Stat first so a missing object is a clean ErrNotFound (GetObject is lazy and
	// would only surface the error on the first Read).
	if _, err := s.client.StatObject(context.Background(), s.bucket, key, minio.StatObjectOptions{}); err != nil {
		if minio.ToErrorResponse(err).Code == "NoSuchKey" {
			return nil, ErrNotFound
		}
		return nil, err
	}
	return s.client.GetObject(context.Background(), s.bucket, key, minio.GetObjectOptions{})
}

func (s *s3BlobStore) remove(ref string) error {
	key, err := s.key(ref)
	if err != nil {
		return err
	}
	// RemoveObject is idempotent: deleting a missing key returns success.
	return s.client.RemoveObject(context.Background(), s.bucket, key, minio.RemoveObjectOptions{})
}

type s3BlobWriter struct {
	store     *s3BlobStore
	key       string
	tmp       *os.File
	committed bool
}

func (w *s3BlobWriter) Write(p []byte) (int, error) { return w.tmp.Write(p) }

func (w *s3BlobWriter) Commit() error {
	if err := w.tmp.Sync(); err != nil {
		w.cleanup()
		return fmt.Errorf("sync s3 staging: %w", err)
	}
	fi, err := w.tmp.Stat()
	if err != nil {
		w.cleanup()
		return err
	}
	if _, err := w.tmp.Seek(0, io.SeekStart); err != nil {
		w.cleanup()
		return err
	}
	_, err = w.store.client.PutObject(context.Background(), w.store.bucket, w.key, w.tmp, fi.Size(),
		minio.PutObjectOptions{ContentType: "application/octet-stream"})
	w.cleanup()
	if err != nil {
		return fmt.Errorf("put object: %w", err)
	}
	w.committed = true
	return nil
}

func (w *s3BlobWriter) Abort() {
	if w.committed {
		return
	}
	w.cleanup()
}

func (w *s3BlobWriter) cleanup() {
	name := w.tmp.Name()
	w.tmp.Close()
	os.Remove(name)
}
