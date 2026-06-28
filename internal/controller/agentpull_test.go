package controller

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"geneza.io/internal/selfupdate"
)

func nodeTarGz(t *testing.T, arch string, agent, bootstrap []byte) []byte {
	t.Helper()
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)
	dir := "geneza-node_linux_" + arch
	for name, body := range map[string][]byte{"geneza-agent": agent, "geneza-bootstrap": bootstrap} {
		_ = tw.WriteHeader(&tar.Header{Name: dir + "/" + name, Mode: 0o755, Size: int64(len(body)), Typeflag: tar.TypeReg})
		tw.Write(body)
	}
	tw.Close()
	gz.Close()
	return buf.Bytes()
}

// TestPullOneArch downloads a node archive, verifies its digest against
// SHA256SUMS, extracts both binaries, and writes them to install_dir under the
// installer-served names.
func TestPullOneArch(t *testing.T) {
	const arch = "amd64"
	agent := []byte("AGENT-BINARY-amd64")
	bootstrap := []byte("BOOTSTRAP-BINARY-amd64")
	archive := nodeTarGz(t, arch, agent, bootstrap)
	archiveName := "geneza-node_linux_" + arch + ".tar.gz"

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.Write(archive) }))
	defer srv.Close()

	sum := sha256.Sum256(archive)
	sums := []byte(fmt.Sprintf("%s  %s\n", hex.EncodeToString(sum[:]), archiveName))
	rel := &selfupdate.Release{TagName: "v1.0.0", Assets: []selfupdate.Asset{{Name: archiveName, URL: srv.URL}}}

	dir := t.TempDir()
	if err := pullOneArch(context.Background(), selfupdate.NewHTTPClient(10*time.Second), rel, sums, dir, arch); err != nil {
		t.Fatalf("pullOneArch: %v", err)
	}
	for name, want := range map[string][]byte{
		"geneza-agent-linux-amd64":     agent,
		"geneza-bootstrap-linux-amd64": bootstrap,
	} {
		got, err := os.ReadFile(filepath.Join(dir, name))
		if err != nil {
			t.Fatalf("read %s: %v", name, err)
		}
		if !bytes.Equal(got, want) {
			t.Fatalf("%s content mismatch", name)
		}
		if info, _ := os.Stat(filepath.Join(dir, name)); info.Mode().Perm()&0o100 == 0 {
			t.Fatalf("%s not executable", name)
		}
	}
}

// TestPullOneArchDigestMismatch fails closed when the archive doesn't match the
// SHA256SUMS entry (the chain-trusted digest).
func TestPullOneArchDigestMismatch(t *testing.T) {
	const arch = "amd64"
	archive := nodeTarGz(t, arch, []byte("a"), []byte("b"))
	archiveName := "geneza-node_linux_" + arch + ".tar.gz"
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.Write(archive) }))
	defer srv.Close()

	sums := []byte("0000000000000000000000000000000000000000000000000000000000000000  " + archiveName + "\n")
	rel := &selfupdate.Release{TagName: "v1.0.0", Assets: []selfupdate.Asset{{Name: archiveName, URL: srv.URL}}}
	if err := pullOneArch(context.Background(), selfupdate.NewHTTPClient(10*time.Second), rel, sums, t.TempDir(), arch); err == nil {
		t.Fatal("expected digest mismatch to be rejected")
	}
}
