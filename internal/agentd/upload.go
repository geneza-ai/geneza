package agentd

import (
	"context"
	"crypto"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"

	genezav1 "geneza.io/internal/pb/geneza/v1"
	"geneza.io/internal/types"
)

const uploadChunkSize = 64 * 1024

// doneMarker is the spool-dir contract with the session host: when a recorded
// session ends, the host writes "<host_session_id>.done" next to the finished
// (encrypted) asciicast. It carries the integrity manifest the host computed over
// the ciphertext; the worker signs the manifest with the node key and uploads.
type doneMarker struct {
	SessionID   string `json:"session_id"` // controller session id (audit key)
	Cast        string `json:"cast"`       // path to the .cast.age file
	SHA256      string `json:"sha256"`     // hex, over the ciphertext
	SizeBytes   int64  `json:"size_bytes"`
	AuditKeyID  string `json:"audit_key_id,omitempty"`
	Principal   string `json:"principal,omitempty"`
	NodeID      string `json:"node_id,omitempty"`
	Action      string `json:"action,omitempty"`
	StartedUnix int64  `json:"started_unix"`
	EndedUnix   int64  `json:"ended_unix"`
	Truncated   bool   `json:"truncated"`
}

// uploadLoop ships finished recordings to the controller: on connect and every
// 30s thereafter. Controller downtime just leaves the spool for the next cycle.
func (w *Worker) uploadLoop(ctx context.Context) {
	t := time.NewTicker(uploadScanPeriod)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		case <-w.uploadKick:
		}
		if err := w.uploadPending(ctx); err != nil {
			w.log.Debug("recording upload cycle incomplete", "err", err)
		}
	}
}

func (w *Worker) kickUpload() {
	select {
	case w.uploadKick <- struct{}{}:
	default:
	}
}

func (w *Worker) uploadPending(ctx context.Context) error {
	markers, err := filepath.Glob(filepath.Join(w.cfg.SpoolDir, "*.done"))
	if err != nil || len(markers) == 0 {
		return err
	}
	conn, err := w.grpcConn()
	if err != nil {
		return err
	}
	client := genezav1.NewNodeControlClient(conn)

	for _, markerPath := range markers {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if err := w.uploadOne(ctx, client, markerPath); err != nil {
			w.log.Warn("recording upload failed (will retry)", "marker", markerPath, "err", err)
		}
	}
	return nil
}

func (w *Worker) uploadOne(ctx context.Context, client genezav1.NodeControlClient, markerPath string) error {
	b, err := os.ReadFile(markerPath)
	if err != nil {
		return err
	}
	var m doneMarker
	if err := json.Unmarshal(b, &m); err != nil {
		return fmt.Errorf("bad done marker: %w", err)
	}
	if m.SessionID == "" || m.Cast == "" {
		return fmt.Errorf("done marker missing session_id or cast")
	}
	castPath := m.Cast
	if !filepath.IsAbs(castPath) {
		castPath = filepath.Join(w.cfg.SpoolDir, castPath)
	}
	manifest, err := w.signRecordingManifest(m)
	if err != nil {
		return err
	}
	f, err := os.Open(castPath)
	if err != nil {
		return err
	}
	defer f.Close()

	uctx, cancel := context.WithTimeout(ctx, 5*time.Minute)
	defer cancel()
	stream, err := client.UploadRecording(uctx)
	if err != nil {
		return err
	}
	// The manifest rides the FIRST and the eof chunk so the controller has the
	// attestation before it commits any bytes and re-checks it against what it
	// actually received at the end.
	buf := make([]byte, uploadChunkSize)
	first := true
	for {
		n, rerr := f.Read(buf)
		eof := rerr == io.EOF
		if rerr != nil && !eof {
			return rerr
		}
		if n > 0 || eof {
			chunk := &genezav1.RecordingChunk{
				SessionId: m.SessionID,
				Data:      buf[:n],
				Eof:       eof,
			}
			if first || eof {
				chunk.Manifest = manifest
			}
			if serr := stream.Send(chunk); serr != nil {
				return serr
			}
			first = false
		}
		if eof {
			break
		}
	}
	ack, err := stream.CloseAndRecv()
	if err != nil {
		return err
	}
	if ack == nil || !ack.Ok {
		return fmt.Errorf("controller did not acknowledge recording")
	}
	// Only after the controller holds the bytes do we drop the local copies.
	if err := os.Remove(castPath); err != nil && !os.IsNotExist(err) {
		w.log.Warn("remove uploaded cast", "path", castPath, "err", err)
	}
	if err := os.Remove(markerPath); err != nil {
		return err
	}
	w.log.Info("recording uploaded", "session", m.SessionID, "cast", filepath.Base(castPath))
	return nil
}

// signRecordingManifest signs the ciphertext attestation with the node identity
// key (the same ECDSA key the node cert binds), so the controller can verify it
// against the certificate authenticating the upload stream. The signature covers
// the ciphertext sha256, its size and the finish time, binding it to one cast.
func (w *Worker) signRecordingManifest(m doneMarker) (*genezav1.RecordingManifest, error) {
	sha, err := hex.DecodeString(m.SHA256)
	if err != nil || len(sha) != 32 {
		return nil, fmt.Errorf("done marker has invalid sha256")
	}
	digest := types.RecordingManifestDigest(m.SessionID, m.SHA256, m.SizeBytes, m.EndedUnix)
	// The node Signer produces an ASN.1-DER ECDSA signature over the pre-hashed
	// digest. With a file key this is an in-process sign; with a pkcs11 key the
	// signature is computed on the token. The controller verifies it against the node
	// cert's public key, so both paths yield the same verifiable manifest.
	sig, err := w.st.Key.Sign(rand.Reader, digest, crypto.SHA256)
	if err != nil {
		return nil, fmt.Errorf("sign recording manifest: %w", err)
	}
	return &genezav1.RecordingManifest{
		Sha256:      sha,
		SizeBytes:   m.SizeBytes,
		NodeSig:     sig,
		AuditKeyId:  m.AuditKeyID,
		StartedUnix: m.StartedUnix,
		EndedUnix:   m.EndedUnix,
		Principal:   m.Principal,
		NodeId:      w.st.NodeID,
		Action:      m.Action,
		Truncated:   m.Truncated,
	}, nil
}
