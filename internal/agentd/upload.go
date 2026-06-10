package agentd

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"

	genezav1 "osie.cloud/geneza/internal/pb/geneza/v1"
)

const uploadChunkSize = 64 * 1024

// doneMarker is the spool-dir contract with the session host: when a
// recorded session ends, the host writes "<host_session_id>.done" next to
// the finished asciicast.
type doneMarker struct {
	SessionID string `json:"session_id"` // gateway session id (audit key)
	Cast      string `json:"cast"`       // path to the .cast file
}

// uploadLoop ships finished recordings to the gateway: on connect and every
// 30s thereafter. Gateway downtime just leaves the spool for the next cycle.
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
	buf := make([]byte, uploadChunkSize)
	for {
		n, rerr := f.Read(buf)
		eof := rerr == io.EOF
		if rerr != nil && !eof {
			return rerr
		}
		if n > 0 || eof {
			if serr := stream.Send(&genezav1.RecordingChunk{
				SessionId: m.SessionID,
				Data:      buf[:n],
				Eof:       eof,
			}); serr != nil {
				return serr
			}
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
		return fmt.Errorf("gateway did not acknowledge recording")
	}
	// Only after the gateway holds the bytes do we drop the local copies.
	if err := os.Remove(castPath); err != nil && !os.IsNotExist(err) {
		w.log.Warn("remove uploaded cast", "path", castPath, "err", err)
	}
	if err := os.Remove(markerPath); err != nil {
		return err
	}
	w.log.Info("recording uploaded", "session", m.SessionID, "cast", filepath.Base(castPath))
	return nil
}
