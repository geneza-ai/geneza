package gateway

import (
	"bytes"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"sync"
	"time"
)

// AuditSink is an append-only off-box mirror of the audit chain. It is the only
// control that survives a gateway-host compromise able to rewrite the local
// chain: records land in a destination the attacker does not control
// (object-lock bucket, SIEM, a separate host). Sinks are best-effort with loud
// logging — the LOCAL chain remains fail-closed for security RPCs — so an
// unreachable sink degrades durability, not availability.
type AuditSink interface {
	Append(line []byte) error
	Close() error
}

// NewAuditSink builds the configured sink. An empty/"none" type yields a no-op.
func NewAuditSink(cfg AuditSinkConfig, log *slog.Logger) (AuditSink, error) {
	switch cfg.Type {
	case "", "none":
		return nopSink{}, nil
	case "file":
		if cfg.Path == "" {
			return nil, fmt.Errorf("audit_sink type=file requires path")
		}
		f, err := os.OpenFile(cfg.Path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
		if err != nil {
			return nil, fmt.Errorf("audit_sink file: %w", err)
		}
		return &fileSink{f: f}, nil
	case "http":
		if cfg.URL == "" {
			return nil, fmt.Errorf("audit_sink type=http requires url")
		}
		return &httpSink{url: cfg.URL, log: log, client: &http.Client{Timeout: 5 * time.Second}}, nil
	default:
		return nil, fmt.Errorf("unknown audit_sink type %q", cfg.Type)
	}
}

type nopSink struct{}

func (nopSink) Append([]byte) error { return nil }
func (nopSink) Close() error        { return nil }

// fileSink appends each record (with a trailing newline) to a file that should
// live on a different mount/host than the gateway data dir.
type fileSink struct {
	mu sync.Mutex
	f  *os.File
}

func (s *fileSink) Append(line []byte) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, err := s.f.Write(append(append([]byte(nil), line...), '\n')); err != nil {
		return err
	}
	return s.f.Sync()
}

func (s *fileSink) Close() error { return s.f.Close() }

// httpSink POSTs each record as a JSON line to an intake endpoint (e.g. a SIEM
// HTTP collector). Failures are logged, not fatal.
type httpSink struct {
	url    string
	client *http.Client
	log    *slog.Logger
}

func (s *httpSink) Append(line []byte) error {
	resp, err := s.client.Post(s.url, "application/json", bytes.NewReader(line))
	if err != nil {
		return err
	}
	resp.Body.Close()
	if resp.StatusCode/100 != 2 {
		return fmt.Errorf("audit sink http %s", resp.Status)
	}
	return nil
}

func (s *httpSink) Close() error { return nil }
