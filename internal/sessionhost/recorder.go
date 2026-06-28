package sessionhost

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"hash"
	"io"
	"os"
	"path/filepath"
	"sync"
	"time"

	"filippo.io/age"
)

// recorder writes an asciicast v2 stream incrementally to the spool directory,
// envelope-encrypted to a per-workspace audit recipient. The plaintext PTY is
// teed off the live session here at the trusted endpoint; the bytes that ever
// touch the disk (and later the controller) are age ciphertext only — a holder of
// the matching private key is the sole party that can ever read the cast.
//
// On finalize it drops a sidecar <host_session_id>.done JSON file carrying the
// controller session id, the cast path, and the integrity manifest (sha256 over the
// CIPHERTEXT, size, audit key id, principal, timing). The worker reads it, signs
// the manifest with the node key, and uploads. That contract is fixed.
type recorder struct {
	mu     sync.Mutex
	f      *os.File       // ciphertext sink on disk
	enc    io.WriteCloser // age stream; events are written here as plaintext
	hash   hash.Hash      // running SHA-256 over the ciphertext
	size   int64          // ciphertext bytes written so far
	cap    int64          // 0 = no cap; ciphertext-byte backstop
	start  time.Time
	cast   string // absolute path to the .cast.age file
	done   string // absolute path to the .done sidecar
	meta   recorderMeta
	closed bool
}

// recorderMeta is the self-describing audit context stamped into the cast header
// and carried (in part) into the .done manifest, so a downloaded cast names the
// session, node, workspace, durable principal and action it captured.
type recorderMeta struct {
	SessionID   string
	WorkspaceID string
	User        string
	Provider    string
	Subject     string
	Action      string
	AuditKeyID  string // stable id of the recipient SET the cast was sealed to
}

type castHeader struct {
	Version   int               `json:"version"`
	Width     int               `json:"width"`
	Height    int               `json:"height"`
	Timestamp int64             `json:"timestamp"`
	Env       map[string]string `json:"env"`
	Geneza    *castAudit        `json:"geneza,omitempty"`
}

// castAudit is the geneza{} block in the asciicast header. The durable principal
// (provider/subject) is the audit key, not the display name.
type castAudit struct {
	SessionID   string `json:"session_id"`
	WorkspaceID string `json:"workspace_id,omitempty"`
	User        string `json:"user,omitempty"`
	Provider    string `json:"provider,omitempty"`
	Subject     string `json:"subject,omitempty"`
	Action      string `json:"action,omitempty"`
	StartedUnix int64  `json:"started_unix"`
}

// doneManifest is the .done sidecar: the worker's upload contract plus the
// integrity descriptor the controller indexes. SHA256 is over the ciphertext.
type doneManifest struct {
	SessionID   string `json:"session_id"`
	Cast        string `json:"cast"`
	SHA256      string `json:"sha256"`
	SizeBytes   int64  `json:"size_bytes"`
	AuditKeyID  string `json:"audit_key_id,omitempty"`
	Principal   string `json:"principal,omitempty"`
	Action      string `json:"action,omitempty"`
	StartedUnix int64  `json:"started_unix"`
	EndedUnix   int64  `json:"ended_unix"`
	Truncated   bool   `json:"truncated"`
}

// newRecorder opens the cast and writes its header. recipientStrs is the
// per-workspace age X25519 recipient SET the cast is sealed to: any one of the
// matching identities can later decrypt it, so naming several (security key +
// break-glass escrow) means losing one custodian key does not orphan the cast.
// An EMPTY set records PLAINTEXT — confidentiality is then the operator's choice
// (whether a workspace audit recipient is configured); integrity is unchanged
// either way (the node signs the manifest over the bytes that hit disk). An
// unparseable recipient is still an error. maxBytes caps the cast (0 = uncapped).
func newRecorder(spoolDir, hostID string, cols, rows uint32, term, shell string, recipientStrs []string, maxBytes int64, meta recorderMeta) (*recorder, error) {
	recipients := make([]age.Recipient, 0, len(recipientStrs))
	for _, rs := range recipientStrs {
		recipient, err := age.ParseX25519Recipient(rs)
		if err != nil {
			return nil, fmt.Errorf("parse audit recipient: %w", err)
		}
		recipients = append(recipients, recipient)
	}
	abs, err := filepath.Abs(spoolDir)
	if err != nil {
		return nil, fmt.Errorf("resolve spool dir: %w", err)
	}
	// Encrypted casts keep the .age suffix; plaintext casts are plain .cast. The
	// controller-side blob ref is independent of this local name.
	ext := ".cast"
	if len(recipients) > 0 {
		ext = ".cast.age"
	}
	cast := filepath.Join(abs, hostID+ext)
	f, err := os.OpenFile(cast, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
	if err != nil {
		return nil, fmt.Errorf("open cast file: %w", err)
	}
	r := &recorder{
		f:     f,
		hash:  sha256.New(),
		cap:   maxBytes,
		start: time.Now(),
		cast:  cast,
		done:  filepath.Join(abs, hostID+".done"),
		meta:  meta,
	}
	// Hash the bytes as they land on disk (ciphertext when sealed, plaintext
	// otherwise): the digest is over exactly what the controller will receive.
	sink := &countingHashWriter{w: f, h: r.hash, n: &r.size}
	if len(recipients) > 0 {
		enc, err := age.Encrypt(sink, recipients...)
		if err != nil {
			f.Close()
			os.Remove(cast)
			return nil, fmt.Errorf("init cast encryption: %w", err)
		}
		r.enc = enc
	} else {
		// Plaintext: events stream straight to the hashing sink.
		r.enc = nopWriteCloser{sink}
	}

	hdr := castHeader{
		Version:   2,
		Width:     int(cols),
		Height:    int(rows),
		Timestamp: r.start.Unix(),
		Env:       map[string]string{"TERM": term, "SHELL": shell},
		Geneza: &castAudit{
			SessionID:   meta.SessionID,
			WorkspaceID: meta.WorkspaceID,
			User:        meta.User,
			Provider:    meta.Provider,
			Subject:     meta.Subject,
			Action:      meta.Action,
			StartedUnix: r.start.Unix(),
		},
	}
	b, err := json.Marshal(hdr)
	if err != nil {
		r.enc.Close()
		f.Close()
		os.Remove(cast)
		return nil, err
	}
	if _, err := r.enc.Write(append(b, '\n')); err != nil {
		r.enc.Close()
		f.Close()
		os.Remove(cast)
		return nil, fmt.Errorf("write cast header: %w", err)
	}
	return r, nil
}

// countingHashWriter tees every write into a running hash and a byte counter as it
// forwards to the underlying sink, so the ciphertext is hashed and measured
// exactly once on the way to disk.
type countingHashWriter struct {
	w io.Writer
	h hash.Hash
	n *int64
}

func (c *countingHashWriter) Write(p []byte) (int, error) {
	n, err := c.w.Write(p)
	if n > 0 {
		c.h.Write(p[:n])
		*c.n += int64(n)
	}
	return n, err
}

// nopWriteCloser adapts the plaintext sink to io.WriteCloser; Close is a no-op
// because finalize closes the underlying cast file itself.
type nopWriteCloser struct{ io.Writer }

func (nopWriteCloser) Close() error { return nil }

// event appends one [elapsed, kind, payload] line into the encrypted stream.
// Errors are swallowed: recording must never break a live session, and a
// truncated-but-sealed cast is still uploadable evidence. Once the ciphertext cap
// is hit the stream is sealed early and flagged truncated; further events no-op.
func (r *recorder) event(kind, payload string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed {
		return
	}
	if r.cap > 0 && r.size >= r.cap {
		return
	}
	line, err := json.Marshal([]any{time.Since(r.start).Seconds(), kind, payload})
	if err != nil {
		return
	}
	_, _ = r.enc.Write(append(line, '\n'))
}

func (r *recorder) output(data []byte) { r.event("o", string(data)) }

func (r *recorder) resizeEvent(cols, rows uint32) {
	r.event("r", fmt.Sprintf("%dx%d", cols, rows))
}

// truncated reports whether the ciphertext cap was reached.
func (r *recorder) truncated() bool {
	return r.cap > 0 && r.size >= r.cap
}

// finalize writes the exit marker, seals the encrypted stream, and writes the
// .done sidecar with the integrity manifest. The .done file must only ever appear
// after the cast is complete and flushed, so the worker never uploads a partial
// blob. Runs exactly once.
func (r *recorder) finalize(exitReason string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed {
		return nil
	}
	truncated := r.cap > 0 && r.size >= r.cap
	if !truncated {
		// ["m", reason]: how the session ended (exited/signaled/killed/reaped).
		if line, err := json.Marshal([]any{time.Since(r.start).Seconds(), "m", exitReason}); err == nil {
			_, _ = r.enc.Write(append(line, '\n'))
		}
	}
	r.closed = true
	if err := r.enc.Close(); err != nil { // flush the final AEAD chunk
		r.f.Close()
		return fmt.Errorf("seal cast: %w", err)
	}
	if err := r.f.Sync(); err != nil {
		r.f.Close()
		return fmt.Errorf("sync cast: %w", err)
	}
	if err := r.f.Close(); err != nil {
		return fmt.Errorf("close cast: %w", err)
	}
	man := doneManifest{
		SessionID:   r.meta.SessionID,
		Cast:        r.cast,
		SHA256:      hex.EncodeToString(r.hash.Sum(nil)),
		SizeBytes:   r.size,
		AuditKeyID:  r.meta.AuditKeyID,
		Principal:   auditPrincipal(r.meta.Provider, r.meta.Subject),
		Action:      r.meta.Action,
		StartedUnix: r.start.Unix(),
		EndedUnix:   time.Now().Unix(),
		Truncated:   truncated,
	}
	b, err := json.Marshal(man)
	if err != nil {
		return err
	}
	if err := os.WriteFile(r.done, b, 0o600); err != nil {
		return fmt.Errorf("write done sidecar: %w", err)
	}
	return nil
}

// auditPrincipal joins the durable provider/subject into the index principal,
// the stable suspension-style key (empty subject => unkeyable, left empty).
func auditPrincipal(provider, subject string) string {
	if subject == "" {
		return ""
	}
	if provider == "" {
		return subject
	}
	return provider + ":" + subject
}

// abort discards a recording whose session failed to start.
func (r *recorder) abort() {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed {
		return
	}
	r.closed = true
	if r.enc != nil {
		r.enc.Close()
	}
	r.f.Close()
	os.Remove(r.cast)
}
