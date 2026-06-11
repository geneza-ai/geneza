package gateway

import (
	"bufio"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"sync"
	"time"
)

// AuditEvent is one hash-chained JSONL record. Hash covers the JSON encoding
// of the record with Hash set to "" (Prev included), so any in-place edit,
// deletion or reordering breaks the chain from that point on.
//
// Detail values are strings on purpose: map[string]string re-marshals
// byte-identically (Go sorts map keys), which the verify pass depends on.
type AuditEvent struct {
	TS      int64             `json:"ts"`
	Type    string            `json:"type"`
	Actor   string            `json:"actor,omitempty"`
	Node    string            `json:"node,omitempty"`
	Session string            `json:"session,omitempty"`
	Detail  map[string]string `json:"detail,omitempty"`
	Prev    string            `json:"prev"`
	Hash    string            `json:"hash"`
}

func auditHash(e AuditEvent) (string, error) {
	e.Hash = ""
	b, err := json.Marshal(e)
	if err != nil {
		return "", err
	}
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:]), nil
}

// Audit is the append-only audit sink. Appends are mutex-serialized and
// fsynced; the chain is fully verified at open so tampering is detected
// before the gateway starts extending a broken chain.
type Audit struct {
	mu   sync.Mutex
	f    *os.File
	path string
	last string // hash of the last appended record
	now  func() time.Time
}

func OpenAudit(path string) (*Audit, error) {
	// Tolerate a torn FINAL line (a crash mid-append): truncate it to the last
	// complete record so a benign gateway crash does not brick startup. Any
	// INTERIOR break or a complete-but-altered record is still fatal (real
	// tampering → fail closed).
	if err := repairTornTail(path); err != nil {
		return nil, fmt.Errorf("audit chain %s: %w", path, err)
	}
	last, _, err := verifyAuditFile(path)
	if err != nil {
		return nil, fmt.Errorf("audit chain %s: %w", path, err)
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		return nil, err
	}
	return &Audit{f: f, path: path, last: last, now: time.Now}, nil
}

// repairTornTail verifies the chain over complete (newline-terminated) lines
// only. If the file ends with a partial line (no trailing newline — the
// signature of an interrupted append), it truncates the file to the last
// complete record. A complete record that fails verification is NOT repaired:
// that is tampering, and the caller fails closed.
func repairTornTail(path string) error {
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	prev := ""
	lastGoodEnd := 0 // byte offset just past the last verified newline
	i := 0
	for i < len(data) {
		nl := i
		for nl < len(data) && data[nl] != '\n' {
			nl++
		}
		complete := nl < len(data) // found a terminating newline
		line := data[i:nl]
		if len(line) == 0 {
			if !complete {
				break
			}
			i = nl + 1
			lastGoodEnd = i
			continue
		}
		if !complete {
			// Trailing partial line: a torn append. Truncate it away.
			return os.Truncate(path, int64(lastGoodEnd))
		}
		var e AuditEvent
		if err := json.Unmarshal(line, &e); err != nil {
			return fmt.Errorf("complete record is malformed (tampered): %w", err)
		}
		if e.Prev != prev {
			return fmt.Errorf("chain break (tampered): prev %q, want %q", e.Prev, prev)
		}
		want, err := auditHash(e)
		if err != nil {
			return err
		}
		if e.Hash != want {
			return fmt.Errorf("record hash mismatch (tampered)")
		}
		prev = e.Hash
		i = nl + 1
		lastGoodEnd = i
	}
	return nil
}

func (a *Audit) Close() error {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.f.Close()
}

// Append writes one event and extends the chain. Errors must be treated as
// fatal by security-relevant callers (no audit, no action).
func (a *Audit) Append(typ, actor, node, session string, detail map[string]string) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	e := AuditEvent{
		TS:      a.now().Unix(),
		Type:    typ,
		Actor:   actor,
		Node:    node,
		Session: session,
		Detail:  detail,
		Prev:    a.last,
	}
	h, err := auditHash(e)
	if err != nil {
		return err
	}
	e.Hash = h
	line, err := json.Marshal(e)
	if err != nil {
		return err
	}
	if _, err := a.f.Write(append(line, '\n')); err != nil {
		return err
	}
	if err := a.f.Sync(); err != nil {
		return err
	}
	a.last = h
	return nil
}

// Verify rescans the whole chain on disk.
func (a *Audit) Verify() (int, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	_, n, err := verifyAuditFile(a.path)
	return n, err
}

// Query returns up to limit raw lines (chronological order, most recent
// window) matching the filters, plus whether the chain verified.
func (a *Audit) Query(sinceUnix int64, typeFilter string, limit int) (lines [][]byte, chainOK bool, err error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if limit <= 0 {
		limit = 100
	}
	var matched [][]byte
	_, _, verr := scanAuditFile(a.path, func(line []byte, e *AuditEvent) {
		if sinceUnix > 0 && e.TS < sinceUnix {
			return
		}
		if typeFilter != "" && e.Type != typeFilter {
			return
		}
		matched = append(matched, append([]byte(nil), line...))
	})
	// A broken chain still returns the records that verified, flagged not-ok.
	chainOK = verr == nil
	if len(matched) > limit {
		matched = matched[len(matched)-limit:]
	}
	return matched, chainOK, nil
}

// VerifyAuditFile verifies a chain without an open Audit (CLI audit-verify).
// Returns the number of records. A missing file is an empty, valid chain.
func VerifyAuditFile(path string) (int, error) {
	_, n, err := verifyAuditFile(path)
	return n, err
}

func verifyAuditFile(path string) (lastHash string, n int, err error) {
	return scanAuditFile(path, nil)
}

// scanAuditFile walks the chain, verifying every link; cb (optional) sees
// each verified line. Verification stops at the first broken record.
func scanAuditFile(path string, cb func(line []byte, e *AuditEvent)) (lastHash string, n int, err error) {
	f, err := os.Open(path)
	if err != nil {
		if os.IsNotExist(err) {
			return "", 0, nil
		}
		return "", 0, err
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64*1024), 4*1024*1024)
	prev := ""
	lineNo := 0
	for sc.Scan() {
		lineNo++
		line := sc.Bytes()
		if len(line) == 0 {
			continue
		}
		var e AuditEvent
		if err := json.Unmarshal(line, &e); err != nil {
			return prev, lineNo - 1, fmt.Errorf("line %d: malformed record: %w", lineNo, err)
		}
		if e.Prev != prev {
			return prev, lineNo - 1, fmt.Errorf("line %d: chain break: prev %q, want %q", lineNo, e.Prev, prev)
		}
		want, err := auditHash(e)
		if err != nil {
			return prev, lineNo - 1, err
		}
		if e.Hash != want {
			return prev, lineNo - 1, fmt.Errorf("line %d: record hash mismatch (tampered)", lineNo)
		}
		if cb != nil {
			cb(line, &e)
		}
		prev = e.Hash
	}
	if err := sc.Err(); err != nil {
		return prev, lineNo, err
	}
	return prev, lineNo, nil
}
