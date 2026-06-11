package gateway

import (
	"bufio"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"sync"
	"time"
)

// AuditEvent is one chained JSONL record. Hash is HMAC-SHA256 over the record
// JSON with Hash="" (Prev and Seq included), so an attacker with only file-write
// access cannot forge or re-chain records without the gateway's audit key; the
// monotonic Seq plus the sidecar checkpoint detect tail truncation. Full
// tamper-evidence against a host that also holds the key requires the off-box
// sink. Detail values are strings so the record re-marshals byte-identically.
type AuditEvent struct {
	Seq     int64             `json:"seq"`
	TS      int64             `json:"ts"`
	Type    string            `json:"type"`
	Actor   string            `json:"actor,omitempty"`
	Node    string            `json:"node,omitempty"`
	Session string            `json:"session,omitempty"`
	Detail  map[string]string `json:"detail,omitempty"`
	Prev    string            `json:"prev"`
	Hash    string            `json:"hash"`
}

// auditMAC is the keyed integrity tag over the record with Hash cleared.
func auditMAC(key []byte, e AuditEvent) (string, error) {
	e.Hash = ""
	b, err := json.Marshal(e)
	if err != nil {
		return "", err
	}
	m := hmac.New(sha256.New, key)
	m.Write(b)
	return hex.EncodeToString(m.Sum(nil)), nil
}

type checkpoint struct {
	Seq   int64  `json:"seq"`
	Hash  string `json:"hash"`
	Count int64  `json:"count"`
}

// Audit is the append-only audit sink. Appends are mutex-serialized, fsynced,
// checkpointed, and mirrored to the off-box sink. The chain is verified at open
// (with tail-truncation detection) before the gateway extends it.
type Audit struct {
	mu      sync.Mutex
	f       *os.File
	path    string
	chkPath string
	key     []byte
	last    string // hash of the last appended record
	seq     int64  // last sequence number
	count   int64  // total records
	sink    AuditSink
	log     *slog.Logger
	now     func() time.Time
}

// OpenAudit opens (creating if needed) the keyed audit chain. keyPath holds the
// HMAC key (created 0600 if absent); chkPath is the sidecar checkpoint; sink
// mirrors records off-box (may be nil).
func OpenAudit(path, keyPath, chkPath string, sink AuditSink, log *slog.Logger) (*Audit, error) {
	if log == nil {
		log = slog.Default()
	}
	if sink == nil {
		sink = nopSink{}
	}
	key, err := loadOrCreateAuditKey(keyPath)
	if err != nil {
		return nil, fmt.Errorf("audit key: %w", err)
	}

	// Tolerate a torn final line (crash mid-append); interior breaks stay fatal.
	if err := repairTornTail(path, key); err != nil {
		return nil, fmt.Errorf("audit chain %s: %w", path, err)
	}
	last, seq, count, err := verifyAuditFile(path, key)
	if err != nil {
		return nil, fmt.Errorf("audit chain %s: %w", path, err)
	}
	// Cross-check the sidecar checkpoint: a tail truncation removes records from
	// the file but the checkpoint remembers the higher seq → fail closed.
	if chk, ok, cerr := loadCheckpoint(chkPath); cerr != nil {
		return nil, fmt.Errorf("audit checkpoint: %w", cerr)
	} else if ok {
		if chk.Seq > seq {
			return nil, fmt.Errorf("audit chain truncated: checkpoint seq %d > file seq %d (records removed)", chk.Seq, seq)
		}
		if chk.Seq == seq && chk.Hash != last {
			return nil, fmt.Errorf("audit checkpoint/file hash mismatch at seq %d (tampered)", seq)
		}
		// chk.Seq < seq is tolerated: a crash after appending but before the
		// checkpoint write. The file is authoritative; rewrite the checkpoint.
	}

	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		return nil, err
	}
	a := &Audit{f: f, path: path, chkPath: chkPath, key: key, last: last, seq: seq, count: count, sink: sink, log: log, now: time.Now}
	if err := a.saveCheckpoint(); err != nil {
		a.log.Warn("audit: initial checkpoint write failed", "err", err)
	}
	return a, nil
}

func loadOrCreateAuditKey(path string) ([]byte, error) {
	b, err := os.ReadFile(path)
	if err == nil {
		key := make([]byte, hex.DecodedLen(len(b)))
		n, derr := hex.Decode(key, b)
		if derr != nil || n != 32 {
			return nil, fmt.Errorf("malformed audit key in %s", path)
		}
		return key[:32], nil
	}
	if !os.IsNotExist(err) {
		return nil, err
	}
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		return nil, err
	}
	if err := os.WriteFile(path, []byte(hex.EncodeToString(key)), 0o600); err != nil {
		return nil, err
	}
	return key, nil
}

func (a *Audit) Close() error {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.sink != nil {
		_ = a.sink.Close()
	}
	return a.f.Close()
}

// Append writes one event, extends the chain, updates the checkpoint, and
// mirrors to the off-box sink. Errors must be fatal for security-relevant
// callers (no audit, no action). Sink errors are logged, not returned.
func (a *Audit) Append(typ, actor, node, session string, detail map[string]string) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	e := AuditEvent{
		Seq:     a.seq + 1,
		TS:      a.now().Unix(),
		Type:    typ,
		Actor:   actor,
		Node:    node,
		Session: session,
		Detail:  detail,
		Prev:    a.last,
	}
	h, err := auditMAC(a.key, e)
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
	a.seq = e.Seq
	a.count++
	if err := a.saveCheckpoint(); err != nil {
		return fmt.Errorf("audit checkpoint: %w", err)
	}
	if a.sink != nil {
		if err := a.sink.Append(line); err != nil {
			a.log.Warn("audit: off-box sink append failed (record kept locally)", "seq", e.Seq, "err", err)
		}
	}
	return nil
}

func (a *Audit) saveCheckpoint() error {
	if a.chkPath == "" {
		return nil
	}
	return writeCheckpoint(a.chkPath, checkpoint{Seq: a.seq, Hash: a.last, Count: a.count})
}

// Verify rescans the whole chain on disk and cross-checks the checkpoint.
func (a *Audit) Verify() (int, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	_, seq, count, err := verifyAuditFile(a.path, a.key)
	if err != nil {
		return int(count), err
	}
	if chk, ok, cerr := loadCheckpoint(a.chkPath); cerr == nil && ok && chk.Seq > seq {
		return int(count), fmt.Errorf("audit chain truncated: checkpoint seq %d > file seq %d", chk.Seq, seq)
	}
	return int(count), nil
}

// Query returns up to limit raw lines (chronological, most recent window)
// matching the filters, plus whether the chain verified.
func (a *Audit) Query(sinceUnix int64, typeFilter string, limit int) (lines [][]byte, chainOK bool, err error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if limit <= 0 {
		limit = 100
	}
	var matched [][]byte
	_, _, _, verr := scanAuditFile(a.path, a.key, func(line []byte, e *AuditEvent) {
		if sinceUnix > 0 && e.TS < sinceUnix {
			return
		}
		if typeFilter != "" && e.Type != typeFilter {
			return
		}
		matched = append(matched, append([]byte(nil), line...))
	})
	chainOK = verr == nil
	if len(matched) > limit {
		matched = matched[len(matched)-limit:]
	}
	return matched, chainOK, nil
}

// VerifyAuditFile verifies a chain without an open Audit (CLI audit-verify).
func VerifyAuditFile(path, keyPath string) (int, error) {
	key, err := loadOrCreateAuditKey(keyPath)
	if err != nil {
		return 0, err
	}
	_, _, n, err := verifyAuditFile(path, key)
	return int(n), err
}

func verifyAuditFile(path string, key []byte) (lastHash string, lastSeq, n int64, err error) {
	return scanAuditFile(path, key, nil)
}

// scanAuditFile walks the chain verifying every link (HMAC, prev linkage,
// strictly-incrementing seq); cb (optional) sees each verified line.
func scanAuditFile(path string, key []byte, cb func(line []byte, e *AuditEvent)) (lastHash string, lastSeq, n int64, err error) {
	f, err := os.Open(path)
	if err != nil {
		if os.IsNotExist(err) {
			return "", 0, 0, nil
		}
		return "", 0, 0, err
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64*1024), 4*1024*1024)
	prev := ""
	var seq, count int64
	lineNo := 0
	for sc.Scan() {
		lineNo++
		line := sc.Bytes()
		if len(line) == 0 {
			continue
		}
		var e AuditEvent
		if jerr := json.Unmarshal(line, &e); jerr != nil {
			return prev, seq, count, fmt.Errorf("line %d: malformed record: %w", lineNo, jerr)
		}
		if e.Prev != prev {
			return prev, seq, count, fmt.Errorf("line %d: chain break: prev %q, want %q", lineNo, e.Prev, prev)
		}
		if e.Seq != seq+1 {
			return prev, seq, count, fmt.Errorf("line %d: seq %d, want %d (gap/reorder)", lineNo, e.Seq, seq+1)
		}
		want, herr := auditMAC(key, e)
		if herr != nil {
			return prev, seq, count, herr
		}
		if subtle.ConstantTimeCompare([]byte(e.Hash), []byte(want)) != 1 {
			return prev, seq, count, fmt.Errorf("line %d: record MAC mismatch (tampered or wrong key)", lineNo)
		}
		if cb != nil {
			cb(line, &e)
		}
		prev = e.Hash
		seq = e.Seq
		count++
	}
	if serr := sc.Err(); serr != nil {
		return prev, seq, count, serr
	}
	return prev, seq, count, nil
}

// repairTornTail truncates a torn final line (no terminating newline — an
// interrupted append) to the last complete record. A complete-but-invalid
// record is NOT repaired (that is tampering → fail closed).
func repairTornTail(path string, key []byte) error {
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	prev := ""
	var seq int64
	lastGoodEnd := 0
	i := 0
	for i < len(data) {
		nl := i
		for nl < len(data) && data[nl] != '\n' {
			nl++
		}
		complete := nl < len(data)
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
			return os.Truncate(path, int64(lastGoodEnd))
		}
		var e AuditEvent
		if jerr := json.Unmarshal(line, &e); jerr != nil {
			return fmt.Errorf("complete record is malformed (tampered): %w", jerr)
		}
		if e.Prev != prev || e.Seq != seq+1 {
			return fmt.Errorf("complete record fails chain (tampered)")
		}
		want, herr := auditMAC(key, e)
		if herr != nil {
			return herr
		}
		if subtle.ConstantTimeCompare([]byte(e.Hash), []byte(want)) != 1 {
			return fmt.Errorf("record MAC mismatch (tampered)")
		}
		prev = e.Hash
		seq = e.Seq
		i = nl + 1
		lastGoodEnd = i
	}
	return nil
}

func loadCheckpoint(path string) (checkpoint, bool, error) {
	if path == "" {
		return checkpoint{}, false, nil
	}
	b, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return checkpoint{}, false, nil
		}
		return checkpoint{}, false, err
	}
	var c checkpoint
	if err := json.Unmarshal(b, &c); err != nil {
		return checkpoint{}, false, fmt.Errorf("malformed checkpoint: %w", err)
	}
	return c, true, nil
}

func writeCheckpoint(path string, c checkpoint) error {
	b, err := json.Marshal(c)
	if err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}
