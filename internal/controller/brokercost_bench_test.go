package controller

// Per-operation cost microbenchmarks for the session-broker hot path. They
// isolate, in process, the costs a single brokered session pays — policy
// evaluation, grant signing, the durable audit append, the durable session
// store write — plus the raw fsync cost as a control, so the per-op ordering is
// attributable rather than inferred. Absolute fsync times are host- and
// disk-contention-dependent; the orderings/ratios between ops are not.
//
// Run: go test ./internal/controller -run '^$' -bench 'Cost' -benchmem -benchtime=2s

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	bbolt "go.etcd.io/bbolt"

	"geneza.io/internal/ca"
	"geneza.io/internal/defaults"
	"geneza.io/internal/policy"
	"geneza.io/internal/types"
)

// auditLine is ~the size of a real audit record so the raw-write controls write
// a representative amount before syncing.
var auditLine = append([]byte(strings.Repeat("x", 300)), '\n')

// BenchmarkCostRawWriteNoSync is the control: append a record-sized line with no
// durability barrier. The delta to BenchmarkCostRawWriteFsync is the pure fsync.
func BenchmarkCostRawWriteNoSync(b *testing.B) {
	f, err := os.Create(filepath.Join(b.TempDir(), "w"))
	if err != nil {
		b.Fatal(err)
	}
	defer f.Close()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := f.Write(auditLine); err != nil {
			b.Fatal(err)
		}
	}
}

// BenchmarkCostRawWriteFsync is the fsync wall in isolation: write + f.Sync().
func BenchmarkCostRawWriteFsync(b *testing.B) {
	f, err := os.Create(filepath.Join(b.TempDir(), "w"))
	if err != nil {
		b.Fatal(err)
	}
	defer f.Close()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := f.Write(auditLine); err != nil {
			b.Fatal(err)
		}
		if err := f.Sync(); err != nil {
			b.Fatal(err)
		}
	}
}

// BenchmarkCostAuditAppend is the real audit hot path: MAC + chain + write +
// fsync + checkpoint rewrite, all under the audit mutex. One per brokered session.
func BenchmarkCostAuditAppend(b *testing.B) {
	dir := b.TempDir()
	a, err := OpenAudit(filepath.Join(dir, "audit.jsonl"), filepath.Join(dir, "audit.key"),
		filepath.Join(dir, "audit.chk"), nil, nil)
	if err != nil {
		b.Fatal(err)
	}
	defer a.Close()
	detail := map[string]string{"action": "exec", "node": "n-123", "decision": "allow"}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if err := a.Append("session_request", "alice", "n-123", fmt.Sprintf("s-%d", i), detail); err != nil {
			b.Fatal(err)
		}
	}
}

func benchSessionRecord() *SessionRecord {
	return &SessionRecord{
		ID: "s-0", User: "alice", Provider: "oidc", Subject: "sub-1",
		NodeID: "n-123", NodeName: "node1", Action: "exec", State: "pending",
		StartedUnix: time.Now().Unix(), Roles: []string{"dev"},
	}
}

// BenchmarkCostStorePutSession is the real durable session write (bbolt tx
// commit with the default fsync). One per brokered session.
func BenchmarkCostStorePutSession(b *testing.B) {
	st, err := OpenStore(filepath.Join(b.TempDir(), "state.db"))
	if err != nil {
		b.Fatal(err)
	}
	defer st.Close()
	rec := benchSessionRecord()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		rec.ID = fmt.Sprintf("s-%d", i)
		if err := st.PutSession("default", rec); err != nil {
			b.Fatal(err)
		}
	}
}

// BenchmarkCostBboltPutNoSync does byte-for-byte the same work as PutSession
// (same bucket walk + JSON encode) on a bbolt opened with NoSync. The delta to
// BenchmarkCostStorePutSession is the bbolt commit fsync.
func BenchmarkCostBboltPutNoSync(b *testing.B) {
	db, err := bbolt.Open(filepath.Join(b.TempDir(), "state.db"), 0o600, &bbolt.Options{NoSync: true})
	if err != nil {
		b.Fatal(err)
	}
	defer db.Close()
	// Mirror OpenStore's one-time root-bucket init that wsChildW relies on.
	if err := db.Update(func(tx *bbolt.Tx) error { _, e := tx.CreateBucketIfNotExists(bucketWS); return e }); err != nil {
		b.Fatal(err)
	}
	rec := benchSessionRecord()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		rec.ID = fmt.Sprintf("s-%d", i)
		err := db.Update(func(tx *bbolt.Tx) error {
			bk, err := wsChildW(tx, "default", childSessions)
			if err != nil {
				return err
			}
			return putJSONB(bk, rec.ID, rec)
		})
		if err != nil {
			b.Fatal(err)
		}
	}
}

// benchPolicyDoc builds a policy whose matching rule is LAST among n, so
// Evaluate scans all n rules (worst case) before allowing.
func benchPolicyDoc(n int) []byte {
	var sb strings.Builder
	sb.WriteString("roles:\n  dev:\n    allow:\n")
	for i := 0; i < n-1; i++ {
		fmt.Fprintf(&sb, "      - actions: [exec]\n        node_labels: {tier: \"r%d\"}\n", i)
	}
	sb.WriteString("      - actions: [exec]\n        node_labels: {env: lab}\n")
	sb.WriteString("bindings: []\n")
	return []byte(sb.String())
}

// BenchmarkCostPolicyEvaluate measures policy decision cost vs rule count.
func BenchmarkCostPolicyEvaluate(b *testing.B) {
	in := policy.Input{
		User: "alice", Roles: []string{"dev"}, NodeID: "n-123", NodeName: "node1",
		NodeLabels: map[string]string{"env": "lab"}, Action: "exec", Now: time.Now(),
	}
	for _, n := range []int{1, 5, 25, 100} {
		st, err := policy.Parse(benchPolicyDoc(n))
		if err != nil {
			b.Fatal(err)
		}
		b.Run(fmt.Sprintf("rules=%d", n), func(b *testing.B) {
			for i := 0; i < b.N; i++ {
				if d := st.Evaluate(in); !d.Allow {
					b.Fatalf("expected allow, got %q", d.Reason)
				}
			}
		})
	}
}

// BenchmarkCostGrantSign is the ed25519 signing of a representative session
// grant — the crypto a broker mints per session.
func BenchmarkCostGrantSign(b *testing.B) {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		b.Fatal(err)
	}
	now := time.Now()
	grant := &types.SessionGrant{
		V: 1, ID: "s-abc", User: "alice", Roles: []string{"dev"}, WorkspaceID: "default",
		NodeID: "n-123", Action: "exec", Command: "/bin/true", AllowPTY: true,
		ClientNoisePub: make([]byte, 32), AgentNoisePub: make([]byte, 32),
		RelayAddr: "relay.example.com:7403", RelayToken: strings.Repeat("t", 43),
		RelayCandidates: []types.RelayCandidate{{RegionID: "default", RelayID: "relay1",
			TurnURL: "turn:relay.example.com:7404?transport=udp", TurnUser: "1700000000:default:relay1", TurnPass: strings.Repeat("p", 44)}},
		IssuedAt: now, ExpiresAt: now.Add(2 * time.Minute), MaxSessionTTL: 12 * time.Hour,
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := types.Sign(priv, "k1", defaults.ContextGrant, grant); err != nil {
			b.Fatal(err)
		}
	}
}

// BenchmarkCostCertIssueFromCSR is the ECDSA leaf issuance on the enroll/login
// path (NOT the per-session broker path) — included to place it in the ordering.
func BenchmarkCostCertIssueFromCSR(b *testing.B) {
	dir := b.TempDir()
	if err := ca.Init(dir, "bench"); err != nil {
		b.Fatal(err)
	}
	caInst, err := ca.Load(dir)
	if err != nil {
		b.Fatal(err)
	}
	key, err := ca.GenerateKey()
	if err != nil {
		b.Fatal(err)
	}
	csrDER, err := x509.CreateCertificateRequest(rand.Reader,
		&x509.CertificateRequest{Subject: pkix.Name{CommonName: "n1"}}, key)
	if err != nil {
		b.Fatal(err)
	}
	csrPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csrDER})
	prof := ca.Profile{Kind: ca.KindNode, Workspace: "default", Name: "n1", TTL: 24 * time.Hour}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := caInst.IssueFromCSR(csrPEM, prof); err != nil {
			b.Fatal(err)
		}
	}
}

// bulkLoadSessions writes m session records into one workspace in a single
// transaction (fast preload; sync behavior follows the db's open options).
func bulkLoadSessions(b *testing.B, db *bbolt.DB, ws string, m int) {
	if err := db.Update(func(tx *bbolt.Tx) error { _, e := tx.CreateBucketIfNotExists(bucketWS); return e }); err != nil {
		b.Fatal(err)
	}
	rec := benchSessionRecord()
	if err := db.Update(func(tx *bbolt.Tx) error {
		bk, err := wsChildW(tx, ws, childSessions)
		if err != nil {
			return err
		}
		for j := 0; j < m; j++ {
			rec.ID = "s-" + strconv.Itoa(j)
			if err := putJSONB(bk, rec.ID, rec); err != nil {
				return err
			}
		}
		return nil
	}); err != nil {
		b.Fatal(err)
	}
}

// BenchmarkScaleListAllSessions measures the continuous-authz sweep's core read
// (full scan + per-record JSON decode + O(M log M) sort) as the live-session
// count M grows. The real sweep calls this 5×/15s, so the per-op time ×5 must
// stay well under 15s or sweeps overlap and the deny path falls behind.
func BenchmarkScaleListAllSessions(b *testing.B) {
	for _, m := range []int{1_000, 10_000, 100_000, 1_000_000} {
		db, err := bbolt.Open(filepath.Join(b.TempDir(), "state.db"), 0o600, &bbolt.Options{NoSync: true})
		if err != nil {
			b.Fatal(err)
		}
		bulkLoadSessions(b, db, "default", m)
		st := &bboltStore{db: db}
		b.Run(fmt.Sprintf("M=%d", m), func(b *testing.B) {
			for i := 0; i < b.N; i++ {
				out, err := st.ListAllSessions()
				if err != nil {
					b.Fatal(err)
				}
				if len(out) != m {
					b.Fatalf("got %d sessions, want %d", len(out), m)
				}
			}
		})
		db.Close()
	}
}

// BenchmarkScalePutSessionAtSize measures a durable (synced) session insert when
// the store already holds M sessions — does bbolt commit cost climb as the
// B-tree/file grows, or stay flat?
func BenchmarkScalePutSessionAtSize(b *testing.B) {
	for _, m := range []int{0, 10_000, 100_000, 1_000_000} {
		db, err := bbolt.Open(filepath.Join(b.TempDir(), "state.db"), 0o600, nil) // default sync
		if err != nil {
			b.Fatal(err)
		}
		bulkLoadSessions(b, db, "default", m)
		st := &bboltStore{db: db}
		rec := benchSessionRecord()
		b.Run(fmt.Sprintf("preloaded=%d", m), func(b *testing.B) {
			for i := 0; i < b.N; i++ {
				rec.ID = "new-" + strconv.Itoa(i)
				if err := st.PutSession("default", rec); err != nil {
					b.Fatal(err)
				}
			}
		})
		db.Close()
	}
}
