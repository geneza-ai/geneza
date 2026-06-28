package controller

import (
	"context"
	"errors"
	"fmt"
	"os"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// The SQL-store tests run against every engine whose DSN is configured in the
// environment (GENEZA_TEST_PG_DSN for Postgres, GENEZA_TEST_MYSQL_DSN for
// MariaDB/MySQL). With neither set the suite skips, so the default `go test ./...`
// (the bbolt path) is unaffected and needs no database.

type sqlEngine struct {
	backend string
	dsn     string
}

func configuredSQLEngines(t *testing.T) []sqlEngine {
	t.Helper()
	var out []sqlEngine
	if dsn := os.Getenv("GENEZA_TEST_PG_DSN"); dsn != "" {
		out = append(out, sqlEngine{backend: "postgres", dsn: dsn})
	}
	if dsn := os.Getenv("GENEZA_TEST_MYSQL_DSN"); dsn != "" {
		out = append(out, sqlEngine{backend: "mariadb", dsn: dsn})
	}
	if len(out) == 0 {
		t.Skip("set GENEZA_TEST_PG_DSN and/or GENEZA_TEST_MYSQL_DSN to run the SQL-store tests")
	}
	return out
}

// forEachSQLEngine runs fn as a subtest against each configured engine, handing it
// a clean store.
func forEachSQLEngine(t *testing.T, fn func(t *testing.T, s *sqlStore)) {
	t.Helper()
	for _, eng := range configuredSQLEngines(t) {
		eng := eng
		t.Run(eng.backend, func(t *testing.T) {
			fn(t, newTestSQLStore(t, eng))
		})
	}
}

// allSQLTables is every table the schema creates; the test harness truncates them
// all so each test starts from a clean slate against the shared database.
var allSQLTables = []string{
	"workspaces", "nodes", "node_modules", "sessions", "recordings", "networks", "subnets",
	"routes", "bindings", "members", "tokens", "source_bindings", "os_enroll",
	"revoked_certs", "suspensions", "auth_sessions", "ws_tickets", "device_codes",
	"handoff_codes", "settings", "artifacts", "cluster_config",
	"agent_affinity", "advertised_services", "relays", "agent_presence", "controllers",
	"node_sboms", "node_components", "node_cve", "advisories",
	"image_components", "node_images", "image_cve",
}

func newTestSQLStore(t *testing.T, eng sqlEngine) *sqlStore {
	t.Helper()
	st, err := OpenSQLStore(context.Background(), eng.backend, eng.dsn)
	if err != nil {
		t.Fatalf("open sql store (%s): %v", eng.backend, err)
	}
	s := st.(*sqlStore)
	for _, tbl := range allSQLTables {
		if _, err := s.db.ExecContext(context.Background(), "TRUNCATE TABLE "+tbl); err != nil {
			t.Fatalf("truncate %s: %v", tbl, err)
		}
	}
	t.Cleanup(func() { s.Close() })
	return s
}

func TestSQLRoundTrip(t *testing.T) {
	forEachSQLEngine(t, func(t *testing.T, s *sqlStore) {
		if err := s.PutWorkspace(&WorkspaceRecord{ID: "ws1", Name: "One", OverlayCIDR: "100.64.0.0/24"}); err != nil {
			t.Fatal(err)
		}
		got, err := s.GetWorkspace("ws1")
		if err != nil || got.Name != "One" {
			t.Fatalf("workspace round-trip: %v %+v", err, got)
		}
		if _, err := s.GetWorkspace("nope"); !errors.Is(err, ErrNotFound) {
			t.Fatalf("missing workspace should be ErrNotFound, got %v", err)
		}
		if err := s.PutNode("ws1", &NodeRecord{ID: "n1", Name: "alpha"}); err != nil {
			t.Fatal(err)
		}
		if ws, err := s.WorkspaceForNode("n1"); err != nil || ws != "ws1" {
			t.Fatalf("WorkspaceForNode: %q %v", ws, err)
		}
		if n, err := s.FindNode("ws1", "alpha"); err != nil || n.ID != "n1" {
			t.Fatalf("FindNode by name: %+v %v", n, err)
		}
	})
}

func TestSQLPutSessionStampsWorkspace(t *testing.T) {
	forEachSQLEngine(t, func(t *testing.T, s *sqlStore) {
		// The broker passes a record with no WorkspaceID and relies on the store to
		// stamp it; the embedded doc must carry it so the continuous-authz sweep can
		// resolve suspension/policy/node by workspace.
		if err := s.PutSession("wsX", &SessionRecord{ID: "sess1", State: SessionActive, Provider: "keystone", Subject: "u-1"}); err != nil {
			t.Fatal(err)
		}
		got, err := s.GetSession("wsX", "sess1")
		if err != nil || got.WorkspaceID != "wsX" {
			t.Fatalf("GetSession workspace = %q (want wsX), err=%v", got.WorkspaceID, err)
		}
		all, err := s.ListAllSessions()
		if err != nil || len(all) != 1 || all[0].WorkspaceID != "wsX" {
			t.Fatalf("ListAllSessions workspace = %+v, err=%v", all, err)
		}
	})
}

func TestSQLUseTokenSingleSpend(t *testing.T) {
	forEachSQLEngine(t, func(t *testing.T, s *sqlStore) {
		now := time.Now()
		if err := s.PutToken("gz-one", &TokenRecord{ExpiresUnix: now.Add(time.Hour).Unix(), MaxUses: 1}); err != nil {
			t.Fatal(err)
		}
		const racers = 20
		var ok, exhausted int64
		var wg sync.WaitGroup
		for i := 0; i < racers; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				_, err := s.UseToken("gz-one", time.Now())
				switch {
				case err == nil:
					atomic.AddInt64(&ok, 1)
				case errors.Is(err, ErrTokenExhausted):
					atomic.AddInt64(&exhausted, 1)
				default:
					t.Errorf("unexpected UseToken error: %v", err)
				}
			}()
		}
		wg.Wait()
		if ok != 1 || exhausted != racers-1 {
			t.Fatalf("single-use token: ok=%d exhausted=%d (want 1 / %d)", ok, exhausted, racers-1)
		}
	})
}

func TestSQLOSMintOnceDedupe(t *testing.T) {
	forEachSQLEngine(t, func(t *testing.T, s *sqlStore) {
		now := time.Now()
		tok := &TokenRecord{WorkspaceID: "ws1", ExpiresUnix: now.Add(time.Hour).Unix(), MaxUses: 5}
		var seq int64
		newToken := func() (string, error) { return fmt.Sprintf("gz-%d", atomic.AddInt64(&seq, 1)), nil }

		const racers = 12
		tokens := make([]string, racers)
		var wg sync.WaitGroup
		for i := 0; i < racers; i++ {
			wg.Add(1)
			go func(idx int) {
				defer wg.Done()
				tk, _, err := s.OSMintOnce("svc#vm1", time.Now(), time.Hour, tok, newToken)
				if err != nil {
					t.Errorf("OSMintOnce: %v", err)
					return
				}
				tokens[idx] = tk
			}(i)
		}
		wg.Wait()
		first := tokens[0]
		for i, tk := range tokens {
			if tk != first {
				t.Fatalf("OSMintOnce handed out different tokens: [0]=%q [%d]=%q", first, i, tk)
			}
		}
	})
}

func TestSQLRedeemHandoffOnce(t *testing.T) {
	forEachSQLEngine(t, func(t *testing.T, s *sqlStore) {
		code, cookie := "the-code", "the-cookie"
		if err := s.PutHandoff(&HandoffRecord{
			CodeHash: hashToken(code), CookieHash: hashToken(cookie),
			ExpiresUnix: time.Now().Add(time.Minute).Unix(),
		}); err != nil {
			t.Fatal(err)
		}
		const racers = 16
		var ok int64
		var wg sync.WaitGroup
		for i := 0; i < racers; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				if _, err := s.RedeemHandoff(code, cookie, time.Now().Unix()); err == nil {
					atomic.AddInt64(&ok, 1)
				}
			}()
		}
		wg.Wait()
		if ok != 1 {
			t.Fatalf("handoff redeemed %d times, want exactly 1", ok)
		}
	})
}

func TestSQLPollDeviceGrantIssuesOnce(t *testing.T) {
	forEachSQLEngine(t, func(t *testing.T, s *sqlStore) {
		device := "dev-code"
		if err := s.PutDeviceGrant(&DeviceGrant{
			DeviceHash: hashToken(device), UserCodeHash: hashToken("USER"),
			State: deviceStateApproved, ExpiresUnix: time.Now().Add(time.Minute).Unix(),
			ApprovedWS: "ws1", ApprovedProvider: "keystone", ApprovedSubject: "u-1",
		}); err != nil {
			t.Fatal(err)
		}
		var issued int64
		issue := func(g *DeviceGrant) ([]byte, error) {
			return []byte(fmt.Sprintf("cert-%d", atomic.AddInt64(&issued, 1))), nil
		}
		const racers = 16
		var gotCert int64
		var wg sync.WaitGroup
		for i := 0; i < racers; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				pem, err := s.PollDeviceGrant(device, time.Now().Unix(), issue)
				if err == nil && len(pem) > 0 {
					atomic.AddInt64(&gotCert, 1)
				}
			}()
		}
		wg.Wait()
		if gotCert != 1 {
			t.Fatalf("device grant issued a cert to %d pollers, want exactly 1", gotCert)
		}
	})
}

func TestSQLPollDeviceGrantSuspendedDenied(t *testing.T) {
	forEachSQLEngine(t, func(t *testing.T, s *sqlStore) {
		device := "dev-susp"
		if err := s.PutDeviceGrant(&DeviceGrant{
			DeviceHash: hashToken(device), UserCodeHash: hashToken("USERX"),
			State: deviceStateApproved, ExpiresUnix: time.Now().Add(time.Minute).Unix(),
			ApprovedWS: "ws1", ApprovedProvider: "keystone", ApprovedSubject: "u-susp",
		}); err != nil {
			t.Fatal(err)
		}
		if err := s.SuspendPrincipal("ws1", "keystone", "u-susp", "x", "admin", "test"); err != nil {
			t.Fatal(err)
		}
		_, err := s.PollDeviceGrant(device, time.Now().Unix(), func(*DeviceGrant) ([]byte, error) {
			t.Fatal("issue must not be called for a suspended principal")
			return nil, nil
		})
		var de deviceTokenError
		if !errors.As(err, &de) || de.code != "access_denied" {
			t.Fatalf("suspended device redeem should be access_denied, got %v", err)
		}
	})
}

func TestSQLUpsertFirstAdminRace(t *testing.T) {
	forEachSQLEngine(t, func(t *testing.T, s *sqlStore) {
		const racers = 8
		var firstAdmins int64
		var wg sync.WaitGroup
		for i := 0; i < racers; i++ {
			wg.Add(1)
			go func(idx int) {
				defer wg.Done()
				rec := &MemberRecord{Provider: "keystone", Subject: fmt.Sprintf("u-%d", idx), Username: fmt.Sprintf("u%d", idx), Roles: []string{"ws-member"}}
				isFirst, err := s.UpsertFirstAdmin("wsrace", rec)
				if err != nil {
					t.Errorf("UpsertFirstAdmin: %v", err)
					return
				}
				if isFirst {
					atomic.AddInt64(&firstAdmins, 1)
				}
			}(i)
		}
		wg.Wait()
		if firstAdmins != 1 {
			t.Fatalf("first-admin elected %d times, want exactly 1", firstAdmins)
		}
		members, err := s.ListMembers("wsrace")
		if err != nil {
			t.Fatal(err)
		}
		admins := 0
		for _, m := range members {
			for _, r := range m.Roles {
				if r == roleWSAdmin {
					admins++
				}
			}
		}
		if admins != 1 {
			t.Fatalf("workspace has %d ws-admins, want exactly 1", admins)
		}
	})
}

func TestSQLClusterConfigCAS(t *testing.T) {
	forEachSQLEngine(t, func(t *testing.T, s *sqlStore) {
		if err := s.SetSignedClusterConfig(1, []byte("v1")); err != nil {
			t.Fatalf("genesis: %v", err)
		}
		if v, _ := s.ClusterConfigVersion(); v != 1 {
			t.Fatalf("version after genesis = %d, want 1", v)
		}
		// A bump to N+1 succeeds; a second writer still targeting the same version
		// loses the compare-and-swap.
		if err := s.SetSignedClusterConfig(2, []byte("v2")); err != nil {
			t.Fatalf("bump to 2: %v", err)
		}
		if err := s.SetSignedClusterConfig(2, []byte("v2-other")); !errors.Is(err, errClusterConfigConflict) {
			t.Fatalf("stale bump should conflict, got %v", err)
		}
		// Concurrent writers at the next version: exactly one wins.
		var wins, conflicts int64
		var wg sync.WaitGroup
		for i := 0; i < 8; i++ {
			wg.Add(1)
			go func(idx int) {
				defer wg.Done()
				err := s.SetSignedClusterConfig(3, []byte(fmt.Sprintf("v3-%d", idx)))
				switch {
				case err == nil:
					atomic.AddInt64(&wins, 1)
				case errors.Is(err, errClusterConfigConflict):
					atomic.AddInt64(&conflicts, 1)
				default:
					t.Errorf("unexpected CAS error: %v", err)
				}
			}(i)
		}
		wg.Wait()
		if wins != 1 {
			t.Fatalf("concurrent version bump: %d winners, want exactly 1 (conflicts=%d)", wins, conflicts)
		}
		if v, _ := s.ClusterConfigVersion(); v != 3 {
			t.Fatalf("final version = %d, want 3", v)
		}
	})
}

func TestSQLNodeIDUniqueAcrossWorkspaces(t *testing.T) {
	forEachSQLEngine(t, func(t *testing.T, s *sqlStore) {
		if err := s.PutNode("ws1", &NodeRecord{ID: "dup", Name: "a"}); err != nil {
			t.Fatal(err)
		}
		if err := s.PutNode("ws2", &NodeRecord{ID: "dup", Name: "b"}); err == nil {
			t.Fatal("a node id claimed in a second workspace must be rejected")
		}
		// The rejected claim must not have moved or mutated the original row: a node
		// silently migrating to a foreign workspace would defeat the per-uuid guard.
		if n, err := s.GetNode("ws1", "dup"); err != nil || n.Name != "a" {
			t.Fatalf("original node must be intact after a rejected claim: %+v %v", n, err)
		}
		if _, err := s.GetNode("ws2", "dup"); !errors.Is(err, ErrNotFound) {
			t.Fatalf("foreign workspace must not have gained the node, got %v", err)
		}
		// A legitimate same-(workspace,id) update must still succeed in place.
		if err := s.PutNode("ws1", &NodeRecord{ID: "dup", Name: "a2"}); err != nil {
			t.Fatalf("same-workspace update must succeed: %v", err)
		}
		if n, err := s.GetNode("ws1", "dup"); err != nil || n.Name != "a2" {
			t.Fatalf("same-workspace update did not apply: %+v %v", n, err)
		}
	})
}

// TestSQLQuerySessions exercises the only query that dynamically assembles $N
// placeholders with reuse (the five-way search LIKE) and engine-specific JSON
// extraction, on both engines. The load-bearing assertion is workspace isolation:
// a mis-bound workspace_id predicate would leak another tenant's sessions.
func TestSQLQuerySessions(t *testing.T) {
	forEachSQLEngine(t, func(t *testing.T, s *sqlStore) {
		seed := func(ws string, recs ...*SessionRecord) {
			for _, r := range recs {
				if err := s.PutSession(ws, r); err != nil {
					t.Fatal(err)
				}
			}
		}
		seed("wsA",
			&SessionRecord{ID: "a1", StartedUnix: 1, State: "active", User: "alice", NodeName: "web-01", Action: "shell"},
			&SessionRecord{ID: "a2", StartedUnix: 2, State: "ended", User: "bob", NodeName: "db-01", Action: "exec"},
			&SessionRecord{ID: "a3", StartedUnix: 3, State: "active", User: "alice", NodeName: "cache-01", Action: "shell"},
		)
		// wsB shares content (alice, web-01) so a cross-tenant leak would be visible.
		seed("wsB", &SessionRecord{ID: "b1", StartedUnix: 4, State: "active", User: "alice", NodeName: "web-01", Action: "shell"})

		items, total, err := s.QuerySessions("wsA", SessionQuery{Page: Page{}})
		if err != nil || total != 3 || len(items) != 3 {
			t.Fatalf("wsA list: total=%d len=%d err=%v (want 3/3)", total, len(items), err)
		}
		for _, it := range items {
			if it.WorkspaceID != "wsA" {
				t.Fatalf("cross-tenant leak: wsA query returned %s/%s", it.WorkspaceID, it.ID)
			}
		}
		if _, total, _ := s.QuerySessions("wsA", SessionQuery{State: "active", Page: Page{}}); total != 2 {
			t.Fatalf("state=active total=%d, want 2", total)
		}
		if _, total, _ := s.QuerySessions("wsA", SessionQuery{User: "alice", Page: Page{}}); total != 2 {
			t.Fatalf("user=alice total=%d, want 2", total)
		}
		// "web-01" exists in both workspaces; the wsA search must return only a1.
		its, total, err := s.QuerySessions("wsA", SessionQuery{Search: "web-01", Page: Page{}})
		if err != nil || total != 1 || len(its) != 1 || its[0].ID != "a1" {
			t.Fatalf("search web-01 in wsA: total=%d items=%+v err=%v (want exactly a1)", total, its, err)
		}
		// Every filter at once, paged: active+alice+shell matches a1,a3; asc by start,
		// offset 1 yields a3.
		its, total, err = s.QuerySessions("wsA", SessionQuery{
			State: "active", User: "alice", Search: "shell",
			Sort: "started", Order: "asc", Page: Page{Limit: 1, Offset: 1},
		})
		if err != nil {
			t.Fatal(err)
		}
		if total != 2 || len(its) != 1 || its[0].ID != "a3" {
			t.Fatalf("combined filter: total=%d items=%+v (want total 2, page [a3])", total, its)
		}
	})
}

// TestSQLCaseSensitiveKeys proves the binary collation on key columns: a serial
// stored lowercase must NOT match an uppercase lookup, or 'deadbeef' and 'DEADBEEF'
// would collide into one denylist row and let a different cert through.
func TestSQLCaseSensitiveKeys(t *testing.T) {
	forEachSQLEngine(t, func(t *testing.T, s *sqlStore) {
		if err := s.RevokeCert(&RevokedCert{Serial: "deadbeef", Reason: "lost"}); err != nil {
			t.Fatal(err)
		}
		if !s.IsCertRevoked("deadbeef") {
			t.Fatal("the exact serial must read as revoked")
		}
		if s.IsCertRevoked("DEADBEEF") {
			t.Fatal("an upper-cased serial must NOT match a lower-cased revocation (case-insensitive collation is a deny-path bug)")
		}
		// Two distinct rows can coexist under a binary collation.
		if err := s.RevokeCert(&RevokedCert{Serial: "DEADBEEF", Reason: "also"}); err != nil {
			t.Fatal(err)
		}
		all, err := s.ListRevokedCerts()
		if err != nil {
			t.Fatal(err)
		}
		if len(all) != 2 {
			t.Fatalf("case-distinct serials should be two rows, got %d", len(all))
		}
	})
}

// TestSQLDeleteNodeMissing proves a delete of an absent node returns ErrNotFound
// (the RowsAffected==0 branch) on every engine.
func TestSQLDeleteNodeMissing(t *testing.T) {
	forEachSQLEngine(t, func(t *testing.T, s *sqlStore) {
		if err := s.DeleteNode("ws1", "ghost"); !errors.Is(err, ErrNotFound) {
			t.Fatalf("deleting a missing node should be ErrNotFound, got %v", err)
		}
		if err := s.PutNode("ws1", &NodeRecord{ID: "real", Name: "r"}); err != nil {
			t.Fatal(err)
		}
		if err := s.DeleteNode("ws1", "real"); err != nil {
			t.Fatalf("deleting a present node should succeed, got %v", err)
		}
	})
}

// TestSQLSuspendVisibleToSecondHandle proves a suspension written by one store
// handle is observable by an independent handle (a second controller) — the
// cross-connection deny visibility every backend must guarantee.
func TestSQLSuspendVisibleToSecondHandle(t *testing.T) {
	for _, eng := range configuredSQLEngines(t) {
		eng := eng
		t.Run(eng.backend, func(t *testing.T) {
			a := newTestSQLStore(t, eng)
			bRaw, err := OpenSQLStore(context.Background(), eng.backend, eng.dsn)
			if err != nil {
				t.Fatal(err)
			}
			b := bRaw.(*sqlStore)
			t.Cleanup(func() { b.Close() })

			if a.IsSuspended("ws1", "keystone", "u-x") {
				t.Fatal("principal must start unsuspended")
			}
			if err := a.SuspendPrincipal("ws1", "keystone", "u-x", "ux", "admin", "r"); err != nil {
				t.Fatal(err)
			}
			if !b.IsSuspended("ws1", "keystone", "u-x") {
				t.Fatal("a suspension written by one handle must be visible to a second handle")
			}
		})
	}
}

// TestSQLIsSuspendedFailsClosed proves the deny read fails closed: against a closed
// store (a dead connection), IsSuspended returns true (deny) and IsSuspendedE
// surfaces the error rather than a stale allow.
func TestSQLIsSuspendedFailsClosed(t *testing.T) {
	for _, eng := range configuredSQLEngines(t) {
		eng := eng
		t.Run(eng.backend, func(t *testing.T) {
			st, err := OpenSQLStore(context.Background(), eng.backend, eng.dsn)
			if err != nil {
				t.Fatal(err)
			}
			s := st.(*sqlStore)
			s.Close() // every subsequent query errors
			if _, err := s.IsSuspendedE("ws1", "keystone", "u-x"); err == nil {
				t.Fatal("IsSuspendedE on a dead connection must surface the error")
			}
			if !s.IsSuspended("ws1", "keystone", "u-x") {
				t.Fatal("IsSuspended must fail CLOSED (deny) on a storage fault")
			}
		})
	}
}

func TestSQLSuspensionProviderNormalization(t *testing.T) {
	forEachSQLEngine(t, func(t *testing.T, s *sqlStore) {
		// Suspend with the console provider; the broker checks with the cert provider
		// (device:-prefixed). Both must resolve to the same deny.
		if err := s.SuspendPrincipal("ws1", "keystone", "u-7", "u7", "admin", "r"); err != nil {
			t.Fatal(err)
		}
		if !s.IsSuspended("ws1", "device:keystone", "u-7") {
			t.Fatal("device:-prefixed provider must match the normalized suspension key")
		}
		if !s.IsSuspended("ws1", "keystone", "u-7") {
			t.Fatal("bare provider must match too")
		}
		if s.IsSuspended("ws1", "keystone", "") {
			t.Fatal("an empty subject (operational cert) is never suspended")
		}
	})
}

func TestSQLRevokeAuthSessionsForSubjectNormalization(t *testing.T) {
	forEachSQLEngine(t, func(t *testing.T, s *sqlStore) {
		if err := s.PutAuthSession(&AuthSession{TokenHash: "h1", User: "alice", Provider: "keystone", Subject: "u-9"}); err != nil {
			t.Fatal(err)
		}
		n, err := s.RevokeAuthSessionsForSubject("device:keystone", "u-9")
		if err != nil || n != 1 {
			t.Fatalf("revoke by normalized subject: n=%d err=%v (want 1)", n, err)
		}
	})
}

// TestSQLClaimAffinityEpoch proves the affinity claim bumps the fence epoch on
// every (re)connect across both engines (the upsert+RETURNING / upsert-then-select
// split).
func TestSQLClaimAffinityEpoch(t *testing.T) {
	forEachSQLEngine(t, func(t *testing.T, s *sqlStore) {
		now := time.Now()
		e1, err := s.ClaimAgentAffinity("node-1", "gw-a", now)
		if err != nil || e1 != 1 {
			t.Fatalf("first claim epoch = %d err=%v (want 1)", e1, err)
		}
		e2, err := s.ClaimAgentAffinity("node-1", "gw-b", now)
		if err != nil || e2 != 2 {
			t.Fatalf("reconnect claim epoch = %d err=%v (want 2)", e2, err)
		}
		gw, ep, ok := s.AgentAffinity("node-1")
		if !ok || gw != "gw-b" || ep != 2 {
			t.Fatalf("affinity directory = (%q,%d,%v), want (gw-b,2,true)", gw, ep, ok)
		}
		// An epoch-mismatched release is a no-op (the live owner is kept).
		if err := s.ReleaseAgentAffinity("node-1", "gw-b", 1); err != nil {
			t.Fatal(err)
		}
		if _, _, ok := s.AgentAffinity("node-1"); !ok {
			t.Fatal("a superseded-epoch release must NOT delete the live owner")
		}
		if err := s.ReleaseAgentAffinity("node-1", "gw-b", 2); err != nil {
			t.Fatal(err)
		}
		if _, _, ok := s.AgentAffinity("node-1"); ok {
			t.Fatal("the matching-epoch release must delete the row")
		}
	})
}

// TestSQLAdvertisedServicesEpochGate proves an older claim never overwrites a newer
// connection's advertised-service set on either engine.
func TestSQLAdvertisedServicesEpochGate(t *testing.T) {
	forEachSQLEngine(t, func(t *testing.T, s *sqlStore) {
		if err := s.PutAdvertisedServices("ws1", "n1", 5, nil); err != nil {
			t.Fatal(err)
		}
		// A lower epoch must not overwrite.
		if err := s.PutAdvertisedServices("ws1", "n1", 3, nil); err != nil {
			t.Fatal(err)
		}
		// The stored epoch stays at 5: a same-or-higher epoch write is accepted.
		if err := s.PutAdvertisedServices("ws1", "n1", 6, nil); err != nil {
			t.Fatal(err)
		}
		var epoch int64
		if err := s.db.QueryRowContext(context.Background(), s.rewrite(
			`SELECT epoch FROM advertised_services WHERE workspace_id=$1 AND node_id=$2`), "ws1", "n1").Scan(&epoch); err != nil {
			t.Fatal(err)
		}
		if epoch != 6 {
			t.Fatalf("advertised-services epoch = %d, want 6 (a lower claim must not regress it)", epoch)
		}
	})
}

func TestSQLTryReconcileLock(t *testing.T) {
	for _, eng := range configuredSQLEngines(t) {
		eng := eng
		t.Run(eng.backend, func(t *testing.T) {
			aRaw, err := OpenSQLStore(context.Background(), eng.backend, eng.dsn)
			if err != nil {
				t.Fatal(err)
			}
			a := aRaw.(*sqlStore)
			defer a.Close()
			bRaw, err := OpenSQLStore(context.Background(), eng.backend, eng.dsn)
			if err != nil {
				t.Fatal(err)
			}
			b := bRaw.(*sqlStore)
			defer b.Close()

			heldA, releaseA, err := a.TryReconcileLock(context.Background())
			if err != nil || !heldA {
				t.Fatalf("first handle should win the rebuild lock: held=%v err=%v", heldA, err)
			}
			heldB, _, err := b.TryReconcileLock(context.Background())
			if err != nil {
				t.Fatal(err)
			}
			if heldB {
				t.Fatal("second handle must NOT hold the lock while the first does")
			}
			releaseA()
			// The lock is transient: once a releases it, b grabs it on the next tick.
			var got bool
			for i := 0; i < 20; i++ {
				h, rel, lerr := b.TryReconcileLock(context.Background())
				if lerr != nil {
					t.Fatal(lerr)
				}
				if h {
					rel()
					got = true
					break
				}
				time.Sleep(50 * time.Millisecond)
			}
			if !got {
				t.Fatal("second handle should grab the lock after the first releases it")
			}
		})
	}
}

func TestSQLOpenFailsClosedOnUnreachable(t *testing.T) {
	for _, eng := range configuredSQLEngines(t) {
		eng := eng
		t.Run(eng.backend, func(t *testing.T) {
			var badDSN string
			switch eng.backend {
			case "postgres":
				badDSN = "postgres://nobody:nobody@127.0.0.1:1/none"
			default:
				badDSN = "nobody:nobody@tcp(127.0.0.1:1)/none"
			}
			if _, err := OpenSQLStore(context.Background(), eng.backend, badDSN); err == nil {
				t.Fatal("opening against an unreachable DSN must fail, not degrade")
			}
		})
	}
}

func TestMigrateBboltToSQL(t *testing.T) {
	forEachSQLEngine(t, func(t *testing.T, dst *sqlStore) {
		src := testStore(t)

		// Seed one record of each enumerable kind into the bbolt source.
		if err := src.PutWorkspace(&WorkspaceRecord{ID: "wsm", Name: "Migrate", OverlayCIDR: "100.64.0.0/24"}); err != nil {
			t.Fatal(err)
		}
		if err := src.PutNetwork(&NetworkRecord{WorkspaceID: "wsm", ID: "net1", VNI: 42}); err != nil {
			t.Fatal(err)
		}
		if err := src.PutNode("wsm", &NodeRecord{ID: "nm1", Name: "node-m"}); err != nil {
			t.Fatal(err)
		}
		if err := src.PutMember("wsm", &MemberRecord{Provider: "keystone", Subject: "u-m", Username: "um", Roles: []string{"ws-admin"}}); err != nil {
			t.Fatal(err)
		}
		if err := src.SuspendPrincipal("wsm", "keystone", "u-bad", "ubad", "admin", "spam"); err != nil {
			t.Fatal(err)
		}
		if err := src.RevokeCert(&RevokedCert{Serial: "deadbeef", Reason: "lost"}); err != nil {
			t.Fatal(err)
		}
		if err := src.SetSignedClusterConfig(3, []byte("signed-cc")); err != nil {
			t.Fatal(err)
		}

		counts, err := MigrateStore(src, dst)
		if err != nil {
			t.Fatalf("migrate: %v", err)
		}
		for _, kind := range []string{"workspaces", "networks", "nodes", "members", "suspensions", "revoked_certs", "cluster_config"} {
			if counts[kind] < 1 {
				t.Errorf("expected at least one %s migrated, got %d", kind, counts[kind])
			}
		}
		// Spot-check the destination.
		if w, err := dst.GetWorkspace("wsm"); err != nil || w.Name != "Migrate" {
			t.Fatalf("workspace not migrated: %+v %v", w, err)
		}
		if !dst.IsSuspended("wsm", "keystone", "u-bad") {
			t.Fatal("suspension not migrated")
		}
		if !dst.IsCertRevoked("deadbeef") {
			t.Fatal("revoked cert not migrated")
		}
		if v, _ := dst.ClusterConfigVersion(); v != 3 {
			t.Fatalf("cluster config version not migrated: %d", v)
		}
		if m, err := dst.GetMember("wsm", "keystone", "u-m"); err != nil || len(m.Roles) == 0 || m.Roles[0] != "ws-admin" {
			t.Fatalf("member not migrated: %+v %v", m, err)
		}
	})
}
