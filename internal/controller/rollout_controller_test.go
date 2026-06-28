package controller

import (
	"context"
	"runtime"
	"testing"
	"time"

	genezav1 "geneza.io/internal/pb/geneza/v1"
)

// --- test helpers ---

func putPresence(t *testing.T, s *Server, id, version string, healthy bool) {
	t.Helper()
	if err := s.store.PutAgentPresence(&AgentPresenceRecord{
		NodeID: id, Version: version, Healthy: healthy, LastSeenUnix: time.Now().Unix(),
	}); err != nil {
		t.Fatal(err)
	}
}

func pubManifest(t *testing.T, s *Server, product, version string) {
	t.Helper()
	key := ManifestKey(product, runtime.GOOS, runtime.GOARCH, version)
	if err := s.store.PutManifest(key, []byte(`{"version":"`+version+`"}`)); err != nil {
		t.Fatal(err)
	}
}

func seedFleet(t *testing.T, s *Server, ids ...string) {
	t.Helper()
	for _, id := range ids {
		seedNode(t, s, "ws", id, id, "1.0.0")
	}
}

// markWaveHealthy sets store presence so the current wave's members report the
// target version healthy.
func markWaveHealthy(t *testing.T, s *Server, r *Rollout) {
	t.Helper()
	for _, id := range waveMembers(r.Eligible, r.Waves[r.WaveIdx]) {
		putPresence(t, s, id, r.Target, true)
	}
}

// soakElapsed backdates the persisted soak/wave clocks so the next tick treats
// the soak (and, when forTimeout, the wave timeout) as already elapsed — lets the
// state machine be tested without sleeping on the wall clock.
func soakElapsed(t *testing.T, s *Server, product string) {
	t.Helper()
	r, err := s.loadRollout(product)
	if err != nil || r == nil {
		t.Fatalf("load rollout: %v", err)
	}
	if r.HealthySince > 0 {
		r.HealthySince = time.Now().Unix() - r.SoakSeconds - 5
	}
	if err := s.saveRollout(r); err != nil {
		t.Fatal(err)
	}
}

func timeoutElapsed(t *testing.T, s *Server, product string) {
	t.Helper()
	r, err := s.loadRollout(product)
	if err != nil || r == nil {
		t.Fatalf("load rollout: %v", err)
	}
	r.WaveEnteredUnix = time.Now().Unix() - r.WaveTimeoutSeconds - 5
	if err := s.saveRollout(r); err != nil {
		t.Fatal(err)
	}
}

func mustTick(t *testing.T, s *Server, product string) {
	t.Helper()
	if err := s.rolloutTick(product); err != nil {
		t.Fatalf("tick: %v", err)
	}
}

// --- pure wave math ---

func TestWaveMembersCumulative(t *testing.T) {
	eligible := []string{"a", "b", "c", "d", "e", "f", "g", "h", "i", "j"} // 10
	cases := []struct {
		pct  int
		want int
	}{{10, 1}, {50, 5}, {100, 10}, {1, 1}, {25, 3}}
	for _, c := range cases {
		if got := len(waveMembers(eligible, c.pct)); got != c.want {
			t.Errorf("waveMembers(%d%%) = %d, want %d", c.pct, got, c.want)
		}
	}
	// Cumulative: every wave is a prefix superset of the previous.
	w10, w50, w100 := waveMembers(eligible, 10), waveMembers(eligible, 50), waveMembers(eligible, 100)
	for i, id := range w10 {
		if w50[i] != id || w100[i] != id {
			t.Fatalf("waves not cumulative at %d", i)
		}
	}
}

func TestHashOrderDeterministic(t *testing.T) {
	in := []string{"n-3", "n-1", "n-2", "n-9", "n-7"}
	a, b := hashOrder(in), hashOrder(append([]string(nil), in...))
	if len(a) != len(in) {
		t.Fatalf("hashOrder dropped ids")
	}
	for i := range a {
		if a[i] != b[i] {
			t.Fatalf("hashOrder not deterministic at %d: %q vs %q", i, a[i], b[i])
		}
	}
}

// --- full state machine ---

func TestRolloutAdvancesAndFinalizes(t *testing.T) {
	s := newClusterConsoleTestServer(t)
	if err := s.store.SetStableVersion("1.0.0"); err != nil {
		t.Fatal(err)
	}
	seedFleet(t, s, "n1", "n2", "n3", "n4")
	pubManifest(t, s, "geneza-agent", "2.0.0")

	if _, err := s.startRollout("geneza-agent", "2.0.0", []int{50, 100}, 30, 300, TriggerAdmin, "admin"); err != nil {
		t.Fatalf("start: %v", err)
	}

	// Wave 0 (50% = 2 nodes). Ring must pin those members to the target.
	r, _ := s.loadRollout("geneza-agent")
	markWaveHealthy(t, s, r)
	mustTick(t, s, "geneza-agent") // observes healthy, arms soak
	if cv, _ := s.store.CanaryVersion(); cv != "2.0.0" {
		t.Fatalf("canary version not pinned to target: %q", cv)
	}
	if cn, _ := s.store.CanaryNodes(); len(cn) != 2 {
		t.Fatalf("wave 0 canary ring = %d nodes, want 2", len(cn))
	}
	soakElapsed(t, s, "geneza-agent")
	mustTick(t, s, "geneza-agent") // advance to wave 1
	r, _ = s.loadRollout("geneza-agent")
	if r.WaveIdx != 1 {
		t.Fatalf("did not advance to wave 1: idx=%d state=%s", r.WaveIdx, r.State)
	}

	// Wave 1 (100% = all 4). Make the whole fleet healthy, soak, finalize.
	for _, id := range []string{"n1", "n2", "n3", "n4"} {
		putPresence(t, s, id, "2.0.0", true)
	}
	mustTick(t, s, "geneza-agent") // arms soak at full width
	soakElapsed(t, s, "geneza-agent")
	mustTick(t, s, "geneza-agent") // finalize

	r, _ = s.loadRollout("geneza-agent")
	if r.State != RolloutDone {
		t.Fatalf("rollout state = %s, want done; blockers=%v", r.State, r.Blockers)
	}
	if sv, _ := s.store.StableVersion(); sv != "2.0.0" {
		t.Fatalf("stable not promoted: %q", sv)
	}
	if cn, _ := s.store.CanaryNodes(); len(cn) != 0 {
		t.Fatalf("canary ring not cleared after finalize: %v", cn)
	}
}

func TestRolloutHaltsAdminOnTimeout(t *testing.T) {
	s := newClusterConsoleTestServer(t)
	_ = s.store.SetStableVersion("1.0.0")
	seedFleet(t, s, "n1", "n2")
	pubManifest(t, s, "geneza-agent", "2.0.0")
	if _, err := s.startRollout("geneza-agent", "2.0.0", []int{100}, 10, 60, TriggerAdmin, "admin"); err != nil {
		t.Fatalf("start: %v", err)
	}
	// Nodes never reach the target (stuck on old version) — a self-rolled-back node.
	putPresence(t, s, "n1", "1.0.0", true)
	putPresence(t, s, "n2", "1.0.0", true)
	mustTick(t, s, "geneza-agent") // blockers, not yet timed out
	if r, _ := s.loadRollout("geneza-agent"); r.State != RolloutActive {
		t.Fatalf("halted too early: %s", r.State)
	}
	timeoutElapsed(t, s, "geneza-agent")
	mustTick(t, s, "geneza-agent")
	r, _ := s.loadRollout("geneza-agent")
	if r.State != RolloutHalted {
		t.Fatalf("state = %s, want halted", r.State)
	}
	if r.HaltReason == "" {
		t.Fatal("halted rollout must carry a reason")
	}
	if sv, _ := s.store.StableVersion(); sv != "1.0.0" {
		t.Fatalf("stable changed despite halt: %q", sv)
	}
	// A halted admin rollout can be resumed (operator decision).
	if _, err := s.resumeRollout("geneza-agent", "admin"); err != nil {
		t.Fatalf("resume: %v", err)
	}
	if r, _ := s.loadRollout("geneza-agent"); r.State != RolloutActive {
		t.Fatalf("resume did not reactivate: %s", r.State)
	}
}

func TestRolloutAutoAbortsOnTimeout(t *testing.T) {
	s := newClusterConsoleTestServer(t)
	_ = s.store.SetStableVersion("1.0.0")
	seedFleet(t, s, "n1", "n2")
	pubManifest(t, s, "geneza-agent", "2.0.0")
	if _, err := s.startRollout("geneza-agent", "2.0.0", []int{100}, 10, 60, TriggerAuto, "auto"); err != nil {
		t.Fatalf("start: %v", err)
	}
	putPresence(t, s, "n1", "1.0.0", true) // never reaches target
	mustTick(t, s, "geneza-agent")
	timeoutElapsed(t, s, "geneza-agent")
	mustTick(t, s, "geneza-agent")
	r, _ := s.loadRollout("geneza-agent")
	if r.State != RolloutAborted {
		t.Fatalf("state = %s, want aborted", r.State)
	}
	// Revert: canary ring cleared, stable untouched.
	if cn, _ := s.store.CanaryNodes(); len(cn) != 0 {
		t.Fatalf("auto-abort did not clear canary ring: %v", cn)
	}
	if cv, _ := s.store.CanaryVersion(); cv != "" {
		t.Fatalf("auto-abort did not clear canary version: %q", cv)
	}
	if sv, _ := s.store.StableVersion(); sv != "1.0.0" {
		t.Fatalf("stable changed on abort: %q", sv)
	}
}

func TestRolloutSoakResetsOnFlap(t *testing.T) {
	s := newClusterConsoleTestServer(t)
	_ = s.store.SetStableVersion("1.0.0")
	seedFleet(t, s, "n1", "n2")
	pubManifest(t, s, "geneza-agent", "2.0.0")
	_, err := s.startRollout("geneza-agent", "2.0.0", []int{100}, 30, 600, TriggerAdmin, "admin")
	if err != nil {
		t.Fatal(err)
	}
	putPresence(t, s, "n1", "2.0.0", true)
	putPresence(t, s, "n2", "2.0.0", true)
	mustTick(t, s, "geneza-agent") // arms soak
	if r, _ := s.loadRollout("geneza-agent"); r.HealthySince == 0 {
		t.Fatal("soak clock not armed on healthy wave")
	}
	// One node flaps unhealthy — the soak clock must reset.
	putPresence(t, s, "n2", "2.0.0", false)
	mustTick(t, s, "geneza-agent")
	if r, _ := s.loadRollout("geneza-agent"); r.HealthySince != 0 {
		t.Fatalf("soak clock not reset on flap: %d", r.HealthySince)
	}
}

func TestManualDesiredRejectedDuringRollout(t *testing.T) {
	s := newClusterConsoleTestServer(t)
	_ = s.store.SetStableVersion("1.0.0")
	seedFleet(t, s, "n1")
	pubManifest(t, s, "geneza-agent", "2.0.0")
	if _, err := s.startRollout("geneza-agent", "2.0.0", []int{100}, 10, 60, TriggerAdmin, "admin"); err != nil {
		t.Fatal(err)
	}
	api := &adminAPIService{s: s}
	_, err := api.SetDesiredVersion(context.Background(), &genezav1.SetDesiredVersionRequest{
		Ring: "stable", Version: "3.0.0", Product: "geneza-agent",
	})
	if err == nil {
		t.Fatal("manual SetDesiredVersion must be rejected while a rollout is active")
	}
}

func TestAutoStartOnPublish(t *testing.T) {
	s := newClusterConsoleTestServer(t)
	_ = s.store.SetStableVersion("1.0.0")
	seedFleet(t, s, "n1", "n2")
	pubManifest(t, s, "geneza-agent", "2.0.0")

	// Disabled: no rollout.
	s.maybeAutoStartRollout("geneza-agent", "2.0.0")
	if r, _ := s.loadRollout("geneza-agent"); r != nil {
		t.Fatal("auto-rollout started while auto-update disabled")
	}
	// Enabled: a publish kicks off an auto rollout.
	if err := s.setAutoUpdate("geneza-agent", true); err != nil {
		t.Fatal(err)
	}
	s.maybeAutoStartRollout("geneza-agent", "2.0.0")
	r, _ := s.loadRollout("geneza-agent")
	if r == nil || r.Trigger != TriggerAuto || r.Target != "2.0.0" || r.State != RolloutActive {
		t.Fatalf("auto rollout not started correctly: %+v", r)
	}
	// Idempotent: a second publish for the in-flight target is a no-op.
	s.maybeAutoStartRollout("geneza-agent", "2.0.0")
	if r2, _ := s.loadRollout("geneza-agent"); r2.CreatedUnix != r.CreatedUnix {
		t.Fatal("second publish restarted the rollout")
	}
}

func TestStartRolloutValidations(t *testing.T) {
	s := newClusterConsoleTestServer(t)
	_ = s.store.SetStableVersion("1.0.0")
	seedFleet(t, s, "n1")
	pubManifest(t, s, "geneza-agent", "2.0.0")

	if _, err := s.startRollout("geneza-agent", "", nil, 0, 0, TriggerAdmin, "a"); err == nil {
		t.Error("empty version must be rejected")
	}
	if _, err := s.startRollout("geneza-agent", "1.0.0", nil, 0, 0, TriggerAdmin, "a"); err == nil {
		t.Error("target == stable must be rejected")
	}
	if _, err := s.startRollout("geneza-agent", "9.9.9", nil, 0, 0, TriggerAdmin, "a"); err == nil {
		t.Error("unpublished version must be rejected")
	}
	if _, err := s.startRollout("geneza-agent", "2.0.0", []int{50, 40}, 0, 0, TriggerAdmin, "a"); err == nil {
		t.Error("non-ascending waves must be rejected")
	}
	if _, err := s.startRollout("geneza-agent", "2.0.0", []int{50}, 0, 0, TriggerAdmin, "a"); err == nil {
		t.Error("waves not ending in 100 must be rejected")
	}
	// Valid start, then a second concurrent start is rejected.
	if _, err := s.startRollout("geneza-agent", "2.0.0", nil, 0, 0, TriggerAdmin, "a"); err != nil {
		t.Fatalf("valid start failed: %v", err)
	}
	if _, err := s.startRollout("geneza-agent", "2.0.0", nil, 0, 0, TriggerAdmin, "a"); err == nil {
		t.Error("a second concurrent rollout must be rejected")
	}
}

// A duplicate tick (e.g. a racing HA replica) must not double-advance or skip a
// wave: re-running the tick against the same store state is a no-op.
func TestRolloutTickIdempotent(t *testing.T) {
	s := newClusterConsoleTestServer(t)
	_ = s.store.SetStableVersion("1.0.0")
	seedFleet(t, s, "n1", "n2", "n3", "n4")
	pubManifest(t, s, "geneza-agent", "2.0.0")
	_, err := s.startRollout("geneza-agent", "2.0.0", []int{50, 100}, 30, 600, TriggerAdmin, "admin")
	if err != nil {
		t.Fatal(err)
	}
	r, _ := s.loadRollout("geneza-agent")
	markWaveHealthy(t, s, r)
	mustTick(t, s, "geneza-agent")
	soakElapsed(t, s, "geneza-agent")
	mustTick(t, s, "geneza-agent") // advance to wave 1
	mustTick(t, s, "geneza-agent") // immediate re-tick must not jump again
	if r, _ := s.loadRollout("geneza-agent"); r.WaveIdx != 1 {
		t.Fatalf("re-tick double-advanced: idx=%d", r.WaveIdx)
	}
}
