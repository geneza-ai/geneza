package controller

import (
	"context"
	"encoding/json"
	"fmt"
	"hash/fnv"
	"log/slog"
	"runtime"
	"sort"
	"strings"
	"time"
)

// Staggered auto-rollout. The manual path (SetDesiredVersion) lets an operator
// pin a canary ring and promote it to stable by hand. This controller automates
// that into percentage waves: it grows the canary ring through a frozen,
// hash-ordered slice of the fleet (e.g. 10% -> 50% -> 100%), advancing to the
// next wave only when the current wave is proven healthy for a soak window, and
// finalizing by promoting the target to stable. It drives the SAME ring
// primitives (rolloutRing / canaryBlockers), so the desired-version rule the
// agents resolve is unchanged.
//
// State lives entirely in the store (no in-memory timers), so the controller is
// stateless across ticks and controller restarts. It runs leader-only under the
// shared reconcile lock, and every wave-health read goes through store-backed
// presence — both required for correctness under multi-controller HA.

const (
	settingAgentRollout    = "agent_rollout"
	settingRelayRollout    = "relay_rollout"
	settingAgentAutoUpdate = "agent_auto_update"
	settingRelayAutoUpdate = "relay_auto_update"

	rolloutTickInterval = 15 * time.Second
)

// Defaults applied when a rollout is started without explicit knobs.
var (
	defaultWaves              = []int{10, 50, 100}
	defaultSoakSeconds  int64 = 120
	defaultWaveTimeout  int64 = 600
)

type RolloutState string

const (
	RolloutActive  RolloutState = "active"  // advancing through waves
	RolloutPaused  RolloutState = "paused"  // operator froze it; ring left as-is
	RolloutHalted  RolloutState = "halted"  // a wave failed; operator decides
	RolloutDone    RolloutState = "done"    // target promoted to stable
	RolloutAborted RolloutState = "aborted" // reverted to the prior stable
)

type RolloutTrigger string

const (
	TriggerAdmin RolloutTrigger = "admin" // operator started it; halt-and-hold on failure
	TriggerAuto  RolloutTrigger = "auto"  // started on publish; revert+abort on failure
)

// Rollout is one product's in-flight staged rollout. Persisted as a JSON setting.
type Rollout struct {
	Product string         `json:"product"`
	Target  string         `json:"target"`
	Waves   []int          `json:"waves"` // cumulative percentages, ascending, last == 100
	WaveIdx int            `json:"wave_idx"`
	State   RolloutState   `json:"state"`
	Trigger RolloutTrigger `json:"trigger"`
	// Eligible is the fleet snapshot frozen at start, in deterministic hash order.
	// Waves are cumulative prefixes of it, so a node never leaves a wave it entered
	// and mid-rollout fleet churn cannot reshuffle membership.
	Eligible   []string `json:"eligible"`
	PrevStable string   `json:"prev_stable,omitempty"`

	SoakSeconds        int64 `json:"soak_seconds"`
	WaveTimeoutSeconds int64 `json:"wave_timeout_seconds"`
	WaveEnteredUnix    int64 `json:"wave_entered_unix"`
	// HealthySince is when the current wave most recently became fully healthy; 0
	// means not currently healthy. Soak accrues from here and resets to 0 on any
	// blocker, so the wave must be CONTINUOUSLY healthy for the whole soak.
	HealthySince int64 `json:"healthy_since,omitempty"`

	Blockers    []string `json:"blockers,omitempty"`
	HaltReason  string   `json:"halt_reason,omitempty"`
	Actor       string   `json:"actor,omitempty"`
	CreatedUnix int64    `json:"created_unix"`
	UpdatedUnix int64    `json:"updated_unix"`
}

func (r *Rollout) terminal() bool { return r.State == RolloutDone || r.State == RolloutAborted }

// active reports whether the controller should keep driving this rollout.
func (r *Rollout) active() bool { return r.State == RolloutActive }

func rolloutSettingKey(product string) (string, error) {
	switch product {
	case "", "geneza-agent":
		return settingAgentRollout, nil
	case "geneza-relay":
		return settingRelayRollout, nil
	default:
		return "", fmt.Errorf("unknown product %q", product)
	}
}

func autoUpdateKey(product string) (string, error) {
	switch product {
	case "", "geneza-agent":
		return settingAgentAutoUpdate, nil
	case "geneza-relay":
		return settingRelayAutoUpdate, nil
	default:
		return "", fmt.Errorf("unknown product %q", product)
	}
}

func (s *Server) loadRollout(product string) (*Rollout, error) {
	key, err := rolloutSettingKey(product)
	if err != nil {
		return nil, err
	}
	b, err := s.store.GetSetting(key)
	if err != nil || len(b) == 0 {
		return nil, err
	}
	var r Rollout
	if err := json.Unmarshal(b, &r); err != nil {
		return nil, fmt.Errorf("decode rollout %s: %w", key, err)
	}
	return &r, nil
}

func (s *Server) saveRollout(r *Rollout) error {
	key, err := rolloutSettingKey(r.Product)
	if err != nil {
		return err
	}
	r.UpdatedUnix = time.Now().Unix()
	b, err := json.Marshal(r)
	if err != nil {
		return err
	}
	return s.store.SetSetting(key, b)
}

func (s *Server) autoUpdateEnabled(product string) bool {
	key, err := autoUpdateKey(product)
	if err != nil {
		return false
	}
	b, _ := s.store.GetSetting(key)
	return string(b) == "1"
}

func (s *Server) setAutoUpdate(product string, on bool) error {
	key, err := autoUpdateKey(product)
	if err != nil {
		return err
	}
	v := []byte("0")
	if on {
		v = []byte("1")
	}
	return s.store.SetSetting(key, v)
}

// ringStable returns the product's current stable (desired baseline) version.
func (s *Server) ringStable(product string) (string, error) {
	switch product {
	case "", "geneza-agent":
		return s.store.StableVersion()
	case "geneza-relay":
		return s.store.RelayStableVersion()
	default:
		return "", fmt.Errorf("unknown product %q", product)
	}
}

// eligibleFleet returns the deterministically-ordered id set a rollout walks for
// a product: every enrolled agent, or every known relay.
func (s *Server) eligibleFleet(product string) ([]string, error) {
	var ids []string
	switch product {
	case "", "geneza-agent":
		nodes, err := s.store.ListAllNodes()
		if err != nil {
			return nil, err
		}
		for _, n := range nodes {
			ids = append(ids, n.ID)
		}
	case "geneza-relay":
		relays, err := s.store.ListRelays("")
		if err != nil {
			return nil, err
		}
		for _, r := range relays {
			ids = append(ids, r.RelayID)
		}
	default:
		return nil, fmt.Errorf("unknown product %q", product)
	}
	return hashOrder(ids), nil
}

// hashOrder returns ids sorted by a stable hash of the id (ties broken by the id
// itself). This spreads waves evenly and reproducibly without alphabetical bias,
// and is deterministic so any controller computes the same order.
func hashOrder(ids []string) []string {
	out := append([]string(nil), ids...)
	sort.Slice(out, func(i, j int) bool {
		hi, hj := fnvHash(out[i]), fnvHash(out[j])
		if hi != hj {
			return hi < hj
		}
		return out[i] < out[j]
	})
	return out
}

func fnvHash(s string) uint64 {
	h := fnv.New64a()
	_, _ = h.Write([]byte(s))
	return h.Sum64()
}

// waveMembers is the cumulative prefix of eligible covering the given percentage
// (ceil), so each wave is a superset of the previous and the last (100%) is all.
func waveMembers(eligible []string, pct int) []string {
	n := len(eligible)
	if n == 0 {
		return nil
	}
	k := (pct*n + 99) / 100 // ceil(pct/100 * n)
	if k > n {
		k = n
	}
	if k < 0 {
		k = 0
	}
	return append([]string(nil), eligible[:k]...)
}

// --- lifecycle (called by the admin RPCs) ---

func normalizeWaves(in []int) ([]int, error) {
	if len(in) == 0 {
		return append([]int(nil), defaultWaves...), nil
	}
	out := append([]int(nil), in...)
	prev := 0
	for _, p := range out {
		if p <= prev || p > 100 {
			return nil, fmt.Errorf("waves must be strictly ascending percentages in (0,100], got %v", in)
		}
		prev = p
	}
	if out[len(out)-1] != 100 {
		return nil, fmt.Errorf("the final wave must be 100, got %v", in)
	}
	return out, nil
}

// startRollout creates and persists a new rollout for a product. trigger=admin
// rollouts halt-and-hold on wave failure; trigger=auto revert+abort.
func (s *Server) startRollout(product, target string, waves []int, soak, waveTimeout int64, trigger RolloutTrigger, actor string) (*Rollout, error) {
	if _, err := rolloutSettingKey(product); err != nil {
		return nil, err
	}
	if target == "" {
		return nil, fmt.Errorf("rollout target version is required")
	}
	if cur, err := s.loadRollout(product); err == nil && cur != nil && !cur.terminal() {
		return nil, fmt.Errorf("a rollout is already in progress for %s (state %s); abort it first", productLabel(product), cur.State)
	}
	stable, err := s.ringStable(product)
	if err != nil {
		return nil, err
	}
	if target == stable {
		return nil, fmt.Errorf("%s is already the stable version", target)
	}
	// The build must be published or the wave can never go healthy. Check the
	// controller's own platform manifest as a proxy for "this version exists".
	if mk := ManifestKey(product, runtime.GOOS, runtime.GOARCH, target); true {
		if b, _ := s.store.GetManifest(mk); len(b) == 0 {
			return nil, fmt.Errorf("no published %s manifest for version %s (publish it first)", productLabel(product), target)
		}
	}
	wv, err := normalizeWaves(waves)
	if err != nil {
		return nil, err
	}
	eligible, err := s.eligibleFleet(product)
	if err != nil {
		return nil, err
	}
	if soak <= 0 {
		soak = defaultSoakSeconds
	}
	if waveTimeout <= 0 {
		waveTimeout = defaultWaveTimeout
	}
	now := time.Now().Unix()
	r := &Rollout{
		Product: product, Target: target, Waves: wv, WaveIdx: 0,
		State: RolloutActive, Trigger: trigger,
		Eligible: eligible, PrevStable: stable,
		SoakSeconds: soak, WaveTimeoutSeconds: waveTimeout, WaveEnteredUnix: now,
		Actor: actor, CreatedUnix: now,
	}
	if err := s.saveRollout(r); err != nil {
		return nil, err
	}
	_ = s.audit.Append("rollout_started", actor, "", "", map[string]string{
		"product": product, "target": target, "trigger": string(trigger),
		"waves": fmt.Sprint(wv), "eligible": fmt.Sprint(len(eligible)),
	})
	slog.Info("rollout started", "product", product, "target", target, "trigger", trigger, "waves", wv, "eligible", len(eligible))
	return r, nil
}

func (s *Server) pauseRollout(product, actor string) (*Rollout, error) {
	r, err := s.requireActiveRollout(product)
	if err != nil {
		return nil, err
	}
	r.State = RolloutPaused
	_ = s.audit.Append("rollout_paused", actor, "", "", map[string]string{"product": product})
	return r, s.saveRollout(r)
}

func (s *Server) resumeRollout(product, actor string) (*Rollout, error) {
	r, err := s.loadRollout(product)
	if err != nil {
		return nil, err
	}
	if r == nil || (r.State != RolloutPaused && r.State != RolloutHalted) {
		return nil, fmt.Errorf("no paused or halted rollout for %s to resume", productLabel(product))
	}
	// Re-soak the current wave from now (a halted wave gets a fresh timeout window).
	r.State = RolloutActive
	r.WaveEnteredUnix = time.Now().Unix()
	r.HealthySince = 0
	r.HaltReason = ""
	_ = s.audit.Append("rollout_resumed", actor, "", "", map[string]string{"product": product, "wave": fmt.Sprint(r.WaveIdx)})
	return r, s.saveRollout(r)
}

func (s *Server) abortRollout(product, actor string) (*Rollout, error) {
	r, err := s.loadRollout(product)
	if err != nil {
		return nil, err
	}
	if r == nil || r.terminal() {
		return nil, fmt.Errorf("no in-progress rollout for %s to abort", productLabel(product))
	}
	if err := s.revertRing(product); err != nil {
		return nil, err
	}
	r.State = RolloutAborted
	r.HaltReason = "aborted by " + actor
	_ = s.audit.Append("rollout_aborted", actor, "", "", map[string]string{"product": product, "target": r.Target})
	slog.Info("rollout aborted", "product", product, "target", r.Target, "by", actor)
	return r, s.saveRollout(r)
}

func (s *Server) requireActiveRollout(product string) (*Rollout, error) {
	r, err := s.loadRollout(product)
	if err != nil {
		return nil, err
	}
	if r == nil || !r.active() {
		return nil, fmt.Errorf("no active rollout for %s", productLabel(product))
	}
	return r, nil
}

// revertRing clears the canary ring so every node falls back to the (unchanged)
// stable version — the rollback for an aborted/failed auto rollout. Stable is
// never advanced until finalize, so clearing the ring is the full revert.
func (s *Server) revertRing(product string) error {
	ring, err := s.ringForProduct(product)
	if err != nil {
		return err
	}
	if err := ring.setCanaryNodes(nil); err != nil {
		return err
	}
	return ring.setCanaryVersion("")
}

// maybeAutoStartRollout is the publish hook: when auto-update is enabled for a
// product and a newer-than-stable version is published with no rollout already
// running, it starts an auto (revert-on-failure) staggered rollout. Idempotent —
// a second publish (e.g. another arch) for the same in-flight target is a no-op.
func (s *Server) maybeAutoStartRollout(product, version string) {
	if !s.autoUpdateEnabled(product) || version == "" {
		return
	}
	if cur, err := s.loadRollout(product); err == nil && cur != nil && !cur.terminal() {
		return // a rollout is already running
	}
	stable, err := s.ringStable(product)
	if err == nil && version == stable {
		return
	}
	if _, err := s.startRollout(product, version, nil, 0, 0, TriggerAuto, "auto:publish"); err != nil {
		slog.Warn("auto-rollout not started", "product", product, "version", version, "err", err)
	}
}

func productLabel(product string) string {
	if product == "" {
		return "geneza-agent"
	}
	return product
}

// --- controller loop ---

// runRolloutController drives every product's rollout forward on a tick. It runs
// leader-only (under the shared reconcile lock) so two controllers never double-
// advance, and is fully store-driven so it resumes cleanly after a restart.
func (s *Server) runRolloutController(ctx context.Context, interval time.Duration) {
	if interval <= 0 {
		interval = rolloutTickInterval
	}
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			held, release, err := s.store.TryReconcileLock(ctx)
			if err != nil || !held {
				continue
			}
			for _, product := range []string{"geneza-agent", "geneza-relay"} {
				if err := s.rolloutTick(product); err != nil {
					slog.Warn("rollout tick", "product", product, "err", err)
				}
			}
			release()
		}
	}
}

// rolloutTick advances one product's rollout by at most one transition. It is
// idempotent: re-running it against the same store state converges to the same
// result, so a duplicate tick (or a racing replica) cannot skip or double a wave.
func (s *Server) rolloutTick(product string) error {
	r, err := s.loadRollout(product)
	if err != nil {
		return err
	}
	if r == nil || !r.active() {
		return nil // nothing to do for paused/halted/terminal/no rollout
	}
	ring, err := s.ringForProduct(product)
	if err != nil {
		return err
	}
	members := waveMembers(r.Eligible, r.Waves[r.WaveIdx])

	// Keep the canary ring pinned to this wave at the target every tick (cheap,
	// idempotent, and self-heals if anything else touched the settings).
	if err := ring.setCanaryVersion(r.Target); err != nil {
		return err
	}
	if err := ring.setCanaryNodes(members); err != nil {
		return err
	}

	now := time.Now().Unix()
	blockers := ring.canaryBlockers(members, r.Target)
	if len(blockers) > 0 {
		r.HealthySince = 0
		r.Blockers = blockers
		if r.WaveTimeoutSeconds > 0 && now-r.WaveEnteredUnix >= r.WaveTimeoutSeconds {
			return s.failWave(r, ring, blockers)
		}
		return s.saveRollout(r)
	}

	// Wave is currently healthy. Require continuous health for the soak window.
	r.Blockers = nil
	if r.HealthySince == 0 {
		r.HealthySince = now
		return s.saveRollout(r)
	}
	if now-r.HealthySince < r.SoakSeconds {
		return s.saveRollout(r)
	}

	// Soak satisfied.
	if r.Waves[r.WaveIdx] >= 100 {
		return s.finalizeRollout(r, ring)
	}
	r.WaveIdx++
	r.WaveEnteredUnix = now
	r.HealthySince = 0
	_ = s.audit.Append("rollout_wave_advanced", r.Actor, "", "", map[string]string{
		"product": product, "wave": fmt.Sprint(r.WaveIdx), "pct": fmt.Sprint(r.Waves[r.WaveIdx]),
	})
	slog.Info("rollout wave advanced", "product", product, "wave", r.WaveIdx, "pct", r.Waves[r.WaveIdx])
	return s.saveRollout(r)
}

// failWave applies the trigger-dependent failure policy: admin rollouts halt and
// hold for the operator; auto rollouts revert the ring and abort.
func (s *Server) failWave(r *Rollout, ring rolloutRing, blockers []string) error {
	reason := strings.Join(blockers, "; ")
	if r.Trigger == TriggerAuto {
		if err := s.revertRing(r.Product); err != nil {
			return err
		}
		r.State = RolloutAborted
		r.HaltReason = "auto-rollout reverted after wave timeout: " + reason
		_ = s.audit.Append("rollout_aborted", "auto", "", "", map[string]string{
			"product": r.Product, "target": r.Target, "reason": reason,
		})
		slog.Warn("auto-rollout reverted", "product", r.Product, "target", r.Target, "reason", reason)
	} else {
		r.State = RolloutHalted
		r.HaltReason = reason
		_ = s.audit.Append("rollout_halted", r.Actor, "", "", map[string]string{
			"product": r.Product, "target": r.Target, "wave": fmt.Sprint(r.WaveIdx), "reason": reason,
		})
		slog.Warn("rollout halted", "product", r.Product, "target", r.Target, "wave", r.WaveIdx, "reason", reason)
	}
	return s.saveRollout(r)
}

// finalizeRollout promotes the target to stable and clears the canary ring once
// the final (100%) wave has soaked healthy. Re-checks health at full width first.
func (s *Server) finalizeRollout(r *Rollout, ring rolloutRing) error {
	if final := ring.canaryBlockers(r.Eligible, r.Target); len(final) > 0 {
		r.HealthySince = 0
		r.Blockers = final
		return s.saveRollout(r)
	}
	if err := ring.setStableVersion(r.Target); err != nil {
		return err
	}
	if err := ring.setCanaryNodes(nil); err != nil {
		return err
	}
	if err := ring.setCanaryVersion(""); err != nil {
		return err
	}
	r.State = RolloutDone
	r.Blockers = nil
	_ = s.audit.Append("rollout_completed", r.Actor, "", "", map[string]string{
		"product": r.Product, "target": r.Target,
	})
	slog.Info("rollout completed", "product", r.Product, "target", r.Target)
	return s.saveRollout(r)
}

// rolloutHealthCounts reports how many of the current wave's members are healthy
// on the target, for the status surface (does not mutate state).
func (s *Server) rolloutHealthCounts(r *Rollout) (total, healthy int) {
	if r == nil || len(r.Waves) == 0 || r.WaveIdx >= len(r.Waves) {
		return 0, 0
	}
	members := waveMembers(r.Eligible, r.Waves[r.WaveIdx])
	ring, err := s.ringForProduct(r.Product)
	if err != nil {
		return len(members), 0
	}
	blocked := make(map[string]bool)
	for _, b := range ring.canaryBlockers(members, r.Target) {
		if id, _, ok := strings.Cut(b, ":"); ok {
			blocked[id] = true
		}
	}
	for _, m := range members {
		if !blocked[m] {
			healthy++
		}
	}
	return len(members), healthy
}
