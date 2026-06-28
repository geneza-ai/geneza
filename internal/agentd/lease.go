package agentd

import (
	"bytes"
	"context"
	"sync"
	"sync/atomic"
	"time"

	"geneza.io/internal/defaults"
	genezav1 "geneza.io/internal/pb/geneza/v1"
	"geneza.io/internal/types"
)

// lease.go is the agent's realtime PEP for a DIRECT (p2p) session, where the
// controller is off the data path. Three signed messages drive it, all verified
// against the SAME trusted grant keys that verify the grant itself
// (types.Verify under ContextSessionPolicy) and all carrying a strictly-monotonic
// per-session epoch the agent rejects on non-increase:
//
//   - LEASE: a fail-closed data-path heartbeat. The controller re-pushes a fresh
//     lease every sweep tick; the agent forwards only while the lease is fresh.
//     On STARVATION (the controller went silent — a partition or a lost revoke) the
//     agent tears the CONDUIT but NOT a detachable PTY: the session-host keeps it
//     for reattach, so unreachability never reaps an authorized detached shell.
//   - REVOKE: an explicit authz denial. It reaps the host PTY too (no reattach).
//   - DELTA: a downgrade-only capability change. It is verified as a subset of
//     the grant and the new caps are stored for per-op enforcement to consume;
//     allow=false is treated as a full cut.

// liveSession is the agent's per-session enforcement state. The cancel func tears
// the conduit; the lease timer self-tears on starvation; caps holds the live
// downgrade the agent enforces at each op; fwds tracks open forward splices so a
// revoke_forward can actively close them in flight.
type liveSession struct {
	cancel         context.CancelFunc
	grant          *types.SessionGrant
	pathClass      string
	clientNoisePub []byte

	mu            sync.Mutex
	epoch         int64
	leaseDeadline time.Time
	leaseTimer    *time.Timer

	caps atomic.Pointer[genezav1.SessionCaps] // the live downgrade (nil = grant-max, no downgrade)

	fwdMu sync.Mutex
	fwds  map[*trackedSplice]struct{} // open direct-tcpip splices, for active teardown

	sftpMu     sync.Mutex
	sftpCancel context.CancelFunc // set while an sftp channel is open; torn on a write-downgrade
}

// trackedSplice is one in-flight forward splice; cancel unblocks its io.Copy pair
// so a revoked target is torn down promptly, not just denied on the next open.
type trackedSplice struct {
	destAddr string
	destPort uint32
	cancel   context.CancelFunc
}

func (ls *liveSession) stopLeaseTimer() {
	ls.mu.Lock()
	if ls.leaseTimer != nil {
		ls.leaseTimer.Stop()
		ls.leaseTimer = nil
	}
	ls.mu.Unlock()
}

// rearmLocked (re)schedules the fail-closed teardown for the session's current
// lease deadline. The caller MUST hold ls.mu, so the epoch, deadline, and timer
// are committed as one unit — onLeaseExpired (which also re-checks the deadline
// under ls.mu) can never observe a new epoch with a stale deadline.
func (ls *liveSession) rearmLocked(expiryUnixMs int64, fire func()) {
	if ls.leaseTimer != nil {
		ls.leaseTimer.Stop()
	}
	ls.leaseDeadline = time.UnixMilli(expiryUnixMs)
	d := time.Until(ls.leaseDeadline)
	if d < 0 {
		d = 0
	}
	ls.leaseTimer = time.AfterFunc(d, fire)
}

// armLeaseTimer arms the initial grace timer for a freshly-registered session.
func (w *Worker) armLeaseTimer(id string, expiryUnixMs int64) {
	w.liveMu.Lock()
	ls := w.live[id]
	w.liveMu.Unlock()
	if ls == nil {
		return
	}
	ls.mu.Lock()
	ls.rearmLocked(expiryUnixMs, func() { w.onLeaseExpired(id) })
	ls.mu.Unlock()
}

// onLeaseExpired is lease STARVATION = the controller went silent. It tears the
// conduit (fail-closed) but never kills the session-host PTY: a detachable
// session becomes detached (the bridge teardown emits "detached") and survives
// for reattach once connectivity + authorization return.
func (w *Worker) onLeaseExpired(id string) {
	w.liveMu.Lock()
	ls := w.live[id]
	w.liveMu.Unlock()
	if ls == nil {
		return
	}
	ls.mu.Lock()
	if time.Now().Before(ls.leaseDeadline) {
		ls.mu.Unlock()
		return // a fresh lease extended the deadline after this timer was queued
	}
	ls.mu.Unlock()
	w.liveMu.Lock()
	delete(w.live, id)
	w.liveMu.Unlock()
	ls.cancel() // tear the conduit; serveSSH/bridgeAndFinish emits detached|ended itself
	w.log.Warn("session lease expired: conduit torn, detachable PTY preserved for reattach",
		"session", id, "path", ls.pathClass)
}

// verifyEnforcement decodes + verifies a signed enforcement envelope against the
// trusted grant keys under the session-policy context, unmarshalling into out.
// REUSES the grant verification path; the on-wire `bytes sig` is the full
// types.Signed envelope so the key id (and rotation) is preserved.
func (w *Worker) verifyEnforcement(sigBytes []byte, out any) error {
	env, err := types.DecodeSigned(sigBytes)
	if err != nil {
		return err
	}
	_, err = types.Verify(w.trustedKeys(), defaults.ContextSessionPolicy, env, out)
	return err
}

// applyLease verifies + applies a fail-closed lease: re-arm the timer if the
// epoch strictly increases and the lease is bound to this live session's client
// key. Idempotent under re-push.
func (w *Worker) applyLease(l *genezav1.SessionLease) {
	var p types.LeasePayload
	if err := w.verifyEnforcement(l.GetSig(), &p); err != nil {
		w.log.Warn("drop unverifiable session lease", "session", l.GetSessionId(), "err", err)
		return
	}
	w.liveMu.Lock()
	ls := w.live[l.GetSessionId()]
	w.liveMu.Unlock()
	if ls == nil {
		return // not live in this worker (a fresh lease will re-arrive each tick)
	}
	if p.SessionID != l.GetSessionId() || !bytes.Equal(p.ClientNoisePub, ls.clientNoisePub) {
		w.log.Warn("drop session lease: binding mismatch", "session", l.GetSessionId())
		return
	}
	id := l.GetSessionId()
	ls.mu.Lock()
	if p.Epoch <= ls.epoch { // replay / rollback
		ls.mu.Unlock()
		return
	}
	ls.epoch = p.Epoch
	ls.rearmLocked(p.ExpiryUnixMs, func() { w.onLeaseExpired(id) }) // epoch+deadline committed atomically
	ls.mu.Unlock()
}

// applyDelta verifies + applies a downgrade-only capability change. allow=false is
// a full cut (reaps the host, like a revoke). Otherwise the caps must be a subset
// of the standing grant; they are stored for per-op enforcement and the lease is
// refreshed.
func (w *Worker) applyDelta(d *genezav1.SessionPolicyDelta) {
	var p types.DeltaPayload
	if err := w.verifyEnforcement(d.GetSig(), &p); err != nil {
		w.log.Warn("drop unverifiable session delta", "session", d.GetSessionId(), "err", err)
		return
	}
	w.liveMu.Lock()
	ls := w.live[d.GetSessionId()]
	w.liveMu.Unlock()
	if ls == nil {
		return
	}
	if p.SessionID != d.GetSessionId() || !bytes.Equal(p.ClientNoisePub, ls.clientNoisePub) {
		w.log.Warn("drop session delta: binding mismatch", "session", d.GetSessionId())
		return
	}
	id := d.GetSessionId()
	ls.mu.Lock()
	grant := ls.grant // immutable after registerLive
	stale := p.Epoch <= ls.epoch
	ls.mu.Unlock()
	if stale {
		return // early reject; re-checked under lock at commit so a race can't roll back
	}

	caps := capsFromProto(d.GetCaps())
	if err := types.VerifyDowngrade(grant, caps); err != nil {
		w.log.Warn("reject non-downgrade session delta", "session", id, "err", err)
		return
	}
	if caps != nil && !caps.Allow {
		w.revokeLive(id, "policy delta: cut") // full cut = authz deny, reaps host
		return
	}
	// Commit epoch + caps + lease atomically with a re-check, so a concurrent
	// higher-epoch message can never be rolled back by this older one.
	ls.mu.Lock()
	if p.Epoch <= ls.epoch {
		ls.mu.Unlock()
		return
	}
	ls.epoch = p.Epoch
	ls.caps.Store(d.GetCaps())
	if p.LeaseExpiryUnixMs > 0 {
		ls.rearmLocked(p.LeaseExpiryUnixMs, func() { w.onLeaseExpired(id) })
	}
	ls.mu.Unlock()

	// Push the downgrade to every authoritative enforcement point:
	//  - the session-host read-only gate (holds for a detached PTY),
	//  - in-flight forwards whose target is no longer allowed, and
	//  - an open sftp channel that just lost write access.
	pc := d.GetCaps()
	w.setHostCaps(id, pc)
	w.tearForwards(id, pc.GetForwardTargets())
	if !pc.GetAllowSftpWrite() {
		w.tearWrites(id)
	}
	w.log.Info("session caps downgraded", "session", id, "epoch", p.Epoch)
}

// applyRevoke verifies a signed revoke before tearing the session down. The sig
// (trusted grant key) authenticates it; for a session live in THIS worker the
// epoch must strictly increase (anti-replay) and the client-key binding must
// match. A revoke for a session NOT live here (an owed teardown for a detached
// PTY, possibly from a prior worker) is honored on a valid signature alone —
// killHostSession by id is idempotent and the NodeControl stream is controller-only.
func (w *Worker) applyRevoke(rev *genezav1.SessionRevoke) {
	var p types.RevokePayload
	if err := w.verifyEnforcement(rev.GetSig(), &p); err != nil {
		w.log.Warn("drop unverifiable session revoke", "session", rev.GetSessionId(), "err", err)
		return
	}
	id := rev.GetSessionId()
	if p.SessionID != id {
		return
	}
	w.liveMu.Lock()
	ls := w.live[id]
	w.liveMu.Unlock()
	if ls != nil {
		if !bytes.Equal(p.ClientNoisePub, ls.clientNoisePub) {
			w.log.Warn("drop session revoke: client key mismatch", "session", id)
			return
		}
		ls.mu.Lock()
		stale := p.Epoch <= ls.epoch
		ls.mu.Unlock()
		if stale {
			w.log.Warn("drop replayed session revoke", "session", id, "epoch", p.Epoch)
			return
		}
	}
	w.revokeLive(id, p.Reason)
}

// trackSplice / untrackSplice register an open forward splice so tearForwards can
// reach it; both are no-ops if the session is gone.
func (w *Worker) trackSplice(id string, ts *trackedSplice) {
	w.liveMu.Lock()
	ls := w.live[id]
	w.liveMu.Unlock()
	if ls == nil {
		return
	}
	ls.fwdMu.Lock()
	if ls.fwds == nil {
		ls.fwds = map[*trackedSplice]struct{}{}
	}
	ls.fwds[ts] = struct{}{}
	ls.fwdMu.Unlock()
}

func (w *Worker) untrackSplice(id string, ts *trackedSplice) {
	w.liveMu.Lock()
	ls := w.live[id]
	w.liveMu.Unlock()
	if ls == nil {
		return
	}
	ls.fwdMu.Lock()
	delete(ls.fwds, ts)
	ls.fwdMu.Unlock()
}

// tearForwards actively closes every open splice whose target is no longer in the
// allowed set (a revoke_forward downgrade), so in-flight traffic stops at once
// rather than only the next channel-open being denied.
func (w *Worker) tearForwards(id string, allowed []string) {
	w.liveMu.Lock()
	ls := w.live[id]
	w.liveMu.Unlock()
	if ls == nil {
		return
	}
	ls.fwdMu.Lock()
	for ts := range ls.fwds {
		if !targetAllowed(allowed, ts.destAddr, ts.destPort) {
			ts.cancel()
		}
	}
	ls.fwdMu.Unlock()
}

// setSftpCancel / clearSftpCancel register the open sftp channel's cancel so a
// mid-session write-downgrade can tear it; tearWrites fires it.
func (w *Worker) setSftpCancel(id string, cancel context.CancelFunc) {
	w.liveMu.Lock()
	ls := w.live[id]
	w.liveMu.Unlock()
	if ls == nil {
		return
	}
	ls.sftpMu.Lock()
	ls.sftpCancel = cancel
	ls.sftpMu.Unlock()
}

func (w *Worker) clearSftpCancel(id string) {
	w.liveMu.Lock()
	ls := w.live[id]
	w.liveMu.Unlock()
	if ls == nil {
		return
	}
	ls.sftpMu.Lock()
	ls.sftpCancel = nil
	ls.sftpMu.Unlock()
}

// tearWrites closes an open sftp channel when a downgrade revokes write access.
// pkg/sftp's NewServer has no per-op hook, so a write-capable session that is
// downgraded mid-flight is torn (the client reconnects read-only); a session that
// is already read-only at open is served with sftp.ReadOnly() (per-op denial).
func (w *Worker) tearWrites(id string) {
	w.liveMu.Lock()
	ls := w.live[id]
	w.liveMu.Unlock()
	if ls == nil {
		return
	}
	ls.sftpMu.Lock()
	if ls.sftpCancel != nil {
		ls.sftpCancel()
	}
	ls.sftpMu.Unlock()
}

// capsAllowForward reports whether the live caps permit a new forward to
// addr:port. A nil caps means no downgrade is in effect (the static grant
// governs); otherwise the target must match an entry in the allowed set.
func capsAllowForward(caps *genezav1.SessionCaps, addr string, port uint32) bool {
	if caps == nil {
		return true
	}
	return targetAllowed(caps.GetForwardTargets(), addr, port)
}

func targetAllowed(allowed []string, addr string, port uint32) bool {
	for _, t := range allowed {
		if ForwardTargetAllowed(t, addr, port) {
			return true
		}
	}
	return false
}

// sessionCaps returns the live caps for a session (nil if none / not live).
func (w *Worker) sessionCaps(id string) *genezav1.SessionCaps {
	w.liveMu.Lock()
	ls := w.live[id]
	w.liveMu.Unlock()
	if ls == nil {
		return nil
	}
	return ls.caps.Load()
}

// sessionAudit returns the path class + current epoch for a live session, for the
// first-class SessionEvent audit fields; zero values if not live in this worker.
func (w *Worker) sessionAudit(id string) (string, int64) {
	w.liveMu.Lock()
	ls := w.live[id]
	w.liveMu.Unlock()
	if ls == nil {
		return "", 0
	}
	ls.mu.Lock()
	epoch := ls.epoch
	ls.mu.Unlock()
	return ls.pathClass, epoch
}

// capsFromProto mirrors a proto SessionCaps into the pb-free types.CapsPayload
// the downgrade verifier consumes.
func capsFromProto(c *genezav1.SessionCaps) *types.CapsPayload {
	if c == nil {
		return nil
	}
	return &types.CapsPayload{
		Allow:            c.GetAllow(),
		AllowPTY:         c.GetAllowPty(),
		AllowInput:       c.GetAllowInput(),
		ForwardTargets:   c.GetForwardTargets(),
		AllowSFTPWrite:   c.GetAllowSftpWrite(),
		AllowNewChannels: c.GetAllowNewChannels(),
	}
}
