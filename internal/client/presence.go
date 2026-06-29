package client

import (
	"context"
	"log/slog"
	"time"

	genezav1 "geneza.io/internal/pb/geneza/v1"
)

// startPresenceHeartbeat beats the continuous-presence factor for a presence-
// required session every heartbeat_interval. For the software stub the beat just
// echoes the rotating challenge with a monotonic counter — a real factor (YubiKey/
// WebAuthn) fills in a signature behind the same call. "Unplug" in the lab = this
// process is killed (or the goroutine stops), so the beats stop, the controller's
// last-presence freezes, and the continuous sweep drops the session. The goroutine
// dies with ctx (session end). A single lost beat is covered by the server's grace
// window; a server `ok:false` means presence/authz is being revoked, so we stop.
func startPresenceHeartbeat(ctx context.Context, api genezav1.WorkspaceAPIClient, resp *genezav1.CreateSessionResponse) {
	if !resp.GetPresentRequired() {
		return
	}
	interval := time.Duration(resp.GetHeartbeatIntervalMillis()) * time.Millisecond
	if interval <= 0 {
		interval = 10 * time.Second
	}
	sid := resp.GetSessionId()
	challenge := resp.GetPresenceChallenge()
	go func() {
		var counter uint32
		t := time.NewTicker(interval)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				counter++
				hr, err := api.Heartbeat(ctx, &genezav1.HeartbeatRequest{
					SessionId: sid,
					Attestation: &genezav1.PresenceAttestation{
						Kind: "software", SessionId: sid, Counter: counter, ClientData: challenge,
					},
				})
				if err != nil {
					slog.Debug("presence heartbeat error (will retry)", "session", sid, "err", err)
					continue
				}
				if !hr.GetOk() {
					slog.Info("presence denied; stopping heartbeat", "session", sid, "reason", hr.GetReason())
					return
				}
				if nc := hr.GetNextChallenge(); len(nc) > 0 {
					challenge = nc
				}
			}
		}
	}()
}
