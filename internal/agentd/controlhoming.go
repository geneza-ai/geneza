package agentd

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net"
	"sync/atomic"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/keepalive"

	"geneza.io/internal/types"
	"geneza.io/internal/wire"
)

// relayHomeCooldown keeps the agent on a direct controller dial for a while after a
// relay-homed control stream fails fast. It is longer than the relay's registrar
// heartbeat so a transiently-bad relay ages out of the signed map before the agent
// reconsiders homing through it.
const relayHomeCooldown = 90 * time.Second

// controlPlan is how streamOnce should reach the controller for this connection:
// directly (the default and single-node path) or homed through a relay.
type controlPlan struct {
	viaRelay         bool
	relayControlAddr string   // the relay's TCP rendezvous address to dial
	relayCertPins    [][]byte // pin the relay leaf to the signed fleet
	controllerID        string   // routing label the relay validates + forwards to
	controllerName      string   // inner-TLS ServerName: the owning controller's cert SAN
}

// controlHomePlan decides whether to home this control connection through a relay.
// It returns the direct plan unless relay homing is enabled, the signed map
// advertises a reachable control-mux relay, the agent knows an owning controller, and
// it is not in a post-failure direct cooldown. On single-node ControllerEndpoints is
// empty, so it always returns direct — byte for byte the current path.
func (w *Worker) controlHomePlan(region string) controlPlan {
	if !w.cfg.RelayHoming() || w.inDirectCooldown() {
		return controlPlan{}
	}
	w.mu.RLock()
	cluster := w.cluster
	w.mu.RUnlock()
	if cluster == nil || len(cluster.ControllerEndpoints) == 0 {
		return controlPlan{}
	}
	// Home through the relay to the SAME controller the direct path would dial right
	// now, so a relay-homed stream and its direct fallback target one controller and
	// advanceController re-targets both together. The bootstrap seed address is not in
	// the signed set, so dialing it falls through to direct — correct, since the
	// relay can only forward to a controller named in its signed map.
	addr := w.controllerAddr()
	gw, ok := matchControllerEndpoint(cluster.ControllerEndpoints, addr)
	if !ok || gw.ControllerID == "" {
		return controlPlan{}
	}
	name, _, err := net.SplitHostPort(addr)
	if err != nil || name == "" {
		return controlPlan{}
	}
	relay, ok := controlMuxRelay(cluster.Relays, region)
	if !ok {
		return controlPlan{}
	}
	return controlPlan{
		viaRelay:         true,
		relayControlAddr: relay.ControlAddr,
		relayCertPins:    w.relayCertPubs(),
		controllerID:        gw.ControllerID,
		controllerName:      name,
	}
}

// matchControllerEndpoint finds the signed controller whose dial set contains addr — the
// controller the agent is currently dialing — so relay homing forwards to that exact
// controller and the inner-TLS ServerName (host(addr)) is one of its cert SANs.
func matchControllerEndpoint(gws []types.ControllerEndpoint, addr string) (types.ControllerEndpoint, bool) {
	for _, gw := range gws {
		for _, a := range gw.Addrs {
			if a == addr {
				return gw, true
			}
		}
	}
	return types.ControllerEndpoint{}, false
}

// controlMuxRelay picks a control-mux relay to home through: one in the agent's
// home region if available, else any advertised control-mux relay (still better
// than no relay). A candidate must carry a TCP control address to dial.
func controlMuxRelay(relays []types.RelayNode, region string) (types.RelayNode, bool) {
	var fallback types.RelayNode
	have := false
	for _, r := range relays {
		if !r.ControlMux || r.ControlAddr == "" {
			continue
		}
		if region != "" && r.RegionID == region {
			return r, true
		}
		if !have {
			fallback, have = r, true
		}
	}
	return fallback, have
}

func (w *Worker) inDirectCooldown() bool {
	w.cooldownMu.Lock()
	defer w.cooldownMu.Unlock()
	return time.Now().Before(w.directUntil)
}

func (w *Worker) startDirectCooldown() {
	w.cooldownMu.Lock()
	w.directUntil = time.Now().Add(relayHomeCooldown)
	w.cooldownMu.Unlock()
}

// controlConn returns the gRPC connection to run the control stream over and
// whether it is homed through a relay. A relay-homed dial that fails falls back to
// a direct controller dial for this attempt (and cools down), because the direct
// controller is always the floor — a total relay outage degrades to today's behavior,
// never to no control plane. cleanup closes a relay-homed conn; the shared direct
// conn (kept for the unary map refresh) is left alone. Cert renewal piggybacks on
// the stream's own transport, direct or relay-homed — harmless either way, since
// it is the agent's own end-to-end mTLS to the controller through the blind relay.
func (w *Worker) controlConn(ctx context.Context, plan controlPlan) (*grpc.ClientConn, func(), bool, error) {
	if plan.viaRelay {
		conn, cleanup, err := w.dialRelayHomed(ctx, plan)
		if err == nil {
			return conn, cleanup, true, nil
		}
		w.log.Warn("relay-homed control dial failed; falling back to direct", "relay", plan.relayControlAddr, "err", err)
		w.startDirectCooldown()
	}
	conn, err := w.grpcConn()
	return conn, func() {}, false, err
}

// dialRelayHomed establishes a control mux to the relay eagerly (so a relay
// failure surfaces here, not as an opaque gRPC error) and wraps it in a gRPC
// client that runs the agent's own end-to-end mTLS to the controller through the
// blind splice. The inner TLS pins the CONTROLLER (its CA + cert SAN) and negotiates
// TLS 1.3, so the relay sees only the SNI and ciphertext — never the agent cert or
// the control payload.
func (w *Worker) dialRelayHomed(ctx context.Context, plan controlPlan) (*grpc.ClientConn, func(), error) {
	dctx, cancel := context.WithTimeout(ctx, relayDialTimeout)
	defer cancel()
	raw, err := dialControlMux(dctx, plan.relayControlAddr, plan.controllerID, w.rootPool(), plan.relayCertPins)
	if err != nil {
		return nil, nil, err
	}

	w.mu.RLock()
	innerTLS := &tls.Config{
		Certificates: []tls.Certificate{w.tlsCert},
		RootCAs:      w.caPool,
		ServerName:   plan.controllerName,
		MinVersion:   tls.VersionTLS13,
	}
	w.mu.RUnlock()

	// The spliced conn is single-use: hand it to gRPC once. If gRPC tries to
	// reconnect the control transport, fail so streamLoop re-homes from scratch.
	var used atomic.Bool
	dialer := func(context.Context, string) (net.Conn, error) {
		if used.Swap(true) {
			return nil, fmt.Errorf("relay-homed control conn already consumed")
		}
		return raw, nil
	}
	conn, err := grpc.NewClient("passthrough:///"+plan.controllerID,
		grpc.WithContextDialer(dialer),
		grpc.WithTransportCredentials(credentials.NewTLS(innerTLS)),
		grpc.WithKeepaliveParams(keepalive.ClientParameters{
			Time:                15 * time.Second,
			Timeout:             20 * time.Second,
			PermitWithoutStream: true,
		}))
	if err != nil {
		_ = raw.Close()
		return nil, nil, err
	}
	// Closing the gRPC conn closes the spliced conn ONLY if gRPC dialed it; if the
	// stream errored before gRPC ever consumed it, close the raw conn ourselves so
	// it cannot leak. Close is idempotent, so the overlap is harmless.
	cleanup := func() {
		_ = conn.Close()
		if !used.Load() {
			_ = raw.Close()
		}
	}
	return conn, cleanup, nil
}

// dialControlMux opens a control mux to a relay: TLS to the relay (pinned to the
// signed fleet, mirroring dialRelay), a RelayHello naming the target controller, and
// the relay's accept. The returned conn carries the agent's end-to-end mTLS to the
// controller through the relay's blind splice.
func dialControlMux(ctx context.Context, relayAddr, controllerID string, rootPool *x509.CertPool, pins [][]byte) (net.Conn, error) {
	tlsCfg := &tls.Config{RootCAs: rootPool, MinVersion: tls.VersionTLS12}
	if len(pins) > 0 {
		tlsCfg.VerifyPeerCertificate = pinRelayCert(pins)
	}
	d := &tls.Dialer{Config: tlsCfg}
	raw, err := d.DialContext(ctx, "tcp", relayAddr)
	if err != nil {
		return nil, fmt.Errorf("relay dial %s: %w", relayAddr, err)
	}
	if err := wire.WriteJSON(raw, wire.RelayHello{V: 1, Kind: wire.RelayKindControl, ControllerID: controllerID}); err != nil {
		raw.Close()
		return nil, fmt.Errorf("control hello: %w", err)
	}
	_ = raw.SetDeadline(time.Now().Add(relayRespTimeout))
	var resp wire.RelayResp
	if err := wire.ReadJSON(raw, &resp); err != nil {
		raw.Close()
		return nil, fmt.Errorf("relay control rendezvous: %w", err)
	}
	if !resp.OK {
		raw.Close()
		return nil, fmt.Errorf("relay refused control mux: %s", resp.Error)
	}
	_ = raw.SetDeadline(time.Time{})
	return raw, nil
}
