package relay

import (
	"context"
	"crypto/ed25519"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"log/slog"
	"math/rand"
	"net"
	"os"
	"strconv"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/keepalive"

	"geneza.io/internal/defaults"
	genezav1 "geneza.io/internal/pb/geneza/v1"
	"geneza.io/internal/types"
	"geneza.io/internal/version"
)

// drainReregister is how often a DRAINING relay re-registers so its falling
// active_count keeps reaching the controller (the heartbeat rides only a fresh
// registration). Healthy relays hold one long-lived watch and never use this.
const drainReregister = 2 * time.Second

// RunRegistrar registers this relay's presence with a controller and watches the
// signed cluster config until ctx is cancelled. It dials the configured seed
// controller, learns the live controller set from the streamed config, and FAILS OVER to
// another controller when its current one dies — so a relay survives a controller outage
// and a controller-node failure, not just the single seed staying up. It authenticates
// with the relay's own mTLS cert (only the dialed address varies, so every controller
// is independently verified). A relay with no registrar_addr (the single-node
// default, where the controller synthesizes the map from its own config) never registers.
func RunRegistrar(ctx context.Context, cfg Config, log *slog.Logger, r *Relay) {
	if cfg.RegistrarAddr == "" {
		return
	}
	tlsCfg, certPub, err := registrarTLS(cfg)
	if err != nil {
		log.Error("relay registrar: tls setup", "err", err)
		return
	}
	port := relayDataPort(cfg)
	hb := &genezav1.RelayHeartbeat{
		RegionId:     cfg.Region,
		RelayId:      cfg.RelayID,
		Addrs:        []string{relayDataEndpoint(cfg)},
		StunPort:     int32(port),
		TurnPort:     int32(port),
		RelayCertPub: certPub,
		Healthy:      true,
		ControlMux:   cfg.ControlMux,
		// Always advertise the TCP rendezvous endpoint (independent of the control-mux
		// capability): the controller's fleet-aware TCP floor dials it, and a control mux
		// uses it only when ControlMux is also set.
		ControlAddr: relayControlEndpoint(cfg),
		Version:     version.Version,
	}
	if r != nil && r.funnel != nil {
		hb.SealPub = r.funnel.sealPub() // the controller seals this relay's funnel certs to it
		if cfg.FunnelListen != "" {
			hb.FunnelIp = cfg.PublicIP // the public IP funnel hostnames resolve to
		}
	}
	// When this relay serves control muxes, verify every signed map it watches and
	// publish the controller-id -> NodeControl-address table the mux routes against. The
	// resolver persists across reconnects so its pinned trust set and version floor
	// survive a controller failover.
	var resolver controllerControlResolver
	onConfig := func(watch *genezav1.RelayWatch) {
		// Funnel certs ride this relay's own watch stream, sealed to its key. Applied
		// declaratively (full set each push), independent of the control-mux role.
		if r != nil && r.funnel != nil {
			r.funnel.apply(watch.GetFunnelCerts())
		}
		if !cfg.ControlMux || r == nil {
			return
		}
		if table, ok := resolver.resolve(watch.GetClusterConfig(), watch.GetTrustAnchors(), watch.GetRoutineMap()); ok {
			r.setControllerNodeControl(table)
		}
	}
	creds := credentials.NewTLS(tlsCfg)
	// Keepalive PINGs so a black-holed controller (node death, no RST) tears this stream
	// and triggers failover instead of blocking Recv forever. Time >= the server's
	// MinTime (10s) so the controller never GOAWAYs us for pinging too fast.
	kp := grpc.WithKeepaliveParams(keepalive.ClientParameters{
		Time:                15 * time.Second,
		Timeout:             20 * time.Second,
		PermitWithoutStream: true,
	})

	// drainCh fires once the relay enters draining; the registrar then advertises
	// healthy=false. It is also passed into each watch so a mid-stream drain breaks
	// the current stream and re-registers unhealthy at once (no wait for a heartbeat).
	var drainCh <-chan struct{}
	if r != nil {
		drainCh = r.DrainSignal()
	}
	const backoffHi = 10 * time.Second
	var discovered []string // controller control-addresses learned from the signed config
	idx, backoff := 0, time.Second
	for {
		if ctx.Err() != nil {
			return
		}
		// The healthy bit is re-evaluated every (re)registration, so once the relay
		// drains, every subsequent heartbeat carries healthy=false. The active count
		// rides each registration too so the controller/rollout can watch a draining relay
		// clear to 0 (the drained gate).
		hb.Healthy = r == nil || !r.Draining()
		if r != nil {
			hb.ActiveCount = int32(r.Active())
		}
		cands := relayCandidates(cfg.RegistrarAddr, discovered)
		addr := cands[idx%len(cands)]
		idx++
		// While draining, bound each watch's lifetime so the relay re-registers on a
		// short cadence and the controller sees active_count fall toward 0 — the heartbeat
		// is only sent at registration, so a long-lived draining watch would freeze the
		// count. The first drain transition still breaks the watch via drainCh at once.
		watchCh, maxLife := drainCh, time.Duration(0)
		if r != nil && r.Draining() {
			watchCh, maxLife = nil, drainReregister // already draining: drainCh stays closed, so cap by time
		}
		lived, learned := relayWatchOnce(ctx, addr, hb, creds, kp, log, onConfig, watchCh, maxLife)
		if len(learned) > 0 {
			discovered = learned
		}
		if ctx.Err() != nil {
			return
		}
		if lived > backoffHi {
			backoff = time.Second // a long-lived stream means the controller was healthy
		}
		// A draining relay re-registers promptly (fixed short gap) so its falling active
		// count flows; a healthy relay uses full-jittered backoff so a fleet does not all
		// reconnect onto one survivor at once.
		wait := time.Duration(rand.Int63n(int64(backoff) + 1))
		if r != nil && r.Draining() {
			wait = drainReregister
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(wait):
		}
		if backoff < backoffHi {
			if backoff *= 2; backoff > backoffHi {
				backoff = backoffHi
			}
		}
	}
}

// relayWatchOnce dials one controller, registers, and streams the signed config until
// the stream ends. It returns how long the stream lived (to reset backoff after a
// healthy run) and the controller control-addresses discovered from the last config.
func relayWatchOnce(ctx context.Context, addr string, hb *genezav1.RelayHeartbeat,
	creds credentials.TransportCredentials, kp grpc.DialOption, log *slog.Logger, onConfig func(*genezav1.RelayWatch), drainCh <-chan struct{}, maxLife time.Duration) (time.Duration, []string) {
	start := time.Now()
	// A drain that fires mid-stream cancels this watch so the outer loop re-registers
	// with healthy=false at once (the heartbeat is sent only at registration). maxLife,
	// when set (a relay already draining), caps the watch so the relay re-registers on a
	// short cadence and its falling active_count keeps reaching the controller.
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	if drainCh != nil {
		go func() {
			select {
			case <-ctx.Done():
			case <-drainCh:
				cancel()
			}
		}()
	}
	if maxLife > 0 {
		timer := time.AfterFunc(maxLife, cancel)
		defer timer.Stop()
	}
	conn, err := grpc.NewClient(addr, grpc.WithTransportCredentials(creds), kp)
	if err != nil {
		log.Warn("relay registrar: dial", "addr", addr, "err", err)
		return time.Since(start), nil
	}
	defer conn.Close()
	stream, err := genezav1.NewRelayRegistryClient(conn).RegisterAndWatch(ctx, hb)
	if err != nil {
		log.Warn("relay registrar: register", "addr", addr, "err", err)
		return time.Since(start), nil
	}
	var discovered []string
	for {
		watch, err := stream.Recv()
		if err != nil {
			if ctx.Err() == nil {
				log.Warn("relay registrar: watch ended", "addr", addr, "err", err)
			}
			return time.Since(start), discovered
		}
		// Failover addresses come from the legacy config when present (split mode always
		// sends it alongside) and otherwise from the routine map — unverified either way,
		// since every dial is independently mTLS-verified, so a forged address only fails
		// to connect.
		if d := relayDiscoverControllers(watch.GetClusterConfig()); len(d) > 0 {
			discovered = d
		} else if d := relayDiscoverControllersFromMap(watch.GetRoutineMap()); len(d) > 0 {
			discovered = d
		}
		if onConfig != nil {
			onConfig(watch)
		}
	}
}

// controllerControlResolver verifies a signed cluster config against a pinned trust
// set (TOFU from the first signed config, mirroring how the agent pins its config
// trust) and extracts the controller-id -> NodeControl dial-address table a control
// mux routes against. Verification is REQUIRED here, unlike relayDiscoverControllers
// (whose addresses are only ever dialed back with the relay's OWN mTLS, so a forged
// address merely fails to connect): the control mux dials these addresses on behalf
// of an UNTRUSTED agent routing label, so an unsigned or untrusted map must never
// populate the table.
type controllerControlResolver struct {
	trust map[string]ed25519.PublicKey // legacy: pinned on the first verified config
	have  int64                        // legacy: highest config version seen (rollback floor)
	// Split-mode pinned state: the offline/threshold TrustKeys + Threshold (TOFU-pinned
	// from the first anchor), and the per-document rollback floors. pinnedTrust is nil
	// until the relay first sees a split pair; once pinned the relay verifies the split
	// pair and never regresses to the legacy config (that would be a downgrade off the
	// anchored trust set).
	pinnedTrust     map[string]ed25519.PublicKey
	pinnedThreshold int
	haveAnchor      int64
	haveMap         int64
}

// resolve verifies the controller control table from a config delivery. When the watch
// carries the split pair AND the relay has pinned (or will TOFU-pin) the anchors, it
// runs the two-step VerifyFleetState against the HELD pinned set and reads the table
// from the verified routine map. Otherwise it falls back to the legacy single-envelope
// verify, exactly as before — unless the relay has already pinned split trust, in which
// case it refuses the legacy fallback. Verification is REQUIRED here (unlike the
// failover-address discovery), since the control mux dials these addresses on behalf of
// an UNTRUSTED agent routing label.
func (g *controllerControlResolver) resolve(legacy, anchorRaw, mapRaw []byte) (map[string][]string, bool) {
	if len(anchorRaw) > 0 && len(mapRaw) > 0 {
		return g.resolveSplit(anchorRaw, mapRaw)
	}
	if g.pinnedTrust != nil {
		return nil, false // a pinned relay must not regress to the legacy config
	}
	return g.resolveLegacy(legacy)
}

func (g *controllerControlResolver) resolveLegacy(signed []byte) (map[string][]string, bool) {
	if len(signed) == 0 {
		return nil, false
	}
	env, err := types.DecodeSigned(signed)
	if err != nil {
		return nil, false
	}
	trust := g.trust
	if trust == nil {
		// First config: pin the trust set from its own keys, anchored by the mTLS-
		// authenticated registrar channel it arrived on — exactly the agent's model.
		var unverified types.ClusterConfig
		if json.Unmarshal(env.Payload, &unverified) != nil {
			return nil, false
		}
		t, terr := unverified.TrustedConfigKeys()
		if terr != nil {
			return nil, false
		}
		trust = t
	}
	cc, err := types.VerifyClusterConfig(trust, env, g.have)
	if err != nil {
		return nil, false
	}
	g.trust = trust
	g.have = cc.ConfigVersion
	return controllerTable(cc.ControllerEndpoints), true
}

func (g *controllerControlResolver) resolveSplit(anchorRaw, mapRaw []byte) (map[string][]string, bool) {
	anchorEnv, err := types.DecodeMultiSigned(anchorRaw)
	if err != nil {
		return nil, false
	}
	mapEnv, err := types.DecodeSigned(mapRaw)
	if err != nil {
		return nil, false
	}
	pinned, threshold := g.pinnedTrust, g.pinnedThreshold
	if pinned == nil {
		// TOFU first-pin from this anchor over the mTLS registrar channel — the relay's
		// counterpart of the agent's first-anchor pin.
		var a types.TrustAnchors
		if json.Unmarshal(anchorEnv.Payload, &a) != nil {
			return nil, false
		}
		p, terr := a.PinnedTrustKeys()
		if terr != nil {
			return nil, false
		}
		pinned, threshold = p, a.Threshold
	}
	fs, err := types.VerifyFleetState(pinned, threshold, g.haveAnchor, g.haveMap, anchorEnv, mapEnv, time.Now())
	if err != nil {
		return nil, false
	}
	g.pinnedTrust = pinned
	g.pinnedThreshold = threshold
	g.haveAnchor = fs.Anchors.AnchorVersion
	g.haveMap = fs.Map.ConfigVersion
	return controllerTable(fs.Map.ControllerEndpoints), true
}

// controllerTable projects the verified controller discovery set onto the id -> dial-address
// table a control mux routes against.
func controllerTable(gws []types.ControllerEndpoint) map[string][]string {
	table := make(map[string][]string, len(gws))
	for _, gw := range gws {
		if gw.ControllerID != "" && len(gw.Addrs) > 0 {
			table[gw.ControllerID] = append([]string(nil), gw.Addrs...)
		}
	}
	return table
}

// relayDiscoverControllersFromMap reads the failover dial addresses from a (signed but
// here unverified) routine map — the split-mode counterpart of relayDiscoverControllers,
// used only when no legacy config rides alongside. As with the legacy path the result
// only chooses a dial address; every dial is independently mTLS-verified.
func relayDiscoverControllersFromMap(mapRaw []byte) []string {
	if len(mapRaw) == 0 {
		return nil
	}
	env, err := types.DecodeSigned(mapRaw)
	if err != nil {
		return nil
	}
	var rm types.RoutineMap
	if json.Unmarshal(env.Payload, &rm) != nil {
		return nil
	}
	return types.FailoverAddrs(rm.ControllerEndpoints, true)
}

// relayDiscoverControllers reads the controller registrar addresses out of a signed
// cluster config WITHOUT verifying the signature: the relay only uses these to
// choose a dial address, and every dial is independently mTLS-verified, so a forged
// endpoint merely fails to connect. The addresses are controller-interleaved + IP-first
// (see types.FailoverAddrs) so a hung controller costs one failover step, and it prefers
// a controller's control-plane addresses, falling back to its gRPC addresses when the
// registrar shares the gRPC listener.
func relayDiscoverControllers(signed []byte) []string {
	if len(signed) == 0 {
		return nil
	}
	env, err := types.DecodeSigned(signed)
	if err != nil {
		return nil
	}
	var cc types.ClusterConfig
	if err := json.Unmarshal(env.Payload, &cc); err != nil {
		return nil
	}
	return types.FailoverAddrs(cc.ControllerEndpoints, true)
}

// relayCandidates returns the dial set: the operator seed first (always retained so
// a fully-stale discovered set can still recover) followed by the deduped discovered
// controllers. The discovered order is already controller-interleaved (so failover reaches
// a different controller each step); the full-jitter reconnect backoff de-correlates a
// fleet so relays do not all reconnect to one survivor at once.
func relayCandidates(seed string, discovered []string) []string {
	out := []string{seed}
	seen := map[string]bool{seed: true}
	for _, a := range discovered {
		if a != "" && !seen[a] {
			seen[a] = true
			out = append(out, a)
		}
	}
	return out
}

// registrarTLS builds the mTLS config the relay uses to reach the controller
// (its own cert for client auth, the controller CA to verify the server) and
// returns the SPKI of the relay's own leaf for the signed-map pin.
func registrarTLS(cfg Config) (*tls.Config, []byte, error) {
	cert, err := tls.LoadX509KeyPair(cfg.CertFile, cfg.KeyFile)
	if err != nil {
		return nil, nil, fmt.Errorf("relay cert: %w", err)
	}
	pool := x509.NewCertPool()
	if cfg.ControllerCAFile != "" {
		pem, err := os.ReadFile(cfg.ControllerCAFile)
		if err != nil {
			return nil, nil, fmt.Errorf("controller ca: %w", err)
		}
		pool.AppendCertsFromPEM(pem)
	}
	leaf, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		return nil, nil, err
	}
	spki, err := x509.MarshalPKIXPublicKey(leaf.PublicKey)
	if err != nil {
		return nil, nil, err
	}
	return &tls.Config{
		Certificates: []tls.Certificate{cert},
		RootCAs:      pool,
		ServerName:   cfg.ControllerServerName,
		MinVersion:   tls.VersionTLS12,
	}, spki, nil
}

func relayDataPort(cfg Config) int {
	if _, p, err := net.SplitHostPort(cfg.DataListen); err == nil {
		if n, e := strconv.Atoi(p); e == nil {
			return n
		}
	}
	return defaults.RelayDataPort
}

func relayDataEndpoint(cfg Config) string {
	host := cfg.PublicIP
	if host == "" {
		host = "127.0.0.1"
	}
	return net.JoinHostPort(host, strconv.Itoa(relayDataPort(cfg)))
}

// relayControlEndpoint is the relay's advertised TCP rendezvous host:port for
// control muxes — its public IP paired with the TCP listen port (where an agent
// dials a control hello), distinct from the UDP data endpoint.
func relayControlEndpoint(cfg Config) string {
	host := cfg.PublicIP
	if host == "" {
		host = "127.0.0.1"
	}
	port := defaults.RelayPort
	if _, p, err := net.SplitHostPort(cfg.Listen); err == nil && p != "" {
		if n, e := strconv.Atoi(p); e == nil {
			port = n
		}
	}
	return net.JoinHostPort(host, strconv.Itoa(port))
}
