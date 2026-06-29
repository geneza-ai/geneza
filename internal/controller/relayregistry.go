package controller

import (
	"context"
	"crypto/x509"
	"log/slog"
	"net"
	"strconv"
	"strings"
	"time"

	"github.com/pion/stun/v3"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"geneza.io/internal/ca"
	genezav1 "geneza.io/internal/pb/geneza/v1"
	"geneza.io/internal/types"
)

// relayHeartbeatInterval is how often a relay re-registers; the registrar tells
// the relay this in the ack and expires a relay that misses several beats.
const relayHeartbeatInterval = 15 * time.Second

// relayStaleTTL drops a relay from the fleet after it misses this much
// heartbeating (a few intervals of slack).
const relayStaleTTL = 60 * time.Second

type relayRegistryService struct {
	genezav1.UnimplementedRelayRegistryServer
	s *Server
}

// validateAndUpsertRelay verifies a relay heartbeat (it presents a relay cert,
// names its own cert identity, and its advertised data endpoint actually answers
// STUN, so a relay cannot register an address it does not serve) and records the
// presence row that feeds the signed-map rebuild. A rejection is a gRPC status, so
// the relay fails over to another controller rather than parsing an ack.
func (r *relayRegistryService) validateAndUpsertRelay(ctx context.Context, hb *genezav1.RelayHeartbeat) (*RelayRecord, error) {
	ident, leaf, ok := identityFrom(ctx)
	if !ok || ident.Kind != ca.KindRelay || leaf == nil {
		return nil, status.Error(codes.PermissionDenied, "relay certificate required")
	}
	region := canonicalRegion(hb.GetRegionId())
	if hb.GetRelayId() == "" || len(hb.GetAddrs()) == 0 {
		return nil, status.Error(codes.InvalidArgument, "region_id, relay_id and addrs are required")
	}
	if strings.ContainsRune(region, ':') {
		return nil, status.Error(codes.InvalidArgument, "region_id must not contain ':'")
	}
	// Bind the registered relay_id to the caller's certificate identity, so a relay
	// can only write its OWN fleet-map row and cannot displace or impersonate
	// another relay's entry.
	if hb.GetRelayId() != ident.Name {
		return nil, status.Error(codes.PermissionDenied, "relay_id must match the relay's certificate name")
	}
	// The map's cert key is derived from the relay's OWN authenticated mTLS leaf,
	// never the self-reported field — otherwise a compromised relay could vouch for
	// an arbitrary cert key and the agent-side pin would then trust a rogue relay.
	certPub, err := x509.MarshalPKIXPublicKey(leaf.PublicKey)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "relay cert key: %v", err)
	}
	if !relayDataReachable(ctx, hb.GetAddrs()[0], relayHeartbeatPort(hb)) {
		return nil, status.Error(codes.FailedPrecondition, "advertised data endpoint did not answer STUN")
	}
	rec := &RelayRecord{
		RelayNode: types.RelayNode{
			RegionID: region, RelayID: hb.GetRelayId(), Addrs: hb.GetAddrs(),
			STUNPort: int(hb.GetStunPort()), TURNPort: int(hb.GetTurnPort()), RelayCertPub: certPub,
			// The capability is self-reported but harmless to over-trust: it only tells
			// agents this relay will ACCEPT a control mux. The relay still SSRF-validates
			// every forward against its own signed controller set, and the agent's stream is
			// end-to-end mTLS to the controller, so a relay claiming the capability it cannot
			// honor merely gets control hellos it then rejects.
			ControlMux:  hb.GetControlMux(),
			ControlAddr: hb.GetControlAddr(),
			// A relay heartbeating healthy=false is draining for a swap: record it so the
			// signed map keeps it VISIBLE (in-flight sessions still pin its cert) while
			// new-session selection excludes it.
			Draining: !hb.GetHealthy(),
		},
		LastSeenUnix: time.Now().Unix(),
		Version:      hb.GetVersion(),
		ActiveCount:  hb.GetActiveCount(),
		SealPub:      hb.GetSealPub(),
		FunnelIP:     hb.GetFunnelIp(),
	}
	if err := r.s.store.UpsertRelay(rec); err != nil {
		return nil, status.Errorf(codes.Internal, "record relay: %v", err)
	}
	// A draining relay (healthy=false): proactively tell every live session on it to
	// re-home NOW, so sessions migrate the instant the relay is marked draining rather
	// than waiting for it to force-close at the drain deadline. Idempotent — a session
	// already off this relay self-filters the notice (it knows its own relay).
	if rec.Draining {
		r.s.notifyRelayDraining(rec.RelayID, rec.ControlAddr)
	}
	return rec, nil
}

// maybeRenewRelayCert signs a relay's renewal CSR (nil cert when there's no CSR or
// signing fails — non-fatal, the relay keeps its still-valid cert and retries). The
// identity and SANs come from the relay's authenticated mTLS leaf, NOT the CSR, so a
// relay can only renew its own cert — the CSR contributes only its (unchanged) key.
func (r *relayRegistryService) maybeRenewRelayCert(ctx context.Context, rec *RelayRecord, csrPEM []byte) (cert, caRoots []byte) {
	if len(csrPEM) == 0 {
		return nil, nil
	}
	ident, leaf, ok := identityFrom(ctx)
	if !ok || leaf == nil || ident.Kind != ca.KindRelay {
		return nil, nil
	}
	// Only sign a genuine near-expiry renewal — the relay gates this too, so a relay
	// that asks early (or a buggy/hostile cert holder spamming reconnects) doesn't
	// churn the serial on every connect.
	if !ca.NeedsRenewal(leaf.NotBefore, leaf.NotAfter, time.Now()) {
		return nil, nil
	}
	certPEM, err := r.s.ca.IssueFromCSR(csrPEM, ca.Profile{
		Kind: ca.KindRelay, Name: ident.Name, TTL: serverCertTTL,
		DNSNames: leaf.DNSNames, IPs: leaf.IPAddresses,
	})
	if err != nil {
		slog.Warn("relay cert renewal failed", "relay", rec.RelayID, "err", err)
		return nil, nil
	}
	if err := r.s.audit.Append("relay_cert_renew", "system", rec.RelayID, "", nil); err != nil {
		slog.Error("audit append failed", "type", "relay_cert_renew", "err", err)
	}
	slog.Info("relay cert renewed", "relay", rec.RelayID)
	return certPEM, r.s.ca.RootsPEM
}

func relayHeartbeatPort(hb *genezav1.RelayHeartbeat) int {
	if p := int(hb.GetTurnPort()); p != 0 {
		return p
	}
	return int(hb.GetStunPort())
}

// RegisterAndWatch records the relay's presence and then streams the signed cluster
// config down — the first time on connect and again whenever its version advances —
// so the relay learns the live controller set (ControllerEndpoints) and can fail over to
// another controller when this one dies. The open stream IS the relay's liveness: a
// ticker re-verifies the data port and refreshes the presence row while the stream
// lives, and gRPC keepalive (configured on both ends) tears a black-holed stream so
// a dead relay's row stops advancing and ages out of the fleet. Presence is never
// deleted on disconnect; the stale-TTL sweep reaps it, so a relay re-homed onto
// another controller is never double-counted (the row is keyed by region+relay id).
func (r *relayRegistryService) RegisterAndWatch(hb *genezav1.RelayHeartbeat, stream genezav1.RelayRegistry_RegisterAndWatchServer) error {
	ctx := stream.Context()
	rec, err := r.validateAndUpsertRelay(ctx, hb)
	if err != nil {
		return err
	}
	slog.Debug("relay registered", "region", rec.RegionID, "relay", rec.RelayID, "addr", rec.Addrs[0])

	// A renewal CSR rides the fresh cert + CA roots back on this first watch message.
	renewedCert, caRoots := r.maybeRenewRelayCert(ctx, rec, hb.GetRenewCsr())

	ver, legacy, anchors, routineMap := r.s.fleetWire()
	funnel, funnelDig := r.s.buildRelayFunnelCerts(rec)
	if err := stream.Send(&genezav1.RelayWatch{
		ClusterConfig: legacy, TrustAnchors: anchors, RoutineMap: routineMap,
		HeartbeatIntervalSecs: int32(relayHeartbeatInterval.Seconds()),
		FunnelCerts:           funnel,
		RenewedRelayCert:      renewedCert,
		CaRoots:               caRoots,
	}); err != nil {
		return err
	}
	lastVer := ver
	lastFunnelDig := funnelDig

	ticker := time.NewTicker(relayHeartbeatInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
			// Refresh presence only while the data port still answers, restoring the
			// per-interval health re-check the old unary heartbeat gave; a relay whose
			// data port died stops being refreshed and ages out.
			if relayDataReachable(ctx, rec.Addrs[0], relayHeartbeatPort(hb)) {
				rec.LastSeenUnix = time.Now().Unix()
				_ = r.s.store.UpsertRelay(rec)
			}
			// Re-push when the signed map advances OR the relay's funnel cert set
			// changes (issue/renew/release). When only the funnel set changed we still
			// send the CURRENT config — the relay re-verifies it idempotently.
			v, lg, an, rm := r.s.fleetWire()
			fc, dig := r.s.buildRelayFunnelCerts(rec)
			if v > lastVer || dig != lastFunnelDig {
				if err := stream.Send(&genezav1.RelayWatch{ClusterConfig: lg, TrustAnchors: an, RoutineMap: rm, FunnelCerts: fc}); err != nil {
					return err
				}
				lastVer = v
				lastFunnelDig = dig
			}
		}
	}
}

// relayDataReachable sends a STUN Binding request to the relay's data endpoint
// (the pion TURN server also answers STUN) and reports whether it replied. It
// retransmits a few times to ride out a lost UDP datagram (so a single drop does
// not skip a presence refresh and age out a live relay) and honours ctx so a
// handler draining mid-probe is not parked. The relay is blind to payload, so this
// only proves reachability, not trust.
func relayDataReachable(ctx context.Context, addr string, port int) bool {
	host, _, err := net.SplitHostPort(addr)
	if err != nil || host == "" {
		host = addr
	}
	target := net.JoinHostPort(host, strconv.Itoa(port))
	dctx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	var d net.Dialer
	conn, err := d.DialContext(dctx, "udp", target)
	if err != nil {
		return false
	}
	defer conn.Close()
	// Force an in-flight Read to return promptly if the caller's ctx is cancelled
	// (a relay disconnect or a controller drain), instead of waiting out the deadline.
	stop := context.AfterFunc(ctx, func() { _ = conn.SetDeadline(time.Now()) })
	defer stop()
	req := stun.MustBuild(stun.TransactionID, stun.BindingRequest)
	buf := make([]byte, 1500)
	for attempt := 0; attempt < 3; attempt++ {
		if ctx.Err() != nil {
			return false
		}
		_ = conn.SetDeadline(time.Now().Add(700 * time.Millisecond))
		if _, err := conn.Write(req.Raw); err != nil {
			return false
		}
		n, err := conn.Read(buf)
		if err != nil {
			continue // lost request or response, or per-attempt timeout: retransmit
		}
		resp := &stun.Message{Raw: append([]byte(nil), buf[:n]...)}
		if resp.Decode() == nil && resp.Type == stun.BindingSuccess {
			return true
		}
	}
	return false
}
