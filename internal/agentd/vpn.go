package agentd

import (
	"context"
	"log/slog"
	"net"
	"strings"

	genezav1 "geneza.io/internal/pb/geneza/v1"
	"geneza.io/internal/types"
	"geneza.io/internal/vpn"
)

// serveVPN is the node ("subnet router" / "exit node") side of an L3 overlay
// session. It opens a TUN, wires kernel forwarding + masquerade so the client's
// overlay packets reach the advertised routes (and replies return), then pumps
// raw IP packets between the TUN and the Noise tunnel until either side closes.
//
// Requires CAP_NET_ADMIN — the agent runs as root in the lab. On any setup
// error the session ends cleanly rather than leaving half-built routes.
func (w *Worker) serveVPN(ctx context.Context, tconn net.Conn, grant *types.SessionGrant, log *slog.Logger, end *terminalEvent) {
	// The pump ending is a transport loss (the Noise conn closed): emit "tunnel
	// closed" so the re-home loop can migrate the VPN onto a surviving relay; the
	// local TUN + routes rebuild on the next generation. A clean ctx cancel (worker
	// shutdown / revoke) reaches here too, but the lease arbiter gates re-home.
	defer end.emit("ended", "tunnel closed", "", 0)

	if grant.OverlayIP == "" {
		log.Error("vpn grant missing overlay ip")
		end.emit("ended", "vpn: no overlay ip", "", -1)
		return
	}
	if len(grant.Routes) == 0 {
		log.Error("vpn grant missing routes")
		end.emit("ended", "vpn: no routes", "", -1)
		return
	}

	tun, err := vpn.OpenTUN("gnz%d")
	if err != nil {
		log.Error("open tun failed", "err", err)
		end.emit("ended", "vpn: tun: "+err.Error(), "", -1)
		return
	}
	defer tun.Close()
	if err := vpn.LinkUpAddr(tun.Name(), ""); err != nil {
		log.Error("tun link up failed", "err", err)
		end.emit("ended", "vpn: link up: "+err.Error(), "", -1)
		return
	}

	// Resolve the egress interface for each advertised route (exit-node uses a
	// public probe; subnet routes use the network address). Deduplicate so we
	// install one masquerade rule per real interface.
	egress := map[string]bool{}
	for _, cidr := range grant.Routes {
		probe := routeProbeIP(cidr)
		ifn, err := vpn.EgressInterface(probe)
		if err != nil {
			log.Error("egress lookup failed", "route", cidr, "probe", probe, "err", err)
			end.emit("ended", "vpn: egress: "+err.Error(), "", -1)
			return
		}
		egress[ifn] = true
	}
	egressIfs := make([]string, 0, len(egress))
	for ifn := range egress {
		egressIfs = append(egressIfs, ifn)
	}

	cleanup, err := vpn.NodeRouteFor(tun.Name(), grant.OverlayIP, egressIfs)
	if err != nil {
		log.Error("vpn node wiring failed", "err", err)
		end.emit("ended", "vpn: wiring: "+err.Error(), "", -1)
		return
	}
	defer cleanup()

	log.Info("vpn session up", "tun", tun.Name(), "client_overlay", grant.OverlayIP,
		"routes", strings.Join(grant.Routes, ","), "egress", strings.Join(egressIfs, ","))
	w.emitEvent(&genezav1.SessionEvent{SessionId: grant.ID, Event: "attached"})

	go func() { <-ctx.Done(); _ = tconn.Close(); _ = tun.Close() }()
	vpn.Pump(tun, tconn, func() { _ = tconn.Close(); _ = tun.Close() })
}

// routeProbeIP returns an IP inside cidr to probe for the egress interface. For
// the exit-node default route (0.0.0.0/0) it probes a public address; for a
// subnet route it uses the network address itself.
func routeProbeIP(cidr string) string {
	ip, _, err := net.ParseCIDR(cidr)
	if err != nil {
		return "1.1.1.1"
	}
	if ip.IsUnspecified() { // 0.0.0.0/0 exit node
		return "1.1.1.1"
	}
	return ip.String()
}
