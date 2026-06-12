package main

import (
	"context"
	"fmt"
	"net"
	"os"
	"os/signal"
	"syscall"

	"github.com/spf13/cobra"

	"osie.cloud/geneza/internal/client"
	genezav1 "osie.cloud/geneza/internal/pb/geneza/v1"
	"osie.cloud/geneza/internal/types"
	"osie.cloud/geneza/internal/vpn"
)

func newVPNCmd() *cobra.Command {
	var dnsZone string
	cmd := &cobra.Command{
		Use:   "vpn NODE SERVICE",
		Short: "Join the overlay through a node's subnet-route or exit-node service (configures a local TUN)",
		Long: "Bring up a layer-3 overlay through NODE's named subnet-route or exit-node SERVICE.\n" +
			"Creates a local TUN interface, assigns the gateway-allocated overlay IP, and installs\n" +
			"the advertised routes (a CIDR for a subnet route, or a full default route for an exit\n" +
			"node). Requires root/CAP_NET_ADMIN. Ctrl-C tears the tunnel and routes down.",
		Args: cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			e, err := loadEnv()
			if err != nil {
				return err
			}
			cc, api, err := dialUser(e)
			if err != nil {
				return err
			}
			defer cc.Close()
			ctx, stop := signal.NotifyContext(cmd.Context(), os.Interrupt, syscall.SIGTERM)
			defer stop()

			sess, err := client.Establish(ctx, api, e.pool, client.SessionParams{
				Node:    args[0],
				Action:  types.ActionVPN,
				Service: args[1],
			})
			if err != nil {
				return err
			}
			defer sess.Close()
			if sess.Action != types.ActionVPN || sess.Tunnel == nil {
				return fmt.Errorf("service %q on %s is not a subnet-route or exit-node service (use `geneza connect` or `geneza ssh` instead)", args[1], args[0])
			}
			if sess.OverlayIP == "" || len(sess.Routes) == 0 {
				return fmt.Errorf("gateway returned an incomplete vpn grant (no overlay ip / routes)")
			}

			return runVPN(ctx, sess, api, dnsZone)
		},
	}
	cmd.Flags().StringVar(&dnsZone, "dns-zone", "geneza", "tenant DNS suffix resolved over the VPN (machine names)")
	return cmd
}

// runVPN brings up the client TUN, installs routes (pinning the relay so the
// encrypted tunnel itself does not get routed back into the overlay for an exit
// node), and pumps IP packets until the context is cancelled.
func runVPN(ctx context.Context, sess *client.Session, api genezav1.UserAPIClient, dnsZone string) error {
	tun, err := vpn.OpenTUN("gnz%d")
	if err != nil {
		return fmt.Errorf("open tun (need root/CAP_NET_ADMIN): %w", err)
	}
	defer tun.Close()

	// The client end of the overlay sits in the same /24 the gateway allocates
	// from; the node routes our /32 back over the tunnel.
	if err := vpn.LinkUpAddr(tun.Name(), sess.OverlayIP+"/24"); err != nil {
		return fmt.Errorf("configure tun: %w", err)
	}

	// Pin the relay's address to the real default gateway BEFORE installing any
	// default route via the TUN, or an exit-node session would route its own
	// encrypted tunnel back into itself.
	var cleanups []func()
	relayIP, _, _ := net.SplitHostPort(sess.Tunnel.RemoteAddr().String())
	exitNode := false
	for _, r := range sess.Routes {
		if r == "0.0.0.0/0" {
			exitNode = true
		}
	}
	if exitNode {
		gw, gerr := vpn.DefaultGateway()
		if gerr != nil {
			return fmt.Errorf("exit node needs the current default gateway: %w", gerr)
		}
		if relayIP != "" {
			if err := vpn.RouteVia(relayIP+"/32", gw); err != nil {
				return fmt.Errorf("pin relay route: %w", err)
			}
			cleanups = append(cleanups, func() { vpn.RemoveRoute(relayIP + "/32") })
		}
	}

	for _, r := range sess.Routes {
		if r == "0.0.0.0/0" {
			// Override the default without deleting it: two /1 routes via the TUN
			// outrank the existing default and revert cleanly on TUN teardown.
			for _, half := range []string{"0.0.0.0/1", "128.0.0.0/1"} {
				if err := vpn.AddRoute(half, tun.Name()); err != nil {
					runCleanups(cleanups)
					return fmt.Errorf("install default-via-tun (%s): %w", half, err)
				}
				h := half
				cleanups = append(cleanups, func() { vpn.DelRoute(h, tun.Name()) })
			}
			continue
		}
		if err := vpn.AddRoute(r, tun.Name()); err != nil {
			runCleanups(cleanups)
			return fmt.Errorf("install route %s: %w", r, err)
		}
		rr := r
		cleanups = append(cleanups, func() { vpn.DelRoute(rr, tun.Name()) })
	}

	// Tenant DNS (MagicDNS-style): a local stub relays *.<zone> queries to the
	// gateway's policy-aware resolver over the authenticated channel, and the
	// system resolver is split-pointed at it for the zone only. Best-effort —
	// the VPN data path works regardless.
	if proxy, perr := vpn.StartDNSProxy(vpn.DNSStubAddr, func(c context.Context, q []byte) ([]byte, error) {
		r, err := api.ResolveDNS(c, &genezav1.DNSQuery{Query: q})
		if err != nil {
			return nil, err
		}
		return r.GetResponse(), nil
	}); perr != nil {
		fmt.Fprintf(os.Stderr, "[vpn] tenant DNS stub not started: %v\n", perr)
	} else {
		cleanups = append(cleanups, func() { _ = proxy.Close() })
		dnsIP, _, _ := net.SplitHostPort(vpn.DNSStubAddr)
		if revert, rerr := vpn.SetLinkResolver(tun.Name(), dnsIP, dnsZone); rerr != nil {
			fmt.Fprintf(os.Stderr, "[vpn] tenant DNS not auto-configured: %v\n", rerr)
		} else {
			cleanups = append(cleanups, revert)
			fmt.Fprintf(os.Stderr, "[vpn] tenant DNS: *.%s resolved via the gateway (stub %s)\n", dnsZone, vpn.DNSStubAddr)
		}
	}
	defer runCleanups(cleanups)

	fmt.Fprintf(os.Stderr, "[vpn %s] up: overlay %s via %s  routes=%v  (Ctrl-C to stop)\n",
		sess.ID, sess.OverlayIP, tun.Name(), sess.Routes)

	go func() { <-ctx.Done(); _ = sess.Tunnel.Close(); _ = tun.Close() }()
	vpn.Pump(tun, sess.Tunnel, func() { _ = sess.Tunnel.Close(); _ = tun.Close() })
	fmt.Fprintln(os.Stderr, "vpn stopped")
	return nil
}

func runCleanups(cs []func()) {
	// Reverse order so routes come down before the relay pin.
	for i := len(cs) - 1; i >= 0; i-- {
		cs[i]()
	}
}
