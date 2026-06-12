package main

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/miekg/dns"
	"github.com/spf13/cobra"

	"osie.cloud/geneza/internal/client"
	genezav1 "osie.cloud/geneza/internal/pb/geneza/v1"
)

// newResolveCmd resolves a machine name in the caller's tenant zone via the
// gateway's policy-aware resolver — the same path `geneza vpn`'s local stub
// uses, but as a one-shot (no TUN/root needed). Handy for ops + e2e.
func newResolveCmd() *cobra.Command {
	var zone string
	cmd := &cobra.Command{
		Use:   "resolve NAME",
		Short: "Resolve a machine name to its overlay IP (policy-aware tenant DNS)",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			name := args[0]
			if !strings.Contains(strings.TrimSuffix(name, "."), ".") {
				name = name + "." + zone // bare label -> <name>.<zone>
			}
			e, err := loadEnv()
			if err != nil {
				return err
			}
			cc, api, err := dialUser(e)
			if err != nil {
				return err
			}
			defer cc.Close()
			ctx, cancel := context.WithTimeout(cmd.Context(), 15*time.Second)
			defer cancel()

			q := new(dns.Msg)
			q.SetQuestion(dns.Fqdn(name), dns.TypeA)
			wire, err := q.Pack()
			if err != nil {
				return err
			}
			resp, err := api.ResolveDNS(ctx, &genezav1.DNSQuery{Query: wire})
			if err != nil {
				return client.Humanize(err)
			}
			var m dns.Msg
			if err := m.Unpack(resp.GetResponse()); err != nil {
				return fmt.Errorf("decode dns reply: %w", err)
			}
			switch m.Rcode {
			case dns.RcodeNameError:
				return fmt.Errorf("%s: NXDOMAIN (unknown machine, or not permitted)", name)
			case dns.RcodeRefused:
				return fmt.Errorf("%s: REFUSED (not in your tenant zone %q)", name, zone)
			case dns.RcodeSuccess:
				for _, rr := range m.Answer {
					if a, ok := rr.(*dns.A); ok {
						fmt.Printf("%s\t%d\tA\t%s\n", strings.TrimSuffix(a.Hdr.Name, "."), a.Hdr.Ttl, a.A)
					}
				}
				if len(m.Answer) == 0 {
					fmt.Printf("%s: no address records\n", name)
				}
				return nil
			default:
				return fmt.Errorf("%s: DNS rcode %d", name, m.Rcode)
			}
		},
	}
	cmd.Flags().StringVar(&zone, "zone", "geneza", "tenant DNS suffix for bare names")
	return cmd
}
