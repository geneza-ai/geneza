package main

import (
	"context"
	"fmt"
	"os"
	"text/tabwriter"
	"time"

	"github.com/spf13/cobra"

	"geneza.io/internal/client"

	genezav1 "geneza.io/internal/pb/geneza/v1"
)

// newRelayCmd groups relay-fleet operations. Relays self-register by holding a
// valid relay cert, so decommissioning one means revoking that cert — and since
// the cert renews itself, `ls` surfaces the CURRENT serial to pass to `cert revoke`.
func newRelayCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "relay",
		Short: "Relay fleet view (and the serial to revoke for decommission)",
	}
	cmd.AddCommand(newRelayLsCmd())
	return cmd
}

func newRelayLsCmd() *cobra.Command {
	return &cobra.Command{
		Use:     "ls",
		Aliases: []string{"list"},
		Short:   "List registered relays, including each relay's current cert serial",
		Args:    cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return withAdmin(cmd.Context(), 30*time.Second, func(ctx context.Context, api genezav1.ClusterAPIClient) error {
				resp, err := api.ListRelays(ctx, &genezav1.Empty{})
				if err != nil {
					return client.Humanize(err)
				}
				if len(resp.GetRelays()) == 0 {
					fmt.Println("no relays registered")
					return nil
				}
				tw := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
				fmt.Fprintln(tw, "RELAY\tREGION\tVERSION\tACTIVE\tSTATE\tLAST-SEEN\tCERT-SERIAL")
				now := time.Now()
				for _, r := range resp.GetRelays() {
					state := "healthy"
					if r.GetDraining() {
						state = "draining"
					}
					seen := "never"
					if r.GetLastSeenUnix() > 0 {
						seen = now.Sub(time.Unix(r.GetLastSeenUnix(), 0)).Round(time.Second).String() + " ago"
					}
					fmt.Fprintf(tw, "%s\t%s\t%s\t%d\t%s\t%s\t%s\n",
						r.GetRelayId(), orDash(r.GetRegionId()), orDash(r.GetVersion()),
						r.GetActiveCount(), state, seen, orDash(r.GetCertSerial()))
				}
				return tw.Flush()
			})
		},
	}
}
