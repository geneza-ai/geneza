package main

import (
	"context"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"geneza.io/internal/client"

	genezav1 "geneza.io/internal/pb/geneza/v1"
)

// newStatusCmd builds `genezactl status` — the cluster-wide roster: every
// node plus the desired agent and relay versions per rollout ring.
func newStatusCmd() *cobra.Command {
	var asJSON bool
	cmd := &cobra.Command{
		Use:   "status",
		Short: "Cluster roster: nodes plus desired agent/relay versions per ring",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			return withAdmin(cmd.Context(), 30*time.Second, func(ctx context.Context, api genezav1.AdminAPIClient) error {
				resp, err := api.GetFleetStatus(ctx, &genezav1.Empty{})
				if err != nil {
					return client.Humanize(err)
				}
				if asJSON {
					return client.PrintJSON(resp)
				}
				fmt.Printf("Agent versions: stable=%s canary=%s\n",
					orDash(resp.GetStableVersion()), orDash(resp.GetCanaryVersion()))
				fmt.Printf("Relay versions: stable=%s canary=%s\n",
					orDash(resp.GetRelayStableVersion()), orDash(resp.GetRelayCanaryVersion()))
				if len(resp.GetCanaryNodes()) > 0 {
					fmt.Printf("Canary nodes: %s\n", strings.Join(resp.GetCanaryNodes(), ", "))
				}
				if len(resp.GetRelayCanaryNodes()) > 0 {
					fmt.Printf("Canary relays:   %s\n", strings.Join(resp.GetRelayCanaryNodes(), ", "))
				}
				fmt.Println()
				rows := make([][]string, 0, len(resp.GetNodes()))
				for _, n := range resp.GetNodes() {
					rows = append(rows, []string{
						n.GetName(),
						n.GetNodeId(),
						client.AdmissionStr(n.GetApproved()),
						client.OnlineStr(n.GetOnline()),
						n.GetVersion(),
						n.GetOs() + "/" + n.GetArch(),
						client.FormatLabels(n.GetLabels()),
						client.Ago(n.GetLastSeenUnix()),
					})
				}
				client.PrintTable(os.Stdout,
					[]string{"NAME", "NODE-ID", "ADMISSION", "ONLINE", "VERSION", "PLATFORM", "LABELS", "LAST-SEEN"}, rows)
				return nil
			})
		},
	}
	cmd.Flags().BoolVar(&asJSON, "json", false, "JSON output")
	return cmd
}
