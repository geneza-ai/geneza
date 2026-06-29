package main

import (
	"context"
	"fmt"
	"os"
	"time"

	"github.com/spf13/cobra"

	"geneza.io/internal/client"

	genezav1 "geneza.io/internal/pb/geneza/v1"
)

// newTrustCmd groups fleet trust-anchor management: ingest an assembled,
// threshold-signed anchor envelope into the controller, activating split mode.
func newTrustCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "trust",
		Short: "Fleet trust anchors (install an offline/threshold-signed anchor)",
	}
	cmd.AddCommand(newTrustInstallCmd())
	return cmd
}

// newTrustInstallCmd builds `genezactl trust install FILE` — ingest an assembled
// MultiSigned TrustAnchors envelope (from `geneza-trust anchors assemble`) into
// the controller. The controller holds no trust key and only stores the
// operator-supplied anchor; this is the online submission step of the offline flow.
func newTrustInstallCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "install FILE",
		Short: "Install an assembled MultiSigned TrustAnchors envelope (activates split mode)",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			raw, err := os.ReadFile(args[0])
			if err != nil {
				return err
			}
			return withAdmin(cmd.Context(), 30*time.Second, func(ctx context.Context, api genezav1.ClusterAPIClient) error {
				resp, err := api.InstallTrustAnchors(ctx, &genezav1.InstallTrustAnchorsRequest{TrustAnchors: raw})
				if err != nil {
					return client.Humanize(err)
				}
				fmt.Printf("installed trust anchors: anchor_version=%d config_version=%d\n", resp.GetAnchorVersion(), resp.GetConfigVersion())
				return nil
			})
		},
	}
}
