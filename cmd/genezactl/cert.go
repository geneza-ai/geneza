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

// newCertCmd groups leaf-certificate revocation: kill a node/user/admin cert
// before its TTL expires.
func newCertCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "cert",
		Short: "Leaf-certificate revocation (kill a cert before its TTL)",
	}
	cmd.AddCommand(newCertRevokeCmd(), newCertLsCmd())
	return cmd
}

func newCertRevokeCmd() *cobra.Command {
	var reason string
	cmd := &cobra.Command{
		Use:   "revoke SERIAL",
		Short: "Revoke a leaf cert by hex serial (denied on its next RPC/reconnect)",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return withAdmin(cmd.Context(), 30*time.Second, func(ctx context.Context, api genezav1.ClusterAPIClient) error {
				if _, err := api.RevokeCert(ctx, &genezav1.RevokeCertRequest{Serial: args[0], Reason: reason}); err != nil {
					return client.Humanize(err)
				}
				fmt.Printf("revoked %s\n", args[0])
				return nil
			})
		},
	}
	cmd.Flags().StringVar(&reason, "reason", "", "reason recorded in the audit log")
	return cmd
}

func newCertLsCmd() *cobra.Command {
	return &cobra.Command{
		Use:     "ls",
		Aliases: []string{"list"},
		Short:   "List revoked cert serials",
		Args:    cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return withAdmin(cmd.Context(), 30*time.Second, func(ctx context.Context, api genezav1.ClusterAPIClient) error {
				resp, err := api.ListRevokedCerts(ctx, &genezav1.Empty{})
				if err != nil {
					return client.Humanize(err)
				}
				tw := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
				fmt.Fprintln(tw, "SERIAL\tBY\tREASON")
				for _, c := range resp.GetCerts() {
					fmt.Fprintf(tw, "%s\t%s\t%s\n", c.GetSerial(), c.GetBy(), c.GetReason())
				}
				return tw.Flush()
			})
		},
	}
}
