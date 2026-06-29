package main

import (
	"context"
	"fmt"
	"time"

	"github.com/spf13/cobra"

	"geneza.io/internal/client"

	genezav1 "geneza.io/internal/pb/geneza/v1"
)

// newPolicyCmd groups controller policy operations.
func newPolicyCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "policy",
		Short: "Controller policy document",
	}
	cmd.AddCommand(newPolicyReloadCmd())
	return cmd
}

func newPolicyReloadCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "reload",
		Short: "Reload the controller policy document",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			return withAdmin(cmd.Context(), 30*time.Second, func(ctx context.Context, api genezav1.ClusterAPIClient) error {
				if _, err := api.ReloadPolicy(ctx, &genezav1.Empty{}); err != nil {
					return client.Humanize(err)
				}
				fmt.Println("Policy reloaded.")
				return nil
			})
		},
	}
}
