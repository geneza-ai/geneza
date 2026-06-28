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

// newExposeCmd builds `geneza expose HOSTNAME TARGET` — publish a workspace
// service to the public internet at a hostname under one of the workspace's
// reserved subdomains.
func newExposeCmd() *cobra.Command {
	var node, mode string
	cmd := &cobra.Command{
		Use:   "expose HOSTNAME TARGET",
		Short: "Expose TARGET (host:port on the overlay) publicly at HOSTNAME",
		Args:  cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			e, err := loadEnv()
			if err != nil {
				return err
			}
			cc, api, err := dialAdmin(e)
			if err != nil {
				return err
			}
			defer cc.Close()
			ctx, cancel := context.WithTimeout(cmd.Context(), 30*time.Second)
			defer cancel()
			resp, err := api.CreateFunnel(ctx, &genezav1.CreateFunnelRequest{
				Hostname: args[0], Target: args[1], Node: node, Mode: mode,
			})
			if err != nil {
				return client.Humanize(err)
			}
			fmt.Printf("exposed %s -> %s (%s)\n", resp.GetHostname(), resp.GetTarget(), resp.GetMode())
			return nil
		},
	}
	cmd.Flags().StringVar(&node, "node", "", "target node id (the host running the service)")
	cmd.Flags().StringVar(&mode, "mode", "http", "proxy mode: http or tcp")
	return cmd
}

// newUnexposeCmd builds `geneza unexpose HOSTNAME` — remove a public exposure.
func newUnexposeCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "unexpose HOSTNAME",
		Short: "Remove a public exposure",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			e, err := loadEnv()
			if err != nil {
				return err
			}
			cc, api, err := dialAdmin(e)
			if err != nil {
				return err
			}
			defer cc.Close()
			ctx, cancel := context.WithTimeout(cmd.Context(), 30*time.Second)
			defer cancel()
			if _, err := api.DeleteFunnel(ctx, &genezav1.DeleteFunnelRequest{Hostname: args[0]}); err != nil {
				return client.Humanize(err)
			}
			fmt.Printf("unexposed %s\n", args[0])
			return nil
		},
	}
}

// newExposedCmd builds `geneza exposed` — list the workspace's public exposures.
func newExposedCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "exposed",
		Short: "List your workspace's public exposures",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			e, err := loadEnv()
			if err != nil {
				return err
			}
			cc, api, err := dialAdmin(e)
			if err != nil {
				return err
			}
			defer cc.Close()
			ctx, cancel := context.WithTimeout(cmd.Context(), 30*time.Second)
			defer cancel()
			resp, err := api.ListFunnels(ctx, &genezav1.Empty{})
			if err != nil {
				return client.Humanize(err)
			}
			tw := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
			fmt.Fprintln(tw, "HOSTNAME\tNODE\tTARGET\tMODE\tBY")
			for _, f := range resp.GetFunnels() {
				fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\n", f.GetHostname(), f.GetNode(), f.GetTarget(), f.GetMode(), f.GetCreatedBy())
			}
			return tw.Flush()
		},
	}
}
