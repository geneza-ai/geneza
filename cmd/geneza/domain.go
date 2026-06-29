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

// newDomainCmd groups managed-domain reservations for the caller's workspace. A
// workspace gets a publicly-trusted wildcard per reserved subdomain, resolvable
// only on the VPN.
func newDomainCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:     "domain",
		Aliases: []string{"domains"},
		Short:   "Managed-domain subdomain reservations for your workspace",
	}
	cmd.AddCommand(newDomainLsCmd(), newDomainReserveCmd(), newDomainReleaseCmd())
	return cmd
}

func newDomainLsCmd() *cobra.Command {
	return &cobra.Command{
		Use:     "ls",
		Aliases: []string{"list"},
		Short:   "List your workspace's reservations and the claimable domains",
		Args:    cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			e, err := loadEnv()
			if err != nil {
				return err
			}
			cc, api, _, err := dialUser(e)
			if err != nil {
				return err
			}
			defer cc.Close()
			ctx, cancel := context.WithTimeout(cmd.Context(), 30*time.Second)
			defer cancel()
			resp, err := api.ListSubdomains(ctx, &genezav1.Empty{})
			if err != nil {
				return client.Humanize(err)
			}
			if !resp.GetEnabled() {
				fmt.Println("managed domain is not enabled on this controller")
				return nil
			}
			fmt.Printf("claimable domains: %v   (max %d per workspace)\n", resp.GetDomains(), resp.GetMax())
			tw := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
			fmt.Fprintln(tw, "ZONE\tDOMAIN\tLABEL\tBY")
			for _, r := range resp.GetReservations() {
				fmt.Fprintf(tw, "%s\t%s\t%s\t%s\n", r.GetZone(), r.GetDomain(), r.GetLabel(), r.GetCreatedBy())
			}
			return tw.Flush()
		},
	}
}

func newDomainReserveCmd() *cobra.Command {
	return &cobra.Command{
		Use:     "reserve DOMAIN [LABEL]",
		Aliases: []string{"claim"},
		Short:   "Reserve a subdomain on a managed domain (LABEL defaults to your workspace token)",
		Args:    cobra.RangeArgs(1, 2),
		RunE: func(cmd *cobra.Command, args []string) error {
			e, err := loadEnv()
			if err != nil {
				return err
			}
			cc, api, _, err := dialUser(e)
			if err != nil {
				return err
			}
			defer cc.Close()
			ctx, cancel := context.WithTimeout(cmd.Context(), 30*time.Second)
			defer cancel()
			req := &genezav1.ReserveSubdomainRequest{Domain: args[0]}
			if len(args) == 2 {
				req.Label = args[1]
			}
			resp, err := api.ReserveSubdomain(ctx, req)
			if err != nil {
				return client.Humanize(err)
			}
			fmt.Printf("reserved %s\n", resp.GetZone())
			return nil
		},
	}
}

func newDomainReleaseCmd() *cobra.Command {
	return &cobra.Command{
		Use:     "release DOMAIN LABEL",
		Aliases: []string{"rm", "remove"},
		Short:   "Release one of your workspace's reservations",
		Args:    cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			e, err := loadEnv()
			if err != nil {
				return err
			}
			cc, api, _, err := dialUser(e)
			if err != nil {
				return err
			}
			defer cc.Close()
			ctx, cancel := context.WithTimeout(cmd.Context(), 30*time.Second)
			defer cancel()
			if _, err := api.ReleaseSubdomain(ctx, &genezav1.ReleaseSubdomainRequest{Domain: args[0], Label: args[1]}); err != nil {
				return client.Humanize(err)
			}
			fmt.Printf("released %s.%s\n", args[1], args[0])
			return nil
		},
	}
}
