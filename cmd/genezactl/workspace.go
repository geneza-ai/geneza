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

// newWorkspaceCmd groups tenancy provisioning: list hosted workspaces and bind
// cloud-qualified sources (openstack:project:..., idp:group:...) to them. Only
// the cluster operator provisions tenants — a tenant cannot create its own.
func newWorkspaceCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:     "workspace",
		Aliases: []string{"workspaces", "ws"},
		Short:   "Tenant workspaces hosted by this controller",
	}
	cmd.AddCommand(newWorkspaceLsCmd(), newWorkspaceBindCmd(), newWorkspaceUnbindCmd(), newWorkspaceBindingsCmd())
	return cmd
}

func newWorkspaceLsCmd() *cobra.Command {
	var asJSON bool
	cmd := &cobra.Command{
		Use:     "ls",
		Aliases: []string{"list"},
		Short:   "List the tenant workspaces this controller hosts",
		Args:    cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			return withAdmin(cmd.Context(), 30*time.Second, func(ctx context.Context, api genezav1.ClusterAPIClient) error {
				resp, err := api.ListWorkspaces(ctx, &genezav1.Empty{})
				if err != nil {
					return client.Humanize(err)
				}
				if asJSON {
					return client.PrintJSON(resp)
				}
				rows := make([][]string, 0, len(resp.GetWorkspaces()))
				for _, w := range resp.GetWorkspaces() {
					rows = append(rows, []string{w.GetId(), orDash(w.GetName()), w.GetOverlayCidr()})
				}
				client.PrintTable(os.Stdout, []string{"ID", "NAME", "OVERLAY"}, rows)
				return nil
			})
		},
	}
	cmd.Flags().BoolVar(&asJSON, "json", false, "JSON output")
	return cmd
}

func newWorkspaceBindCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "bind KEY WORKSPACE",
		Short: "Bind a cloud-qualified source (openstack:project:<svc>:<uuid>, idp:group:<realm>:<g>, ...) to a workspace",
		Args:  cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			return withAdmin(cmd.Context(), 30*time.Second, func(ctx context.Context, api genezav1.ClusterAPIClient) error {
				if _, err := api.BindSource(ctx, &genezav1.BindSourceRequest{Key: args[0], WorkspaceId: args[1]}); err != nil {
					return client.Humanize(err)
				}
				fmt.Printf("bound %s -> %s\n", args[0], args[1])
				return nil
			})
		},
	}
}

func newWorkspaceUnbindCmd() *cobra.Command {
	return &cobra.Command{
		Use:     "unbind KEY",
		Aliases: []string{"rm", "remove"},
		Short:   "Remove a source binding",
		Args:    cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return withAdmin(cmd.Context(), 30*time.Second, func(ctx context.Context, api genezav1.ClusterAPIClient) error {
				if _, err := api.UnbindSource(ctx, &genezav1.UnbindSourceRequest{Key: args[0]}); err != nil {
					return client.Humanize(err)
				}
				fmt.Printf("unbound %s\n", args[0])
				return nil
			})
		},
	}
}

func newWorkspaceBindingsCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "bindings",
		Short: "List source bindings",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return withAdmin(cmd.Context(), 30*time.Second, func(ctx context.Context, api genezav1.ClusterAPIClient) error {
				resp, err := api.ListSourceBindings(ctx, &genezav1.Empty{})
				if err != nil {
					return client.Humanize(err)
				}
				tw := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
				fmt.Fprintln(tw, "KEY\tWORKSPACE\tBY\tAUTO")
				for _, b := range resp.GetBindings() {
					fmt.Fprintf(tw, "%s\t%s\t%s\t%v\n", b.GetKey(), b.GetWorkspaceId(), b.GetCreatedBy(), b.GetAutoProvisioned())
				}
				return tw.Flush()
			})
		},
	}
}
