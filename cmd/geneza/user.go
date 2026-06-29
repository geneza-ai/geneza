package main

import (
	"context"
	"fmt"
	"time"

	"github.com/spf13/cobra"

	"geneza.io/internal/client"

	genezav1 "geneza.io/internal/pb/geneza/v1"
)

// newUserCmd groups principal authorization: suspend/unsuspend a person (or a
// provider subject) and list who is suspended. This is authorization, not
// authentication — a suspension is sticky and survives the principal re-logging
// in with a valid token.
func newUserCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:     "user",
		Aliases: []string{"users", "principal"},
		Short:   "Principal authorization: suspend / unsuspend / list",
	}
	cmd.AddCommand(newUserSuspendCmd(true), newUserSuspendCmd(false), newUserSuspensionsCmd())
	return cmd
}

func newUserSuspendCmd(suspend bool) *cobra.Command {
	var ws, provider, subject, reason string
	verb := "suspend"
	short := "Revoke a principal's AUTHORIZATION (sticky; survives re-login) — nukes their live tunnel + browser sessions and denies new ones, even with a valid token"
	if !suspend {
		verb = "unsuspend"
		short = "Restore a suspended principal's authorization"
	}
	cmd := &cobra.Command{
		Use:   verb + " <username>",
		Short: short,
		Args:  cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			username := ""
			if len(args) == 1 {
				username = args[0]
			}
			if username == "" && subject == "" {
				return fmt.Errorf("provide a <username> or --subject")
			}
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
			req := &genezav1.SuspendPrincipalRequest{Workspace: ws, Provider: provider, Subject: subject, Username: username, Reason: reason}
			if suspend {
				if _, err := api.SuspendPrincipal(ctx, req); err != nil {
					return client.Humanize(err)
				}
				fmt.Printf("Suspended authorization for %s — live sessions dropped; new sessions denied until unsuspend.\n", orStr(username, subject))
			} else {
				if _, err := api.LiftSuspension(ctx, req); err != nil {
					return client.Humanize(err)
				}
				fmt.Printf("Restored authorization for %s.\n", orStr(username, subject))
			}
			return nil
		},
	}
	f := cmd.Flags()
	f.StringVar(&ws, "workspace", "", "workspace (default \"default\")")
	f.StringVar(&provider, "provider", "", "keystone|oidc|local (optional; resolved from sessions/members)")
	f.StringVar(&subject, "subject", "", "stable provider subject id (optional; exact principal)")
	if suspend {
		f.StringVar(&reason, "reason", "", "reason (audited)")
	}
	return cmd
}

func newUserSuspensionsCmd() *cobra.Command {
	return &cobra.Command{
		Use:     "suspensions",
		Aliases: []string{"ls"},
		Short:   "List suspended principals (authorization revoked)",
		Args:    cobra.NoArgs,
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
			resp, err := api.ListSuspensions(ctx, &genezav1.Empty{})
			if err != nil {
				return client.Humanize(err)
			}
			if len(resp.GetSuspensions()) == 0 {
				fmt.Println("No suspended principals.")
				return nil
			}
			for _, s := range resp.GetSuspensions() {
				fmt.Printf("%s  %s:%s  (%s)  by %s: %s\n",
					s.GetWorkspace(), s.GetProvider(), s.GetSubject(), s.GetUsername(), s.GetSuspendedBy(), s.GetReason())
			}
			return nil
		},
	}
}
