package main

import (
	"context"
	"fmt"
	"time"

	"github.com/spf13/cobra"

	"geneza.io/internal/client"

	genezav1 "geneza.io/internal/pb/geneza/v1"
)

// newKickCmd builds `geneza kick [SESSION] --user U` — drop a live session, or
// all of a user's. This acts on a SESSION (transient), distinct from `user
// suspend` (sticky authorization revocation) and `node quarantine` (a host).
func newKickCmd() *cobra.Command {
	var (
		user   string
		reason string
	)
	cmd := &cobra.Command{
		Use:   "kick [SESSION]",
		Short: "Kick a live session (or all of a user's with --user)",
		Args:  cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if (len(args) == 0) == (user == "") {
				return fmt.Errorf("provide a session id OR --user, not both")
			}
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
			if user != "" {
				resp, err := api.RevokeUser(ctx, &genezav1.RevokeUserRequest{User: user, Reason: reason})
				if err != nil {
					return client.Humanize(err)
				}
				fmt.Printf("Kicked %d session(s) for user %s.\n", resp.GetRevoked(), user)
				return nil
			}
			if _, err := api.RevokeSession(ctx, &genezav1.RevokeSessionRequest{SessionId: args[0], Reason: reason}); err != nil {
				return client.Humanize(err)
			}
			fmt.Printf("Kicked session %s.\n", args[0])
			return nil
		},
	}
	cmd.Flags().StringVar(&user, "user", "", "kick all sessions for this user")
	cmd.Flags().StringVar(&reason, "reason", "", "reason (audited)")
	return cmd
}
