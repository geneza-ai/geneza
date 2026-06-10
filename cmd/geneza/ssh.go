package main

import (
	"context"
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"osie.cloud/geneza/internal/client"
	"osie.cloud/geneza/internal/types"
)

func newSSHCmd() *cobra.Command {
	var (
		detachable bool
		noPTY      bool
	)
	cmd := &cobra.Command{
		Use:   "ssh NODE",
		Short: "Open an interactive shell on a node (escape: ~d detach, ~. close, ~~ literal)",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			e, err := loadEnv()
			if err != nil {
				return err
			}
			cc, api, err := dialUser(e)
			if err != nil {
				return err
			}
			defer cc.Close()
			ctx := cmd.Context()

			sess, err := client.Establish(ctx, api, e.pool, client.SessionParams{
				Node:           args[0],
				Action:         types.ActionShell,
				WantPTY:        !noPTY,
				WantDetachable: detachable,
			})
			if err != nil {
				return err
			}
			defer sess.Close()

			var reattach func(context.Context) (*client.Session, error)
			if detachable {
				fmt.Fprintf(os.Stderr, "[session %s]\n", sess.ID)
				// On a tunnel failure the shell survives in the session host;
				// recovery is an attach to the same gateway session.
				rp := client.SessionParams{
					Node:            args[0],
					Action:          types.ActionAttach,
					AttachSessionID: sess.ID,
					WantPTY:         !noPTY,
					WantDetachable:  true,
				}
				reattach = func(rctx context.Context) (*client.Session, error) {
					return client.Establish(rctx, api, e.pool, rp)
				}
			}

			code, err := client.RunAttached(ctx, sess, client.AttachOptions{
				PTY:              !noPTY,
				Detachable:       detachable,
				GatewaySessionID: sess.ID,
				Reattach:         reattach,
			})
			if err != nil {
				return err
			}
			if code != 0 {
				os.Exit(code) // RunAttached has already restored the terminal
			}
			return nil
		},
	}
	cmd.Flags().BoolVar(&detachable, "detachable", false, "keep the session alive server-side after detach/disconnect")
	cmd.Flags().BoolVar(&detachable, "detach", false, "alias for --detachable")
	cmd.Flags().MarkHidden("detach") //nolint:errcheck
	cmd.Flags().BoolVar(&noPTY, "no-pty", false, "do not allocate a PTY")
	return cmd
}
