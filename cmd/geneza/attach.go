package main

import (
	"context"
	"fmt"
	"os"
	"time"

	"github.com/spf13/cobra"

	"geneza.io/internal/client"
	"geneza.io/internal/types"

	genezav1 "geneza.io/internal/pb/geneza/v1"
)

func newAttachCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "attach SESSION-ID",
		Short: "Reattach to a detached (or live) session",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			sid := args[0]
			e, err := loadEnv()
			if err != nil {
				return err
			}
			cc, api, cert, err := dialUser(e)
			if err != nil {
				return err
			}
			defer cc.Close()
			ctx := cmd.Context()

			// The controller resolves the session to its host session; we only
			// need to know which node to broker the tunnel to.
			lsCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
			info, err := findSession(lsCtx, api, sid)
			cancel()
			if err != nil {
				return err
			}

			params := client.SessionParams{
				Node:            info.GetNodeId(),
				Action:          types.ActionAttach,
				AttachSessionID: sid,
				WantPTY:         true,
				WantDetachable:  true,
			}
			establish := func(ectx context.Context) (*client.Session, error) {
				return client.Establish(ectx, api, e.Pool, cert, params)
			}
			sess, err := establish(ctx)
			if err != nil {
				return err
			}
			defer sess.Close()
			fmt.Fprintf(os.Stderr, "[session %s]\n", info.GetSessionId())

			code, err := client.RunAttached(ctx, sess, client.AttachOptions{
				PTY:              true,
				Detachable:       true,
				ControllerSessionID: info.GetSessionId(),
				Reattach:         establish, // one-shot auto-retry on tunnel failure
			})
			if err != nil {
				return err
			}
			if code != 0 {
				os.Exit(code)
			}
			return nil
		},
	}
}

// findSession resolves a user-supplied id against ListSessions, accepting
// either the controller session id or the host session id.
func findSession(ctx context.Context, api genezav1.WorkspaceAPIClient, sid string) (*genezav1.SessionInfo, error) {
	// Resolve against the most recent sessions (the server page cap); a session you
	// are reattaching to is recent, so it falls in this window.
	resp, err := api.ListSessions(ctx, &genezav1.ListSessionsRequest{MineOnly: false, Limit: 1000})
	if err != nil {
		return nil, client.Humanize(err)
	}
	for _, s := range resp.GetSessions() {
		if s.GetSessionId() == sid || (s.GetHostSessionId() != "" && s.GetHostSessionId() == sid) {
			return s, nil
		}
	}
	return nil, fmt.Errorf("session %q not found (see 'geneza ps')", sid)
}
