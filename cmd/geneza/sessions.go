package main

import (
	"context"
	"os"
	"time"

	"github.com/spf13/cobra"

	"osie.cloud/geneza/internal/client"

	genezav1 "osie.cloud/geneza/internal/pb/geneza/v1"
)

func newSessionsCmd() *cobra.Command {
	var (
		all    bool
		asJSON bool
	)
	cmd := &cobra.Command{
		Use:   "sessions",
		Short: "List sessions (default: only your own)",
		Args:  cobra.NoArgs,
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
			ctx, cancel := context.WithTimeout(cmd.Context(), 30*time.Second)
			defer cancel()
			resp, err := api.ListSessions(ctx, &genezav1.ListSessionsRequest{MineOnly: !all})
			if err != nil {
				return client.Humanize(err)
			}
			if asJSON {
				return printJSON(resp)
			}
			rows := make([][]string, 0, len(resp.GetSessions()))
			for _, s := range resp.GetSessions() {
				node := s.GetNodeName()
				if node == "" {
					node = s.GetNodeId()
				}
				rows = append(rows, []string{
					s.GetSessionId(),
					node,
					s.GetUser(),
					s.GetAction(),
					s.GetState(),
					client.Ago(s.GetStartedUnix()),
					boolStr(s.GetDetachable()),
				})
			}
			client.PrintTable(os.Stdout,
				[]string{"SESSION-ID", "NODE", "USER", "ACTION", "STATE", "STARTED", "DETACHABLE"}, rows)
			return nil
		},
	}
	cmd.Flags().BoolVar(&all, "all", false, "show all users' sessions (admin)")
	cmd.Flags().BoolVar(&asJSON, "json", false, "JSON output")
	return cmd
}
