package main

import (
	"context"
	"os"
	"time"

	"github.com/spf13/cobra"

	"geneza.io/internal/client"

	genezav1 "geneza.io/internal/pb/geneza/v1"
)

// newPsCmd builds `geneza ps` — list sessions (yours by default; --all for
// everyone, which requires the admin role).
func newPsCmd() *cobra.Command {
	var (
		all    bool
		asJSON bool
		limit  int
		offset int
	)
	cmd := &cobra.Command{
		Use:     "ps",
		Aliases: []string{"sessions"},
		Short:   "List sessions (default: only your own; --all for everyone)",
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
			resp, err := api.ListSessions(ctx, &genezav1.ListSessionsRequest{
				MineOnly: !all, Limit: int32(limit), Offset: int32(offset),
			})
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
			printPageHint(os.Stdout, len(rows), int(resp.GetTotal()), offset)
			return nil
		},
	}
	cmd.Flags().BoolVar(&all, "all", false, "show all users' sessions (admin)")
	cmd.Flags().BoolVar(&asJSON, "json", false, "JSON output")
	cmd.Flags().IntVar(&limit, "limit", 0, "max rows per page (0 = server default)")
	cmd.Flags().IntVar(&offset, "offset", 0, "skip this many rows (paging)")
	return cmd
}
