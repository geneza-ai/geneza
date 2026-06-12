package main

import (
	"context"
	"fmt"
	"os"
	"time"

	"github.com/spf13/cobra"

	"osie.cloud/geneza/internal/client"

	genezav1 "osie.cloud/geneza/internal/pb/geneza/v1"
)

func newLsCmd() *cobra.Command {
	var asJSON bool
	cmd := &cobra.Command{
		Use:   "ls",
		Short: "List nodes",
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
			resp, err := api.ListNodes(ctx, &genezav1.ListNodesRequest{})
			if err != nil {
				return client.Humanize(err)
			}
			if asJSON {
				return printJSON(resp)
			}
			rows := make([][]string, 0, len(resp.GetNodes()))
			for _, n := range resp.GetNodes() {
				rows = append(rows, []string{
					n.GetName(),
					n.GetNodeId(),
					admissionStr(n.GetApproved()),
					onlineStr(n.GetOnline()),
					client.FormatLabels(n.GetLabels()),
					n.GetVersion(),
					fmt.Sprintf("%d/%d", n.GetActiveSessions(), n.GetDetachedSessions()),
					client.Ago(n.GetLastSeenUnix()),
				})
			}
			client.PrintTable(os.Stdout,
				[]string{"NAME", "NODE-ID", "ADMISSION", "ONLINE", "LABELS", "VERSION", "SESSIONS", "LAST-SEEN"}, rows)
			return nil
		},
	}
	cmd.Flags().BoolVar(&asJSON, "json", false, "JSON output")
	return cmd
}
