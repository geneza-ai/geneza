package main

import (
	"context"
	"fmt"
	"os"
	"time"

	"github.com/spf13/cobra"

	"geneza.io/internal/client"

	genezav1 "geneza.io/internal/pb/geneza/v1"
)

func newLsCmd() *cobra.Command {
	var (
		asJSON bool
		limit  int
		offset int
	)
	cmd := &cobra.Command{
		Use:   "ls [NODE]",
		Short: "List nodes; with NODE, list the services that node exposes",
		Args:  cobra.MaximumNArgs(1),
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
			if len(args) == 1 {
				return listNodeServices(ctx, api, args[0], asJSON)
			}
			resp, err := api.ListNodes(ctx, &genezav1.ListNodesRequest{
				Limit: int32(limit), Offset: int32(offset),
			})
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
			printPageHint(os.Stdout, len(rows), int(resp.GetTotal()), offset)
			return nil
		},
	}
	cmd.Flags().BoolVar(&asJSON, "json", false, "JSON output")
	cmd.Flags().IntVar(&limit, "limit", 0, "max rows per page (0 = server default)")
	cmd.Flags().IntVar(&offset, "offset", 0, "skip this many rows (paging)")
	return cmd
}

// listNodeServices renders the services a single node exposes (rdp, db,
// http, subnet-route, exit-node, ...) — the `geneza ls NODE` form.
func listNodeServices(ctx context.Context, api genezav1.UserAPIClient, node string, asJSON bool) error {
	resp, err := api.ListServices(ctx, &genezav1.ListServicesRequest{Node: node})
	if err != nil {
		return client.Humanize(err)
	}
	if asJSON {
		return printJSON(resp)
	}
	rows := make([][]string, 0, len(resp.GetServices()))
	for _, s := range resp.GetServices() {
		rows = append(rows, []string{
			s.GetName(), s.GetKind(), s.GetNodeName(), s.GetAddr(), boolStr(s.GetOnline()),
		})
	}
	client.PrintTable(os.Stdout, []string{"SERVICE", "KIND", "NODE", "ADDR", "ONLINE"}, rows)
	return nil
}
