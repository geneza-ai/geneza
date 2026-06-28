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

// newCvesCmd builds `geneza cves` — the workspace fleet's CVE affectedness, in
// three lenses on one verb: the rollup (default), one node's CVEs
// (--node), or the nodes a given CVE affects (--cve). Requires
// workspace-member standing.
func newCvesCmd() *cobra.Command {
	var (
		asJSON       bool
		node         string
		cve          string
		filter       string
		affectedOnly bool
		limit        int
		offset       int
	)
	cmd := &cobra.Command{
		Use:   "cves",
		Short: "Fleet CVE affectedness (rollup, or --node M / --cve CVE)",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			if node != "" && cve != "" {
				return fmt.Errorf("--node and --cve are mutually exclusive")
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

			switch {
			case node != "":
				resp, err := api.ListNodeCVEs(ctx, &genezav1.ListNodeCVEsRequest{
					NodeId: node, AffectedOnly: affectedOnly, Limit: int32(limit), Offset: int32(offset),
				})
				if err != nil {
					return client.Humanize(err)
				}
				if asJSON {
					return printJSON(resp)
				}
				rows := make([][]string, 0, len(resp.GetCves()))
				for _, c := range resp.GetCves() {
					rows = append(rows, nodeCVERow(c))
				}
				client.PrintTable(os.Stdout,
					[]string{"CVE", "PACKAGE", "STATUS", "SEVERITY", "FIXED-IN"}, rows)
				printPageHint(os.Stdout, len(rows), int(resp.GetTotal()), offset)
				return nil
			case cve != "":
				resp, err := api.ListNodesAffectedByCVE(ctx, &genezav1.ListNodesAffectedByCVERequest{
					Cve: cve, Limit: int32(limit), Offset: int32(offset),
				})
				if err != nil {
					return client.Humanize(err)
				}
				if asJSON {
					return printJSON(resp)
				}
				rows := make([][]string, 0, len(resp.GetNodes()))
				for _, n := range resp.GetNodes() {
					rows = append(rows, affectedNodeRow(n))
				}
				client.PrintTable(os.Stdout,
					[]string{"NODE", "PACKAGE", "STATUS", "FIXED-IN"}, rows)
				printPageHint(os.Stdout, len(rows), int(resp.GetTotal()), offset)
				return nil
			default:
				resp, err := api.ListWorkspaceCVEs(ctx, &genezav1.ListWorkspaceCVEsRequest{
					Cve: filter, Limit: int32(limit), Offset: int32(offset),
				})
				if err != nil {
					return client.Humanize(err)
				}
				if asJSON {
					return printJSON(resp)
				}
				rows := make([][]string, 0, len(resp.GetCves()))
				for _, c := range resp.GetCves() {
					rows = append(rows, workspaceCVERow(c))
				}
				client.PrintTable(os.Stdout,
					[]string{"CVE", "SEVERITY", "STATUS", "NODES", "FIXED-IN"}, rows)
				printPageHint(os.Stdout, len(rows), int(resp.GetTotal()), offset)
				return nil
			}
		},
	}
	cmd.Flags().BoolVar(&asJSON, "json", false, "JSON output")
	cmd.Flags().StringVar(&node, "node", "", "show the CVEs affecting this node")
	cmd.Flags().StringVar(&cve, "cve", "", "show the nodes affected by this CVE-id")
	cmd.Flags().StringVar(&filter, "filter", "", "filter the rollup by a CVE-id substring")
	cmd.Flags().BoolVar(&affectedOnly, "affected-only", false, "with --node, show only still-affected rows")
	cmd.Flags().IntVar(&limit, "limit", 0, "max rows per page (0 = server default)")
	cmd.Flags().IntVar(&offset, "offset", 0, "skip this many rows (paging)")
	return cmd
}

// workspaceCVERow is one row of the `geneza cves` rollup: the CVE, its severity,
// the representative status, the count of distinct affected nodes, and the
// fixing version.
func workspaceCVERow(c *genezav1.WorkspaceCVEInfo) []string {
	return []string{
		c.GetCve(),
		orDash(c.GetSeverity()),
		c.GetStatus(),
		fmt.Sprintf("%d", c.GetNodeCount()),
		orDash(c.GetFixedVersion()),
	}
}

// nodeCVERow is one row of `geneza cves --node`: the CVE, the affected
// package, the verdict status, a severity-with-triage cell, and the distro's
// fixed-in version.
func nodeCVERow(c *genezav1.NodeCVEInfo) []string {
	return []string{
		c.GetCve(),
		c.GetPurl(),
		c.GetStatus(),
		severityCell(c),
		orDash(c.GetFixedVersion()),
	}
}

// affectedNodeRow is one row of `geneza cves --cve`: the node, the affected
// package on it, the verdict status, and the fixed-in version.
func affectedNodeRow(c *genezav1.NodeCVEInfo) []string {
	return []string{
		c.GetNodeId(),
		c.GetPurl(),
		c.GetStatus(),
		orDash(c.GetFixedVersion()),
	}
}

// severityCell renders the severity plus an exploited/predicted hint so the most
// urgent rows stand out at a glance: KEV (a known-exploited CVE) and a high EPSS
// (exploit-prediction) are the operator's triage signals.
func severityCell(c *genezav1.NodeCVEInfo) string {
	s := c.GetSeverity()
	if s == "" {
		s = "-"
	}
	if c.GetKev() {
		s += " KEV"
	}
	if c.GetEpss() >= 0.5 {
		s += fmt.Sprintf(" epss=%.2f", c.GetEpss())
	}
	return s
}
