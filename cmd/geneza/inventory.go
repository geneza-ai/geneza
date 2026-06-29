package main

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"geneza.io/internal/client"

	genezav1 "geneza.io/internal/pb/geneza/v1"
)

// setNodeModuleMerged toggles ONE module on a node without clobbering the others:
// it reads the node's current (effective) module set, applies the change, and
// writes the full set back. SetNodeModules replaces the whole set, so callers
// must send everything they want to keep — this is the non-clobbering wrapper.
func setNodeModuleMerged(ctx context.Context, api genezav1.WorkspaceAPIClient, node, name string, enabled bool, settings map[string]string) error {
	cur, err := api.GetNodeModules(ctx, &genezav1.GetNodeModulesRequest{Node: node})
	if err != nil {
		return client.Humanize(err)
	}
	out := make([]*genezav1.ModuleSpec, 0, len(cur.GetModules())+1)
	found := false
	for _, m := range cur.GetModules() {
		if m.GetName() == name {
			found = true
			out = append(out, &genezav1.ModuleSpec{Name: name, Enabled: enabled, Settings: settings})
			continue
		}
		out = append(out, &genezav1.ModuleSpec{Name: m.GetName(), Enabled: m.GetEnabled(), Settings: m.GetSettings()})
	}
	if !found {
		out = append(out, &genezav1.ModuleSpec{Name: name, Enabled: enabled, Settings: settings})
	}
	if _, err := api.SetNodeModules(ctx, &genezav1.SetNodeModulesRequest{Node: node, Modules: out}); err != nil {
		return client.Humanize(err)
	}
	return nil
}

// newNodeInventoryCmd groups the per-node software inventory (SBOM): toggle the
// collector module, view the components, and export CycloneDX / OpenVEX. The
// inventory module is on by default; this is how an admin manages and reads it.
func newNodeInventoryCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "inventory",
		Short: "Per-node software inventory (SBOM): enable/disable, show, export",
	}
	cmd.AddCommand(
		newNodeInventoryToggleCmd(true),
		newNodeInventoryToggleCmd(false),
		newNodeInventoryShowCmd(),
		newNodeInventoryExportCmd(),
	)
	return cmd
}

// newNodeInventoryToggleCmd builds `node inventory enable|disable NODE`.
func newNodeInventoryToggleCmd(enable bool) *cobra.Command {
	use, short := "enable NODE", "Enable SBOM collection on a node (the inventory module)"
	if !enable {
		use, short = "disable NODE", "Disable SBOM collection on a node"
	}
	return &cobra.Command{
		Use:   use,
		Short: short,
		Args:  cobra.ExactArgs(1),
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
			if err := setNodeModuleMerged(ctx, api, args[0], "inventory", enable, nil); err != nil {
				return err
			}
			if enable {
				fmt.Printf("Inventory enabled on %s — the agent will report its SBOM shortly.\n", args[0])
			} else {
				fmt.Printf("Inventory disabled on %s.\n", args[0])
			}
			return nil
		},
	}
}

// newNodeInventoryShowCmd builds `node inventory show NODE` — list the node's
// collected components (the SBOM).
func newNodeInventoryShowCmd() *cobra.Command {
	var (
		asJSON bool
		limit  int
		offset int
	)
	cmd := &cobra.Command{
		Use:   "show NODE",
		Short: "List the software components collected from a node",
		Args:  cobra.ExactArgs(1),
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
			resp, err := api.ListNodeComponents(ctx, &genezav1.ListNodeComponentsRequest{
				NodeId: args[0], Limit: int32(limit), Offset: int32(offset),
			})
			if err != nil {
				return client.Humanize(err)
			}
			if asJSON {
				return printJSON(resp)
			}
			rows := make([][]string, 0, len(resp.GetComponents()))
			for _, c := range resp.GetComponents() {
				rows = append(rows, []string{
					c.GetName(), c.GetVersion(), orDash(c.GetEcosystem()), orDash(c.GetSource()), c.GetPurl(),
				})
			}
			client.PrintTable(os.Stdout, []string{"NAME", "VERSION", "ECOSYSTEM", "SOURCE", "PURL"}, rows)
			printPageHint(os.Stdout, len(rows), int(resp.GetTotal()), offset)
			if resp.GetTotal() == 0 {
				fmt.Println("no components reported yet — is the inventory module enabled? (geneza node inventory enable " + args[0] + ")")
			}
			return nil
		},
	}
	cmd.Flags().BoolVar(&asJSON, "json", false, "JSON output")
	cmd.Flags().IntVar(&limit, "limit", 0, "max rows per page (0 = server default)")
	cmd.Flags().IntVar(&offset, "offset", 0, "skip this many rows (paging)")
	return cmd
}

// newNodeInventoryExportCmd builds `node inventory export NODE` — fetch the
// node's CycloneDX SBOM (default) or OpenVEX findings from the controller's
// cert-authed :7402 endpoint, written to -o or stdout.
func newNodeInventoryExportCmd() *cobra.Command {
	var (
		vex     bool
		outFile string
	)
	cmd := &cobra.Command{
		Use:   "export NODE",
		Short: "Export a node's CycloneDX SBOM (default) or OpenVEX findings (--vex)",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			e, err := loadEnv()
			if err != nil {
				return err
			}
			cert, _, err := e.Store.ClientCert()
			if err != nil {
				return err
			}
			path := "sbom"
			if vex {
				path = "findings.vex"
			}
			base := strings.TrimRight(e.Profile.ControllerHTTP, "/")
			url := fmt.Sprintf("%s/api/v1/nodes/%s/%s", base, args[0], path)
			hc := client.MutualTLSHTTPClient(e.Pool, cert)
			req, err := http.NewRequestWithContext(cmd.Context(), http.MethodGet, url, nil)
			if err != nil {
				return err
			}
			resp, err := hc.Do(req)
			if err != nil {
				return fmt.Errorf("controller unreachable: %w", err)
			}
			defer resp.Body.Close()
			body, _ := io.ReadAll(resp.Body)
			if resp.StatusCode != http.StatusOK {
				return fmt.Errorf("export failed (HTTP %d): %s", resp.StatusCode, strings.TrimSpace(string(body)))
			}
			if outFile == "" || outFile == "-" {
				_, err = os.Stdout.Write(body)
				return err
			}
			if err := os.WriteFile(outFile, body, 0o644); err != nil {
				return err
			}
			fmt.Fprintf(os.Stderr, "wrote %s (%d bytes)\n", outFile, len(body))
			return nil
		},
	}
	cmd.Flags().BoolVar(&vex, "vex", false, "export OpenVEX findings instead of the CycloneDX SBOM")
	cmd.Flags().StringVarP(&outFile, "output", "o", "", "write to this file (default: stdout)")
	return cmd
}
