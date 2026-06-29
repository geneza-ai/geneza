package main

import (
	"context"
	"fmt"
	"os"
	"time"

	"github.com/spf13/cobra"

	"geneza.io/internal/client"
	"geneza.io/internal/enrollcode"

	genezav1 "geneza.io/internal/pb/geneza/v1"
)

// newNodeCmd groups the node lifecycle: enroll → approve → quarantine →
// retire, plus the pending roster and per-node monitoring.
func newNodeCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:     "node",
		Aliases: []string{"nodes"},
		Short:   "Node lifecycle: enroll, approve, quarantine, retire",
	}
	cmd.AddCommand(
		newNodeEnrollCmd(),
		newNodeApproveCmd(),
		newNodeQuarantineCmd(),
		newNodeRetireCmd(),
		newNodePendingCmd(),
		newNodeMonitorCmd(),
		newNodeInventoryCmd(),
	)
	return cmd
}

// newNodeEnrollCmd mints a one-time enrollment code and prints the ready-to-paste
// install one-liner. The code bundles the join token and the pinned root-key
// fingerprint — the fingerprint is what makes curl|bash safe: the new node
// refuses to install unless the root key it downloads hashes to the pinned value.
func newNodeEnrollCmd() *cobra.Command {
	var (
		ttl         time.Duration
		uses        int
		labels      string
		autoApprove bool
	)
	cmd := &cobra.Command{
		Use:   "enroll",
		Short: "Mint a one-time enrollment code and print the install one-liner",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			lbls, err := parseLabels(labels)
			if err != nil {
				return err
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
			resp, err := api.CreateJoinToken(ctx, &genezav1.CreateJoinTokenRequest{
				TtlSeconds:  int64(ttl.Seconds()),
				Labels:      lbls,
				MaxUses:     int32(uses),
				AutoApprove: autoApprove,
			})
			if err != nil {
				return client.Humanize(err)
			}
			fmt.Printf("Token:    %s\n", resp.GetToken())
			fmt.Printf("Expires:  %s\n", time.Unix(resp.GetExpiresUnix(), 0).Local().Format(time.RFC3339))
			if autoApprove {
				fmt.Println("Approval: AUTO (enrolled nodes are usable immediately)")
			} else {
				fmt.Println("Approval: PENDING (run `geneza node approve <node>` after enroll)")
			}
			if fp := resp.GetRootFingerprint(); fp != "" {
				// One opaque code carries the token + the pinned root fingerprint
				// (and, on split-front deploys, the endpoints). install.sh decodes it.
				code := enrollcode.Encode(enrollcode.Fields{Token: resp.GetToken(), RootFP: fp})
				fmt.Printf("\nRun this on the new node:\n  curl -fsSL %s/install.sh | sudo sh -s -- %s\n",
					e.Profile.ControllerHTTP, code)
				if !autoApprove {
					fmt.Println("\nThen approve it:  geneza node approve <node>   (watch arrivals: geneza node pending)")
				}
			} else {
				fmt.Println("\n(Controller serves no root pubkey; set root_pubkey_file + install_dir to enable curl|bash install.)")
			}
			return nil
		},
	}
	cmd.Flags().DurationVar(&ttl, "ttl", time.Hour, "code lifetime")
	cmd.Flags().IntVar(&uses, "uses", 1, "maximum enrollments with this code")
	cmd.Flags().StringVar(&labels, "labels", "", "labels stamped onto enrolling nodes (k=v,...)")
	cmd.Flags().BoolVar(&autoApprove, "auto-approve", false, "enrolled nodes are usable immediately (skip the admin approval gate)")
	return cmd
}

// newNodeApproveCmd builds `geneza node approve NODE` — flip a pending
// (or quarantined) node to approved so sessions can be brokered to it.
func newNodeApproveCmd() *cobra.Command {
	var reason string
	cmd := &cobra.Command{
		Use:   "approve NODE",
		Short: "Approve a pending or quarantined node (allow sessions to it)",
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
			if _, err := api.ApproveNode(ctx, &genezav1.ApproveNodeRequest{Node: args[0], Approve: true, Reason: reason}); err != nil {
				return client.Humanize(err)
			}
			fmt.Printf("approved %s\n", args[0])
			return nil
		},
	}
	cmd.Flags().StringVar(&reason, "reason", "", "human justification (required to re-approve a quarantined node)")
	return cmd
}

// newNodeQuarantineCmd builds `geneza node quarantine NODE` — revoke a
// node's approval, dropping its live sessions.
func newNodeQuarantineCmd() *cobra.Command {
	var reason string
	cmd := &cobra.Command{
		Use:   "quarantine NODE",
		Short: "Revoke a node's approval (kills its live sessions)",
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
			if _, err := api.ApproveNode(ctx, &genezav1.ApproveNodeRequest{Node: args[0], Approve: false, Reason: reason}); err != nil {
				return client.Humanize(err)
			}
			fmt.Printf("quarantined %s (approval revoked)\n", args[0])
			return nil
		},
	}
	cmd.Flags().StringVar(&reason, "reason", "", "reason for the manual quarantine (recorded in the audit log)")
	return cmd
}

// newNodeRetireCmd builds `geneza node retire NODE` — delete a node's
// record; it must re-enroll to return.
func newNodeRetireCmd() *cobra.Command {
	return &cobra.Command{
		Use:     "retire NODE",
		Aliases: []string{"rm", "remove", "decommission"},
		Short:   "Retire a node (delete its record; it must re-enroll to return)",
		Args:    cobra.ExactArgs(1),
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
			if _, err := api.RemoveNode(ctx, &genezav1.RemoveNodeRequest{Node: args[0]}); err != nil {
				return client.Humanize(err)
			}
			fmt.Printf("retired %s\n", args[0])
			return nil
		},
	}
}

// newNodePendingCmd builds `geneza node pending` — nodes awaiting
// approval or under an active drift quarantine, with the cause, so an operator
// knows what needs a `node approve`.
func newNodePendingCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "pending",
		Short: "List nodes awaiting approval or under quarantine (with cause)",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
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
			resp, err := api.ListNodes(ctx, &genezav1.ListNodesRequest{})
			if err != nil {
				return client.Humanize(err)
			}
			rows := make([][]string, 0)
			for _, nd := range resp.GetNodes() {
				state := ""
				switch {
				case nd.GetQuarantineReason() != "":
					state = "quarantined: " + nd.GetQuarantineReason()
				case !nd.GetApproved():
					state = "awaiting approval"
				default:
					continue
				}
				rows = append(rows, []string{nd.GetName(), nd.GetNodeId(), state, onlineStr(nd.GetOnline())})
			}
			client.PrintTable(os.Stdout, []string{"NAME", "NODE-ID", "STATE", "ONLINE"}, rows)
			if len(rows) == 0 {
				fmt.Println("no nodes are pending or quarantined")
			}
			return nil
		},
	}
}

func newNodeMonitorCmd() *cobra.Command {
	var (
		off      bool
		interval int
		show     bool
	)
	cmd := &cobra.Command{
		Use:   "monitor NODE",
		Short: "Enable/disable built-in monitoring (node-exporter) on a node",
		Long: "Toggle the embedded node-exporter module on a node. Metrics are scraped\n" +
			"on demand over the dial-out control channel (no listener is opened) and\n" +
			"forwarded to the controller's metrics store. --show prints the current modules.",
		Args: cobra.ExactArgs(1),
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

			if show {
				resp, err := api.GetNodeModules(ctx, &genezav1.GetNodeModulesRequest{Node: args[0]})
				if err != nil {
					return client.Humanize(err)
				}
				if len(resp.GetModules()) == 0 {
					fmt.Printf("%s: no modules configured\n", args[0])
					return nil
				}
				for _, m := range resp.GetModules() {
					state := "disabled"
					if m.GetEnabled() {
						state = "enabled"
					}
					fmt.Printf("%s: %s (%s) settings=%v\n", args[0], m.GetName(), state, m.GetSettings())
				}
				return nil
			}

			settings := map[string]string{}
			if interval > 0 {
				settings["scrape_interval_seconds"] = fmt.Sprintf("%d", interval)
			}
			// Merge, don't replace: toggling node-exporter must not wipe the
			// node's other modules (e.g. the default-on inventory module).
			if err := setNodeModuleMerged(ctx, api, args[0], "node-exporter", !off, settings); err != nil {
				return err
			}
			if off {
				fmt.Printf("Monitoring disabled on %s.\n", args[0])
			} else {
				fmt.Printf("Monitoring enabled on %s (node-exporter).\n", args[0])
			}
			return nil
		},
	}
	cmd.Flags().BoolVar(&off, "off", false, "disable monitoring instead of enabling")
	cmd.Flags().IntVar(&interval, "interval", 0, "scrape interval in seconds (default 15)")
	cmd.Flags().BoolVar(&show, "show", false, "show the node's current modules")
	return cmd
}
