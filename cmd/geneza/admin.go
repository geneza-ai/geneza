package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"osie.cloud/geneza/internal/client"
	"osie.cloud/geneza/internal/types"

	genezav1 "osie.cloud/geneza/internal/pb/geneza/v1"
)

func newAdminCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "admin",
		Short: "Fleet administration (requires the admin role)",
	}
	tokens := &cobra.Command{Use: "tokens", Short: "Join-token management"}
	tokens.AddCommand(newTokensNewCmd())
	nodes := &cobra.Command{Use: "nodes", Short: "Machine admission (approve / quarantine / remove)"}
	nodes.AddCommand(newNodeApproveCmd(true), newNodeApproveCmd(false), newNodeRemoveCmd())
	cmd.AddCommand(
		tokens,
		nodes,
		newFleetCmd(),
		newPublishCmd(),
		newDesiredCmd(),
		newPolicyReloadCmd(),
		newAuditCmd(),
		newRevokeCmd(),
		newMonitorCmd(),
	)
	return cmd
}

// newNodeRemoveCmd builds `admin nodes rm NODE` — decommission a machine.
func newNodeRemoveCmd() *cobra.Command {
	return &cobra.Command{
		Use:     "rm NODE",
		Aliases: []string{"remove", "delete"},
		Short:   "Decommission a machine (delete its record; it must re-enroll to return)",
		Args:    cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
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
			if _, err := api.RemoveNode(ctx, &genezav1.RemoveNodeRequest{Node: args[0]}); err != nil {
				return client.Humanize(err)
			}
			fmt.Printf("removed %s\n", args[0])
			return nil
		},
	}
}

// newNodeApproveCmd builds `admin nodes approve NODE` (approve=true) or
// `admin nodes deny NODE` (approve=false, re-quarantine a node).
func newNodeApproveCmd(approve bool) *cobra.Command {
	use, short := "approve NODE", "Approve a pending machine (allow sessions to it)"
	if !approve {
		use, short = "deny NODE", "Revoke a machine's approval (quarantine; kills its live sessions)"
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
			cc, api, err := dialAdmin(e)
			if err != nil {
				return err
			}
			defer cc.Close()
			ctx, cancel := context.WithTimeout(cmd.Context(), 30*time.Second)
			defer cancel()
			if _, err := api.ApproveNode(ctx, &genezav1.ApproveNodeRequest{Node: args[0], Approve: approve}); err != nil {
				return client.Humanize(err)
			}
			if approve {
				fmt.Printf("approved %s\n", args[0])
			} else {
				fmt.Printf("quarantined %s (approval revoked)\n", args[0])
			}
			return nil
		},
	}
}

func newMonitorCmd() *cobra.Command {
	var (
		off      bool
		interval int
		show     bool
	)
	cmd := &cobra.Command{
		Use:   "monitor NODE",
		Short: "Enable/disable built-in monitoring (node-exporter) on a machine",
		Long: "Toggle the embedded node-exporter module on a node. Metrics are scraped\n" +
			"on demand over the dial-out control channel (no listener is opened) and\n" +
			"stored in the gateway's embedded TSDB. --show prints the current modules.",
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
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
			spec := &genezav1.ModuleSpec{Name: "node-exporter", Enabled: !off, Settings: settings}
			if _, err := api.SetNodeModules(ctx, &genezav1.SetNodeModulesRequest{
				Node: args[0], Modules: []*genezav1.ModuleSpec{spec},
			}); err != nil {
				return client.Humanize(err)
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

func newRevokeCmd() *cobra.Command {
	var (
		user   string
		reason string
	)
	cmd := &cobra.Command{
		Use:   "revoke [session-id]",
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
				fmt.Printf("Revoked %d session(s) for user %s.\n", resp.GetRevoked(), user)
				return nil
			}
			if _, err := api.RevokeSession(ctx, &genezav1.RevokeSessionRequest{SessionId: args[0], Reason: reason}); err != nil {
				return client.Humanize(err)
			}
			fmt.Printf("Revoked session %s.\n", args[0])
			return nil
		},
	}
	cmd.Flags().StringVar(&user, "user", "", "revoke all sessions for this user")
	cmd.Flags().StringVar(&reason, "reason", "", "reason (audited)")
	return cmd
}

func parseLabels(s string) (map[string]string, error) {
	if s == "" {
		return nil, nil
	}
	out := map[string]string{}
	for _, kv := range strings.Split(s, ",") {
		k, v, ok := strings.Cut(strings.TrimSpace(kv), "=")
		if !ok || k == "" {
			return nil, fmt.Errorf("bad label %q (want k=v,...)", kv)
		}
		out[k] = v
	}
	return out, nil
}

func newTokensNewCmd() *cobra.Command {
	var (
		ttl         time.Duration
		uses        int
		labels      string
		autoApprove bool
	)
	cmd := &cobra.Command{
		Use:   "new",
		Short: "Mint a one-time enrollment token",
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
			cc, api, err := dialAdmin(e)
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
				fmt.Println("Approval: AUTO (enrolled machines are usable immediately)")
			} else {
				fmt.Println("Approval: pending (run `geneza admin nodes approve <id>` after enroll)")
			}
			// Convenience: print the ready-to-paste curl|bash one-liner. The
			// --root-fp pin (from the gateway) is what makes curl|bash safe — the
			// new machine verifies the trust anchor it downloads at bootstrap.
			if fp := resp.GetRootFingerprint(); fp != "" {
				grpc := e.profile.GatewayGRPC
				fmt.Printf("\nInstall on the new machine:\n  curl -fsSL %s/install.sh | sudo bash -s -- \\\n      --token %s --root-fp %s --gateway-grpc %s\n",
					e.profile.GatewayHTTP, resp.GetToken(), fp, grpc)
			} else {
				fmt.Println("\n(Gateway serves no root pubkey; set root_pubkey_file + install_dir to enable curl|bash install.)")
			}
			return nil
		},
	}
	cmd.Flags().DurationVar(&ttl, "ttl", time.Hour, "token lifetime")
	cmd.Flags().IntVar(&uses, "uses", 1, "maximum enrollments with this token")
	cmd.Flags().StringVar(&labels, "labels", "", "labels stamped onto enrolling nodes (k=v,...)")
	cmd.Flags().BoolVar(&autoApprove, "auto-approve", false, "enrolled nodes are usable immediately (skip the admin approval gate)")
	return cmd
}

func newFleetCmd() *cobra.Command {
	var asJSON bool
	cmd := &cobra.Command{
		Use:   "fleet",
		Short: "Fleet status: nodes plus desired versions per ring",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
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
			resp, err := api.GetFleetStatus(ctx, &genezav1.Empty{})
			if err != nil {
				return client.Humanize(err)
			}
			if asJSON {
				return printJSON(resp)
			}
			fmt.Printf("Desired versions: stable=%s canary=%s\n",
				orDash(resp.GetStableVersion()), orDash(resp.GetCanaryVersion()))
			if len(resp.GetCanaryNodes()) > 0 {
				fmt.Printf("Canary nodes:     %s\n", strings.Join(resp.GetCanaryNodes(), ", "))
			}
			fmt.Println()
			rows := make([][]string, 0, len(resp.GetNodes()))
			for _, n := range resp.GetNodes() {
				rows = append(rows, []string{
					n.GetName(),
					n.GetNodeId(),
					admissionStr(n.GetApproved()),
					onlineStr(n.GetOnline()),
					n.GetVersion(),
					n.GetOs() + "/" + n.GetArch(),
					client.FormatLabels(n.GetLabels()),
					client.Ago(n.GetLastSeenUnix()),
				})
			}
			client.PrintTable(os.Stdout,
				[]string{"NAME", "NODE-ID", "ADMISSION", "ONLINE", "VERSION", "PLATFORM", "LABELS", "LAST-SEEN"}, rows)
			return nil
		},
	}
	cmd.Flags().BoolVar(&asJSON, "json", false, "JSON output")
	return cmd
}

func orDash(s string) string {
	if s == "" {
		return "-"
	}
	return s
}

const publishChunkSize = 64 * 1024

func newPublishCmd() *cobra.Command {
	var (
		manifestPath string
		binaryPath   string
	)
	cmd := &cobra.Command{
		Use:   "publish --manifest signed.json --binary PATH",
		Short: "Upload an offline-signed agent artifact to the gateway",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			manifestBytes, err := os.ReadFile(manifestPath)
			if err != nil {
				return err
			}
			// Sanity-check locally before shipping: the envelope must decode
			// and its payload must be a Manifest. (Signature verification is
			// the gateway's and the bootstrap's job — the CLI may not even
			// know the artifact key.)
			signed, err := types.DecodeSigned(manifestBytes)
			if err != nil {
				return fmt.Errorf("%s: %w", manifestPath, err)
			}
			var m types.Manifest
			if err := json.Unmarshal(signed.Payload, &m); err != nil {
				return fmt.Errorf("%s: payload is not a manifest: %w", manifestPath, err)
			}

			f, err := os.Open(binaryPath)
			if err != nil {
				return err
			}
			defer f.Close()

			e, err := loadEnv()
			if err != nil {
				return err
			}
			cc, api, err := dialAdmin(e)
			if err != nil {
				return err
			}
			defer cc.Close()

			stream, err := api.PublishArtifact(cmd.Context())
			if err != nil {
				return client.Humanize(err)
			}
			// Manifest first, then 64KB data chunks, then EOF.
			if err := stream.Send(&genezav1.ArtifactChunk{SignedManifest: manifestBytes}); err != nil {
				return client.Humanize(err)
			}
			buf := make([]byte, publishChunkSize)
			var sent int64
			for {
				n, rerr := f.Read(buf)
				if n > 0 {
					if err := stream.Send(&genezav1.ArtifactChunk{Data: buf[:n]}); err != nil {
						return client.Humanize(err)
					}
					sent += int64(n)
				}
				if rerr == io.EOF {
					break
				}
				if rerr != nil {
					return rerr
				}
			}
			if err := stream.Send(&genezav1.ArtifactChunk{Eof: true}); err != nil {
				return client.Humanize(err)
			}
			resp, err := stream.CloseAndRecv()
			if err != nil {
				return client.Humanize(err)
			}
			fmt.Printf("Published %s %s (%s/%s): %d bytes, sha256 %s\n",
				m.Product, resp.GetVersion(), m.OS, m.Arch, sent, resp.GetSha256())
			return nil
		},
	}
	cmd.Flags().StringVar(&manifestPath, "manifest", "", "offline-signed manifest (types.Signed JSON)")
	cmd.Flags().StringVar(&binaryPath, "binary", "", "agent binary blob")
	cmd.MarkFlagRequired("manifest") //nolint:errcheck
	cmd.MarkFlagRequired("binary")   //nolint:errcheck
	return cmd
}

func newDesiredCmd() *cobra.Command {
	var (
		ring        string
		ver         string
		canaryNodes string
	)
	cmd := &cobra.Command{
		Use:   "desired --ring stable|canary --version V",
		Short: "Set the desired agent version for a rollout ring",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			if ring != "stable" && ring != "canary" {
				return errors.New("--ring must be stable or canary")
			}
			var nodes []string
			if canaryNodes != "" {
				for _, n := range strings.Split(canaryNodes, ",") {
					if n = strings.TrimSpace(n); n != "" {
						nodes = append(nodes, n)
					}
				}
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
			if _, err := api.SetDesiredVersion(ctx, &genezav1.SetDesiredVersionRequest{
				Ring:        ring,
				Version:     ver,
				CanaryNodes: nodes,
			}); err != nil {
				return client.Humanize(err)
			}
			fmt.Printf("Desired version for %s set to %s\n", ring, ver)
			return nil
		},
	}
	cmd.Flags().StringVar(&ring, "ring", "", "rollout ring: stable|canary")
	cmd.Flags().StringVar(&ver, "version", "", "desired agent version")
	cmd.Flags().StringVar(&canaryNodes, "canary-nodes", "", "set canary ring membership (node ids, comma-separated)")
	cmd.MarkFlagRequired("ring")    //nolint:errcheck
	cmd.MarkFlagRequired("version") //nolint:errcheck
	return cmd
}

func newPolicyReloadCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "policy-reload",
		Short: "Reload the gateway policy document",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
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
			if _, err := api.ReloadPolicy(ctx, &genezav1.Empty{}); err != nil {
				return client.Humanize(err)
			}
			fmt.Println("Policy reloaded.")
			return nil
		},
	}
}

func newAuditCmd() *cobra.Command {
	var (
		since      time.Duration
		limit      int
		typeFilter string
	)
	cmd := &cobra.Command{
		Use:   "audit",
		Short: "Query the hash-chained audit log",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			e, err := loadEnv()
			if err != nil {
				return err
			}
			cc, api, err := dialAdmin(e)
			if err != nil {
				return err
			}
			defer cc.Close()
			ctx, cancel := context.WithTimeout(cmd.Context(), 60*time.Second)
			defer cancel()
			resp, err := api.QueryAudit(ctx, &genezav1.QueryAuditRequest{
				SinceUnix:  time.Now().Add(-since).Unix(),
				TypeFilter: typeFilter,
				Limit:      int32(limit),
			})
			if err != nil {
				return client.Humanize(err)
			}
			for _, r := range resp.GetRecords() {
				fmt.Println(strings.TrimRight(string(r.GetJson()), "\n"))
			}
			if !resp.GetChainOk() {
				// Tamper evidence is the whole point of the chain: scream.
				fmt.Fprintln(os.Stderr, "audit: HASH CHAIN BROKEN — records may have been tampered with")
				os.Exit(1)
			}
			fmt.Fprintf(os.Stderr, "audit: %d records, hash chain OK\n", len(resp.GetRecords()))
			return nil
		},
	}
	cmd.Flags().DurationVar(&since, "since", time.Hour, "how far back to query")
	cmd.Flags().IntVar(&limit, "limit", 100, "maximum records")
	cmd.Flags().StringVar(&typeFilter, "type", "", "filter by record type")
	return cmd
}
