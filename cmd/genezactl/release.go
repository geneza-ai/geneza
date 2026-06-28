package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"geneza.io/internal/client"
	"geneza.io/internal/types"

	genezav1 "geneza.io/internal/pb/geneza/v1"
)

// newReleaseCmd groups fleet software-version management: publish a signed
// artifact, pin the target version a ring converges to, and drive the staggered
// rollout. Agent and relay are two products under one set of verbs.
func newReleaseCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "release",
		Short: "Fleet software versions: publish, target, rollout (agent + relay)",
	}
	cmd.AddCommand(newReleasePublishCmd(), newReleaseTargetCmd(), newReleaseRolloutCmd())
	return cmd
}

// normalizeProduct maps the short `--product agent|relay` (and the long
// geneza-agent|geneza-relay) onto the canonical product name the controller
// keys rollout rings by. The controller treats "" and geneza-agent identically.
func normalizeProduct(p string) (string, error) {
	switch p {
	case "", "agent", "geneza-agent":
		return "geneza-agent", nil
	case "relay", "geneza-relay":
		return "geneza-relay", nil
	default:
		return "", fmt.Errorf("--product must be agent or relay (got %q)", p)
	}
}

const publishChunkSize = 64 * 1024

func newReleasePublishCmd() *cobra.Command {
	var (
		manifestPath string
		binaryPath   string
	)
	cmd := &cobra.Command{
		Use:   "publish --manifest signed.json --binary PATH",
		Short: "Upload an offline-signed agent/relay artifact to the controller",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			manifestBytes, err := os.ReadFile(manifestPath)
			if err != nil {
				return err
			}
			// Sanity-check locally before shipping: the envelope must decode
			// and its payload must be a Manifest. (Signature verification is
			// the controller's and the bootstrap's job — the CLI may not even
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

			e, err := client.LoadEnv(flagProfile)
			if err != nil {
				return err
			}
			cc, api, err := e.DialAdmin()
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
	cmd.Flags().StringVar(&binaryPath, "binary", "", "artifact binary blob")
	cmd.MarkFlagRequired("manifest") //nolint:errcheck
	cmd.MarkFlagRequired("binary")   //nolint:errcheck
	return cmd
}

// newReleaseTargetCmd builds `genezactl release target` — set (or --show) the
// target version a product's rollout ring converges to. It merges what used to
// be two commands (agent desired + relay-update) behind one --product flag.
func newReleaseTargetCmd() *cobra.Command {
	var (
		product     string
		ring        string
		ver         string
		canaryNodes string
		show        bool
	)
	cmd := &cobra.Command{
		Use:   "target --product agent|relay --ring stable|canary --version V",
		Short: "Set (or --show) the target version a rollout ring converges to",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			prod, err := normalizeProduct(product)
			if err != nil {
				return err
			}
			return withAdmin(cmd.Context(), 30*time.Second, func(ctx context.Context, api genezav1.AdminAPIClient) error {
				if show {
					st, err := api.GetFleetStatus(ctx, &genezav1.Empty{})
					if err != nil {
						return client.Humanize(err)
					}
					if prod == "geneza-relay" {
						fmt.Printf("relay stable: %s\nrelay canary: %s\nrelay canary relays: %s\n",
							orDash(st.GetRelayStableVersion()), orDash(st.GetRelayCanaryVersion()),
							orDash(strings.Join(st.GetRelayCanaryNodes(), ",")))
						return nil
					}
					fmt.Printf("agent stable: %s\nagent canary: %s\nagent canary nodes: %s\n",
						orDash(st.GetStableVersion()), orDash(st.GetCanaryVersion()),
						orDash(strings.Join(st.GetCanaryNodes(), ",")))
					return nil
				}

				if ring != "stable" && ring != "canary" {
					return errors.New("--ring must be stable or canary (or pass --show)")
				}
				var nodes []string
				if canaryNodes != "" {
					for _, n := range strings.Split(canaryNodes, ",") {
						if n = strings.TrimSpace(n); n != "" {
							nodes = append(nodes, n)
						}
					}
				}
				if _, err := api.SetDesiredVersion(ctx, &genezav1.SetDesiredVersionRequest{
					Product:     prod,
					Ring:        ring,
					Version:     ver,
					CanaryNodes: nodes,
				}); err != nil {
					return client.Humanize(err)
				}
				fmt.Printf("target %s version for %s set to %s\n", product, ring, ver)
				return nil
			})
		},
	}
	cmd.Flags().StringVar(&product, "product", "agent", "product ring: agent|relay")
	cmd.Flags().StringVar(&ring, "ring", "", "rollout ring: stable|canary")
	cmd.Flags().StringVar(&ver, "version", "", "target version")
	cmd.Flags().StringVar(&canaryNodes, "canary-nodes", "", "set canary ring membership (ids, comma-separated)")
	cmd.Flags().BoolVar(&show, "show", false, "print the current rollout ring and exit")
	return cmd
}

func newReleaseRolloutCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "rollout",
		Short: "Drive a staggered, health-gated rollout of a product (agent/relay)",
	}
	cmd.AddCommand(
		newRolloutStartCmd(),
		newRolloutStatusCmd(),
		newRolloutControlCmd("pause", "Pause an active rollout (ring left as-is)"),
		newRolloutControlCmd("resume", "Resume a paused or halted rollout (re-soaks the current wave)"),
		newRolloutControlCmd("abort", "Abort a rollout and revert the ring to the prior stable"),
		newRolloutAutoCmd(),
	)
	return cmd
}

func parseWaves(s string) ([]int32, error) {
	if strings.TrimSpace(s) == "" {
		return nil, nil
	}
	var out []int32
	for _, p := range strings.Split(s, ",") {
		n, err := strconv.Atoi(strings.TrimSpace(p))
		if err != nil {
			return nil, fmt.Errorf("invalid wave percentage %q", p)
		}
		out = append(out, int32(n))
	}
	return out, nil
}

func printRollout(r *genezav1.RolloutStatusResponse) {
	if !r.GetPresent() {
		fmt.Printf("%s: no rollout in progress (auto-update %s)\n", r.GetProduct(), onOff(r.GetAutoUpdate()))
		return
	}
	curPct := int32(0)
	if int(r.GetWaveIdx()) < len(r.GetWaves()) {
		curPct = r.GetWaves()[r.GetWaveIdx()]
	}
	fmt.Printf("%s rollout → %s\n", r.GetProduct(), r.GetTarget())
	fmt.Printf("  state:       %s (%s)\n", r.GetState(), r.GetTrigger())
	fmt.Printf("  wave:        %d/%d at %d%%  (members %d, healthy %d, eligible %d)\n",
		r.GetWaveIdx()+1, len(r.GetWaves()), curPct, r.GetWaveMembers(), r.GetWaveHealthy(), r.GetEligibleCount())
	fmt.Printf("  soak:        %ds (remaining %ds), wave-timeout %ds\n",
		r.GetSoakSeconds(), r.GetSoakRemainingSeconds(), r.GetWaveTimeoutSeconds())
	if len(r.GetBlockers()) > 0 {
		fmt.Printf("  blockers:    %s\n", strings.Join(r.GetBlockers(), "; "))
	}
	if r.GetHaltReason() != "" {
		fmt.Printf("  halt reason: %s\n", r.GetHaltReason())
	}
	fmt.Printf("  auto-update: %s\n", onOff(r.GetAutoUpdate()))
}

func newRolloutStartCmd() *cobra.Command {
	var (
		product  string
		version  string
		wavesStr string
		soak     time.Duration
		waveTO   time.Duration
	)
	cmd := &cobra.Command{
		Use:   "start --version V [--product agent|relay] [--waves 10,50,100] [--soak 2m] [--wave-timeout 10m]",
		Short: "Start a staggered rollout to a published version",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if version == "" {
				return errors.New("--version is required")
			}
			prod, err := normalizeProduct(product)
			if err != nil {
				return err
			}
			waves, err := parseWaves(wavesStr)
			if err != nil {
				return err
			}
			return withAdmin(cmd.Context(), 30*time.Second, func(ctx context.Context, api genezav1.AdminAPIClient) error {
				resp, err := api.StartRollout(ctx, &genezav1.StartRolloutRequest{
					Product:            prod,
					Version:            version,
					Waves:              waves,
					SoakSeconds:        int64(soak.Seconds()),
					WaveTimeoutSeconds: int64(waveTO.Seconds()),
				})
				if err != nil {
					return client.Humanize(err)
				}
				printRollout(resp)
				return nil
			})
		},
	}
	cmd.Flags().StringVar(&product, "product", "agent", "product ring: agent|relay")
	cmd.Flags().StringVar(&version, "version", "", "target version (must be published, != stable)")
	cmd.Flags().StringVar(&wavesStr, "waves", "", "cumulative wave percentages, e.g. 10,50,100 (default 10,50,100)")
	cmd.Flags().DurationVar(&soak, "soak", 0, "per-wave continuous-health dwell (default 2m)")
	cmd.Flags().DurationVar(&waveTO, "wave-timeout", 0, "halt/abort if a wave doesn't go healthy within this (default 10m)")
	return cmd
}

func newRolloutStatusCmd() *cobra.Command {
	var product string
	cmd := &cobra.Command{
		Use:   "status [--product agent|relay]",
		Short: "Show a product's rollout status",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			prod, err := normalizeProduct(product)
			if err != nil {
				return err
			}
			return withAdmin(cmd.Context(), 30*time.Second, func(ctx context.Context, api genezav1.AdminAPIClient) error {
				resp, err := api.GetRolloutStatus(ctx, &genezav1.RolloutControlRequest{Product: prod})
				if err != nil {
					return client.Humanize(err)
				}
				printRollout(resp)
				return nil
			})
		},
	}
	cmd.Flags().StringVar(&product, "product", "agent", "product ring: agent|relay")
	return cmd
}

func newRolloutControlCmd(verb, short string) *cobra.Command {
	var product string
	cmd := &cobra.Command{
		Use:   verb + " [--product agent|relay]",
		Short: short,
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			prod, err := normalizeProduct(product)
			if err != nil {
				return err
			}
			return withAdmin(cmd.Context(), 30*time.Second, func(ctx context.Context, api genezav1.AdminAPIClient) error {
				req := &genezav1.RolloutControlRequest{Product: prod}
				var resp *genezav1.RolloutStatusResponse
				var cerr error
				switch verb {
				case "pause":
					resp, cerr = api.PauseRollout(ctx, req)
				case "resume":
					resp, cerr = api.ResumeRollout(ctx, req)
				case "abort":
					resp, cerr = api.AbortRollout(ctx, req)
				}
				if cerr != nil {
					return client.Humanize(cerr)
				}
				printRollout(resp)
				return nil
			})
		},
	}
	cmd.Flags().StringVar(&product, "product", "agent", "product ring: agent|relay")
	return cmd
}

func newRolloutAutoCmd() *cobra.Command {
	var product string
	cmd := &cobra.Command{
		Use:   "auto on|off [--product agent|relay]",
		Short: "Enable/disable auto-rollout when a newer version is published",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			var enabled bool
			switch args[0] {
			case "on", "true", "enable":
				enabled = true
			case "off", "false", "disable":
				enabled = false
			default:
				return errors.New("argument must be on or off")
			}
			prod, err := normalizeProduct(product)
			if err != nil {
				return err
			}
			return withAdmin(cmd.Context(), 30*time.Second, func(ctx context.Context, api genezav1.AdminAPIClient) error {
				if _, err := api.SetAutoUpdate(ctx, &genezav1.SetAutoUpdateRequest{Product: prod, Enabled: enabled}); err != nil {
					return client.Humanize(err)
				}
				fmt.Printf("auto-update for %s: %s\n", product, onOff(enabled))
				return nil
			})
		},
	}
	cmd.Flags().StringVar(&product, "product", "agent", "product ring: agent|relay")
	return cmd
}
