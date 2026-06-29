// Command genezactl is the cluster operator CLI: fleet-wide, non-tenant
// administration of a Geneza deployment — software releases and staggered
// rollouts, agent/relay versions, tenancy provisioning, certificate revocation,
// trust anchors, and policy. Tenant/workspace operations live in `geneza`. State
// lives under $GENEZA_HOME (default ~/.geneza)/<profile>/, shared with geneza.
package main

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"time"

	"github.com/spf13/cobra"

	"geneza.io/internal/client"
	"geneza.io/internal/version"

	genezav1 "geneza.io/internal/pb/geneza/v1"
)

var (
	flagProfile string
	flagVerbose bool
)

func main() {
	root := &cobra.Command{
		Use:           "genezactl",
		Short:         "Geneza cluster operator CLI — releases, relays, tenancy, trust",
		SilenceUsage:  true,
		SilenceErrors: true,
		PersistentPreRun: func(cmd *cobra.Command, args []string) {
			lvl := slog.LevelWarn
			if flagVerbose {
				lvl = slog.LevelDebug
			}
			slog.SetDefault(slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: lvl})))
		},
	}
	root.PersistentFlags().StringVar(&flagProfile, "profile", "default", "profile name under $GENEZA_HOME (~/.geneza)")
	root.PersistentFlags().BoolVarP(&flagVerbose, "verbose", "v", false, "debug logging")

	root.AddCommand(
		newVersionCmd(),
		newStatusCmd(),
		newReleaseCmd(),
		newWorkspaceCmd(),
		newCertCmd(),
		newTrustCmd(),
		newPolicyCmd(),
		newRelayCmd(),
	)

	if err := root.ExecuteContext(context.Background()); err != nil {
		fmt.Fprintln(os.Stderr, "genezactl:", err)
		os.Exit(1)
	}
}

func newVersionCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "version",
		Short: "Print the client version",
		Args:  cobra.NoArgs,
		Run: func(cmd *cobra.Command, args []string) {
			fmt.Printf("genezactl %s\n", version.Version)
		},
	}
}

// withAdmin loads the profile, dials the AdminAPI, and runs fn under a timeout —
// the connection boilerplate every cluster command shares. Streaming commands
// (publish) dial directly instead, since they manage their own deadline.
func withAdmin(ctx context.Context, timeout time.Duration, fn func(context.Context, genezav1.AdminAPIClient) error) error {
	e, err := client.LoadEnv(flagProfile)
	if err != nil {
		return err
	}
	cc, api, err := e.DialAdmin()
	if err != nil {
		return err
	}
	defer cc.Close()
	cctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	return fn(cctx, api)
}

// orDash renders an empty string as "-" in tables.
func orDash(s string) string {
	if s == "" {
		return "-"
	}
	return s
}

// onOff renders a bool as on/off.
func onOff(b bool) string {
	if b {
		return "on"
	}
	return "off"
}
