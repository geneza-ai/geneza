// Command geneza is the tenant operator CLI: the native, true end-to-end access
// path for a workspace's daily ops and workspace-scoped administration. State
// lives under $GENEZA_HOME (default ~/.geneza)/<profile>/. Cluster-wide
// administration (relays, releases, trust, tenancy) lives in genezactl.
package main

import (
	"context"
	"crypto/tls"
	"fmt"
	"log/slog"
	"os"

	"github.com/spf13/cobra"
	"google.golang.org/grpc"
	"google.golang.org/protobuf/proto"

	"geneza.io/internal/client"
	"geneza.io/internal/version"

	genezav1 "geneza.io/internal/pb/geneza/v1"
)

var (
	flagProfile    string
	flagVerbose    bool
	flagHomeRegion string
)

func main() {
	root := &cobra.Command{
		Use:           "geneza",
		Short:         "Geneza operator CLI — identity-aware, relay-based remote access",
		SilenceUsage:  true,
		SilenceErrors: true,
		PersistentPreRun: func(cmd *cobra.Command, args []string) {
			lvl := slog.LevelWarn
			if flagVerbose {
				lvl = slog.LevelDebug
			}
			slog.SetDefault(slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: lvl})))
			// Feed --home-region through the same GENEZA_HOME_REGION env path every
			// session builder reads, so one flag covers all session commands.
			if flagHomeRegion != "" {
				_ = os.Setenv("GENEZA_HOME_REGION", flagHomeRegion)
			}
		},
	}
	root.PersistentFlags().StringVar(&flagProfile, "profile", "default", "profile name under $GENEZA_HOME (~/.geneza)")
	root.PersistentFlags().BoolVarP(&flagVerbose, "verbose", "v", false, "debug logging")
	root.PersistentFlags().StringVar(&flagHomeRegion, "home-region", "", "declared client region for cross-region relay selection (or GENEZA_HOME_REGION)")

	root.AddCommand(
		// identity
		newLoginCmd(),
		newLogoutCmd(),
		newWhoamiCmd(),
		newVersionCmd(),
		newUpdateCmd(),
		// daily access
		newLsCmd(),
		newSSHCmd(),
		newExecCmd(),
		newCpCmd(),
		newConnectCmd(),
		newForwardCmd(),
		newVPNCmd(),
		newPsCmd(),
		newAttachCmd(),
		newKickCmd(),
		newCvesCmd(),
		// public exposure
		newExposeCmd(),
		newUnexposeCmd(),
		newExposedCmd(),
		// workspace administration, grouped by the object each acts on
		newNodeCmd(),
		newUserCmd(),
		newDomainCmd(),
		newAuditCmd(),
	)

	if err := root.ExecuteContext(context.Background()); err != nil {
		fmt.Fprintln(os.Stderr, "geneza:", err)
		os.Exit(1)
	}
}

func newVersionCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "version",
		Short: "Print the client version",
		Args:  cobra.NoArgs,
		Run: func(cmd *cobra.Command, args []string) {
			fmt.Printf("geneza %s\n", version.Version)
		},
	}
}

// The CLI plumbing lives in internal/client so both binaries (geneza and
// genezactl) share one implementation; these are thin, same-named forwarders
// that keep every command's call sites identical.

func loadEnv() (*client.Env, error) { return client.LoadEnv(flagProfile) }

func dialUser(e *client.Env) (*grpc.ClientConn, genezav1.UserAPIClient, *tls.Certificate, error) {
	return e.DialUser()
}

func dialAdmin(e *client.Env) (*grpc.ClientConn, genezav1.AdminAPIClient, error) {
	return e.DialAdmin()
}

func printJSON(m proto.Message) error   { return client.PrintJSON(m) }
func onlineStr(online bool) string      { return client.OnlineStr(online) }
func admissionStr(approved bool) string { return client.AdmissionStr(approved) }
func boolStr(b bool) string             { return client.BoolStr(b) }
