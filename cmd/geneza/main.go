// Command geneza is the operator CLI: the native, true end-to-end access
// path. State lives under $GENEZA_HOME (default ~/.geneza)/<profile>/.
package main

import (
	"context"
	"crypto/x509"
	"fmt"
	"log/slog"
	"os"

	"github.com/spf13/cobra"
	"google.golang.org/grpc"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"

	"golang.org/x/term"

	"osie.cloud/geneza/internal/client"
	"osie.cloud/geneza/internal/version"

	genezav1 "osie.cloud/geneza/internal/pb/geneza/v1"
)

var (
	flagProfile string
	flagVerbose bool
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
		},
	}
	root.PersistentFlags().StringVar(&flagProfile, "profile", "default", "profile name under $GENEZA_HOME (~/.geneza)")
	root.PersistentFlags().BoolVarP(&flagVerbose, "verbose", "v", false, "debug logging")

	root.AddCommand(
		newLoginCmd(),
		newLogoutCmd(),
		newWhoamiCmd(),
		newVersionCmd(),
		newLsCmd(),
		newSSHCmd(),
		newAttachCmd(),
		newSessionsCmd(),
		newExecCmd(),
		newCpCmd(),
		newForwardCmd(),
		newServicesCmd(),
		newConnectCmd(),
		newVPNCmd(),
		newResolveCmd(),
		newAdminCmd(),
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

// env bundles the loaded profile state every authenticated command needs.
type env struct {
	store   *client.Store
	profile *client.Profile
	pool    *x509.CertPool
}

func loadEnv() (*env, error) {
	st, err := client.NewStore(flagProfile)
	if err != nil {
		return nil, err
	}
	prof, err := st.LoadProfile()
	if err != nil {
		return nil, err
	}
	pool, err := st.LoadCAPool(prof.CASHA256)
	if err != nil {
		return nil, err
	}
	return &env{store: st, profile: prof, pool: pool}, nil
}

// dialUser opens the mTLS gRPC connection used by every post-login command.
func dialUser(e *env) (*grpc.ClientConn, genezav1.UserAPIClient, error) {
	cert, _, err := e.store.ClientCert()
	if err != nil {
		return nil, nil, err
	}
	cc, err := client.DialGateway(e.profile.GatewayGRPC, e.pool, cert)
	if err != nil {
		return nil, nil, err
	}
	return cc, genezav1.NewUserAPIClient(cc), nil
}

func dialAdmin(e *env) (*grpc.ClientConn, genezav1.AdminAPIClient, error) {
	cert, _, err := e.store.ClientCert()
	if err != nil {
		return nil, nil, err
	}
	cc, err := client.DialGateway(e.profile.GatewayGRPC, e.pool, cert)
	if err != nil {
		return nil, nil, err
	}
	return cc, genezav1.NewAdminAPIClient(cc), nil
}

// printJSON renders a proto message for --json scripting output.
func printJSON(m proto.Message) error {
	b, err := protojson.MarshalOptions{Multiline: true, Indent: "  "}.Marshal(m)
	if err != nil {
		return err
	}
	fmt.Println(string(b))
	return nil
}

// colorsEnabled honors NO_COLOR and only colors real terminals.
func colorsEnabled() bool {
	if os.Getenv("NO_COLOR") != "" {
		return false
	}
	return term.IsTerminal(int(os.Stdout.Fd()))
}

func colorize(s, code string) string {
	if !colorsEnabled() {
		return s
	}
	return "\x1b[" + code + "m" + s + "\x1b[0m"
}

func onlineStr(online bool) string {
	if online {
		return colorize("yes", "32")
	}
	return colorize("no", "31")
}

// admissionStr renders the zero-trust admission gate: approved machines can have
// sessions brokered to them; pending ones cannot until an admin approves.
func admissionStr(approved bool) string {
	if approved {
		return colorize("approved", "32")
	}
	return colorize("PENDING", "33")
}

func boolStr(b bool) string {
	if b {
		return "yes"
	}
	return "no"
}
