// The session-host subcommand lives in its own file: it is the only place
// the agent binary touches internal/sessionhost (owned by another team), so
// the rest of cmd/geneza-agent stays buildable while that package evolves.
package main

import (
	"github.com/spf13/cobra"

	"osie.cloud/geneza/internal/defaults"
	"osie.cloud/geneza/internal/sessionhost"
	"osie.cloud/geneza/internal/version"
)

func init() {
	var (
		socket string
		spool  string
	)
	cmd := &cobra.Command{
		Use:   "session-host",
		Short: "Run the session host (PTY owner; supervised separately from the worker)",
		RunE: func(cmd *cobra.Command, args []string) error {
			return sessionhost.Run(version.Version, socket, spool)
		},
	}
	cmd.Flags().StringVar(&socket, "socket", defaults.SessionHostSock, "unix socket path for the session-host gRPC API")
	cmd.Flags().StringVar(&spool, "spool", defaults.VarDir+"/spool", "spool directory for session recordings")
	rootCmd.AddCommand(cmd)
}
