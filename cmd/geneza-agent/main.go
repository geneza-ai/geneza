// geneza-agent is the per-node agent: 'enroll' bootstraps machine identity,
// 'worker' runs the control channel + data path, 'session-host' runs the
// separately supervised PTY owner (see sessionhost_cmd.go).
package main

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"github.com/spf13/cobra"

	"osie.cloud/geneza/internal/agentd"
	"osie.cloud/geneza/internal/defaults"
	"osie.cloud/geneza/internal/version"
)

var rootCmd = &cobra.Command{
	Use:           "geneza-agent",
	Short:         "Geneza node agent (enrollment, control channel, session data path)",
	SilenceUsage:  true,
	SilenceErrors: true,
}

func newLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelDebug}))
}

// signalContext cancels on SIGINT/SIGTERM so loops shut down cleanly.
func signalContext() context.Context {
	ctx, cancel := context.WithCancel(context.Background())
	ch := make(chan os.Signal, 1)
	signal.Notify(ch, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-ch
		cancel()
	}()
	return ctx
}

func parseLabels(s string) (map[string]string, error) {
	labels := map[string]string{}
	if s == "" {
		return labels, nil
	}
	for _, pair := range strings.Split(s, ",") {
		k, v, ok := strings.Cut(strings.TrimSpace(pair), "=")
		if !ok || k == "" {
			return nil, fmt.Errorf("bad label %q (want k=v,...)", pair)
		}
		labels[k] = v
	}
	return labels, nil
}

func enrollCmd() *cobra.Command {
	var (
		configPath string
		token      string
		gateway    string
		name       string
		labelsStr  string
		force      bool
	)
	cmd := &cobra.Command{
		Use:   "enroll",
		Short: "Enroll this node with the gateway (one-time token)",
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg, err := agentd.LoadConfig(configPath)
			if err != nil {
				return err
			}
			labels, err := parseLabels(labelsStr)
			if err != nil {
				return err
			}
			return agentd.Enroll(signalContext(), newLogger(), cfg, agentd.EnrollOptions{
				Token:   token,
				Gateway: gateway,
				Name:    name,
				Labels:  labels,
				Force:   force,
			})
		},
	}
	cmd.Flags().StringVar(&configPath, "config", defaults.EtcDir+"/agent.yaml", "agent config file")
	cmd.Flags().StringVar(&token, "token", "", "one-time join token (gz-...)")
	cmd.Flags().StringVar(&gateway, "gateway", "", "gateway gRPC address host:port (overrides config)")
	cmd.Flags().StringVar(&name, "name", "", "requested node name (default: hostname)")
	cmd.Flags().StringVar(&labelsStr, "labels", "", "node labels k=v,k2=v2 (merged over config labels)")
	cmd.Flags().BoolVar(&force, "force", false, "re-enroll even if a node identity already exists")
	return cmd
}

func workerCmd() *cobra.Command {
	var (
		configPath string
		noSpawn    bool
	)
	cmd := &cobra.Command{
		Use:   "worker",
		Short: "Run the agent worker (control channel + session data path)",
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg, err := agentd.LoadConfig(configPath)
			if err != nil {
				return err
			}
			w, err := agentd.NewWorker(newLogger(), cfg, noSpawn)
			if err != nil {
				return err
			}
			if err := w.Run(signalContext()); err != nil && err != context.Canceled {
				return err
			}
			return nil
		},
	}
	cmd.Flags().StringVar(&configPath, "config", defaults.EtcDir+"/agent.yaml", "agent config file")
	cmd.Flags().BoolVar(&noSpawn, "no-spawn-session-host", false,
		"do not spawn/supervise the session host (it is supervised externally, e.g. by the bootstrap)")
	return cmd
}

func versionCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "version",
		Short: "Print the agent version",
		Run: func(cmd *cobra.Command, args []string) {
			fmt.Println(version.Version)
		},
	}
}

func main() {
	rootCmd.AddCommand(enrollCmd(), workerCmd(), versionCmd())
	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}
