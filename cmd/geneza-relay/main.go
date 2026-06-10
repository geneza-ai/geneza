// Command geneza-relay runs the stateless, payload-blind rendezvous relay
// (ARCHITECTURE.md §4). It pairs endpoints by one-time token and splices
// ciphertext; it holds no keys and no session state.
package main

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"

	"github.com/spf13/cobra"

	"osie.cloud/geneza/internal/defaults"
	"osie.cloud/geneza/internal/relay"
	"osie.cloud/geneza/internal/version"
)

func main() {
	var configPath string

	root := &cobra.Command{
		Use:           "geneza-relay",
		Short:         "Geneza rendezvous relay (stateless, payload-blind)",
		Version:       version.Version,
		SilenceUsage:  true,
		SilenceErrors: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			return run(configPath)
		},
	}
	root.Flags().StringVar(&configPath, "config",
		filepath.Join(defaults.EtcDir, "relay.yaml"), "path to relay.yaml")

	root.AddCommand(&cobra.Command{
		Use:   "version",
		Short: "Print the relay version",
		Run: func(cmd *cobra.Command, args []string) {
			fmt.Println(version.Version)
		},
	})

	if err := root.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, "geneza-relay:", err)
		os.Exit(1)
	}
}

func run(configPath string) error {
	cfg, err := relay.Load(configPath)
	if err != nil {
		return err
	}
	log := slog.New(slog.NewTextHandler(os.Stderr, nil))
	slog.SetDefault(log)
	log.Info("geneza-relay starting", "version", version.Version, "config", configPath)

	r := relay.New(cfg, log)

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM, os.Interrupt)
	defer stop()

	serveErr := make(chan error, 1)
	go func() { serveErr <- r.ListenAndServe() }()

	select {
	case err := <-serveErr:
		return err
	case <-ctx.Done():
		stop() // a second signal kills us the normal way
		log.Info("relay: signal received, draining", "timeout", cfg.DrainTimeout.String())
		dctx, cancel := context.WithTimeout(context.Background(), cfg.DrainTimeout)
		defer cancel()
		_ = r.Shutdown(dctx)
		<-serveErr // Serve returns ErrClosed once the listener is closed
		return nil
	}
}
