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

	"geneza.io/internal/defaults"
	"geneza.io/internal/relay"
	"geneza.io/internal/version"
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
	root.AddCommand(newDetectPublicIPCmd())

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

	// The bootstrap's "drain but keep serving" signal (SIGUSR1 on unix): the relay
	// sheds new work and lets its sessions migrate off (the controller proactively
	// re-homes them) while the listener stays up so in-flight flows ride out the
	// drain — distinct from SIGTERM, which drains AND force-closes after DrainTimeout.
	// The bootstrap sends it before a swap, waits for the relay to clear (drain-status
	// file -> active 0), then SIGTERMs it. Drain() is idempotent.
	notifyDrainSignal(ctx, log, r.Drain)

	// When bootstrap-supervised (health_file set), start touching the update
	// health file once the listener is actually bound and serving — the signal the
	// bootstrap's health gate watches to commit a relay self-update or roll it back.
	if cfg.HealthFile != "" {
		r.SetOnServing(func() { go relay.RunHealthFile(ctx, cfg.HealthFile, log) })
	}
	// The drain-status file is the bootstrap's drained gate: once the relay drains it
	// reports its falling active count here, and the bootstrap waits for 0 before the
	// swap. Start it eagerly (not gated on serving) so the file exists before any drain.
	if cfg.DrainStatusFile != "" {
		go relay.RunDrainStatusFile(ctx, cfg.DrainStatusFile, r, log)
	}

	// Heartbeat presence to the controller registrar in a regional deployment (no-op
	// when registrar_addr is unset, the single-node default). The relay is passed so
	// a control-mux relay can publish the verified controller routing table it learns.
	go relay.RunRegistrar(ctx, cfg, log, r)

	serveErr := make(chan error, 1)
	go func() { serveErr <- r.ListenAndServe() }()

	select {
	case err := <-serveErr:
		return err
	case <-ctx.Done():
		stop() // a second signal kills us the normal way
		log.Info("relay: signal received, draining", "timeout", cfg.DrainTimeout.String())
		// Advertise unhealthy first: the controller sheds this relay from new-session
		// selection (and the registrar re-registers healthy=false) while in-flight
		// flows keep running, then Shutdown drains them within the window and
		// force-closes. A second signal skips straight to force-close via stop().
		r.Drain()
		dctx, cancel := context.WithTimeout(context.Background(), cfg.DrainTimeout)
		defer cancel()
		_ = r.Shutdown(dctx)
		<-serveErr // Serve returns ErrClosed once the listener is closed
		return nil
	}
}
