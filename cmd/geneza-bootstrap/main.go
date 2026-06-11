// geneza-bootstrap is the tiny stage-1 of the two-stage agent
// (ARCHITECTURE.md §9). It is the ONLY thing installed by the OS package and
// it almost never changes. It does exactly four jobs: verify offline
// signatures against the pinned artifact key, swap worker binaries
// atomically, supervise the worker and session host, and roll back on a
// failed health gate.
//
// Dependency budget (enforced by review, the point of this file's
// smallness): Go stdlib + internal/types + internal/version +
// internal/update (which itself is stdlib + types + defaults). No gRPC, no
// cobra, no YAML.
//
// The session host is supervised here, NOT by the worker, so a worker swap
// never kills live PTYs: updates stop/start only the worker.
package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"syscall"
	"time"

	"osie.cloud/geneza/internal/types"
	"osie.cloud/geneza/internal/update"
	"osie.cloud/geneza/internal/version"
)

func main() {
	cfgPath := flag.String("config", "/etc/geneza/bootstrap.json", "bootstrap config (JSON)")
	flag.Parse()

	log := slog.New(slog.NewTextHandler(os.Stderr, nil))
	log.Info("geneza-bootstrap starting", "version", version.Version, "config", *cfgPath, "platform", runtime.GOOS+"/"+runtime.GOARCH)

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
	defer stop()

	if err := run(ctx, *cfgPath, log); err != nil {
		log.Error("bootstrap exiting with error", "err", err)
		os.Exit(1)
	}
	log.Info("geneza-bootstrap stopped")
}

type bootstrap struct {
	cfg       *config
	log       *slog.Logger
	client    *http.Client
	installer *update.Installer
	nodeID    string

	mu      sync.Mutex
	current string // version whose binary the worker runs / session host restarts from
	st      *update.State

	worker      *update.Supervisor
	sessionHost *update.Supervisor
	lastDesired string // last desired version observed (for bad-list reset)
}

func run(ctx context.Context, cfgPath string, log *slog.Logger) error {
	cfg, err := loadConfig(cfgPath)
	if err != nil {
		return err
	}

	// The pinned artifact public key is the root of binary trust. No key, no
	// start — running without it would mean trusting gateway TLS alone,
	// which is exactly the failure mode §9 exists to prevent.
	pub, err := types.LoadPublicKeyPEM(cfg.ArtifactPubFile)
	if err != nil {
		return fmt.Errorf("pinned artifact public key (artifact_pub_file): %w", err)
	}
	log.Info("pinned artifact signing key loaded", "key_id", types.KeyIDFor(pub), "file", cfg.ArtifactPubFile)

	client, err := update.NewHTTPClient(cfg.CARootsFile, log)
	if err != nil {
		return err
	}

	for _, d := range []string{cfg.VersionsDir, cfg.RunDir, cfg.SpoolDir, filepath.Dir(cfg.StateFile), filepath.Dir(cfg.NodeIDFile)} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			return err
		}
	}

	st, err := update.LoadState(cfg.StateFile)
	if err != nil {
		// A corrupt state file must not brick the node: log loudly, start
		// from empty state, and let adoption/reconcile re-establish truth.
		log.Error("state file unreadable; starting from empty state", "file", cfg.StateFile, "err", err)
		st = &update.State{}
	}

	b := &bootstrap{
		cfg:    cfg,
		log:    log,
		client: client,
		st:     st,
		nodeID: nodeID(cfg, log),
		installer: &update.Installer{
			Client:      client,
			GatewayURL:  cfg.GatewayHTTPURL,
			Pub:         pub,
			Product:     "geneza-agent",
			OS:          runtime.GOOS,
			Arch:        runtime.GOARCH,
			VersionsDir: cfg.VersionsDir,
			Log:         log,
		},
	}

	if err := b.resolveCurrent(ctx); err != nil {
		return err
	}
	log.Info("current worker version resolved", "version", b.current, "binary", b.binPath(b.current))

	b.startChildren()
	defer b.stopChildren()

	ticker := time.NewTicker(cfg.pollInterval())
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			log.Info("shutdown signal received")
			return nil
		case <-ticker.C:
			b.reconcile(ctx)
		}
	}
}

func nodeID(cfg *config, log *slog.Logger) string {
	if b, err := os.ReadFile(cfg.NodeIDFile); err == nil {
		if id := strings.TrimSpace(string(b)); id != "" {
			return id
		}
	}
	// Pre-enrollment (the worker writes node-id after enrolling) the
	// hostname is good enough for the desired-version poll.
	hn, err := os.Hostname()
	if err != nil || hn == "" {
		hn = "unknown"
	}
	log.Info("no node-id file yet; using hostname for update polls", "node", hn)
	return hn
}

func (b *bootstrap) binPath(v string) string {
	return filepath.Join(b.cfg.VersionsDir, v, "geneza-agent")
}

func (b *bootstrap) currentBinPath() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.binPath(b.current)
}

func (b *bootstrap) saveState() {
	if err := b.st.Save(b.cfg.StateFile); err != nil {
		b.log.Error("failed to persist updater state", "file", b.cfg.StateFile, "err", err)
	}
}

// resolveCurrent determines which worker version to run, in priority order:
// persisted state, a deploy-seeded single version dir, or — on a completely
// blank node — polling the gateway until an installable version appears.
func (b *bootstrap) resolveCurrent(ctx context.Context) error {
	if b.st.Current != "" {
		p := b.binPath(b.st.Current)
		if fi, err := os.Stat(p); err == nil && fi.Mode().IsRegular() {
			b.current = b.st.Current
			return nil
		}
		b.log.Error("state names a version whose binary is missing; falling back to adoption/poll",
			"version", b.st.Current, "binary", p)
	}

	if v, ok := adoptSeeded(b.cfg.VersionsDir); ok {
		b.log.Info("adopting deploy-seeded worker version", "version", v)
		b.current = v
		b.st.Current = v
		b.saveState()
		return nil
	}

	b.log.Info("no local worker found; polling gateway for first install", "gateway", b.cfg.GatewayHTTPURL)
	for {
		d, err := b.fetchDesired(ctx)
		switch {
		case err != nil:
			b.log.Warn("desired-version poll failed", "err", err)
		case d == nil:
			b.log.Info("gateway has no desired version for this node yet")
		case d.SignedManifest == nil:
			b.log.Warn("gateway desires a version but provided no signed manifest", "version", d.Version)
		default:
			b.installer.MinCreatedAt = b.floorTime()
			if _, m, err := b.installer.Install(ctx, d.SignedManifest); err != nil {
				b.log.Error("first install failed; will retry", "version", d.Version, "err", err)
			} else {
				b.current = m.Version
				b.st.Current = m.Version
				b.st.RaiseFloor(m.CreatedAt.Unix())
				b.saveState()
				return nil
			}
		}
		select {
		case <-ctx.Done():
			return fmt.Errorf("terminated before a worker could be installed: %w", ctx.Err())
		case <-time.After(b.cfg.pollInterval()):
		}
	}
}

// adoptSeeded returns the single version present under versionsDir, if there
// is exactly one containing a geneza-agent binary (image-baked deployments).
func adoptSeeded(versionsDir string) (string, bool) {
	ents, err := os.ReadDir(versionsDir)
	if err != nil {
		return "", false
	}
	var found []string
	for _, e := range ents {
		if !e.IsDir() {
			continue
		}
		if fi, err := os.Stat(filepath.Join(versionsDir, e.Name(), "geneza-agent")); err == nil && fi.Mode().IsRegular() {
			found = append(found, e.Name())
		}
	}
	if len(found) == 1 {
		return found[0], true
	}
	return "", false
}

func (b *bootstrap) startChildren() {
	// Session host first so its socket exists when the worker comes up. Its
	// command path is resolved at every (re)start so that when it
	// eventually dies it restarts from the CURRENT version — but it is
	// never proactively restarted by updates: live PTYs survive worker
	// swaps, which is the entire reason for the two-process split.
	b.sessionHost = update.NewSupervisor("session-host", func() (string, []string) {
		return b.currentBinPath(), []string{
			"session-host",
			"--socket", b.cfg.SessionHostSocket,
			"--spool", b.cfg.SpoolDir,
		}
	}, b.log, nil)
	b.sessionHost.Start()

	b.worker = b.startWorker(b.currentBinPath())
}

func (b *bootstrap) startWorker(binPath string) *update.Supervisor {
	return update.StartSupervised("worker", binPath, []string{
		"worker",
		"--config", b.cfg.AgentConfig,
		"--no-spawn-session-host",
	}, b.log)
}

func (b *bootstrap) stopChildren() {
	// Worker first: it is the session host's client. Background contexts —
	// the supervisors' own SIGTERM grace bounds the wait.
	if b.worker != nil {
		b.worker.Stop(context.Background())
	}
	if b.sessionHost != nil {
		b.sessionHost.Stop(context.Background())
	}
}

func (b *bootstrap) fetchDesired(ctx context.Context) (*types.DesiredVersionResponse, error) {
	pctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	b.mu.Lock()
	cur := b.current
	b.mu.Unlock()
	return update.FetchDesired(pctx, b.client, b.cfg.GatewayHTTPURL, b.nodeID, cur)
}

// reconcile is one iteration of the desired-state loop: poll, and if the
// gateway wants a different (non-bad) version, install -> swap -> health
// gate -> commit or roll back. Every decision is logged: this loop is the
// audit trail of the update path.
func (b *bootstrap) reconcile(ctx context.Context) {
	d, err := b.fetchDesired(ctx)
	if err != nil {
		b.log.Warn("desired-version poll failed", "err", err)
		return
	}
	if d == nil {
		b.log.Debug("gateway has no desired version; nothing to do")
		return
	}

	// The bad list applies to one desired value; when the operator moves
	// the target, old failures become retryable again.
	if b.st.ResetBadOnChange(d.Version, b.lastDesired) {
		b.log.Info("desired version changed; clearing failed-version list",
			"was", b.lastDesired, "now", d.Version)
		b.saveState()
	}
	b.lastDesired = d.Version

	if d.Version == b.current {
		b.log.Debug("already at desired version", "version", b.current)
		return
	}
	if b.st.IsBad(d.Version) {
		b.log.Warn("skipping desired version: failed its health gate previously",
			"version", d.Version, "current", b.current)
		return
	}
	if d.SignedManifest == nil {
		b.log.Warn("desired version has no signed manifest; cannot install", "version", d.Version)
		return
	}

	b.log.Info("update available", "current", b.current, "desired", d.Version)
	b.installer.MinCreatedAt = b.floorTime()
	newPath, m, err := b.installer.Install(ctx, d.SignedManifest)
	if err != nil {
		// Fail closed: current worker keeps running untouched.
		b.log.Error("install failed; keeping current version", "desired", d.Version, "err", err)
		return
	}
	if m.Version != d.Version {
		b.log.Error("signed manifest version does not match gateway's desired version; refusing swap",
			"manifest", m.Version, "desired", d.Version)
		return
	}
	b.swapWorker(ctx, newPath, m.Version, m.CreatedAt.Unix())
}

// floorTime is the anti-rollback high-water mark as a time.Time (zero when no
// version has ever been committed, which disables the check for a fresh node).
func (b *bootstrap) floorTime() time.Time {
	if b.st.FloorUnix <= 0 {
		return time.Time{}
	}
	return time.Unix(b.st.FloorUnix, 0)
}

// swapWorker performs the health-gated swap and, on failure, the CRITICAL
// rollback to the previous binary. The session host is never touched.
func (b *bootstrap) swapWorker(ctx context.Context, newPath, newVersion string, createdUnix int64) {
	oldVersion := b.current
	oldPath := b.binPath(oldVersion)
	healthFile := update.WorkerHealthFile(b.cfg.RunDir)

	// Capture the gate epoch BEFORE removing the stale file and starting
	// the new worker, so a fast health write still counts as fresh.
	gateStart := time.Now()
	if err := os.Remove(healthFile); err != nil && !os.IsNotExist(err) {
		b.log.Warn("could not remove stale health file", "file", healthFile, "err", err)
	}

	b.log.Info("swapping worker", "from", oldVersion, "to", newVersion, "health_timeout", b.cfg.healthTimeout())
	b.worker.Stop(context.Background())
	b.worker = b.startWorker(newPath)

	gerr := update.HealthGateSince(ctx, healthFile, gateStart, b.cfg.healthTimeout())
	if gerr == nil {
		b.mu.Lock()
		b.current = newVersion
		b.mu.Unlock()
		b.st.Previous = oldVersion
		b.st.Current = newVersion
		b.st.Bad = nil
		b.st.RaiseFloor(createdUnix) // advance the anti-rollback high-water mark
		b.saveState()
		if err := update.Prune(b.cfg.VersionsDir, []string{newVersion, oldVersion}); err != nil {
			b.log.Warn("prune failed", "err", err)
		}
		b.log.Info("update committed", "current", newVersion, "previous", oldVersion)
		return
	}

	if ctx.Err() != nil {
		// Shutdown raced the gate; do not condemn the version on an
		// interrupted observation. The next bootstrap run re-evaluates.
		b.log.Warn("health gate interrupted by shutdown; version not marked bad", "version", newVersion)
		return
	}

	b.log.Error("CRITICAL: new worker failed health gate; rolling back",
		"version", newVersion, "err", gerr)
	b.worker.Stop(context.Background())
	b.st.MarkBad(newVersion)
	b.saveState()
	rbStart := time.Now()
	if rmErr := os.Remove(healthFile); rmErr != nil && !os.IsNotExist(rmErr) {
		b.log.Warn("could not remove stale health file before rollback", "file", healthFile, "err", rmErr)
	}
	b.worker = b.startWorker(oldPath)
	// Confirm the rolled-back (previously good) worker actually comes back
	// healthy; otherwise the node is left with no live worker and an operator
	// must be told loudly. There is nothing further to roll back to.
	if hErr := update.HealthGateSince(ctx, healthFile, rbStart, b.cfg.healthTimeout()); hErr != nil && ctx.Err() == nil {
		b.log.Error("CRITICAL: rolled-back worker did not pass its health gate; node may have NO healthy worker",
			"version", oldVersion, "err", hErr)
		return
	}
	b.log.Error("CRITICAL: rolled back to previous worker", "version", oldVersion, "bad", newVersion)
}
