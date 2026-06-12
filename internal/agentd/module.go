package agentd

import (
	"context"
	"log/slog"
	"sync"
	"time"

	genezav1 "osie.cloud/geneza/internal/pb/geneza/v1"
)

// Module is a pluggable agent capability that the control plane can toggle and
// (re)configure in realtime. node-exporter is the first; future exporters or
// agents implement the same tiny contract and drop into the registry. A module
// that produces metrics renders them in Prometheus text exposition on Gather();
// the manager pushes those up the control channel on the module's interval.
type Module interface {
	Name() string
	// Start brings the module up with the given settings. The ctx is cancelled
	// when the module is disabled or the worker shuts down.
	Start(ctx context.Context, settings map[string]string) error
	Stop()
	// Gather renders current metrics as Prometheus exposition text. Returns
	// (nil, nil) for modules that expose no metrics.
	Gather() ([]byte, error)
}

// ModuleFactory constructs a fresh, un-started module instance.
type ModuleFactory func(log *slog.Logger) (Module, error)

const (
	defaultScrapeInterval = 15 * time.Second
	minScrapeInterval     = 2 * time.Second
)

// moduleManager reconciles the agent's running modules against the gateway's
// desired ModuleConfig and pushes each metrics module's exposition up the
// control stream on its scrape interval. All node-side; nothing listens.
type moduleManager struct {
	log       *slog.Logger
	push      func(*genezav1.AgentMsg) // enqueue an AgentMsg on the control stream
	factories map[string]ModuleFactory

	mu      sync.Mutex
	running map[string]*moduleInstance
	version int64
}

type moduleInstance struct {
	mod      Module
	cancel   context.CancelFunc
	settings map[string]string
}

func newModuleManager(log *slog.Logger, push func(*genezav1.AgentMsg)) *moduleManager {
	return &moduleManager{
		log:       log.With("component", "modules"),
		push:      push,
		factories: builtinModuleFactories(),
		running:   map[string]*moduleInstance{},
	}
}

// reconcile diffs the desired ModuleConfig against the running set and
// starts/stops/restarts to match. Idempotent and monotonic: a stale (lower
// version) config is ignored so a reconnect re-push can't regress state.
func (m *moduleManager) reconcile(cfg *genezav1.ModuleConfig) {
	m.mu.Lock()
	defer m.mu.Unlock()

	if cfg.GetVersion() < m.version {
		return
	}
	m.version = cfg.GetVersion()

	desired := map[string]*genezav1.ModuleSpec{}
	for _, s := range cfg.GetModules() {
		if s.GetEnabled() {
			desired[s.GetName()] = s
		}
	}

	// Stop modules no longer desired, or whose settings changed (restart).
	for name, inst := range m.running {
		spec, want := desired[name]
		if !want || settingsChanged(inst.settings, spec.GetSettings()) {
			m.stopLocked(name)
		}
	}
	// Start modules newly desired (or just restarted above).
	for name, spec := range desired {
		if _, up := m.running[name]; up {
			continue
		}
		m.startLocked(name, spec.GetSettings())
	}
}

func (m *moduleManager) startLocked(name string, settings map[string]string) {
	factory, ok := m.factories[name]
	if !ok {
		m.log.Warn("unknown module requested; ignoring", "module", name)
		return
	}
	mod, err := factory(m.log)
	if err != nil {
		m.log.Error("module construct failed", "module", name, "err", err)
		return
	}
	ctx, cancel := context.WithCancel(context.Background())
	if err := mod.Start(ctx, settings); err != nil {
		cancel()
		m.log.Error("module start failed", "module", name, "err", err)
		return
	}
	m.running[name] = &moduleInstance{mod: mod, cancel: cancel, settings: cloneSettings(settings)}
	go m.pushLoop(ctx, mod, scrapeInterval(settings))
	m.log.Info("module started", "module", name, "interval", scrapeInterval(settings).String())
}

func (m *moduleManager) stopLocked(name string) {
	inst, ok := m.running[name]
	if !ok {
		return
	}
	inst.cancel()
	inst.mod.Stop()
	delete(m.running, name)
	m.log.Info("module stopped", "module", name)
}

// stopAll tears every module down (worker shutdown).
func (m *moduleManager) stopAll() {
	m.mu.Lock()
	defer m.mu.Unlock()
	for name := range m.running {
		m.stopLocked(name)
	}
}

// pushLoop renders + pushes the module's metrics immediately and then every
// interval until the module's ctx is cancelled.
func (m *moduleManager) pushLoop(ctx context.Context, mod Module, interval time.Duration) {
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		m.scrapeAndPush(mod)
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}

func (m *moduleManager) scrapeAndPush(mod Module) {
	msg := &genezav1.MetricsPush{Module: mod.Name(), UnixMs: time.Now().UnixMilli()}
	if data, err := mod.Gather(); err != nil {
		msg.Error = err.Error()
	} else if len(data) > 0 {
		msg.Exposition = data
	} else {
		return // nothing to push this round
	}
	m.push(&genezav1.AgentMsg{Msg: &genezav1.AgentMsg_Metrics{Metrics: msg}})
}

func scrapeInterval(settings map[string]string) time.Duration {
	if v := settings["scrape_interval_seconds"]; v != "" {
		if d, err := time.ParseDuration(v + "s"); err == nil && d >= minScrapeInterval {
			return d
		}
	}
	return defaultScrapeInterval
}

func settingsChanged(a, b map[string]string) bool {
	if len(a) != len(b) {
		return true
	}
	for k, v := range a {
		if b[k] != v {
			return true
		}
	}
	return false
}

func cloneSettings(s map[string]string) map[string]string {
	out := make(map[string]string, len(s))
	for k, v := range s {
		out[k] = v
	}
	return out
}
