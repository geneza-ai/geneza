package agentd

import (
	"bytes"
	"context"
	"fmt"
	"log/slog"
	"strings"
	"sync"

	"github.com/alecthomas/kingpin/v2"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/common/expfmt"
	"github.com/prometheus/node_exporter/collector"
)

// builtinModuleFactories is the registry of modules the agent can run. Adding a
// new exporter/agent is one line here plus its Module implementation.
func builtinModuleFactories() map[string]ModuleFactory {
	return map[string]ModuleFactory{
		"node-exporter": newNodeExporterModule,
		"inventory":     newInventoryModule,
	}
}

// kingpinDefaultsOnce applies node_exporter's collector flag DEFAULTS exactly
// once. node_exporter registers its per-collector knobs on the global kingpin
// CommandLine; their values stay zero until kingpin parses, so without this the
// embedded collectors would see empty mount-point regexes etc. Parsing an empty
// arg list applies every default without touching our own (cobra) CLI args.
var kingpinDefaultsOnce sync.Once

func applyNodeExporterDefaults() {
	kingpinDefaultsOnce.Do(func() {
		_, _ = kingpin.CommandLine.Parse([]string{})
	})
}

// nodeExporterModule embeds the upstream node_exporter collectors in-process and
// renders their metrics on demand. No HTTP listener is opened — metrics leave
// the node only when the manager pushes Gather() output up the control channel.
type nodeExporterModule struct {
	log *slog.Logger
	reg *prometheus.Registry
}

func newNodeExporterModule(log *slog.Logger) (Module, error) {
	return &nodeExporterModule{log: log.With("module", "node-exporter")}, nil
}

func (n *nodeExporterModule) Name() string { return "node-exporter" }

func (n *nodeExporterModule) Start(_ context.Context, settings map[string]string) error {
	applyNodeExporterDefaults()

	// settings["collectors"] optionally restricts to a named subset; empty means
	// node_exporter's default-enabled collector set (cpu, meminfo, filesystem,
	// netdev, loadavg, diskstats, ...).
	var filters []string
	if c := strings.TrimSpace(settings["collectors"]); c != "" {
		for _, f := range strings.Split(c, ",") {
			if f = strings.TrimSpace(f); f != "" {
				filters = append(filters, f)
			}
		}
	}

	nc, err := collector.NewNodeCollector(n.log, filters...)
	if err != nil {
		return fmt.Errorf("node_exporter collector: %w", err)
	}
	reg := prometheus.NewRegistry()
	if err := reg.Register(nc); err != nil {
		return fmt.Errorf("register node collector: %w", err)
	}
	n.reg = reg
	enabled := make([]string, 0, len(nc.Collectors))
	for name := range nc.Collectors {
		enabled = append(enabled, name)
	}
	n.log.Info("node-exporter ready", "collectors", len(enabled))
	return nil
}

func (n *nodeExporterModule) Stop() { n.reg = nil }

// Gather scrapes the embedded collectors and renders Prometheus text exposition.
func (n *nodeExporterModule) Gather() ([]byte, error) {
	if n.reg == nil {
		return nil, nil
	}
	mfs, err := n.reg.Gather()
	if err != nil {
		// Partial scrapes are normal (a single collector erroring); still emit
		// whatever gathered rather than dropping the whole sample.
		n.log.Debug("node-exporter partial gather", "err", err)
	}
	var buf bytes.Buffer
	enc := expfmt.NewEncoder(&buf, expfmt.NewFormat(expfmt.TypeTextPlain))
	for _, mf := range mfs {
		if encErr := enc.Encode(mf); encErr != nil {
			return nil, fmt.Errorf("encode exposition: %w", encErr)
		}
	}
	return buf.Bytes(), nil
}
