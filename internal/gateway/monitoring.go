package gateway

import (
	"log/slog"
	"net"
	"time"

	genezav1 "osie.cloud/geneza/internal/pb/geneza/v1"
)

// localRelayAddr is where the in-process web-shell proxy dials the relay: the
// relay listens on this VM, so use loopback with the relay's port (taken from
// the public relay_addrs the gateway hands out) and avoid a NAT hairpin.
func (s *Server) localRelayAddr() string {
	if len(s.cfg.RelayAddrs) == 0 {
		return "127.0.0.1:7403"
	}
	_, port, err := net.SplitHostPort(s.cfg.RelayAddrs[0])
	if err != nil || port == "" {
		return "127.0.0.1:7403"
	}
	return net.JoinHostPort("127.0.0.1", port)
}

// moduleConfigProto builds the wire ModuleConfig from a stored record.
func moduleConfigProto(rec *NodeModulesRecord) *genezav1.ModuleConfig {
	cfg := &genezav1.ModuleConfig{Version: rec.Version}
	for _, m := range rec.Modules {
		cfg.Modules = append(cfg.Modules, &genezav1.ModuleSpec{
			Name:     m.Name,
			Enabled:  m.Enabled,
			Settings: m.Settings,
		})
	}
	return cfg
}

// pushNodeModules sends a node its current desired module set (best-effort: if
// the node is offline it reconciles on reconnect, which re-pushes).
func (s *Server) pushNodeModules(nodeID string) {
	rec, err := s.store.GetNodeModules(nodeID)
	if err != nil {
		slog.Warn("load node modules", "node", nodeID, "err", err)
		return
	}
	if err := s.registry.SendModuleConfig(nodeID, moduleConfigProto(rec)); err != nil {
		slog.Debug("module config not pushed (node offline?)", "node", nodeID, "err", err)
	}
}

// ingestNodeMetrics feeds one agent metrics push into the embedded TSDB, tagging
// every series with the node's identity so metrics are per-node queryable
// (instance/node/node_id/job, matching Prometheus node_exporter conventions).
func (s *Server) ingestNodeMetrics(nodeID, nodeName string, mp *genezav1.MetricsPush) {
	if s.metrics == nil {
		return
	}
	if mp.GetError() != "" {
		slog.Warn("agent module reported scrape error", "node", nodeID, "module", mp.GetModule(), "err", mp.GetError())
		return
	}
	if len(mp.GetExposition()) == 0 {
		return
	}
	ts := mp.GetUnixMs()
	if ts == 0 {
		ts = time.Now().UnixMilli()
	}
	labels := map[string]string{
		"instance": nodeName,
		"node":     nodeName,
		"node_id":  nodeID,
		"job":      mp.GetModule(),
	}
	if _, err := s.metrics.Ingest(labels, mp.GetExposition(), ts); err != nil {
		slog.Warn("metrics ingest failed", "node", nodeID, "module", mp.GetModule(), "err", err)
	}
}
