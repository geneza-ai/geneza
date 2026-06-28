package controller

import (
	"log/slog"
	"net"
	"time"

	genezav1 "geneza.io/internal/pb/geneza/v1"
)

// localRelayAddr is where the in-process web-shell proxy dials the relay: the
// relay listens on this VM, so use loopback with the relay's port (taken from
// the public relay_addrs the controller hands out) and avoid a NAT hairpin.
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
func (s *Server) pushNodeModules(ws, nodeID string) {
	rec, err := s.store.GetNodeModules(ws, nodeID)
	if err != nil {
		slog.Warn("load node modules", "node", nodeID, "err", err)
		return
	}
	if s.registry.handle(nodeID) == nil {
		// Not held here: ring the owning controller to re-derive and push, or no-op if
		// the node is offline (reconnect re-derives).
		s.router.RouteModcfg(ws, nodeID)
		return
	}
	if err := s.registry.SendModuleConfig(nodeID, moduleConfigProto(rec)); err != nil {
		slog.Debug("module config not pushed (node offline?)", "node", nodeID, "err", err)
	}
}

// ingestNodeMetrics forwards one agent metrics push to the metrics backend,
// tagging every series with the node's identity so metrics are per-node
// queryable (instance/node/node_id/job, matching Prometheus node_exporter
// conventions).
func (s *Server) ingestNodeMetrics(ws, nodeID, nodeName string, mp *genezav1.MetricsPush) {
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
		"instance":  nodeName,
		"node":      nodeName,
		"node_id":   nodeID,
		"job":       mp.GetModule(),
		"workspace": ws,
	}
	s.metrics.EnqueueIngest(labels, mp.GetExposition(), ts)
}
