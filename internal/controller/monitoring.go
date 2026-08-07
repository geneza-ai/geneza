package controller

import (
	"log/slog"
	"net"
	"sort"
	"strings"
	"time"

	genezav1 "geneza.io/internal/pb/geneza/v1"
)

// defaultNodeModules are enabled on every node unless a stored entry overrides
// them. Inventory (SBOM collection — the source of the CVE/vuln surface) and
// node-exporter (host metrics) are both on by default, so a freshly enrolled node
// reports its software set and its health out of the box; an admin turns either
// off per node from the console's node Settings tab, which writes an explicit
// disabled entry.
//
// node-exporter defaults on even when no metrics_url is configured: the agent
// scrapes and pushes, and ingestNodeMetrics drops it. That costs the node a local
// scrape rather than leaving an operator who later configures a backend with a
// fleet that silently collects nothing — the same trade inventory already makes
// against vuln_feed.
var defaultNodeModules = []NodeModule{
	{Name: "inventory", Enabled: true},
	{Name: "node-exporter", Enabled: true},
}

// effectiveNodeModules merges a node's stored module set over the defaults: a
// stored entry (enabled OR disabled) wins, defaults fill in the rest. This is
// what the agent is told to run and what the admin sees, so default-on holds for
// every node, new or existing, without rewriting any stored record.
func effectiveNodeModules(rec *NodeModulesRecord) []NodeModule {
	byName := map[string]NodeModule{}
	for _, d := range defaultNodeModules {
		byName[d.Name] = d
	}
	if rec != nil {
		for _, m := range rec.Modules {
			byName[m.Name] = m
		}
	}
	out := make([]NodeModule, 0, len(byName))
	for _, m := range byName {
		out = append(out, m)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

// localRelayAddr optionally overrides where the in-process web-shell proxy dials
// the relay. It returns loopback ONLY when the relay is on this same host, and
// "" (no override — use the grant's real relay address) otherwise.
func (s *Server) localRelayAddr() string {
	if len(s.cfg.RelayAddrs) == 0 {
		return ""
	}
	host, port, err := net.SplitHostPort(s.cfg.RelayAddrs[0])
	if err != nil || port == "" {
		return ""
	}
	// ONLY when the relay really is on this box. This override exists to dodge a
	// NAT hairpin in the single-host deployment, where controller and relay share
	// a machine and dialling the public name would leave and re-enter the host.
	//
	// Returning loopback unconditionally breaks every multi-host topology — the
	// relay layer is a separate instance in deploy/openstack and in anything
	// multi-region — with "relay connect 127.0.0.1:7403: connection refused",
	// which reads like the relay is down rather than like the controller dialled
	// the wrong machine. Empty means "no override": use the address the grant
	// carries, which is the relay's real one.
	if !s.relayColocated(host) {
		return ""
	}
	return net.JoinHostPort("127.0.0.1", port)
}

// relayColocated reports whether the configured relay is this controller's own
// host: either it is already loopback, or it is advertised under a name/address
// this controller also answers to.
func (s *Server) relayColocated(host string) bool {
	if host == "" {
		return false
	}
	if strings.EqualFold(host, "localhost") {
		return true
	}
	if ip := net.ParseIP(host); ip != nil && ip.IsLoopback() {
		return true
	}
	for _, n := range s.cfg.Advertise.DNSNames {
		if strings.EqualFold(n, host) {
			return true
		}
	}
	for _, n := range s.cfg.Advertise.IPs {
		if n == host {
			return true
		}
	}
	return false
}

// moduleConfigProto builds the wire ModuleConfig from a stored record, applying
// the module defaults (so the default-on inventory module is pushed/shown even
// when the node has no stored entry for it).
func moduleConfigProto(rec *NodeModulesRecord) *genezav1.ModuleConfig {
	var version int64
	if rec != nil {
		version = rec.Version
	}
	cfg := &genezav1.ModuleConfig{Version: version}
	for _, m := range effectiveNodeModules(rec) {
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
