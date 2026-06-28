package controller

import (
	"context"
	"log/slog"
	"net"
	"sort"
	"strings"
	"time"

	"geneza.io/internal/webpki"
)

// funnelPublicPort is the port public clients connect to (browsers use 443); the
// reconciler probes it to validate a relay's advertised funnel IP before
// publishing it to public DNS.
const funnelPublicPort = "443"

// Funnel-DNS reconciler: publishes PUBLIC A records pointing each funnel hostname
// at the healthy, non-draining relays' funnel IPs, and withdraws them on
// drain/death/release (the §7a drain → DNS-reconcile → failover design). It runs
// leader-only on the managed-cert controller tick. A managed name's wildcard is
// VPN-only; only the explicitly-funneled hostnames get public A records here.
type funnelDNSReconciler struct {
	store    Store
	managers map[string]webpki.RecordManager // base domain -> A-record manager (nil entries skipped)

	// reachable validates a relay's advertised funnel IP is actually reachable
	// before it is published to public DNS (so a misconfigured public_ip cannot
	// blackhole clients). Injectable for tests; defaults to a TCP probe.
	reachable func(ip string) bool
	published map[string][]string // fqdn -> last-published IP set (in-memory)
}

func newFunnelDNSReconciler(store Store, managers map[string]webpki.RecordManager) *funnelDNSReconciler {
	return &funnelDNSReconciler{
		store: store, managers: managers, reachable: funnelIPReachable,
		published: map[string][]string{},
	}
}

// funnelIPReachable probes the relay's public funnel listener. It checks
// reachability from the CONTROLLER (like the existing data-endpoint STUN probe) —
// not from the public internet — so it catches gross misconfig (wrong IP, dead
// listener), not every path difference.
func funnelIPReachable(ip string) bool {
	c, err := net.DialTimeout("tcp", net.JoinHostPort(ip, funnelPublicPort), 3*time.Second)
	if err != nil {
		return false
	}
	c.Close()
	return true
}

// managerFor returns the A-record manager for the domain a hostname falls under.
func (r *funnelDNSReconciler) managerFor(hostname string) webpki.RecordManager {
	var best string
	for base := range r.managers {
		if (hostname == base || strings.HasSuffix(hostname, "."+base)) && len(base) > len(best) {
			best = base
		}
	}
	if best == "" {
		return nil
	}
	return r.managers[best]
}

// healthyFunnelIPs is the public IP set funnel hostnames should resolve to: the
// non-draining, fresh relays advertising a funnel IP. Sorted + de-duplicated for a
// stable comparison.
func (r *funnelDNSReconciler) healthyFunnelIPs(now time.Time) []string {
	relays, err := r.store.ListRelays("")
	if err != nil {
		slog.Warn("funnel dns: list relays", "err", err)
		return nil
	}
	cutoff := now.Add(-relayStaleTTL).Unix()
	seen := map[string]bool{}
	var ips []string
	for _, rl := range relays {
		if rl.Draining || rl.FunnelIP == "" || rl.LastSeenUnix < cutoff || seen[rl.FunnelIP] {
			continue
		}
		seen[rl.FunnelIP] = true
		if r.reachable != nil && !r.reachable(rl.FunnelIP) {
			slog.Warn("funnel dns: advertised funnel IP unreachable; not publishing", "relay", rl.RelayID, "ip", rl.FunnelIP)
			continue
		}
		ips = append(ips, rl.FunnelIP)
	}
	sort.Strings(ips)
	return ips
}

// reconcile converges public A records to (funnel hostname -> healthy relay IPs).
func (r *funnelDNSReconciler) reconcile(ctx context.Context) {
	if len(r.managers) == 0 {
		return
	}
	ips := r.healthyFunnelIPs(time.Now())
	binds, err := r.store.ListFunnelBindings()
	if err != nil {
		slog.Warn("funnel dns: list bindings", "err", err)
		return
	}
	desired := make(map[string][]string, len(binds))
	for _, b := range binds {
		if r.managerFor(b.Hostname) == nil {
			continue // domain managed statically (e.g. cloudflare v1)
		}
		desired[b.Hostname] = ips // every funnel points at the whole healthy pool (v1)
	}
	// Publish new/changed record sets.
	for fqdn, want := range desired {
		if equalStrings(r.published[fqdn], want) {
			continue
		}
		if len(want) == 0 {
			continue // no healthy relays; leave the last good set rather than blackhole
		}
		if err := r.managerFor(fqdn).SetA(ctx, fqdn, want); err != nil {
			slog.Warn("funnel dns: set A", "fqdn", fqdn, "err", err)
			continue
		}
		r.published[fqdn] = want
		slog.Info("funnel dns published", "fqdn", fqdn, "ips", want)
	}
	// Withdraw records for funnels that no longer exist.
	for fqdn := range r.published {
		if _, ok := desired[fqdn]; ok {
			continue
		}
		mgr := r.managerFor(fqdn)
		if mgr == nil {
			delete(r.published, fqdn)
			continue
		}
		if err := mgr.RemoveA(ctx, fqdn); err != nil {
			slog.Warn("funnel dns: remove A", "fqdn", fqdn, "err", err)
			continue
		}
		delete(r.published, fqdn)
		slog.Info("funnel dns withdrawn", "fqdn", fqdn)
	}
}

func equalStrings(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
