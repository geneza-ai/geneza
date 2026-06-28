package controller

import (
	"fmt"
	"sort"
)

// MigrateStore copies durable state from one Store backend to another through the
// Store interface alone, so it works for any pair of backends (the only use today
// is bbolt -> sqlStore). It returns a per-kind count of copied records.
//
// Scope: it copies the records the interface can enumerate — workspaces and their
// networks/subnets/nodes/node-modules/bindings/members/suspensions/sessions, plus
// the global source bindings, revoked certs, auth sessions, rollout settings and
// the signed cluster config. Short-lived single-use ephemerals that the interface
// does not list (join tokens, in-flight device-grant and handoff codes, WS
// tickets, OpenStack mint-once dedupe rows) are intentionally NOT copied: they
// expire on their own and the destination re-establishes single-use going
// forward. The caller (the operator) flips the config to the new backend after a
// successful copy.
func MigrateStore(src, dst Store) (map[string]int, error) {
	counts := map[string]int{}
	bump := func(kind string, n int) { counts[kind] += n }

	wss, err := src.ListWorkspaces()
	if err != nil {
		return counts, fmt.Errorf("list workspaces: %w", err)
	}
	for _, ws := range wss {
		if err := dst.PutWorkspace(ws); err != nil {
			return counts, fmt.Errorf("put workspace %s: %w", ws.ID, err)
		}
		bump("workspaces", 1)

		nets, err := src.ListNetworks(ws.ID)
		if err != nil {
			return counts, fmt.Errorf("list networks %s: %w", ws.ID, err)
		}
		for _, n := range nets {
			if err := dst.PutNetwork(n); err != nil {
				return counts, fmt.Errorf("put network %s/%s: %w", ws.ID, n.ID, err)
			}
			bump("networks", 1)
			// Bindings are keyed by (vni, node); the only way to enumerate them is per
			// Network vni, which the networks above give us.
			binds, err := src.ListBindings(ws.ID, n.VNI)
			if err != nil {
				return counts, fmt.Errorf("list bindings %s/%d: %w", ws.ID, n.VNI, err)
			}
			for _, b := range binds {
				if err := dst.PutBinding(b); err != nil {
					return counts, fmt.Errorf("put binding %s/%d/%s: %w", ws.ID, n.VNI, b.NodeID, err)
				}
				bump("bindings", 1)
			}
		}

		subs, err := src.ListSubnets(ws.ID)
		if err != nil {
			return counts, fmt.Errorf("list subnets %s: %w", ws.ID, err)
		}
		for _, sn := range subs {
			if err := dst.PutSubnet(sn); err != nil {
				return counts, fmt.Errorf("put subnet %s/%s: %w", ws.ID, sn.ID, err)
			}
			bump("subnets", 1)
		}

		nodes, err := src.ListNodes(ws.ID)
		if err != nil {
			return counts, fmt.Errorf("list nodes %s: %w", ws.ID, err)
		}
		for _, nd := range nodes {
			if err := dst.PutNode(ws.ID, nd); err != nil {
				return counts, fmt.Errorf("put node %s/%s: %w", ws.ID, nd.ID, err)
			}
			bump("nodes", 1)
			mods, err := src.GetNodeModules(ws.ID, nd.ID)
			if err != nil {
				return counts, fmt.Errorf("get node modules %s/%s: %w", ws.ID, nd.ID, err)
			}
			if len(mods.Modules) > 0 {
				if _, err := dst.SetNodeModules(ws.ID, nd.ID, mods.Modules); err != nil {
					return counts, fmt.Errorf("put node modules %s/%s: %w", ws.ID, nd.ID, err)
				}
				bump("node_modules", 1)
			}
		}

		members, err := src.ListMembers(ws.ID)
		if err != nil {
			return counts, fmt.Errorf("list members %s: %w", ws.ID, err)
		}
		for _, m := range members {
			if err := dst.PutMember(ws.ID, m); err != nil {
				return counts, fmt.Errorf("put member %s/%s:%s: %w", ws.ID, m.Provider, m.Subject, err)
			}
			bump("members", 1)
		}

		susps, err := src.ListSuspensions(ws.ID)
		if err != nil {
			return counts, fmt.Errorf("list suspensions %s: %w", ws.ID, err)
		}
		for _, sp := range susps {
			if err := dst.SuspendPrincipal(sp.Workspace, sp.Provider, sp.Subject, sp.Username, sp.SuspendedBy, sp.Reason); err != nil {
				return counts, fmt.Errorf("put suspension %s/%s:%s: %w", sp.Workspace, sp.Provider, sp.Subject, err)
			}
			bump("suspensions", 1)
		}

		sessions, err := src.ListSessions(ws.ID)
		if err != nil {
			return counts, fmt.Errorf("list sessions %s: %w", ws.ID, err)
		}
		for _, se := range sessions {
			if err := dst.PutSession(ws.ID, se); err != nil {
				return counts, fmt.Errorf("put session %s/%s: %w", ws.ID, se.ID, err)
			}
			bump("sessions", 1)
		}
	}

	srcBindings, err := src.ListSourceBindings()
	if err != nil {
		return counts, fmt.Errorf("list source bindings: %w", err)
	}
	for _, sb := range srcBindings {
		if err := dst.PutSourceBinding(sb); err != nil {
			return counts, fmt.Errorf("put source binding %s: %w", sb.Key, err)
		}
		bump("source_bindings", 1)
	}

	revoked, err := src.ListRevokedCerts()
	if err != nil {
		return counts, fmt.Errorf("list revoked certs: %w", err)
	}
	for _, rc := range revoked {
		if err := dst.RevokeCert(rc); err != nil {
			return counts, fmt.Errorf("put revoked cert %s: %w", rc.Serial, err)
		}
		bump("revoked_certs", 1)
	}

	auths, err := src.ListAuthSessions()
	if err != nil {
		return counts, fmt.Errorf("list auth sessions: %w", err)
	}
	for _, as := range auths {
		if err := dst.PutAuthSession(as); err != nil {
			return counts, fmt.Errorf("put auth session: %w", err)
		}
		bump("auth_sessions", 1)
	}

	// Rollout settings (known keys) and the signed cluster config.
	if v, err := src.StableVersion(); err == nil && v != "" {
		if err := dst.SetStableVersion(v); err != nil {
			return counts, fmt.Errorf("put stable version: %w", err)
		}
		bump("settings", 1)
	}
	if v, err := src.CanaryVersion(); err == nil && v != "" {
		if err := dst.SetCanaryVersion(v); err != nil {
			return counts, fmt.Errorf("put canary version: %w", err)
		}
		bump("settings", 1)
	}
	if nodes, err := src.CanaryNodes(); err == nil && len(nodes) > 0 {
		if err := dst.SetCanaryNodes(nodes); err != nil {
			return counts, fmt.Errorf("put canary nodes: %w", err)
		}
		bump("settings", 1)
	}
	if ver, err := src.ClusterConfigVersion(); err == nil && ver > 0 {
		signed, serr := src.SignedClusterConfig()
		if serr != nil {
			return counts, fmt.Errorf("read signed cluster config: %w", serr)
		}
		if len(signed) > 0 {
			if err := dst.SetSignedClusterConfig(ver, signed); err != nil {
				return counts, fmt.Errorf("put signed cluster config: %w", err)
			}
			bump("cluster_config", 1)
		}
	}

	return counts, nil
}

// MigrateAndReport runs the migration after refusing a non-empty destination
// (unless force), and returns a human-readable per-kind summary.
func MigrateAndReport(src, dst Store, force bool) (string, error) {
	if !force {
		has, err := storeHasData(dst)
		if err != nil {
			return "", fmt.Errorf("check destination: %w", err)
		}
		if has {
			return "", fmt.Errorf("destination store already has data; pass --force to overwrite")
		}
	}
	counts, err := MigrateStore(src, dst)
	report := "migrated:\n" + formatMigrationReport(counts)
	if err != nil {
		return report, err
	}
	return report, nil
}

// storeHasData reports whether a destination store already holds durable records,
// so a migration can refuse to overwrite one that is not empty.
func storeHasData(st Store) (bool, error) {
	wss, err := st.ListWorkspaces()
	if err != nil {
		return false, err
	}
	return len(wss) > 0, nil
}

// formatMigrationReport renders the per-kind counts in a stable order.
func formatMigrationReport(counts map[string]int) string {
	kinds := make([]string, 0, len(counts))
	for k := range counts {
		kinds = append(kinds, k)
	}
	sort.Strings(kinds)
	out := ""
	for _, k := range kinds {
		out += fmt.Sprintf("  %-16s %d\n", k, counts[k])
	}
	return out
}
