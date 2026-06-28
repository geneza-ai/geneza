package controller

import (
	"fmt"
	"io"
	"log/slog"

	"geneza.io/internal/nodeseal"
	genezav1 "geneza.io/internal/pb/geneza/v1"
)

// Managed-domain certificate distribution to agents. A node's workspace may have
// reserved subdomains; each has a wildcard the cert manager issued. The controller
// seals each cert's PEM bundle to the node's Noise static key and pushes the full
// set over the existing mTLS control stream. Delivery is best-effort + on-connect
// re-push: an offline node reconciles when it reconnects, and the agent applies
// the set declaratively, so the push is idempotent and self-healing.

// readManagedCertBundle reads a stored cert's PEM bundle (private key + chain).
func (s *Server) readManagedCertBundle(ref string) ([]byte, error) {
	r, err := s.recordingBlobs.open(ref)
	if err != nil {
		return nil, err
	}
	defer r.Close()
	return io.ReadAll(r)
}

// buildNodeCertBundle assembles the node's managed certs, each sealed to the
// node's Noise key. A cert whose blob can't be read is skipped (logged) so one
// bad cert doesn't starve the rest.
func (s *Server) buildNodeCertBundle(ws string, node *NodeRecord) (*genezav1.CertBundle, error) {
	if len(node.NoisePub) != 32 {
		return nil, fmt.Errorf("node %s has no usable noise key", node.ID)
	}
	certs, err := s.store.ListManagedCerts()
	if err != nil {
		return nil, err
	}
	var (
		out      []*genezav1.SealedCert
		maxEpoch int64
	)
	for _, c := range certs {
		if c.WorkspaceID != ws || c.Kind != KindWorkspaceWildcard {
			continue // agents serve the workspace wildcards; funnel leaves go to relays
		}
		bundle, err := s.readManagedCertBundle(c.Ref)
		if err != nil {
			slog.Warn("managed cert blob unreadable", "cert", c.ID, "err", err)
			continue
		}
		sealed, err := nodeseal.Seal(bundle, node.NoisePub)
		if err != nil {
			slog.Warn("seal managed cert", "cert", c.ID, "node", node.ID, "err", err)
			continue
		}
		out = append(out, &genezav1.SealedCert{
			Zone:     c.Label + "." + c.Domain,
			Sealed:   sealed,
			Epoch:    c.Epoch,
			Sha256:   c.Sha256,
			NotAfter: c.NotAfter,
		})
		if c.Epoch > maxEpoch {
			maxEpoch = c.Epoch
		}
	}
	return &genezav1.CertBundle{Version: maxEpoch, Certs: out}, nil
}

// pushNodeCerts builds and sends a node's sealed cert set if it is approved,
// noise-capable, and connected to this controller. Best-effort: a node homed on
// another controller re-derives on its own connect.
func (s *Server) pushNodeCerts(ws, nodeID string) {
	if s.managedCerts == nil {
		return
	}
	if s.registry.handle(nodeID) == nil {
		return // not held here; the owning controller pushes on its connect
	}
	node, err := s.store.GetNode(ws, nodeID)
	if err != nil {
		return
	}
	if !node.Approved || len(node.NoisePub) != 32 {
		return
	}
	bundle, err := s.buildNodeCertBundle(ws, node)
	if err != nil {
		slog.Warn("build node cert bundle", "node", nodeID, "err", err)
		return
	}
	if err := s.registry.SendCertBundle(nodeID, bundle); err != nil {
		slog.Debug("cert bundle not pushed (node offline?)", "node", nodeID, "err", err)
	}
}

// repushWorkspaceCerts re-pushes the managed cert set to every connected,
// approved node of a workspace — called after an issue/renew/release so agents
// hot-swap without waiting for a reconnect.
func (s *Server) repushWorkspaceCerts(ws string) {
	if s.managedCerts == nil {
		return
	}
	nodes, err := s.store.ListNodes(ws)
	if err != nil {
		slog.Warn("repush workspace certs: list nodes", "ws", ws, "err", err)
		return
	}
	for _, n := range nodes {
		s.pushNodeCerts(ws, n.ID)
	}
}
