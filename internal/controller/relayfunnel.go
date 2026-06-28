package controller

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"log/slog"
	"sort"

	"geneza.io/internal/nodeseal"
	genezav1 "geneza.io/internal/pb/geneza/v1"
)

// buildRelayFunnelCerts returns the funnel leaf certs this relay should serve,
// each sealed to the relay's X25519 key, plus a digest over the (unsealed) set
// so the watch loop re-sends only on a logical change — not on every reseal
// (age ciphertext is non-deterministic) and not every tick. For v1 every relay
// serves every funnel (one public pool); tenant-affinity pools are a later
// refinement.
func (s *Server) buildRelayFunnelCerts(rec *RelayRecord) ([]*genezav1.SealedCert, string) {
	if s.managedCerts == nil || len(rec.SealPub) != 32 {
		return nil, ""
	}
	certs, err := s.store.ListManagedCerts()
	if err != nil {
		slog.Warn("relay funnel certs: list", "relay", rec.RelayID, "err", err)
		return nil, ""
	}
	// hostname -> registration token, so the relay can authorize agent registrations.
	tokens := map[string]string{}
	if binds, err := s.store.ListFunnelBindings(); err == nil {
		for _, b := range binds {
			tokens[b.Hostname] = b.RegToken
		}
	}
	sort.Slice(certs, func(i, j int) bool { return certs[i].ID < certs[j].ID })
	var out []*genezav1.SealedCert
	h := sha256.New()
	for _, c := range certs {
		if c.Kind != KindFunnelLeaf {
			continue
		}
		bundle, err := s.readManagedCertBundle(c.Ref)
		if err != nil {
			slog.Warn("relay funnel cert blob unreadable", "cert", c.ID, "err", err)
			continue
		}
		sealed, err := nodeseal.Seal(bundle, rec.SealPub)
		if err != nil {
			slog.Warn("seal relay funnel cert", "cert", c.ID, "relay", rec.RelayID, "err", err)
			continue
		}
		zone := c.Label + "." + c.Domain // == the funnel hostname
		out = append(out, &genezav1.SealedCert{
			Zone: zone, Sealed: sealed, Epoch: c.Epoch, Sha256: c.Sha256, NotAfter: c.NotAfter,
			RegToken: tokens[zone],
		})
		// The digest gates re-sends on logical change — include the token so a
		// rotated registration secret reaches the relay.
		fmt.Fprintf(h, "%s:%d:%s;", zone, c.Epoch, tokens[zone])
	}
	return out, hex.EncodeToString(h.Sum(nil))
}
