package gateway

import (
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"net"
	"strconv"
	"time"

	"github.com/pion/turn/v5"

	"osie.cloud/geneza/internal/defaults"
)

// turncreds.go mints gateway-side ephemeral TURN credentials (coturn REST style)
// for the pion data plane — replacing the hand-rolled rid/flow-secret protocol.
// Credentials are DERIVED from (shared secret, username), not stored: the relay
// validates them with the same secret and holds no per-user state. The username
// embeds an expiry + an opaque session id (no durable principal reaches the
// relay). See docs/dataplane-libs-plan.md §3.3.

const defaultTURNCredTTL = time.Hour

// turnCredsFor mints selfID's TURN credentials for the flow with peerID in a
// Network, and assigns the ICE controller role deterministically (lo of the pair
// Dials) — reusing the same ordering the rid path used.
func (s *Server) turnCredsFor(selfID, peerID string) (url, user, pass, realm string, controlling bool, err error) {
	addr := s.relayDataAddr()
	if addr == "" {
		return "", "", "", "", false, errors.New("no relay data address configured")
	}
	host, port, e := net.SplitHostPort(addr)
	if e != nil {
		return "", "", "", "", false, e
	}
	url = fmt.Sprintf("turn:%s?transport=udp", net.JoinHostPort(host, port))

	if s.cfg.RelaySharedSecret == "" {
		return "", "", "", "", false, errors.New("relay_shared_secret not configured")
	}
	user, pass, err = turn.GenerateLongTermTURNRESTCredentials(s.cfg.RelaySharedSecret, opaqueSessionID(), defaultTURNCredTTL)
	if err != nil {
		return "", "", "", "", false, err
	}

	realm = s.cfg.RelayRealm
	if realm == "" {
		realm = "geneza"
	}
	lo := selfID
	if peerID < lo {
		lo = peerID
	}
	return url, user, pass, realm, selfID == lo, nil
}

// relayDataAddr returns the relay's UDP data endpoint agents dial out to:
// relay_data_addrs[0] if set, else host(relay_addrs[0]):RelayDataPort.
func (s *Server) relayDataAddr() string {
	if len(s.cfg.RelayDataAddrs) > 0 && s.cfg.RelayDataAddrs[0] != "" {
		return s.cfg.RelayDataAddrs[0]
	}
	if len(s.cfg.RelayAddrs) == 0 {
		return ""
	}
	host, _, err := net.SplitHostPort(s.cfg.RelayAddrs[0])
	if err != nil || host == "" {
		return ""
	}
	return net.JoinHostPort(host, strconv.Itoa(defaults.RelayDataPort))
}

// opaqueSessionID is a rotating, non-durable id placed in the TURN username so
// the relay never sees a stable principal (preserves the rid model's anonymity).
func opaqueSessionID() string {
	var b [12]byte
	_, _ = rand.Read(b[:])
	return base64.RawURLEncoding.EncodeToString(b[:])
}
