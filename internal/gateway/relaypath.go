package gateway

import (
	"crypto/rand"
	"encoding/binary"
	"errors"
	"net"
	"strconv"
	"sync"

	"osie.cloud/geneza/internal/defaults"
)

// relaypath.go mints + persists the blind-relay coordinates (rid pair + flow
// secret) for an ordered peer pair within a Network, and resolves the relay's
// UDP data address. The relay never sees the rid→(VNI,pair) mapping; possession
// of a gateway-minted rid is the capability. See docs/magicsock-design.md §3.

const ridMask48 = (uint64(1) << 48) - 1

var relayPathMu sync.Mutex // serializes get-or-create so a pair gets one record

// relayCoords are the relay coordinates for ONE endpoint's view of a peer flow.
type relayCoords struct {
	relayAddr  string
	selfRid    uint64 // rid this endpoint REGisters + receives on
	peerRid    uint64 // rid this endpoint addresses the peer's DATA to
	flowSecret []byte
}

// relayPathFor returns selfID's relay coordinates for the flow with peerID in a
// Network (VNI), creating + persisting the rid pair on first use (idempotent and
// order-independent: both endpoints resolve the same shared record).
func (s *Server) relayPathFor(ws string, vni uint32, selfID, peerID string) (relayCoords, error) {
	addr := s.relayDataAddr()
	if addr == "" {
		return relayCoords{}, errors.New("no relay data address configured")
	}
	lo, hi := selfID, peerID
	if lo > hi {
		lo, hi = hi, lo
	}

	relayPathMu.Lock()
	defer relayPathMu.Unlock()

	rec, err := s.store.GetRelayPath(ws, vni, lo, hi)
	if err != nil {
		if !errors.Is(err, ErrNotFound) {
			return relayCoords{}, err
		}
		ridLo, e1 := mintRid()
		ridHi, e2 := mintRid()
		secret, e3 := mintSecret()
		if e1 != nil || e2 != nil || e3 != nil {
			return relayCoords{}, errors.New("mint relay path: rng failure")
		}
		rec = &RelayPathRecord{
			WorkspaceID: ws, VNI: vni, NodeLo: lo, NodeHi: hi,
			RidLo: ridLo, RidHi: ridHi, FlowSecret: secret,
		}
		if err := s.store.PutRelayPath(rec); err != nil {
			return relayCoords{}, err
		}
	}

	c := relayCoords{relayAddr: addr, flowSecret: rec.FlowSecret}
	if selfID == lo {
		c.selfRid, c.peerRid = rec.RidLo, rec.RidHi
	} else {
		c.selfRid, c.peerRid = rec.RidHi, rec.RidLo
	}
	return c, nil
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

func mintRid() (uint64, error) {
	var b [8]byte
	if _, err := rand.Read(b[:]); err != nil {
		return 0, err
	}
	rid := binary.BigEndian.Uint64(b[:]) & ridMask48
	if rid == 0 {
		rid = 1 // 0 is reserved (avoids an all-zero header looking unset)
	}
	return rid, nil
}

func mintSecret() ([]byte, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return nil, err
	}
	return b, nil
}
