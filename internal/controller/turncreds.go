package controller

import (
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"net"
	"sort"
	"strconv"
	"time"

	"github.com/pion/turn/v5"

	"geneza.io/internal/defaults"
	genezav1 "geneza.io/internal/pb/geneza/v1"
	"geneza.io/internal/types"
)

// turncreds.go mints controller-side ephemeral TURN credentials (coturn REST style)
// for the pion data plane — replacing the hand-rolled rid/flow-secret protocol.
// Credentials are DERIVED from (shared secret, username), not stored: the relay
// validates them with the same secret and holds no per-user state. The username
// embeds an expiry + an opaque session id (no durable principal reaches the
// relay). See docs/dataplane-libs-plan.md.

const defaultTURNCredTTL = time.Hour

// relaySecret returns this controller's region and that region's active minting
// secret. It fails closed when the region has no configured secret — a controller
// that cannot mint a credential its region's relay will accept must not pretend
// to. Single-node configs synthesize the "default" region from the flat secret.
func (s *Server) relaySecret() (region, current string, err error) {
	region = canonicalRegion(s.cfg.Region)
	sec, ok := s.cfg.RelaySecrets[region]
	if !ok || sec.Current == "" {
		return "", "", errors.New("no relay secret configured for region " + region)
	}
	return region, sec.Current, nil
}

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

	region, secret, serr := s.relaySecret()
	if serr != nil {
		return "", "", "", "", false, serr
	}
	// Tag the username with the region (the library prepends the expiry and HMACs
	// the whole string, so the region cannot be altered without breaking the MAC).
	// The relay validates only credentials tagged for its own region.
	user, pass, err = turn.GenerateLongTermTURNRESTCredentials(secret, region+":"+opaqueSessionID(), defaultTURNCredTTL)
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

// sessionTURNCredTTLFallback bounds a session's TURN creds when no grant TTL is
// configured. Normally the creds TTL is derived from (and capped at) the grant
// TTL so the TURN credentials never outlive the grant they belong to.
const sessionTURNCredTTLFallback = 2 * time.Minute

// sessionTURNCredTTL returns the TURN-cred lifetime for a session: the grant
// TTL (so the creds die with the grant), or the fallback when unset.
func (s *Server) sessionTURNCredTTL() time.Duration {
	if ttl := s.cfg.GrantTTL.D(); ttl > 0 {
		return ttl
	}
	return sessionTURNCredTTLFallback
}

// sessionTurnCreds mints TURN creds for ONE session, with the REST username's id
// part BOUND to the session_id (so the relay can scope permission/quota per
// session) and a short TTL. The same creds serve both endpoints; the ICE role is
// fixed by the caller (client Dials, agent Accepts). Returns nil creds when no
// relay data address is configured (host-only/loopback).
func (s *Server) sessionTurnCreds(sessionID string, controlling bool) (*genezav1.TurnCreds, error) {
	addr := s.relayDataAddr()
	if addr == "" {
		return nil, nil
	}
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, err
	}
	region, secret, serr := s.relaySecret()
	if serr != nil {
		return nil, serr
	}
	user, pass, err := turn.GenerateLongTermTURNRESTCredentials(secret, region+":sess-"+sessionID, s.sessionTURNCredTTL())
	if err != nil {
		return nil, err
	}
	realm := s.cfg.RelayRealm
	if realm == "" {
		realm = "geneza"
	}
	return &genezav1.TurnCreds{
		TurnUrl:     fmt.Sprintf("turn:%s?transport=udp", net.JoinHostPort(host, port)),
		Username:    user,
		Password:    pass,
		Realm:       realm,
		Controlling: controlling,
	}, nil
}

// relayDataAddr returns the relay's UDP data endpoint agents dial out to:
// relay_data_addrs[0] if set, else host(relay_addrs[0]):RelayDataPort.
func (s *Server) relayDataAddr() string { return s.cfg.relayDataAddr() }

// relayCandidateFor mints a region-tagged TURN credential for one relay in the
// signed fleet, bound to the session id. The relay validates it against that
// region's secret. The TURN URL is the relay's data endpoint from the signed map.
func (s *Server) relayCandidateFor(region string, relay types.RelayNode, sessionID string) (types.RelayCandidate, error) {
	sec, ok := s.cfg.RelaySecrets[region]
	if !ok || sec.Current == "" {
		return types.RelayCandidate{}, errors.New("no relay secret for region " + region)
	}
	if len(relay.Addrs) == 0 {
		return types.RelayCandidate{}, errors.New("relay " + relay.RelayID + " has no address")
	}
	host, _, err := net.SplitHostPort(relay.Addrs[0])
	if err != nil || host == "" {
		host = relay.Addrs[0]
	}
	port := relay.TURNPort
	if port == 0 {
		port = defaults.RelayDataPort
	}
	user, pass, err := turn.GenerateLongTermTURNRESTCredentials(sec.Current, region+":sess-"+sessionID, s.sessionTURNCredTTL())
	if err != nil {
		return types.RelayCandidate{}, err
	}
	realm := s.cfg.RelayRealm
	if realm == "" {
		realm = "geneza"
	}
	return types.RelayCandidate{
		RegionID: region, RelayID: relay.RelayID,
		TurnURL:  fmt.Sprintf("turn:%s?transport=udp", net.JoinHostPort(host, strconv.Itoa(port))),
		TurnUser: user, TurnPass: pass, Realm: realm,
	}, nil
}

// selectRelayCandidates returns the signed per-session relay candidate list: the
// relays in each peer's home region (so either peer's relay validates), each with
// TURN credentials minted under that region's secret. A peer whose home region is
// absent from the fleet falls back to the default region — fail-open to the one
// default region only, never across explicit regions. Single-node yields exactly
// one default-region candidate, identical to the scalar session credential.
func (s *Server) selectRelayCandidates(sessionID, clientRegion, agentRegion string) []types.RelayCandidate {
	// Only the session-p2p path uses relay candidates; with it off, every session
	// stays on the relay floor and the grant carries no candidate list (so the
	// signed grant is byte-identical to the pre-fleet default).
	if !s.cfg.SessionP2P {
		return nil
	}
	// Draining and stale relays are excluded here so a NEW session is never minted a
	// candidate pinned to a relay about to swap (they stay VISIBLE in the signed map
	// for in-flight sessions, just out of this selectable set).
	relays := s.selectableRelays()
	if len(relays) == 0 {
		return nil
	}
	byRegion := map[string][]types.RelayNode{}
	for _, r := range relays {
		byRegion[r.RegionID] = append(byRegion[r.RegionID], r)
	}
	want := map[string]bool{}
	for _, region := range []string{canonicalRegion(clientRegion), canonicalRegion(agentRegion)} {
		if len(byRegion[region]) == 0 {
			region = defaultRegion
		}
		want[region] = true
	}
	var out []types.RelayCandidate
	for region := range want {
		for _, r := range byRegion[region] {
			if cand, err := s.relayCandidateFor(region, r, sessionID); err == nil {
				out = append(out, cand)
			}
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].RegionID != out[j].RegionID {
			return out[i].RegionID < out[j].RegionID
		}
		return out[i].RelayID < out[j].RelayID
	})
	return out
}

// relayCandidatesToProto converts the signed candidate list to its wire form for
// the client (which, unlike the agent, does not re-verify the signed grant).
func relayCandidatesToProto(cands []types.RelayCandidate) []*genezav1.RelayCandidate {
	if len(cands) == 0 {
		return nil
	}
	out := make([]*genezav1.RelayCandidate, 0, len(cands))
	for _, c := range cands {
		out = append(out, &genezav1.RelayCandidate{
			RegionId: c.RegionID, TurnUrl: c.TurnURL, Username: c.TurnUser,
			Password: c.TurnPass, Realm: c.Realm, RelayId: c.RelayID,
		})
	}
	return out
}

// opaqueSessionID is a rotating, non-durable id placed in the TURN username so
// the relay never sees a stable principal (preserves the rid model's anonymity).
func opaqueSessionID() string {
	var b [12]byte
	_, _ = rand.Read(b[:])
	return base64.RawURLEncoding.EncodeToString(b[:])
}
