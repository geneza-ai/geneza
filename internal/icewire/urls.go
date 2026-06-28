// Package icewire holds the pion-ICE wiring primitives shared by Geneza's two ICE
// consumers: the L3 Network overlay (internal/vpn's multi-peer shared-GSO Bind)
// and the per-session transport (internal/sessionconn). Both build the same
// STUN+TURN URL / candidate-type set to stand up a pion ice.Agent, and both
// classify a selected pair as direct-vs-relayed; keeping one copy here stops the
// two from drifting. It is the ICE counterpart of the existing internal/wire
// (on-the-wire framing): a low-level substrate that imports no Geneza consumer
// (only pion/ice + pion/stun), so it sits strictly below both callers. Everything
// caller-specific — agent topology, timeouts, socket muxing, the session-only SCTP
// reliability layer — lives in the consumer, NOT here.
package icewire

import (
	"fmt"

	"github.com/pion/ice/v4"
	"github.com/pion/stun/v3"
)

// URLs builds the STUN+TURN URL set and the candidate types for an ICE agent:
//   - turnURL == ""      → host-only (loopback / tests): host candidates only.
//   - relayOnly == true  → require_relay: the blind TURN floor only (no IP disclosure).
//   - otherwise          → host + server-reflexive + relay (direct-when-punchable,
//     TURN floor as the fallback).
//
// The TURN credential (turnUser/turnPass, a coturn-REST token) is attached to the
// TURN URI; the STUN URI reuses the same host:port (the relay also speaks STUN).
func URLs(turnURL, turnUser, turnPass string, relayOnly bool) ([]*stun.URI, []ice.CandidateType, error) {
	if turnURL == "" {
		return nil, []ice.CandidateType{ice.CandidateTypeHost}, nil
	}
	turnURI, err := stun.ParseURI(turnURL)
	if err != nil {
		return nil, nil, fmt.Errorf("turn url: %w", err)
	}
	turnURI.Username, turnURI.Password = turnUser, turnPass
	if relayOnly {
		return []*stun.URI{turnURI}, []ice.CandidateType{ice.CandidateTypeRelay}, nil
	}
	stunURI := &stun.URI{Scheme: stun.SchemeTypeSTUN, Host: turnURI.Host, Port: turnURI.Port, Proto: stun.ProtoTypeUDP}
	return []*stun.URI{turnURI, stunURI},
		[]ice.CandidateType{ice.CandidateTypeHost, ice.CandidateTypeServerReflexive, ice.CandidateTypeRelay},
		nil
}

// RelayCred is one region-tagged TURN option: a TURN URL plus its coturn-REST
// credentials. A list of them lets one ice.Agent fail over between relays.
type RelayCred struct {
	TurnURL, TurnUser, TurnPass, Realm string
}

// URLsMulti builds the STUN+TURN URL set across several relay candidates: each
// candidate contributes a TURN URI (with its credentials) plus a STUN sibling on
// the same host:port, all handed to one ice.Agent. pion picks the lowest-latency
// working pair and re-nominates past a blackholed relay. With a single candidate
// the output is identical to URLs, so a single-relay deployment is unchanged.
func URLsMulti(creds []RelayCred, relayOnly bool) ([]*stun.URI, []ice.CandidateType, error) {
	var uris []*stun.URI
	for _, c := range creds {
		if c.TurnURL == "" {
			continue
		}
		turnURI, err := stun.ParseURI(c.TurnURL)
		if err != nil {
			return nil, nil, fmt.Errorf("turn url: %w", err)
		}
		turnURI.Username, turnURI.Password = c.TurnUser, c.TurnPass
		uris = append(uris, turnURI)
		if !relayOnly {
			uris = append(uris, &stun.URI{Scheme: stun.SchemeTypeSTUN, Host: turnURI.Host, Port: turnURI.Port, Proto: stun.ProtoTypeUDP})
		}
	}
	if len(uris) == 0 {
		return nil, []ice.CandidateType{ice.CandidateTypeHost}, nil
	}
	if relayOnly {
		return uris, []ice.CandidateType{ice.CandidateTypeRelay}, nil
	}
	return uris, []ice.CandidateType{ice.CandidateTypeHost, ice.CandidateTypeServerReflexive, ice.CandidateTypeRelay}, nil
}

// IsRelayed reports whether a selected candidate pair traverses the TURN relay
// (either end is a relay candidate). A pair that is not relayed is a direct
// (host/server-reflexive) hole-punched path.
func IsRelayed(local, remote ice.Candidate) bool {
	return local.Type() == ice.CandidateTypeRelay || remote.Type() == ice.CandidateTypeRelay
}
