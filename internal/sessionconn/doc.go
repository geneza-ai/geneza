// Package sessionconn is the per-session transport: it hands a Geneza session
// (exec/ssh/sftp/forward) a reliable net.Conn carried over a pion-ICE path, on
// which the caller runs the UNCHANGED E2E Noise IK tunnel + SSH. One ephemeral,
// grant-gated ICE agent is created per session by the controller broker — there is
// no shared overlay socket here (that is internal/vpn's job); a session is a
// session everywhere (API `Session*`, CLI `geneza ps`/`exec`/`ssh`, store
// `SessionRecord`) and this package is only HOW it connects, reported as the
// `path` attribute (`direct` or `relayed`), never a new noun.
//
// Two layers, each a standard library glued in (cardinal principle, not
// reinvented):
//
//   - AVAILABILITY (ice.go): a pion ice.Agent establishes a UDP path — DIRECT
//     (host candidate for a fully-exposed peer, or server-reflexive hole-punch
//     behind a NAT) when reachable, else the blind relay's TURN-UDP floor
//     (`:7404`). ICE always gathers a relay candidate, so a path always exists.
//     The shared URL/candidate-type building and direct-vs-relayed classification
//     come from internal/icewire (also used by the VPN overlay).
//
//   - RELIABILITY (sctp.go): the ICE path is lossy/unordered UDP, but SSH-inside-
//     Noise needs an ordered reliable byte stream, so one pion/sctp Association +
//     Stream is layered on (the WebRTC DataChannel model, minus DTLS). This is
//     SESSION-ONLY — the VPN carries raw datagrams over WireGuard and never needs
//     it, which is exactly why it lives here and not in icewire.
//
// Design: docs/p2p-transport-spec.md; reliability tradeoff:
// docs/session-reliability-decision.md.
//
// CRITICAL INVARIANT: this package changes ONLY the net.Conn handed to
// tunnel.Server/tunnel.Client. The E2E Noise IK tunnel and the agent's
// independent signed-grant authorize callback
// (remoteStatic == grant.ClientNoisePub) are byte-for-byte unchanged — ICE is an
// AVAILABILITY layer, never the security boundary. The agent runs the same
// EvaluateOffer + Noise-authorize sequence regardless of transport; a stranger
// who hole-punches to the agent's ICE socket cannot complete the Noise handshake
// and is dropped before any application byte.
package sessionconn
