// Package wire implements the length-prefixed frame protocol used on raw
// tunnel/relay connections (4-byte big-endian length + payload).
package wire

import (
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
)

const MaxFrame = 1 << 20

func WriteFrame(w io.Writer, p []byte) error {
	if len(p) > MaxFrame {
		return fmt.Errorf("frame too large: %d", len(p))
	}
	var hdr [4]byte
	binary.BigEndian.PutUint32(hdr[:], uint32(len(p)))
	if _, err := w.Write(hdr[:]); err != nil {
		return err
	}
	_, err := w.Write(p)
	return err
}

func ReadFrame(r io.Reader) ([]byte, error) {
	return ReadFrameLimit(r, MaxFrame)
}

// ReadFrameLimit is ReadFrame with a caller-chosen maximum, checked BEFORE
// allocating, so a peer cannot pin the receiver's memory by declaring a huge
// length. The data tunnel passes its real per-frame ceiling here.
func ReadFrameLimit(r io.Reader, limit uint32) ([]byte, error) {
	var hdr [4]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		return nil, err
	}
	n := binary.BigEndian.Uint32(hdr[:])
	if n > limit {
		return nil, fmt.Errorf("frame too large: %d (limit %d)", n, limit)
	}
	p := make([]byte, n)
	if _, err := io.ReadFull(r, p); err != nil {
		return nil, err
	}
	return p, nil
}

func WriteJSON(w io.Writer, v any) error {
	b, err := json.Marshal(v)
	if err != nil {
		return err
	}
	return WriteFrame(w, b)
}

func ReadJSON(r io.Reader, v any) error {
	b, err := ReadFrame(r)
	if err != nil {
		return err
	}
	return json.Unmarshal(b, v)
}

// Relay rendezvous protocol: each endpoint connects to the relay (TLS) and
// sends a RelayHello frame. The relay pairs the initiator and responder that
// presented the same token, answers both with RelayResp{OK:true}, then
// splices bytes blindly. Tokens are single-use and expire unmatched.
//
// Kind discriminates the two uses of the relay's TCP listener. The empty string
// (the zero value, and the only thing legacy peers ever send) is the single-use
// token rendezvous above. "control" is a persistent, payload-blind control mux:
// instead of pairing a token, the relay forwards the connection straight to the
// controller the hello names, so an agent runs its end-to-end mTLS control stream
// through the relay to the controller. A control hello carries no token or role; the
// new fields are omitempty so a rendezvous hello serializes byte-for-byte as before.
type RelayHello struct {
	V     int    `json:"v"`     // 1
	Token string `json:"token"` // gz-<hex> (rendezvous only)
	Role  string `json:"role"`  // "i" (initiator/client) | "r" (responder/agent) (rendezvous only)
	// Kind is "" (rendezvous), RelayKindControl, RelayKindFunnelReg, or
	// RelayKindFunnelData.
	Kind string `json:"kind,omitempty"`
	// ControllerID is the control mux's target controller — a routing LABEL the relay
	// validates against its signed map and resolves to a dial address itself; it is
	// NEVER an address the agent supplies.
	ControllerID string `json:"gw,omitempty"`
	// Host is the funnel hostname an agent registers to serve (RelayKindFunnelReg).
	Host string `json:"host,omitempty"`
	// RegToken authorizes a funnel registration: the controller-minted per-binding
	// secret, delivered only to the authorized agent. The relay rejects a
	// registration whose token does not match the one the controller pushed it.
	RegToken string `json:"rt,omitempty"`
}

// FunnelDial is sent by the relay to a registered agent over its funnel
// registration connection: a public client arrived for the registered host, so
// the agent should dial back a data connection presenting Token.
type FunnelDial struct {
	Token string `json:"token"`
}

type RelayResp struct {
	OK    bool   `json:"ok"`
	Error string `json:"error,omitempty"`
}

const (
	RoleInitiator = "i"
	RoleResponder = "r"

	// RelayKindControl marks a persistent control mux (RelayHello.Kind); the empty
	// string is the single-use token rendezvous.
	RelayKindControl = "control"
	// RelayKindFunnelReg is an agent's persistent funnel registration ("I serve
	// Host"); the relay sends FunnelDial over it when a public client arrives.
	RelayKindFunnelReg = "funnel-reg"
	// RelayKindFunnelData is an agent's per-request funnel data leg: the relay
	// splices the (TLS-terminated) public plaintext to it, matched by Token.
	RelayKindFunnelData = "funnel-data"
)
