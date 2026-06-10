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
	var hdr [4]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		return nil, err
	}
	n := binary.BigEndian.Uint32(hdr[:])
	if n > MaxFrame {
		return nil, fmt.Errorf("frame too large: %d", n)
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
type RelayHello struct {
	V     int    `json:"v"`     // 1
	Token string `json:"token"` // gz-<hex>
	Role  string `json:"role"`  // "i" (initiator/client) | "r" (responder/agent)
}

type RelayResp struct {
	OK    bool   `json:"ok"`
	Error string `json:"error,omitempty"`
}

const (
	RoleInitiator = "i"
	RoleResponder = "r"
)
