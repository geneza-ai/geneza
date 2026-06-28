// Package attachproto frames SessionHost stream messages (ClientToHost /
// HostToClient) over any reliable byte stream — concretely, the
// "geneza-attach" SSH channel inside the tunnel. Both the CLI client and the
// agent worker use these helpers, so the wire format cannot drift.
//
// Framing: 4-byte big-endian length + protobuf-marshaled message.
//
// Channel open convention: the "geneza-attach" channel's extra data is JSON
// AttachOpenParams. Which host session is created/attached is decided by the
// agent from the signed grant (never from unauthenticated channel data).
package attachproto

import (
	"encoding/json"
	"fmt"
	"io"

	"google.golang.org/protobuf/proto"

	genezav1 "geneza.io/internal/pb/geneza/v1"
	"geneza.io/internal/wire"
)

// AttachOpenParams rides as the SSH channel-open extra data.
type AttachOpenParams struct {
	LastSeenSeq uint64 `json:"last_seen_seq"`
	Cols        uint32 `json:"cols"`
	Rows        uint32 `json:"rows"`
	Term        string `json:"term"`
}

func (p *AttachOpenParams) Marshal() []byte {
	b, _ := json.Marshal(p)
	return b
}

func ParseAttachOpenParams(b []byte) (*AttachOpenParams, error) {
	var p AttachOpenParams
	if len(b) == 0 {
		return &p, nil
	}
	if err := json.Unmarshal(b, &p); err != nil {
		return nil, fmt.Errorf("attach open params: %w", err)
	}
	return &p, nil
}

func writeMsg(w io.Writer, m proto.Message) error {
	b, err := proto.Marshal(m)
	if err != nil {
		return err
	}
	return wire.WriteFrame(w, b)
}

func WriteClientMsg(w io.Writer, m *genezav1.ClientToHost) error { return writeMsg(w, m) }
func WriteHostMsg(w io.Writer, m *genezav1.HostToClient) error   { return writeMsg(w, m) }

func ReadClientMsg(r io.Reader) (*genezav1.ClientToHost, error) {
	b, err := wire.ReadFrame(r)
	if err != nil {
		return nil, err
	}
	var m genezav1.ClientToHost
	if err := proto.Unmarshal(b, &m); err != nil {
		return nil, err
	}
	return &m, nil
}

func ReadHostMsg(r io.Reader) (*genezav1.HostToClient, error) {
	b, err := wire.ReadFrame(r)
	if err != nil {
		return nil, err
	}
	var m genezav1.HostToClient
	if err := proto.Unmarshal(b, &m); err != nil {
		return nil, err
	}
	return &m, nil
}

// ChannelTypeAttach is the custom SSH channel type for persistent sessions.
const ChannelTypeAttach = "geneza-attach"
