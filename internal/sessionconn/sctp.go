package sessionconn

import (
	"context"
	"fmt"
	"io"
	"net"
	"sync"

	"github.com/pion/logging"
	"github.com/pion/sctp"
)

// sctp.go is the session transport's RELIABILITY layer, paired with ice.go (the
// AVAILABILITY layer). ICE gives a connected but LOSSY, UNORDERED UDP path
// (direct hole-punch or the TURN-UDP floor); SSH-inside-Noise needs an ordered,
// reliable byte stream. We get that the WebRTC DataChannel way: one pion/sctp
// Association carrying one Stream, with SCTP doing reliability, ordering, and
// congestion control. No DTLS — the unchanged Noise IK handshake above already
// gives mutual auth + AEAD, and SCTP sits BELOW it, so the relay only ever
// forwards Noise ciphertext. Decision + tradeoff analysis (vs kcp/quic/ICE-TCP):
// docs/session-reliability-decision.md.

const (
	// sessionMTU pins SCTP's send MTU below the direct AND the TURN-framed floor.
	// We do not PMTUD: ICMP-needs-frag is unreliable over TURN and the selected
	// pair can flip direct<->relay mid-session, so a fixed conservative floor is
	// the robust choice (SCTP self-fragments larger messages across DATA chunks).
	sessionMTU = 1200
	// sctpMaxMessage bounds one SCTP message AND sizes the receive scratch buffer,
	// so a read can never short-buffer (see sctpConn.Read).
	sctpMaxMessage = 64 * 1024
)

// sctpConn presents a pion SCTP stream as a net.Conn. SCTP streams are
// MESSAGE-oriented (each Read returns exactly one message); net.Conn — which
// tunnel.Client/Server and x/crypto/ssh consume — is BYTE-oriented. sctpConn is
// the standard adapter between those two well-defined interfaces. It does NOT
// implement reliability or ordering — SCTP does all of that; it only bridges the
// message<->byte boundary.
//
// Why this is correct (not luck): SCTP delivers the peer's messages reliably and
// strictly IN ORDER, so concatenating their payloads reproduces exactly the byte
// stream the writer produced. Read pulls one whole message into a max-sized
// scratch buffer (so it can never truncate) and hands the caller bytes from it,
// decoupling the caller's read size from the SCTP message size.
type sctpConn struct {
	*sctp.Stream // Write / Close / SetDeadline etc. pass through unchanged
	assoc        *sctp.Association
	ice          net.Conn

	rmu  sync.Mutex
	pend []byte // bytes from the last message not yet handed to the caller
	rbuf []byte // reusable per-message scratch, sized to sctpMaxMessage
}

func (c *sctpConn) Read(p []byte) (int, error) {
	c.rmu.Lock()
	defer c.rmu.Unlock()
	for len(c.pend) == 0 {
		n, err := c.Stream.Read(c.rbuf) // exactly one SCTP message into a max-sized buf
		if n > 0 {
			c.pend = append(c.pend[:0], c.rbuf[:n]...)
		}
		if err != nil {
			if err == io.ErrShortBuffer {
				continue // unreachable (rbuf == MaxMessageSize); kept as a guard
			}
			if len(c.pend) == 0 {
				return 0, err
			}
			break // deliver buffered bytes now; surface the error on the next Read
		}
	}
	n := copy(p, c.pend)
	c.pend = c.pend[n:]
	return n, nil
}

func (c *sctpConn) LocalAddr() net.Addr  { return c.ice.LocalAddr() }
func (c *sctpConn) RemoteAddr() net.Addr { return c.ice.RemoteAddr() }

// Close tears the stack down top-down: reset the stream (peer Read -> EOF), close
// the association (graceful — pion flushes SHUTDOWN and waits for its read loop),
// then the ICE conn (which cancels the session ctx + closes the agent). A single
// Close from the Noise conn chains all the way to the socket.
func (c *sctpConn) Close() error {
	_ = c.Stream.Close()
	_ = c.assoc.Close()
	return c.ice.Close()
}

func sctpConfig(ic net.Conn) sctp.Config {
	return sctp.Config{
		NetConn:        ic,
		MTU:            sessionMTU,
		BlockWrite:     true, // TCP-style write backpressure when the reader is slow (sftp)
		MaxMessageSize: sctpMaxMessage,
		LoggerFactory:  logging.NewDefaultLoggerFactory(),
	}
}

func newSCTPConn(ic net.Conn, s *sctp.Stream, a *sctp.Association) *sctpConn {
	return &sctpConn{Stream: s, assoc: a, ice: ic, rbuf: make([]byte, sctpMaxMessage)}
}

// clientStream runs the SCTP client over the ICE conn and opens the one stream
// (the controlling/initiator side).
func clientStream(ic net.Conn) (net.Conn, error) {
	a, err := sctp.Client(sctpConfig(ic))
	if err != nil {
		return nil, err
	}
	s, err := a.OpenStream(0, sctp.PayloadTypeWebRTCBinary)
	if err != nil {
		_ = a.Close()
		return nil, err
	}
	return newSCTPConn(ic, s, a), nil
}

// serverStream runs the SCTP server over the ICE conn and accepts the one stream
// (the controlled/responder side). AcceptStream returns when the client makes the
// stream visible with its first write — the Noise msg1 — the same client-writes-
// first ordering the relay path had.
func serverStream(ic net.Conn) (net.Conn, error) {
	a, err := sctp.Server(sctpConfig(ic))
	if err != nil {
		return nil, err
	}
	s, err := a.AcceptStream()
	if err != nil {
		_ = a.Close()
		return nil, err
	}
	s.SetDefaultPayloadType(sctp.PayloadTypeWebRTCBinary)
	return newSCTPConn(ic, s, a), nil
}

// Dial is the controlling/client side: ICE connect + SCTP client -> a reliable
// net.Conn ready to hand to tunnel.Client. Returns the path class (direct|relayed).
func Dial(ctx context.Context, cfg Config, sig Signaler) (net.Conn, string, error) {
	ic, path, err := Connect(ctx, cfg, sig)
	if err != nil {
		return nil, "", err
	}
	sc, err := clientStream(ic)
	if err != nil {
		_ = ic.Close()
		return nil, "", fmt.Errorf("sctp client: %w", err)
	}
	return sc, path, nil
}

// Accept is the controlled/agent side: ICE connect + SCTP server -> a reliable
// net.Conn ready to hand to tunnel.Server.
func Accept(ctx context.Context, cfg Config, sig Signaler) (net.Conn, string, error) {
	ic, path, err := Connect(ctx, cfg, sig)
	if err != nil {
		return nil, "", err
	}
	sc, err := serverStream(ic)
	if err != nil {
		_ = ic.Close()
		return nil, "", fmt.Errorf("sctp server: %w", err)
	}
	return sc, path, nil
}
