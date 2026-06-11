// Package tunnel implements the end-to-end encrypted data tunnel between a
// client and an agent: a Noise IK handshake (Curve25519 / ChaChaPoly /
// BLAKE2s) over any reliable byte stream (typically a relay-spliced TCP
// connection), yielding a net.Conn whose payloads the relay cannot read.
//
// The initiator (client) embeds its signed session grant in the first
// handshake message; the responder (agent) authorizes it before completing
// the handshake, so an unauthorized peer never receives a single byte of
// application data.
package tunnel

import (
	"crypto/rand"
	"errors"
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/flynn/noise"

	"osie.cloud/geneza/internal/wire"
)

const (
	// MaxPlaintext keeps every Noise message under the 65535-byte limit.
	MaxPlaintext = 32 * 1024
	// maxCipherFrame bounds a single ciphertext frame on the wire: one
	// MaxPlaintext chunk plus the ChaCha20-Poly1305 tag (16 bytes), with a
	// little slack. The Read path rejects anything larger before allocating.
	maxCipherFrame = MaxPlaintext + 256
	prologue       = "geneza/1"
)

var cipherSuite = noise.NewCipherSuite(noise.DH25519, noise.CipherChaChaPoly, noise.HashBLAKE2s)

// GenerateKeypair creates a Curve25519 static keypair for tunnel endpoints.
func GenerateKeypair() (noise.DHKey, error) {
	return cipherSuite.GenerateKeypair(rand.Reader)
}

// Conn is an encrypted stream over a raw connection. It implements net.Conn.
type Conn struct {
	raw net.Conn

	rmu     sync.Mutex
	dec     *noise.CipherState
	readBuf []byte

	wmu sync.Mutex
	enc *noise.CipherState

	remoteStatic []byte
}

// RemoteStatic returns the peer's Curve25519 static public key.
func (c *Conn) RemoteStatic() []byte { return c.remoteStatic }

func (c *Conn) Read(p []byte) (int, error) {
	c.rmu.Lock()
	defer c.rmu.Unlock()
	for len(c.readBuf) == 0 {
		// A tunnel frame is at most one MaxPlaintext chunk + the AEAD tag; cap
		// the read there so a blind/compromised relay cannot make us allocate a
		// huge buffer per frame.
		ct, err := wire.ReadFrameLimit(c.raw, maxCipherFrame)
		if err != nil {
			return 0, err
		}
		pt, err := c.dec.Decrypt(nil, nil, ct)
		if err != nil {
			return 0, fmt.Errorf("tunnel decrypt: %w", err)
		}
		c.readBuf = pt
	}
	n := copy(p, c.readBuf)
	c.readBuf = c.readBuf[n:]
	return n, nil
}

func (c *Conn) Write(p []byte) (int, error) {
	c.wmu.Lock()
	defer c.wmu.Unlock()
	total := 0
	for len(p) > 0 {
		chunk := p
		if len(chunk) > MaxPlaintext {
			chunk = p[:MaxPlaintext]
		}
		ct, err := c.enc.Encrypt(nil, nil, chunk)
		if err != nil {
			return total, fmt.Errorf("tunnel encrypt: %w", err)
		}
		if err := wire.WriteFrame(c.raw, ct); err != nil {
			return total, err
		}
		total += len(chunk)
		p = p[len(chunk):]
	}
	return total, nil
}

func (c *Conn) Close() error                       { return c.raw.Close() }
func (c *Conn) LocalAddr() net.Addr                { return c.raw.LocalAddr() }
func (c *Conn) RemoteAddr() net.Addr               { return c.raw.RemoteAddr() }
func (c *Conn) SetDeadline(t time.Time) error      { return c.raw.SetDeadline(t) }
func (c *Conn) SetReadDeadline(t time.Time) error  { return c.raw.SetReadDeadline(t) }
func (c *Conn) SetWriteDeadline(t time.Time) error { return c.raw.SetWriteDeadline(t) }

func handshakeConfig(initiator bool, static noise.DHKey, peerStatic []byte, sessionID string) noise.Config {
	return noise.Config{
		CipherSuite:   cipherSuite,
		Pattern:       noise.HandshakeIK,
		Initiator:     initiator,
		StaticKeypair: static,
		PeerStatic:    peerStatic,
		Prologue:      []byte(prologue + ":" + sessionID),
		Random:        rand.Reader,
	}
}

// Client runs the initiator side of the IK handshake over raw. payload
// (typically the encoded signed grant) rides in the first handshake message,
// encrypted to the responder's static key. Returns the secure conn and the
// responder's handshake payload (the agent's acceptance message).
func Client(raw net.Conn, static noise.DHKey, agentStaticPub []byte, sessionID string, payload []byte) (*Conn, []byte, error) {
	hs, err := noise.NewHandshakeState(handshakeConfig(true, static, agentStaticPub, sessionID))
	if err != nil {
		return nil, nil, fmt.Errorf("noise init: %w", err)
	}
	msg1, _, _, err := hs.WriteMessage(nil, payload)
	if err != nil {
		return nil, nil, fmt.Errorf("noise msg1: %w", err)
	}
	if err := wire.WriteFrame(raw, msg1); err != nil {
		return nil, nil, err
	}
	msg2, err := wire.ReadFrame(raw)
	if err != nil {
		return nil, nil, fmt.Errorf("waiting for agent acceptance: %w", err)
	}
	respPayload, cs0, cs1, err := hs.ReadMessage(nil, msg2)
	if err != nil {
		return nil, nil, fmt.Errorf("noise msg2: %w", err)
	}
	// Initiator: cs0 encrypts initiator->responder, cs1 the reverse.
	c := &Conn{raw: raw, enc: cs0, dec: cs1, remoteStatic: hs.PeerStatic()}
	return c, respPayload, nil
}

// ErrRejected is returned by Server when authorize rejects the initiator.
var ErrRejected = errors.New("tunnel: peer rejected")

// Server runs the responder side. authorize receives the initiator's static
// public key and handshake payload (signed grant) and must return the
// acceptance payload, or an error to abort before any application data flows.
func Server(raw net.Conn, static noise.DHKey, sessionID string, authorize func(remoteStatic, payload []byte) ([]byte, error)) (*Conn, error) {
	hs, err := noise.NewHandshakeState(handshakeConfig(false, static, nil, sessionID))
	if err != nil {
		return nil, fmt.Errorf("noise init: %w", err)
	}
	msg1, err := wire.ReadFrame(raw)
	if err != nil {
		return nil, err
	}
	payload, _, _, err := hs.ReadMessage(nil, msg1)
	if err != nil {
		return nil, fmt.Errorf("noise msg1: %w", err)
	}
	accept, err := authorize(hs.PeerStatic(), payload)
	if err != nil {
		return nil, fmt.Errorf("%w: %s", ErrRejected, err)
	}
	msg2, cs0, cs1, err := hs.WriteMessage(nil, accept)
	if err != nil {
		return nil, fmt.Errorf("noise msg2: %w", err)
	}
	if err := wire.WriteFrame(raw, msg2); err != nil {
		return nil, err
	}
	// Responder: cs0 decrypts initiator->responder, cs1 encrypts the reverse.
	c := &Conn{raw: raw, enc: cs1, dec: cs0, remoteStatic: hs.PeerStatic()}
	return c, nil
}
