package client

import (
	"context"
	"crypto/x509"
	"strings"
	"testing"

	genezav1 "geneza.io/internal/pb/geneza/v1"
	"geneza.io/internal/tunnel"
)

// DialSession is the single transport entrypoint every client (native CLI, desktop,
// web-shell proxy) uses. A nil signaling api — the in-process web proxy, which has no
// SessionSignal stream — must NEVER attempt ICE even when the controller offered TURN
// creds; it goes straight to the relay-TCP floor. This guards the exact divergence
// that once stalled the web shell ~15s waiting out an ICE gather.
func TestDialSessionNilAPISkipsICE(t *testing.T) {
	key, err := tunnel.GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	resp := &genezav1.CreateSessionResponse{
		Turn:          &genezav1.TurnCreds{TurnUrl: "turn:example:3478"}, // a TURN offer IS present...
		RelayAddr:     "127.0.0.1:1",                                     // ...but the relay floor is unreachable
		RelayToken:    "gz-deadbeefcafe",
		AgentNoisePub: make([]byte, 32),
	}
	// nil api: must take the relay floor (and fail there), never touch ICE.
	_, err = DialSession(context.Background(), nil, x509.NewCertPool(), resp, key, "")
	if err == nil {
		t.Fatal("expected a relay-connect failure")
	}
	if !strings.Contains(err.Error(), "relay") {
		t.Fatalf("a nil-api session with a TURN offer must take the relay floor, got: %v", err)
	}
}
