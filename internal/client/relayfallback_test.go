package client

import (
	"context"
	"crypto/x509"
	"errors"
	"net"
	"testing"
	"time"

	genezav1 "geneza.io/internal/pb/geneza/v1"
)

// The in-process web-shell proxy passes a local-dial override so a single-host
// install does not hairpin out and back through its own public IP. That override is
// an INFERENCE — "the relay is on this machine, so it answers on loopback" — and it
// is false whenever the controller and the relay sit in separate network namespaces,
// which is exactly what the compose and Kubernetes deployments do: 127.0.0.1 there is
// the controller CONTAINER's loopback, not the relay's.
//
// The override must therefore be a preference, not a hard dependency: when it fails,
// fall back to the address the grant carries. That address is reachable by
// construction — every agent and native client already dials it.
func TestDialRelayClientFallsBackWhenLocalOverrideFails(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	reached := make(chan struct{}, 1)
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			select {
			case reached <- struct{}{}:
			default:
			}
			c.Close()
		}
	}()

	resp := &genezav1.CreateSessionResponse{
		RelayAddr:  ln.Addr().String(),
		RelayToken: "gz-deadbeefcafe",
	}

	// 127.0.0.1:1 stands in for the wrong-namespace loopback: nothing listens there.
	_, err = dialRelayClient(context.Background(), x509.NewCertPool(), resp, "127.0.0.1:1")
	// The fallback reaches a bare TCP listener, so the TLS handshake still fails —
	// what matters is WHICH address the final attempt went to.
	if err == nil {
		t.Fatal("expected the TLS handshake against a bare listener to fail")
	}

	select {
	case <-reached:
	case <-time.After(5 * time.Second):
		t.Fatal("the local-dial override failed and the grant address was never tried: " +
			"a containerized controller can never open a web shell")
	}
}

// The retry boundary is "did the hello land yet". Everything up to and including the
// TLS handshake happens BEFORE the hello is written, so it is safe to try elsewhere;
// after that the relay holds a single-use rendezvous slot for the token and a second
// hello is refused ("endpoint with this role already waiting"), which would replace a
// real error with a confusing one. Only the pre-hello phase is tagged retryable.
func TestRelayDialErrorMarksOnlyPreHelloFailures(t *testing.T) {
	// Nothing listening: the TCP connect fails inside the TLS dialer, before any
	// hello could be written.
	_, err := dialRelayFloorOnce(context.Background(), x509.NewCertPool(),
		"127.0.0.1:1", "127.0.0.1:1", "gz-deadbeefcafe")
	if err == nil {
		t.Fatal("expected a connect failure")
	}
	var dialErr relayDialError
	if !errors.As(err, &dialErr) {
		t.Fatalf("an unreachable relay must be a retryable relayDialError, got %T: %v", err, err)
	}

	// A malformed floor entry fails before the dial and is NOT a reach failure —
	// retrying another target would not help.
	_, err = dialRelayFloorOnce(context.Background(), x509.NewCertPool(),
		"no-port-here", "no-port-here", "gz-deadbeefcafe")
	if err == nil {
		t.Fatal("expected a parse failure")
	}
	if errors.As(err, &dialErr) {
		t.Fatalf("a malformed relay address must not be marked retryable: %v", err)
	}
}

// Without an override the grant address is dialed directly — the fallback must not
// change the ordinary path, nor dial anything twice.
func TestDialRelayClientNoOverrideDialsGrantAddress(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	conns := make(chan struct{}, 8)
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			conns <- struct{}{}
			c.Close()
		}
	}()

	resp := &genezav1.CreateSessionResponse{
		RelayAddr:  ln.Addr().String(),
		RelayToken: "gz-deadbeefcafe",
	}
	if _, err := dialRelayClient(context.Background(), x509.NewCertPool(), resp, ""); err == nil {
		t.Fatal("expected the TLS handshake against a bare listener to fail")
	}

	select {
	case <-conns:
	case <-time.After(5 * time.Second):
		t.Fatal("the grant address was never dialed")
	}
	// Exactly one attempt: no override means nothing to retry.
	select {
	case <-conns:
		t.Fatal("dialed the grant address twice with no override in play")
	case <-time.After(300 * time.Millisecond):
	}
}
