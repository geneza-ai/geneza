package relay

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"io"
	"log/slog"
	"net"
	"runtime"
	"testing"
	"time"

	"geneza.io/internal/types"
	"geneza.io/internal/wire"
)

func relayConnCount(r *Relay) int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.conns) + len(r.muxConns)
}

func waitConnCount(t *testing.T, r *Relay, want int, within time.Duration) {
	t.Helper()
	deadline := time.Now().Add(within)
	for time.Now().Before(deadline) {
		if relayConnCount(r) == want {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("relay tracked conns = %d, want %d after %s", relayConnCount(r), want, within)
}

// drainController accepts control-mux forwards and drains them until the relay tears
// the splice down — a stand-in controller that holds the conn open.
func drainController(t *testing.T) (addr string, dialer func(string) (net.Conn, error)) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) { _, _ = io.Copy(io.Discard, c); c.Close() }(c)
		}
	}()
	return ln.Addr().String(), func(a string) (net.Conn, error) { return net.DialTimeout("tcp", a, time.Second) }
}

// A control mux tracks exactly the agent + controller conns while live, and an abrupt
// agent death reaps BOTH — no stale/zombie conn is stranded in the relay.
func TestControlMuxConnLifecycle(t *testing.T) {
	gwAddr, dialer := drainController(t)
	r, addr := startControlRelay(t, map[string][]string{"gw-test": {gwAddr}}, dialer)
	base := relayConnCount(r) // 0

	c := dialControlHello(t, addr, "gw-test")
	resp, err := readResp(t, c, 2*time.Second)
	if err != nil || !resp.OK {
		t.Fatalf("mux refused: err=%v resp=%+v", err, resp)
	}
	// Live: the agent conn + the dialed controller conn are both tracked.
	waitConnCount(t, r, base+2, 2*time.Second)

	// Abruptly kill the agent side (no graceful close) — the relay must reap both.
	c.Close()
	waitConnCount(t, r, base, 3*time.Second)
}

// Control muxes are capped by their OWN budget (MaxControlMux), separate from the
// ephemeral-splice cap — so a relay full of homed agents rejects new muxes but does
// NOT starve token rendezvous, and vice-versa.
func TestControlMuxCapSeparateFromSplices(t *testing.T) {
	gwAddr, dialer := drainController(t)
	cfg := testConfig()
	cfg.ControlMux = true
	cfg.MaxControlMux = 1 // at most one homed agent
	ln, err := net.Listen("tcp", cfg.Listen)
	if err != nil {
		t.Fatal(err)
	}
	r := New(cfg, slog.New(slog.DiscardHandler))
	r.dialControlController = dialer
	r.setControllerNodeControl(map[string][]string{"gw-test": {gwAddr}})
	go r.Serve(ln) //nolint:errcheck
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		_ = r.Shutdown(ctx)
	})
	addr := ln.Addr().String()

	// First mux is admitted and holds both legs.
	c1 := dialControlHello(t, addr, "gw-test")
	if resp, err := readResp(t, c1, 2*time.Second); err != nil || !resp.OK {
		t.Fatalf("first mux refused: err=%v resp=%+v", err, resp)
	}
	waitConnCount(t, r, 2, 2*time.Second)

	// Second mux is explicitly rejected at the cap (not silently dropped).
	c2 := dialControlHello(t, addr, "gw-test")
	resp, err := readResp(t, c2, 2*time.Second)
	if err != nil {
		t.Fatalf("second mux read: %v", err)
	}
	if resp.OK {
		t.Fatal("second control mux admitted past MaxControlMux=1")
	}

	// A token rendezvous is NOT starved by the full mux cap — separate budgets.
	tok := newToken(t)
	ini := dialHello(t, addr, tok, wire.RoleInitiator)
	_ = dialHello(t, addr, tok, wire.RoleResponder)
	if rr, err := readResp(t, ini, 2*time.Second); err != nil || !rr.OK {
		t.Fatalf("token rendezvous starved by a full mux cap: err=%v resp=%+v", err, rr)
	}
}

// Repeated connect/abrupt-disconnect churn leaks no goroutines and strands no
// tracked conns — the long-lived control-mux path cleans up like the splice path.
func TestControlMuxNoGoroutineLeak(t *testing.T) {
	gwAddr, dialer := drainController(t)
	r, addr := startControlRelay(t, map[string][]string{"gw-test": {gwAddr}}, dialer)

	cycle := func() {
		c := dialControlHello(t, addr, "gw-test")
		if _, err := readResp(t, c, 2*time.Second); err != nil {
			t.Fatalf("mux: %v", err)
		}
		c.Close()
		waitConnCount(t, r, 0, 3*time.Second)
	}
	cycle() // warm up lazy goroutines (stats loop, accept loop) before the baseline
	runtime.GC()
	base := runtime.NumGoroutine()
	for i := 0; i < 30; i++ {
		cycle()
	}
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		runtime.GC()
		if runtime.NumGoroutine() <= base+5 {
			if relayConnCount(r) != 0 {
				t.Fatalf("tracked conns not drained: %d", relayConnCount(r))
			}
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatalf("goroutines grew under churn: base=%d now=%d", base, runtime.NumGoroutine())
}

func signedControllerMap(t *testing.T, priv ed25519.PrivateKey, keyID string, version int64, gws []types.ControllerEndpoint) []byte {
	t.Helper()
	cc := types.ClusterConfig{
		ConfigVersion:    version,
		GrantKeys:        []types.GrantKey{{KeyID: keyID, PublicKey: ed25519.PublicKey(priv.Public().(ed25519.PublicKey))}},
		TrustKeys:        []types.TrustKey{{KeyID: keyID, PublicKey: ed25519.PublicKey(priv.Public().(ed25519.PublicKey))}},
		ControllerEndpoints: gws,
	}
	env, err := types.Sign(priv, keyID, "cluster-config", cc)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := env.Encode()
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

// The resolver only populates the control-mux routing table from a signed,
// signature-verified map: it pins trust from the first config (TOFU), refuses an
// untrusted-key or rolled-back map, and never lets an unverified map steer a dial.
func TestControllerControlResolver(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	keyID := types.KeyIDFor(pub)

	var res controllerControlResolver

	v1 := signedControllerMap(t, priv, keyID, 1, []types.ControllerEndpoint{
		{ControllerID: "gw-a", Addrs: []string{"10.0.0.1:7401"}},
		{ControllerID: "gw-b", Addrs: []string{"10.0.0.2:7401"}},
	})
	table, ok := res.resolve(v1, nil, nil)
	if !ok || len(table) != 2 || table["gw-a"][0] != "10.0.0.1:7401" {
		t.Fatalf("first signed map not resolved: ok=%v table=%v", ok, table)
	}

	// A newer config from the pinned key updates the table.
	v2 := signedControllerMap(t, priv, keyID, 2, []types.ControllerEndpoint{
		{ControllerID: "gw-a", Addrs: []string{"10.0.0.9:7401"}},
	})
	table, ok = res.resolve(v2, nil, nil)
	if !ok || len(table) != 1 || table["gw-a"][0] != "10.0.0.9:7401" {
		t.Fatalf("newer signed map not adopted: ok=%v table=%v", ok, table)
	}

	// A config signed by a DIFFERENT (untrusted) key is refused — it cannot inject a
	// rogue NodeControl address for the relay to dial.
	otherPub, otherPriv, _ := ed25519.GenerateKey(rand.Reader)
	rogue := signedControllerMap(t, otherPriv, types.KeyIDFor(otherPub), 3, []types.ControllerEndpoint{
		{ControllerID: "gw-evil", Addrs: []string{"169.254.169.254:80"}},
	})
	if _, ok := res.resolve(rogue, nil, nil); ok {
		t.Fatal("untrusted-key map was accepted into the routing table")
	}

	// A rolled-back version is refused.
	if _, ok := res.resolve(v1, nil, nil); ok {
		t.Fatal("rolled-back map was accepted")
	}

	// Garbage is refused.
	if _, ok := res.resolve([]byte("not-a-signed-config"), nil, nil); ok {
		t.Fatal("garbage map was accepted")
	}
}

// The resolver verifies the SPLIT pair the same way: it TOFU-pins the offline trust
// key from the first anchor, reads the controller table from the grant-key-signed routine
// map, refuses a routine map bound to a forged anchor (wrong digest) even when grant
// -key-signed, and refuses an anchor not signed by the pinned trust key.
func TestControllerControlResolverSplit(t *testing.T) {
	oPub, oPriv, oID, _ := types.GenerateSigningKey()
	gPub, gPriv, gID, _ := types.GenerateSigningKey()

	mkAnchor := func(v int64, trust []types.TrustKey, trustPriv ed25519.PrivateKey, trustID string) ([]byte, []byte) {
		a := types.TrustAnchors{
			AnchorVersion: v,
			GrantKeys:     []types.GrantKey{{KeyID: gID, PublicKey: gPub}},
			TrustKeys:     trust,
		}
		payload, _ := json.Marshal(&a)
		one, _ := types.SignOne(trustPriv, trustID, "trust-anchors", payload)
		env, _ := (&types.MultiSigned{Payload: payload, Sigs: []types.OneSig{one}}).Encode()
		return env, payload
	}
	mkMap := func(cv, av int64, anchorPayload []byte, gws []types.ControllerEndpoint) []byte {
		rm := types.RoutineMap{
			ConfigVersion: cv, AnchorVersion: av, AnchorDigest: types.AnchorDigestOf(anchorPayload),
			ControllerEndpoints: gws,
		}
		env, _ := types.Sign(gPriv, gID, "routine-map", rm)
		raw, _ := env.Encode()
		return raw
	}

	officer := []types.TrustKey{{KeyID: oID, PublicKey: oPub}}
	anchorEnv, anchorPayload := mkAnchor(1, officer, oPriv, oID)
	mapEnv := mkMap(1, 1, anchorPayload, []types.ControllerEndpoint{{ControllerID: "gw-a", Addrs: []string{"10.0.0.1:7401"}}})

	var res controllerControlResolver
	table, ok := res.resolve(nil, anchorEnv, mapEnv)
	if !ok || table["gw-a"][0] != "10.0.0.1:7401" {
		t.Fatalf("split pair not resolved: ok=%v table=%v", ok, table)
	}

	// A grant-key-signed routine map bound to a FORGED anchor (an attacker key added,
	// so a different payload and digest) is refused: the grant key cannot pair its
	// forgery with a trust set the relay holds.
	atkPub, _, _, _ := types.GenerateSigningKey()
	forgedAnchorPayload, _ := json.Marshal(&types.TrustAnchors{
		AnchorVersion: 1,
		GrantKeys:     []types.GrantKey{{KeyID: gID, PublicKey: gPub}, {KeyID: "attacker", PublicKey: atkPub}},
		TrustKeys:     officer,
	})
	forgedMap := mkMap(2, 1, forgedAnchorPayload, []types.ControllerEndpoint{{ControllerID: "gw-evil", Addrs: []string{"169.254.169.254:80"}}})
	if _, ok := res.resolve(nil, anchorEnv, forgedMap); ok {
		t.Fatal("grant-key-forged routine map (wrong anchor digest) was accepted")
	}

	// An anchor signed by a NON-pinned key (its own TrustKeys say "trust me") is refused.
	aPub, aPriv, aID, _ := types.GenerateSigningKey()
	rogueAnchor, roguePayload := mkAnchor(2, []types.TrustKey{{KeyID: aID, PublicKey: aPub}}, aPriv, aID)
	rogueMap := mkMap(2, 2, roguePayload, []types.ControllerEndpoint{{ControllerID: "gw-evil", Addrs: []string{"169.254.169.254:80"}}})
	if _, ok := res.resolve(nil, rogueAnchor, rogueMap); ok {
		t.Fatal("anchor signed by a non-pinned key was accepted")
	}

	// A pinned relay refuses to regress to a legacy-only config.
	legacy := signedControllerMap(t, gPriv, gID, 9, []types.ControllerEndpoint{{ControllerID: "gw-evil", Addrs: []string{"169.254.169.254:80"}}})
	if _, ok := res.resolve(legacy, nil, nil); ok {
		t.Fatal("a pinned relay regressed to a legacy config")
	}
}

// A legacy rendezvous hello still serializes without the new fields, so an old
// relay/agent interoperates byte-for-byte; a control hello carries a kind + gw and
// no token/role.
func TestRelayHelloWireBackCompat(t *testing.T) {
	b, err := json.Marshal(wire.RelayHello{V: 1, Token: "gz-deadbeef", Role: wire.RoleInitiator})
	if err != nil {
		t.Fatal(err)
	}
	if got := string(b); got != `{"v":1,"token":"gz-deadbeef","role":"i"}` {
		t.Fatalf("rendezvous hello not byte-identical: %s", got)
	}
	if bytes.Contains(b, []byte("kind")) || bytes.Contains(b, []byte(`"gw"`)) {
		t.Fatalf("rendezvous hello leaked a control field: %s", b)
	}
}

func TestValidateHelloControlKind(t *testing.T) {
	ok := func(h wire.RelayHello) {
		t.Helper()
		if err := validateHello(h); err != nil {
			t.Fatalf("want valid, got %v for %+v", err, h)
		}
	}
	bad := func(h wire.RelayHello) {
		t.Helper()
		if err := validateHello(h); err == nil {
			t.Fatalf("want invalid, got nil for %+v", h)
		}
	}
	ok(wire.RelayHello{V: 1, Kind: wire.RelayKindControl, ControllerID: "geneza-core"})
	ok(wire.RelayHello{V: 1, Kind: wire.RelayKindControl, ControllerID: "gw-01a.region_1"})
	bad(wire.RelayHello{V: 1, Kind: wire.RelayKindControl})                                       // no controller id
	bad(wire.RelayHello{V: 1, Kind: wire.RelayKindControl, ControllerID: "bad id!"})                 // charset
	bad(wire.RelayHello{V: 1, Kind: wire.RelayKindControl, ControllerID: "g", Token: "gz-deadbeef"}) // token on control
	bad(wire.RelayHello{V: 1, Kind: wire.RelayKindControl, ControllerID: "g", Role: wire.RoleInitiator})
	bad(wire.RelayHello{V: 1, Kind: "weird", ControllerID: "g"}) // unknown kind
	// The token rendezvous path is unchanged.
	ok(wire.RelayHello{V: 1, Token: "gz-deadbeefcafef00d", Role: wire.RoleResponder})
	bad(wire.RelayHello{V: 1, Role: wire.RoleResponder}) // missing token
}

func TestSafeDialTarget(t *testing.T) {
	// A literal safe IP is returned as the exact dial target (no re-resolution).
	got, err := safeDialTarget("10.70.70.10:7401")
	if err != nil || got != "10.70.70.10:7401" {
		t.Fatalf("safe target: got %q err %v", got, err)
	}
	for _, a := range []string{
		"127.0.0.1:7401",     // loopback
		"169.254.169.254:80", // cloud metadata (link-local)
		"0.0.0.0:7401",       // unspecified
		"[::1]:7401",         // loopback v6
		"224.0.0.1:7401",     // multicast
		"not-a-host-port",    // malformed
	} {
		if _, err := safeDialTarget(a); err == nil {
			t.Fatalf("unsafe target %q was allowed", a)
		}
	}
}

// startControlRelay starts a relay with control-mux enabled, a preset signed
// controller table, and (optionally) a test dialer — set BEFORE Serve so the handler
// goroutine observes them without a race.
func startControlRelay(t *testing.T, table map[string][]string, dialer func(string) (net.Conn, error)) (*Relay, string) {
	t.Helper()
	cfg := testConfig()
	cfg.ControlMux = true
	ln, err := net.Listen("tcp", cfg.Listen)
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	r := New(cfg, slog.New(slog.DiscardHandler))
	if dialer != nil {
		r.dialControlController = dialer
	}
	if table != nil {
		r.setControllerNodeControl(table)
	}
	go r.Serve(ln) //nolint:errcheck
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		_ = r.Shutdown(ctx)
	})
	return r, ln.Addr().String()
}

func dialControlHello(t *testing.T, addr, controllerID string) net.Conn {
	t.Helper()
	c, err := net.DialTimeout("tcp", addr, time.Second)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	t.Cleanup(func() { c.Close() })
	if err := wire.WriteJSON(c, wire.RelayHello{V: 1, Kind: wire.RelayKindControl, ControllerID: controllerID}); err != nil {
		t.Fatalf("write control hello: %v", err)
	}
	return c
}

// With control-mux disabled the relay rejects a control hello outright and never
// touches the token-pairing tables.
func TestControlMuxGateDefaultOff(t *testing.T) {
	cfg := testConfig() // ControlMux defaults false
	r, addr := startRelay(t, cfg)
	c := dialControlHello(t, addr, "geneza-core")
	resp, err := readResp(t, c, time.Second)
	if err != nil {
		t.Fatalf("read resp: %v", err)
	}
	if resp.OK {
		t.Fatal("control hello accepted with control mux disabled")
	}
	r.mu.Lock()
	np := len(r.pending)
	r.mu.Unlock()
	if np != 0 {
		t.Fatalf("control hello touched the token-pairing table: pending=%d", np)
	}
}

// Control-mux enabled but no signed controller set held yet => fail closed.
func TestControlMuxFailClosedNoMap(t *testing.T) {
	_, addr := startControlRelay(t, nil, nil)
	c := dialControlHello(t, addr, "geneza-core")
	resp, err := readResp(t, c, time.Second)
	if err != nil {
		t.Fatalf("read resp: %v", err)
	}
	if resp.OK {
		t.Fatal("control hello accepted with no signed controller map")
	}
}

// A controller id absent from the signed map is rejected and the relay dials nothing.
func TestControlMuxUnknownController(t *testing.T) {
	dialed := false
	dialer := func(string) (net.Conn, error) { dialed = true; return nil, io.EOF }
	_, addr := startControlRelay(t, map[string][]string{"gw-one": {"10.0.0.1:7401"}}, dialer)
	c := dialControlHello(t, addr, "gw-two")
	resp, err := readResp(t, c, time.Second)
	if err != nil {
		t.Fatalf("read resp: %v", err)
	}
	if resp.OK {
		t.Fatal("control hello for an unknown controller was accepted")
	}
	if dialed {
		t.Fatal("relay dialed for an unknown controller label")
	}
}

// Even a SIGNED map entry pointing at an unsafe (loopback) target is refused by the
// production dial path's deny-list, so a misconfigured map cannot turn the relay
// into an internal-port probe.
func TestControlMuxRefusesUnsafeSignedTarget(t *testing.T) {
	// No dialer override => the default dial path with safeDialTarget runs.
	_, addr := startControlRelay(t, map[string][]string{"gw-one": {"127.0.0.1:7401"}}, nil)
	c := dialControlHello(t, addr, "gw-one")
	resp, err := readResp(t, c, time.Second)
	if err != nil {
		t.Fatalf("read resp: %v", err)
	}
	if resp.OK {
		t.Fatal("control hello to a loopback signed target was accepted")
	}
}

// The relay blind-forwards the agent's bytes to the controller and back, verbatim and
// over a PLAIN (non-TLS) leg — the load-bearing claim that a raw splice carries an
// agent's own stream while the relay parses nothing.
func TestControlMuxBlindSplice(t *testing.T) {
	// Fake controller: accept one conn, read the agent's bytes, reply.
	gwLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer gwLn.Close()
	gotAtController := make(chan []byte, 1)
	go func() {
		gc, err := gwLn.Accept()
		if err != nil {
			return
		}
		defer gc.Close()
		buf := make([]byte, len("hello-from-agent"))
		if _, err := io.ReadFull(gc, buf); err != nil {
			return
		}
		gotAtController <- buf
		_, _ = gc.Write([]byte("hello-from-controller"))
		time.Sleep(50 * time.Millisecond)
	}()

	gwAddr := gwLn.Addr().String()
	dialer := func(addr string) (net.Conn, error) {
		// Bypass the loopback deny-list (the fake controller is on 127.0.0.1); dial the
		// signed addr the relay resolved, proving the relay dials what the table says.
		return net.DialTimeout("tcp", addr, time.Second)
	}
	_, addr := startControlRelay(t, map[string][]string{"gw-test": {gwAddr}}, dialer)

	c := dialControlHello(t, addr, "gw-test")
	resp, err := readResp(t, c, 2*time.Second)
	if err != nil {
		t.Fatalf("read resp: %v", err)
	}
	if !resp.OK {
		t.Fatalf("control mux refused: %s", resp.Error)
	}
	// Agent -> controller, verbatim.
	if _, err := c.Write([]byte("hello-from-agent")); err != nil {
		t.Fatalf("agent write: %v", err)
	}
	select {
	case got := <-gotAtController:
		if string(got) != "hello-from-agent" {
			t.Fatalf("controller got %q, want verbatim agent bytes", got)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("controller never received the agent's bytes")
	}
	// Controller -> agent, verbatim.
	_ = c.SetReadDeadline(time.Now().Add(2 * time.Second))
	rbuf := make([]byte, len("hello-from-controller"))
	if _, err := io.ReadFull(c, rbuf); err != nil {
		t.Fatalf("agent read: %v", err)
	}
	if string(rbuf) != "hello-from-controller" {
		t.Fatalf("agent got %q, want verbatim controller bytes", rbuf)
	}
}
