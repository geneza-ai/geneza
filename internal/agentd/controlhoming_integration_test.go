package agentd

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"io"
	"log/slog"
	"net"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"

	"geneza.io/internal/ca"
	genezav1 "geneza.io/internal/pb/geneza/v1"
	"geneza.io/internal/wire"
)

// fakeNodeControl is a minimal NodeControl server: it records the agent's hello
// and pings back, proving a bidirectional control stream established end to end.
type fakeNodeControl struct {
	genezav1.UnimplementedNodeControlServer
	gotHello chan string
}

func (f *fakeNodeControl) Stream(stream grpc.BidiStreamingServer[genezav1.AgentMsg, genezav1.ControllerMsg]) error {
	msg, err := stream.Recv()
	if err != nil {
		return err
	}
	if h := msg.GetHello(); h != nil {
		select {
		case f.gotHello <- h.GetNodeId():
		default:
		}
	}
	_ = stream.Send(&genezav1.ControllerMsg{Msg: &genezav1.ControllerMsg_Ping{Ping: &genezav1.Ping{}}})
	<-stream.Context().Done()
	return nil
}

func spki(t *testing.T, certPEM []byte) []byte {
	t.Helper()
	blk, _ := pem.Decode(certPEM) // leaf is the first block
	if blk == nil {
		t.Fatal("no PEM block in cert")
	}
	leaf, err := x509.ParseCertificate(blk.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKIXPublicKey(leaf.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	return der
}

// The full relay-homed control path in process: the agent dials a blind raw-
// splicing relay, which forwards to a gRPC NodeControl server over plain TCP; the
// agent's end-to-end mTLS terminates on the controller THROUGH the splice, so the
// controller authenticates the agent's own node cert and a control stream flows both
// ways while the relay parses nothing.
func TestRelayHomedControlEndToEnd(t *testing.T) {
	dir := t.TempDir()
	if err := ca.Init(dir, "test"); err != nil {
		t.Fatal(err)
	}
	caInst, err := ca.Load(dir)
	if err != nil {
		t.Fatal(err)
	}
	caPool, err := ca.PoolFromPEM(caInst.RootsPEM)
	if err != nil {
		t.Fatal(err)
	}

	gwCertPEM, gwKeyPEM, err := caInst.IssueServerKeypair(ca.Profile{Kind: ca.KindController, Name: "gw-a", DNSNames: []string{"gw-a.example"}, TTL: time.Hour})
	if err != nil {
		t.Fatal(err)
	}
	gwTLS, err := tls.X509KeyPair(gwCertPEM, gwKeyPEM)
	if err != nil {
		t.Fatal(err)
	}
	relayCertPEM, relayKeyPEM, err := caInst.IssueServerKeypair(ca.Profile{Kind: ca.KindRelay, Name: "relay1", IPs: []net.IP{net.ParseIP("127.0.0.1")}, TTL: time.Hour})
	if err != nil {
		t.Fatal(err)
	}
	relayTLS, err := tls.X509KeyPair(relayCertPEM, relayKeyPEM)
	if err != nil {
		t.Fatal(err)
	}
	agentCertPEM, agentKeyPEM, err := caInst.IssueServerKeypair(ca.Profile{Kind: ca.KindNode, Workspace: "default", Name: "n1", TTL: time.Hour})
	if err != nil {
		t.Fatal(err)
	}
	agentTLS, err := tls.X509KeyPair(agentCertPEM, agentKeyPEM)
	if err != nil {
		t.Fatal(err)
	}

	// Fake controller: a real gRPC NodeControl server requiring agent mTLS.
	gwLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer gwLn.Close()
	grpcSrv := grpc.NewServer(grpc.Creds(credentials.NewTLS(&tls.Config{
		Certificates: []tls.Certificate{gwTLS},
		ClientCAs:    caPool,
		ClientAuth:   tls.RequireAndVerifyClientCert,
		MinVersion:   tls.VersionTLS13,
	})))
	fakeGW := &fakeNodeControl{gotHello: make(chan string, 1)}
	genezav1.RegisterNodeControlServer(grpcSrv, fakeGW)
	go grpcSrv.Serve(gwLn) //nolint:errcheck
	defer grpcSrv.Stop()

	// Fake relay: terminate the agent's relay TLS, read the control hello, dial the
	// controller over PLAIN TCP, and raw-splice — never parsing the inner stream.
	relayLn, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{Certificates: []tls.Certificate{relayTLS}, MinVersion: tls.VersionTLS13})
	if err != nil {
		t.Fatal(err)
	}
	defer relayLn.Close()
	go func() {
		c, err := relayLn.Accept()
		if err != nil {
			return
		}
		var hello wire.RelayHello
		if err := wire.ReadJSON(c, &hello); err != nil || hello.Kind != wire.RelayKindControl || hello.ControllerID != "gw-a" {
			c.Close()
			return
		}
		gwConn, err := net.Dial("tcp", gwLn.Addr().String())
		if err != nil {
			c.Close()
			return
		}
		if err := wire.WriteJSON(c, wire.RelayResp{OK: true}); err != nil {
			c.Close()
			gwConn.Close()
			return
		}
		go func() { _, _ = io.Copy(gwConn, c); gwConn.Close() }()
		_, _ = io.Copy(c, gwConn)
		c.Close()
	}()

	w := &Worker{log: slog.New(slog.DiscardHandler), cfg: &Config{}, tlsCert: agentTLS, caPool: caPool}
	plan := controlPlan{
		viaRelay:         true,
		relayControlAddr: relayLn.Addr().String(),
		relayCertPins:    [][]byte{spki(t, relayCertPEM)},
		controllerID:        "gw-a",
		controllerName:      "gw-a.example",
	}

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	conn, cleanup, err := w.dialRelayHomed(ctx, plan)
	if err != nil {
		t.Fatalf("dialRelayHomed: %v", err)
	}
	defer cleanup()
	stream, err := genezav1.NewNodeControlClient(conn).Stream(ctx)
	if err != nil {
		t.Fatalf("open stream through relay: %v", err)
	}
	if err := stream.Send(&genezav1.AgentMsg{Msg: &genezav1.AgentMsg_Hello{Hello: &genezav1.AgentHello{NodeId: "n1"}}}); err != nil {
		t.Fatalf("send hello: %v", err)
	}
	select {
	case got := <-fakeGW.gotHello:
		if got != "n1" {
			t.Fatalf("controller received hello for %q, want n1", got)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("controller never received the agent hello through the relay")
	}
	gw, err := stream.Recv()
	if err != nil {
		t.Fatalf("recv controller->agent through relay: %v", err)
	}
	if gw.GetPing() == nil {
		t.Fatalf("expected a ping back through the relay, got %T", gw.GetMsg())
	}
}

// dialRelayHomed establishes the relay conn eagerly, then hands it to gRPC via a
// single-use dialer. If the stream never runs (gRPC never consumes the conn),
// cleanup() must STILL close it — otherwise the relay-homed conn leaks.
func TestRelayHomedCleanupClosesUnconsumedConn(t *testing.T) {
	dir := t.TempDir()
	if err := ca.Init(dir, "test"); err != nil {
		t.Fatal(err)
	}
	caInst, err := ca.Load(dir)
	if err != nil {
		t.Fatal(err)
	}
	caPool, _ := ca.PoolFromPEM(caInst.RootsPEM)
	relayCertPEM, relayKeyPEM, err := caInst.IssueServerKeypair(ca.Profile{Kind: ca.KindRelay, Name: "r1", IPs: []net.IP{net.ParseIP("127.0.0.1")}, TTL: time.Hour})
	if err != nil {
		t.Fatal(err)
	}
	relayTLS, _ := tls.X509KeyPair(relayCertPEM, relayKeyPEM)
	agentCertPEM, agentKeyPEM, err := caInst.IssueServerKeypair(ca.Profile{Kind: ca.KindNode, Workspace: "default", Name: "n1", TTL: time.Hour})
	if err != nil {
		t.Fatal(err)
	}
	agentTLS, _ := tls.X509KeyPair(agentCertPEM, agentKeyPEM)

	// Fake relay: do the control-hello handshake, then block reading until the agent
	// closes the conn — signalling that the conn was actually closed.
	relayLn, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{Certificates: []tls.Certificate{relayTLS}, MinVersion: tls.VersionTLS13})
	if err != nil {
		t.Fatal(err)
	}
	defer relayLn.Close()
	rawClosed := make(chan struct{}, 1)
	go func() {
		c, err := relayLn.Accept()
		if err != nil {
			return
		}
		var hello wire.RelayHello
		if err := wire.ReadJSON(c, &hello); err != nil {
			c.Close()
			return
		}
		_ = wire.WriteJSON(c, wire.RelayResp{OK: true})
		_, _ = c.Read(make([]byte, 1)) // returns when the agent closes the conn
		c.Close()
		select {
		case rawClosed <- struct{}{}:
		default:
		}
	}()

	w := &Worker{log: slog.New(slog.DiscardHandler), cfg: &Config{}, tlsCert: agentTLS, caPool: caPool}
	plan := controlPlan{
		viaRelay:         true,
		relayControlAddr: relayLn.Addr().String(),
		relayCertPins:    [][]byte{spki(t, relayCertPEM)},
		controllerID:        "gw-a",
		controllerName:      "gw-a.example",
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	conn, cleanup, err := w.dialRelayHomed(ctx, plan)
	if err != nil {
		t.Fatalf("dialRelayHomed: %v", err)
	}
	_ = conn // deliberately never open a stream — gRPC never consumes the spliced conn

	cleanup()
	select {
	case <-rawClosed:
	case <-time.After(5 * time.Second):
		t.Fatal("cleanup did not close the unconsumed relay-homed conn — it leaked")
	}
}
