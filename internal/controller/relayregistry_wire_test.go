package controller

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"net"
	"strconv"
	"testing"
	"time"

	"github.com/pion/stun/v3"
	"google.golang.org/grpc"

	"geneza.io/internal/ca"
	genezav1 "geneza.io/internal/pb/geneza/v1"
)

type fakeRelayWatchStream struct {
	grpc.ServerStream
	ctx  context.Context
	sent chan *genezav1.RelayWatch
}

func (f *fakeRelayWatchStream) Context() context.Context { return f.ctx }
func (f *fakeRelayWatchStream) Send(w *genezav1.RelayWatch) error {
	select {
	case f.sent <- w:
	default:
	}
	return nil
}

// startSTUNResponder answers BindingRequests so validateAndUpsertRelay's data-port
// reachability probe passes. Returns the UDP port.
func startSTUNResponder(t *testing.T) int {
	t.Helper()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { pc.Close() })
	go func() {
		buf := make([]byte, 1500)
		for {
			n, addr, err := pc.ReadFrom(buf)
			if err != nil {
				return
			}
			req := &stun.Message{Raw: append([]byte(nil), buf[:n]...)}
			if req.Decode() != nil {
				continue
			}
			resp := stun.MustBuild(stun.TransactionID, stun.BindingSuccess)
			_, _ = pc.WriteTo(resp.Raw, addr)
		}
	}()
	return pc.LocalAddr().(*net.UDPAddr).Port
}

// TestRegisterAndWatchRenewsOverWire drives the real RegisterAndWatch: a relay
// heartbeat carrying a renew_csr (near-expiry cert) must come back with a signed
// renewed_relay_cert + ca_roots on the first watch message — the full controller
// wire path, STUN gate included.
func TestRegisterAndWatchRenewsOverWire(t *testing.T) {
	srv := newReplayServer(t)
	rr := &relayRegistryService{s: srv}
	port := startSTUNResponder(t)

	relayKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	leafCSR, _ := ca.MakeCSR(relayKey, "relay-wire")
	leafPEM, err := srv.ca.IssueFromCSR(leafCSR, ca.Profile{
		Kind: ca.KindRelay, Name: "relay-wire", TTL: 30 * time.Second, // near expiry
		DNSNames: []string{"relay-wire.example.com"},
	})
	if err != nil {
		t.Fatal(err)
	}
	blk, _ := pem.Decode(leafPEM)
	leaf, _ := x509.ParseCertificate(blk.Bytes)

	ctx, cancel := context.WithCancel(context.WithValue(context.Background(), peerInfoKey{},
		&peerInfo{identity: &ca.Identity{Kind: ca.KindRelay, Name: "relay-wire"}, leaf: leaf}))
	defer cancel()

	renewCSR, _ := ca.MakeCSR(relayKey, "relay-wire")
	hb := &genezav1.RelayHeartbeat{
		RegionId: "r1", RelayId: "relay-wire",
		Addrs:    []string{net.JoinHostPort("127.0.0.1", strconv.Itoa(port))},
		StunPort: int32(port), TurnPort: int32(port),
		Healthy: true, RenewCsr: renewCSR,
	}
	stream := &fakeRelayWatchStream{ctx: ctx, sent: make(chan *genezav1.RelayWatch, 1)}

	go func() { _ = rr.RegisterAndWatch(hb, stream) }()

	select {
	case w := <-stream.sent:
		if len(w.GetRenewedRelayCert()) == 0 {
			t.Fatal("first watch must carry the renewed cert")
		}
		if string(w.GetCaRoots()) != string(srv.ca.RootsPEM) {
			t.Error("watch must carry CA roots for pinning")
		}
		rblk, _ := pem.Decode(w.GetRenewedRelayCert())
		renewed, err := x509.ParseCertificate(rblk.Bytes)
		if err != nil {
			t.Fatalf("renewed cert parse: %v", err)
		}
		if got := renewed.URIs[0].String(); got != "geneza://relay/relay-wire" {
			t.Errorf("identity = %q, want geneza://relay/relay-wire", got)
		}
		if !renewed.NotAfter.After(leaf.NotAfter) {
			t.Error("renewed cert should extend the expiry")
		}
		renewedPub, _ := x509.MarshalPKIXPublicKey(renewed.PublicKey)
		csrPub, _ := x509.MarshalPKIXPublicKey(&relayKey.PublicKey)
		if string(renewedPub) != string(csrPub) {
			t.Error("renewed cert must bind the relay's key")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for the renewed watch")
	}
}
