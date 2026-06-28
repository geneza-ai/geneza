package sessionconn

import (
	"context"
	"sync"
	"testing"
	"time"
)

// pipeSignaler is an in-memory Signaler pair: whatever one side sends is what the
// other side receives. It models the controller forwarding ICE creds/candidates
// between the two grant-named principals, without any network.
type pipeSignaler struct {
	out chan *Signal // this side sends here
	in  chan *Signal // this side receives here
}

func newSignalerPair() (a, b *pipeSignaler) {
	ch1 := make(chan *Signal, 64) // a->b
	ch2 := make(chan *Signal, 64) // b->a
	return &pipeSignaler{out: ch1, in: ch2}, &pipeSignaler{out: ch2, in: ch1}
}

func (p *pipeSignaler) SendCreds(ufrag, pwd string) error {
	p.out <- &Signal{Ufrag: ufrag, Pwd: pwd}
	return nil
}

func (p *pipeSignaler) SendCandidate(cand string) error {
	p.out <- &Signal{Candidate: cand}
	return nil
}

func (p *pipeSignaler) Recv(ctx context.Context) (*Signal, error) {
	select {
	case s := <-p.in:
		return s, nil
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

// Two host-only ICE agents must connect over the in-memory signaler and exchange
// data both ways; with no TURN configured the selected pair is host→host (direct).
func TestConnectLoopbackDirect(t *testing.T) {
	sigA, sigB := newSignalerPair()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	type res struct {
		conn interface {
			Read([]byte) (int, error)
			Write([]byte) (int, error)
			Close() error
		}
		path string
		err  error
	}
	ra, rb := make(chan res, 1), make(chan res, 1)
	// Host-only config (TurnURL=="") → host candidates, no STUN/TURN.
	cfgA := Config{Controlling: true, Gather: 8 * time.Second}
	cfgB := Config{Controlling: false, Gather: 8 * time.Second}

	go func() { c, p, e := Connect(ctx, cfgA, sigA); ra <- res{c, p, e} }()
	go func() { c, p, e := Connect(ctx, cfgB, sigB); rb <- res{c, p, e} }()

	var a, b res
	for i := 0; i < 2; i++ {
		select {
		case a = <-ra:
			if a.err != nil {
				t.Fatalf("controlling Connect: %v", a.err)
			}
		case b = <-rb:
			if b.err != nil {
				t.Fatalf("controlled Connect: %v", b.err)
			}
		case <-ctx.Done():
			t.Fatal("ICE did not connect before timeout")
		}
	}
	defer a.conn.Close()
	defer b.conn.Close()

	if a.path != PathDirect || b.path != PathDirect {
		t.Fatalf("host-only must select a direct pair: a=%s b=%s", a.path, b.path)
	}

	// Data both ways proves the selected pair is a live transport.
	roundtrip(t, a.conn, b.conn, []byte("ping-from-a"))
	roundtrip(t, b.conn, a.conn, []byte("pong-from-b"))
}

func roundtrip(t *testing.T, from, to interface {
	Read([]byte) (int, error)
	Write([]byte) (int, error)
	Close() error
}, msg []byte) {
	t.Helper()
	var wg sync.WaitGroup
	wg.Add(1)
	var got []byte
	var rerr error
	go func() {
		defer wg.Done()
		buf := make([]byte, 256)
		n, err := to.Read(buf)
		if err != nil {
			rerr = err
			return
		}
		got = buf[:n]
	}()
	time.Sleep(20 * time.Millisecond)
	if _, err := from.Write(msg); err != nil {
		t.Fatalf("write: %v", err)
	}
	done := make(chan struct{})
	go func() { wg.Wait(); close(done) }()
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("read timed out")
	}
	if rerr != nil {
		t.Fatalf("read: %v", rerr)
	}
	if string(got) != string(msg) {
		t.Fatalf("got %q want %q", got, msg)
	}
}

// A bad/empty remote credential exchange must time out rather than hang forever.
func TestConnectTimesOutWithoutPeer(t *testing.T) {
	sigA, _ := newSignalerPair() // peer never answers
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_, _, err := Connect(ctx, Config{Controlling: true, Gather: 1 * time.Second}, sigA)
	if err == nil {
		t.Fatal("expected a timeout error when the peer never sends creds")
	}
}
