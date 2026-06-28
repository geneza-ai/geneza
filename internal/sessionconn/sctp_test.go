package sessionconn

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net"
	"testing"
	"time"
)

// Dial/Accept must establish a RELIABLE ORDERED byte stream over the loopback
// ICE pair. The controlling (Dial) side writes first — mirroring the real flow
// where the client sends Noise msg1 immediately, which is what makes the pion
// stream visible to the server's AcceptStream. A >MTU payload written in
// odd-sized chunks must arrive byte-exact and in order (SCTP fragments/
// reassembles; the streamConn drain hands the reader pure bytes); the reverse
// direction proves full duplex. Conns are closed by the test (not the
// goroutines) so neither side aborts the other's in-flight data.
func TestReliableStreamLoopback(t *testing.T) {
	sigA, sigB := newSignalerPair()
	ctx, cancel := context.WithTimeout(context.Background(), 25*time.Second)
	defer cancel()

	payload := make([]byte, 256*1024)
	for i := range payload {
		payload[i] = byte(i*7 + 3)
	}

	type res struct {
		conn net.Conn
		err  error
	}
	rA := make(chan res, 1)
	rB := make(chan res, 1)

	go func() {
		c, path, err := Dial(ctx, Config{Controlling: true, Gather: 8 * time.Second}, sigA)
		if err != nil {
			rA <- res{nil, fmt.Errorf("dial: %w", err)}
			return
		}
		if path != PathDirect {
			rA <- res{c, fmt.Errorf("dial path = %s, want direct", path)}
			return
		}
		for off := 0; off < len(payload); {
			end := off + 1000 // odd-sized chunks exercise the byte-stream drain
			if end > len(payload) {
				end = len(payload)
			}
			if _, werr := c.Write(payload[off:end]); werr != nil {
				rA <- res{c, fmt.Errorf("write at %d: %w", off, werr)}
				return
			}
			off = end
		}
		_ = c.SetReadDeadline(time.Now().Add(10 * time.Second))
		buf := make([]byte, 16)
		n, rerr := c.Read(buf)
		if rerr != nil || string(buf[:n]) != "pong" {
			rA <- res{c, fmt.Errorf("reverse read: got %q err %v", buf[:n], rerr)}
			return
		}
		rA <- res{c, nil}
	}()

	go func() {
		c, _, err := Accept(ctx, Config{Controlling: false, Gather: 8 * time.Second}, sigB)
		if err != nil {
			rB <- res{nil, fmt.Errorf("accept: %w", err)}
			return
		}
		got := make([]byte, len(payload))
		if _, rerr := io.ReadFull(c, got); rerr != nil {
			rB <- res{c, fmt.Errorf("readfull: %w", rerr)}
			return
		}
		if !bytes.Equal(got, payload) {
			rB <- res{c, fmt.Errorf("payload mismatch")}
			return
		}
		if _, werr := c.Write([]byte("pong")); werr != nil {
			rB <- res{c, fmt.Errorf("pong write: %w", werr)}
			return
		}
		rB <- res{c, nil}
	}()

	var conns []net.Conn
	for i := 0; i < 2; i++ {
		select {
		case r := <-rA:
			if r.conn != nil {
				conns = append(conns, r.conn)
			}
			if r.err != nil {
				t.Fatal(r.err)
			}
		case r := <-rB:
			if r.conn != nil {
				conns = append(conns, r.conn)
			}
			if r.err != nil {
				t.Fatal(r.err)
			}
		case <-ctx.Done():
			t.Fatal("reliable transfer did not complete in time")
		}
	}
	for _, c := range conns {
		_ = c.Close()
	}
}
