package sessionhost

import (
	"bytes"
	"testing"
)

func TestRingEvictionAndDeltaAvailability(t *testing.T) {
	r := newRing(100)
	for i := 1; i <= 5; i++ {
		r.add(uint64(i), false, bytes.Repeat([]byte{byte(i)}, 30))
	}
	// 5x30 bytes against a 100-byte budget: whole-chunk eviction keeps 3,4,5.
	if len(r.chunks) != 3 || r.chunks[0].seq != 3 || r.size != 90 {
		t.Fatalf("eviction wrong: %d chunks, first seq %d, size %d",
			len(r.chunks), r.chunks[0].seq, r.size)
	}

	chunks, ok := r.deltaFrom(2, 5)
	if !ok || len(chunks) != 3 {
		t.Fatalf("delta (2,5] should be complete with 3 chunks, got ok=%v n=%d", ok, len(chunks))
	}
	for i, c := range chunks {
		if c.seq != uint64(3+i) {
			t.Fatalf("delta chunk %d has seq %d", i, c.seq)
		}
	}
	// Returned chunks are copies: mutating them must not corrupt the ring.
	chunks[0].data[0] = 0xff
	if r.chunks[0].data[0] == 0xff {
		t.Fatal("deltaFrom returned aliased ring memory")
	}

	if _, ok := r.deltaFrom(1, 5); ok {
		t.Fatal("delta needing evicted frame 2 must be unavailable")
	}
	if d, ok := r.deltaFrom(5, 5); !ok || len(d) != 0 {
		t.Fatalf("empty delta must be trivially available, got ok=%v n=%d", ok, len(d))
	}
	if _, ok := r.deltaFrom(6, 5); ok {
		t.Fatal("client ahead of current seq must not get a delta")
	}
}

func TestRingOversizeChunkKept(t *testing.T) {
	r := newRing(10)
	r.add(1, false, make([]byte, 50))
	if len(r.chunks) != 1 {
		t.Fatal("newest chunk must survive even when over budget")
	}
	r.add(2, true, make([]byte, 50))
	if len(r.chunks) != 1 || r.chunks[0].seq != 2 {
		t.Fatalf("expected only seq 2 retained, got %d chunks first seq %d",
			len(r.chunks), r.chunks[0].seq)
	}
	if _, ok := r.deltaFrom(0, 2); ok {
		t.Fatal("delta from 0 must be unavailable after eviction")
	}
	d, ok := r.deltaFrom(1, 2)
	if !ok || len(d) != 1 || d[0].seq != 2 || !d[0].stderr {
		t.Fatalf("delta from 1 wrong: ok=%v %+v", ok, d)
	}
}

func TestRingZeroize(t *testing.T) {
	r := newRing(100)
	r.add(1, false, []byte("secret-output"))
	internal := r.chunks[0].data
	r.zeroize()
	if len(r.chunks) != 0 || r.size != 0 {
		t.Fatal("zeroize must drop all chunks")
	}
	for _, b := range internal {
		if b != 0 {
			t.Fatal("zeroize must overwrite chunk plaintext")
		}
	}
	if _, ok := r.deltaFrom(0, 1); ok {
		t.Fatal("no delta after zeroize")
	}
}
