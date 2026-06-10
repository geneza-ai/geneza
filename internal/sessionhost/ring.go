package sessionhost

// ringChunk is one PTY/pipe read worth of output. Sequence numbers are
// assigned by the session pump and are contiguous: the chunk following the
// chunk with seq N always has seq N+1 (output and stderr share the counter).
type ringChunk struct {
	seq    uint64
	stderr bool
	data   []byte
}

// ring is the bounded scrollback used for delta replay on reattach. Whole
// chunks are evicted oldest-first once the byte budget is exceeded; the most
// recent chunk is always retained even if it alone exceeds the budget so the
// ring never has a hole at its tail. Evicted and zeroized chunk bytes are
// overwritten because they hold session plaintext.
type ring struct {
	max    int
	size   int
	chunks []ringChunk
}

func newRing(max int) *ring {
	if max <= 0 {
		max = defaultRingBytes
	}
	return &ring{max: max}
}

// add appends a copy of data under seq, then evicts whole old chunks while
// over budget (keeping at least the newest chunk).
func (r *ring) add(seq uint64, stderr bool, data []byte) {
	d := make([]byte, len(data))
	copy(d, data)
	r.chunks = append(r.chunks, ringChunk{seq: seq, stderr: stderr, data: d})
	r.size += len(d)
	for r.size > r.max && len(r.chunks) > 1 {
		old := r.chunks[0]
		zeroBytes(old.data)
		r.size -= len(old.data)
		r.chunks[0] = ringChunk{}
		r.chunks = r.chunks[1:]
	}
}

// deltaFrom returns copies of every retained chunk with seq > after, plus
// whether that set is complete, i.e. covers all frames in (after, cur].
// Incomplete means at least one needed frame was already evicted (or the
// client's seq is from a different epoch); the caller must fall back to a
// snapshot. Copies are returned so a later zeroize cannot corrupt frames that
// are still queued for delivery.
func (r *ring) deltaFrom(after, cur uint64) ([]ringChunk, bool) {
	if after > cur {
		return nil, false // client claims to be ahead of us: not our history
	}
	if after == cur {
		return nil, true // nothing to replay
	}
	if len(r.chunks) == 0 || r.chunks[0].seq > after+1 {
		return nil, false
	}
	i := 0
	for i < len(r.chunks) && r.chunks[i].seq <= after {
		i++
	}
	out := make([]ringChunk, 0, len(r.chunks)-i)
	for ; i < len(r.chunks); i++ {
		c := r.chunks[i]
		d := make([]byte, len(c.data))
		copy(d, c.data)
		out = append(out, ringChunk{seq: c.seq, stderr: c.stderr, data: d})
	}
	return out, true
}

// zeroize best-effort overwrites all retained plaintext and drops the chunks.
func (r *ring) zeroize() {
	for i := range r.chunks {
		zeroBytes(r.chunks[i].data)
	}
	r.chunks = nil
	r.size = 0
}

func zeroBytes(b []byte) {
	for i := range b {
		b[i] = 0
	}
}
