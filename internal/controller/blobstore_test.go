package controller

import (
	"bytes"
	"errors"
	"io"
	"sync"
	"sync/atomic"
	"testing"
)

// TestLocalBlobStoreConcurrentWriteOnce proves the write-once fence is atomic: many
// streams uploading the same ref at once must yield exactly one committed blob, and
// that blob must be one writer's bytes verbatim — never an interleave of several.
// A shared temp file plus a rename-based commit would let every writer "win" and
// corrupt the committed ciphertext, silently breaking the indexed-hash guarantee.
func TestLocalBlobStoreConcurrentWriteOnce(t *testing.T) {
	bs := newLocalBlobStore(t.TempDir())
	const ref = "local:s-0000deadbeef.cast.age"
	const racers = 8

	payloads := make([][]byte, racers)
	for i := range payloads {
		payloads[i] = bytes.Repeat([]byte{byte('A' + i)}, 64<<10)
	}

	var wins, exists int64
	var mu sync.Mutex
	var winner []byte
	var wg sync.WaitGroup
	for i := 0; i < racers; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			w, err := bs.create(ref)
			if errors.Is(err, errBlobExists) {
				atomic.AddInt64(&exists, 1)
				return
			}
			if err != nil {
				t.Errorf("create: %v", err)
				return
			}
			if _, err := w.Write(payloads[idx]); err != nil {
				w.Abort()
				t.Errorf("write: %v", err)
				return
			}
			if err := w.Commit(); err != nil {
				if errors.Is(err, errBlobExists) {
					atomic.AddInt64(&exists, 1)
					return
				}
				t.Errorf("commit: %v", err)
				return
			}
			atomic.AddInt64(&wins, 1)
			mu.Lock()
			winner = payloads[idx]
			mu.Unlock()
		}(i)
	}
	wg.Wait()

	if wins != 1 {
		t.Fatalf("write-once: %d commits won, want exactly 1 (errBlobExists=%d)", wins, exists)
	}
	rc, err := bs.open(ref)
	if err != nil {
		t.Fatalf("open committed blob: %v", err)
	}
	defer rc.Close()
	got, err := io.ReadAll(rc)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, winner) {
		t.Fatalf("committed blob (%d bytes) is not the winning writer's payload (%d bytes) — interleaved?", len(got), len(winner))
	}
}
