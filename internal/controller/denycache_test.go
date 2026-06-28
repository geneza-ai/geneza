package controller

import (
	"errors"
	"testing"
	"time"
)

// a controllable clock + loader for deterministic TTL tests.
type fakeLoader struct {
	deny bool
	err  error
	hits int
}

func (f *fakeLoader) load() (bool, error) { f.hits++; return f.deny, f.err }

func newTestCache(failClosed bool, t0 *time.Time) *denyCache {
	c := newDenyCache(3*time.Second, failClosed)
	c.now = func() time.Time { return *t0 }
	return c
}

// A negative (allow) verdict is cached for the TTL even if the store flips to
// deny; once the entry lapses the store is re-read. An explicit invalidate beats
// the TTL.
func TestDenyCacheNegativeThenTTLThenInvalidate(t *testing.T) {
	now := time.Unix(1000, 0)
	c := newTestCache(true, &now)
	key := principalKey("ws", "keystone", "p")
	ldr := &fakeLoader{deny: false}
	if c.suspended(key, ldr.load) {
		t.Fatal("expected allow on first read")
	}
	ldr.deny = true // store now says deny, but no invalidation yet
	now = now.Add(2 * time.Second)
	if c.suspended(key, ldr.load) {
		t.Fatal("within TTL the cached allow must still hold")
	}
	// An explicit invalidate forces an immediate re-read, beating the TTL.
	c.invalidateSuspension("ws", "keystone", "p")
	if !c.suspended(key, ldr.load) {
		t.Fatal("after invalidate the store re-read must deny immediately")
	}
}

// The headline guarantee: a lost invalidation extends access by at most the TTL.
func TestDenyCacheLostInvalidationBoundedByTTL(t *testing.T) {
	for _, failClosed := range []bool{true, false} {
		now := time.Unix(2000, 0)
		c := newTestCache(failClosed, &now)
		ldr := &fakeLoader{deny: false}
		c.certRevoked("s", ldr.load) // caches allow
		ldr.deny = true              // revoked in the store, invalidation lost
		now = now.Add(3*time.Second - time.Millisecond)
		if c.certRevoked("s", ldr.load) {
			t.Fatalf("failClosed=%v: still within TTL, must allow", failClosed)
		}
		now = now.Add(2 * time.Millisecond) // just past TTL
		if !c.certRevoked("s", ldr.load) {
			t.Fatalf("failClosed=%v: past TTL must re-read and deny", failClosed)
		}
	}
}

// SQL/global backend: on a store fault with a lapsed entry, fail CLOSED.
func TestDenyCacheFailClosedAfterTTLOnError(t *testing.T) {
	now := time.Unix(3000, 0)
	c := newTestCache(true, &now)
	ldr := &fakeLoader{deny: false}
	c.certRevoked("s", ldr.load) // cache allow
	// blip during the fresh window: cached allow still served (no store hit)
	now = now.Add(1 * time.Second)
	ldr.err = errors.New("db down")
	before := ldr.hits
	if c.certRevoked("s", ldr.load) {
		t.Fatal("fresh cached allow must be served through a blip")
	}
	if ldr.hits != before {
		t.Fatal("a fresh entry must not hit the store")
	}
	// entry lapses while the store is still down -> fail closed (deny)
	now = now.Add(3 * time.Second)
	if !c.certRevoked("s", ldr.load) {
		t.Fatal("lapsed entry + store fault on the global path must fail closed")
	}
}

// bbolt/local backend: a read fault never denies (single-node fail-open).
func TestDenyCacheBboltStaysFailOpen(t *testing.T) {
	now := time.Unix(4000, 0)
	c := newTestCache(false, &now)
	ldr := &fakeLoader{deny: false, err: errors.New("local read fault")}
	if c.certRevoked("never-seen", ldr.load) {
		t.Fatal("local read fault with no prior entry must allow")
	}
	// prime a deny, then lapse it under a fault: honor last-known, then allow
	ldr.err = nil
	ldr.deny = true
	c.certRevoked("seen", ldr.load) // cache deny
	now = now.Add(5 * time.Second)  // lapse
	ldr.err = errors.New("fault")
	if !c.certRevoked("seen", ldr.load) {
		t.Fatal("local fault should honor the last-known deny verdict")
	}
}

// A positive (deny) verdict is also cached within the TTL.
func TestDenyCachePositiveHonoredWithinTTL(t *testing.T) {
	now := time.Unix(5000, 0)
	c := newTestCache(true, &now)
	ldr := &fakeLoader{deny: true}
	if !c.certRevoked("s", ldr.load) {
		t.Fatal("expected deny")
	}
	ldr.deny = false // store flips to allow, no invalidation
	now = now.Add(2 * time.Second)
	if !c.certRevoked("s", ldr.load) {
		t.Fatal("cached deny must hold within TTL")
	}
}

// Eviction keys must match the read keys through provider normalization: a
// "keystone" write evicts a "device:keystone" read of the same principal.
func TestDenyCacheKeyNormalization(t *testing.T) {
	now := time.Unix(6000, 0)
	c := newTestCache(true, &now)
	readKey := principalKey("ws1", "device:keystone", "alice")
	ldr := &fakeLoader{deny: false}
	c.suspended(readKey, ldr.load) // cache allow under the device:-provider key
	// admin writes with the bare provider
	c.invalidateSuspension("ws1", "keystone", "alice")
	if _, ok := c.suspEntries[readKey]; ok {
		t.Fatal("invalidate with bare provider must evict the device:-provider read key")
	}
}

// An invalidation that lands WHILE a read is in flight must win: the in-flight
// loader must not resurrect the stale ALLOW the invalidation dropped. Modeled
// deterministically by having the loader trigger the invalidation mid-load.
func TestDenyCacheNoResurrectionAcrossInFlightInvalidate(t *testing.T) {
	now := time.Unix(8000, 0)
	c := newTestCache(true, &now)
	key := principalKey("ws", "keystone", "p")
	// loader samples the pre-suspend state (allow), then the suspend lands +
	// invalidates before the loader's result is cached.
	racingLoader := func() (bool, error) {
		c.invalidateSuspension("ws", "keystone", "p") // the suspend's eviction races in
		return false, nil                             // stale allow read before the suspend committed
	}
	if c.suspended(key, racingLoader) {
		t.Fatal("the racing read returns its (stale) value to its own caller")
	}
	// The stale allow must NOT have been cached — a fresh read sees the deny.
	if _, ok := c.suspEntries[key]; ok {
		t.Fatal("resurrection: a load that straddled an invalidate was cached")
	}
	if !c.suspended(key, func() (bool, error) { return true, nil }) {
		t.Fatal("next read must re-load and deny, not serve a resurrected allow")
	}
}

// gc removes lapsed entries but keeps fresh ones.
func TestDenyCacheGC(t *testing.T) {
	now := time.Unix(7000, 0)
	c := newTestCache(true, &now)
	c.certRevoked("fresh", (&fakeLoader{deny: true}).load)
	now = now.Add(1 * time.Second)
	c.certRevoked("old", (&fakeLoader{deny: true}).load)
	now = now.Add(2*time.Second + time.Millisecond) // "fresh" lapsed (3.001s), "old" still fresh (2.001s)
	c.gc()
	if _, ok := c.revEntries["fresh"]; ok {
		t.Fatal("gc must drop the lapsed entry")
	}
	if _, ok := c.revEntries["old"]; !ok {
		t.Fatal("gc must keep the still-fresh entry")
	}
}
