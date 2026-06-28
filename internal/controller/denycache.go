package controller

import (
	"sync"
	"time"
)

// denyCache memoizes the two hot deny-path reads (cert revocation, principal
// suspension) for a short TTL so a transient store fault does not mass-deny (or
// mass-query) every authenticated RPC, and a lost cross-controller invalidation
// extends access by at most the TTL. It caches POSITIVE (deny) and NEGATIVE
// (allow) verdicts; both expire.
//
// The fail policy on a refresh fault is the backend's, fixed at construction so
// the hot path carries no per-call branch:
//   - failClosed=false (bbolt, single-node): a local read fault has always meant
//     "allow" — a lapsed/absent entry on error returns the last-known verdict if
//     any, else allow. Byte-for-byte the historical single-node behavior.
//   - failClosed=true (SQL, global): a lapsed/absent entry on a store fault
//     DENIES — a global storage fault never re-opens access past the TTL.
type denyCache struct {
	mu          sync.Mutex
	revEntries  map[string]denyEntry // key: serialHex (lower-case)
	suspEntries map[string]denyEntry // key: principalKey(ws, provider, subject)
	gen         uint64               // bumped on every invalidation (see lookup)
	ttl         time.Duration
	failClosed  bool
	now         func() time.Time // injectable for tests
}

// denyCacheTTL bounds how long a cached allow survives a lost cross-controller deny
// invalidation, and how long a transient store fault is smoothed before the cache
// re-reads. Kept small — the continuous-authz sweep is the longer backstop.
const denyCacheTTL = 3 * time.Second

type denyEntry struct {
	deny    bool
	expires time.Time
}

func newDenyCache(ttl time.Duration, failClosed bool) *denyCache {
	return &denyCache{
		revEntries:  map[string]denyEntry{},
		suspEntries: map[string]denyEntry{},
		ttl:         ttl,
		failClosed:  failClosed,
		now:         time.Now,
	}
}

// lookup returns the deny verdict for key, serving a fresh cache entry or else
// calling loader (the authoritative error-returning store read). A successful
// load is cached for ttl. A load fault is NOT cached (so the next call retries
// the store immediately) and resolves by the backend's fail policy.
func (c *denyCache) lookup(m map[string]denyEntry, key string, loader func() (bool, error)) bool {
	now := c.now()
	c.mu.Lock()
	ent, ok := m[key]
	if ok && now.Before(ent.expires) {
		c.mu.Unlock()
		return ent.deny
	}
	gen := c.gen
	c.mu.Unlock()

	deny, err := loader()
	if err == nil {
		c.mu.Lock()
		// Cache only if no invalidation raced this load: an in-flight read that
		// started before a suspend/revoke could otherwise re-insert the stale ALLOW
		// the invalidation just dropped, defeating the "invalidate beats the TTL"
		// guarantee. A straddled load is simply not cached (re-read next call).
		if c.gen == gen {
			m[key] = denyEntry{deny: deny, expires: c.now().Add(c.ttl)}
		}
		c.mu.Unlock()
		return deny
	}
	// Loader faulted on a lapsed/absent entry.
	if !c.failClosed {
		if ok {
			return ent.deny // local store: honor the last-known verdict
		}
		return false // local store: a read fault has always allowed
	}
	return true // global store: fail closed
}

// certRevoked reports whether serial is revoked, caching the result.
func (c *denyCache) certRevoked(serial string, loader func() (bool, error)) bool {
	return c.lookup(c.revEntries, serial, loader)
}

// suspended reports whether the principal keyed by key is suspended, caching it.
func (c *denyCache) suspended(key string, loader func() (bool, error)) bool {
	return c.lookup(c.suspEntries, key, loader)
}

// invalidateRevoked drops a cert entry so the next read re-loads from the store —
// called after a local RevokeCert write. A revoke on a peer controller has no bus
// fanout (unlike suspension), so a remote controller re-denies within the TTL when
// its entry lapses and it re-reads the shared store.
func (c *denyCache) invalidateRevoked(serial string) {
	c.mu.Lock()
	delete(c.revEntries, serial)
	c.gen++
	c.mu.Unlock()
}

// invalidateSuspension drops a principal entry (positive OR negative) so a suspend
// takes effect within ~0 (not ttl) and a lift restores access within ~0. The key
// is computed identically to the read (principalKey normalizes the provider), or
// a device:keystone-provider read would never be evicted by a keystone write.
func (c *denyCache) invalidateSuspension(ws, provider, subject string) {
	key := principalKey(ws, provider, subject)
	c.mu.Lock()
	delete(c.suspEntries, key)
	c.gen++
	c.mu.Unlock()
}

// flush drops ALL cached verdicts and bumps the generation, so a resync after a
// LISTEN reconnect cannot trust any cached allow that a missed invalidation
// doorbell should have evicted. The gen bump also voids any in-flight load that
// straddles the flush (the same guard lookup relies on).
func (c *denyCache) flush() {
	c.mu.Lock()
	clear(c.revEntries)
	clear(c.suspEntries)
	c.gen++
	c.mu.Unlock()
}

// gc drops expired entries so a long-lived controller does not accumulate one entry
// per distinct serial/principal ever seen. Invalidation only removes named keys,
// so this is the periodic sweep for entries that simply lapsed.
func (c *denyCache) gc() {
	now := c.now()
	c.mu.Lock()
	for _, m := range []map[string]denyEntry{c.revEntries, c.suspEntries} {
		for k, e := range m {
			if !now.Before(e.expires) {
				delete(m, k)
			}
		}
	}
	c.mu.Unlock()
}

// runGC sweeps expired entries on a ticker until ctx is done.
func (c *denyCache) runGC(stop <-chan struct{}) {
	t := time.NewTicker(c.ttl)
	defer t.Stop()
	for {
		select {
		case <-stop:
			return
		case <-t.C:
			c.gc()
		}
	}
}
