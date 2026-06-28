package controller

import (
	"context"
	"crypto/sha256"
	"encoding/base32"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"hash/fnv"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"time"

	bbolt "go.etcd.io/bbolt"

	"geneza.io/internal/webpki"
)

// Managed-domain certificates: publicly-trusted TLS certs the controller mints for
// the operator's managed domain via ACME DNS-01 (see docs/managed-domain-spec.md
// and internal/webpki). One wildcard per workspace (*.w-<token>.<base>) covers
// every machine and service in the workspace; funnel hostnames get narrow leaves
// later. The cert chain + key are written to the general-purpose blob store; this
// record is the index and renewal state. The blob is as sensitive as the on-disk
// CA key and lives under the same controller-owned storage; sealing it at rest is a
// later hardening, and distribution to agents/relays seals it per recipient.

var bucketManagedCerts = []byte("managed_certs") // global: certID -> ManagedCertRecord

// Certificate kinds.
const (
	KindWorkspaceWildcard = "workspace_wildcard"
	KindFunnelLeaf        = "funnel_leaf"
)

// ManagedCertRecord indexes one issued certificate. Ref points at the blob
// holding the PEM bundle (private key followed by the cert chain). Epoch is
// monotonic per certID and bumped on every (re)issue, so a recipient can detect
// a missed update; Sha256 is over the chain for the same reason.
type ManagedCertRecord struct {
	ID          string   `json:"id"`           // "sub-<label>-<domain>" for a reservation wildcard
	WorkspaceID string   `json:"workspace_id"` // owning tenant
	Domain      string   `json:"domain"`       // managed base domain
	Label       string   `json:"label"`        // reserved subdomain label
	Kind        string   `json:"kind"`         // KindWorkspaceWildcard | KindFunnelLeaf
	Names       []string `json:"names"`        // certificate SANs
	Ref         string   `json:"ref"`          // blob ref for the PEM bundle
	NotBefore   int64    `json:"not_before"`
	NotAfter    int64    `json:"not_after"`
	Epoch       int64    `json:"epoch"`
	Sha256      string   `json:"sha256"` // hex, over the chain PEM
	IssuedUnix  int64    `json:"issued_unix"`
}

// managedWorkspaceToken derives a stable, DNS-safe default subdomain label for a
// workspace: "w-" + lowercase base32 of a 64-bit FNV-1a hash of the id. It is the
// label a reservation falls back to when an admin claims one without naming it —
// stable across renames, and it does not leak the human workspace name into
// public DNS or Certificate Transparency. Mirrors vniForWorkspace's
// derive-don't-count approach, with 64 bits so collisions are not a concern.
func managedWorkspaceToken(workspaceID string) string {
	h := fnv.New64a()
	_, _ = h.Write([]byte(workspaceID))
	var b [8]byte
	binary.BigEndian.PutUint64(b[:], h.Sum64())
	enc := base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(b[:])
	return "w-" + strings.ToLower(enc)
}

// reservationWildcardNames is the SAN set for a reservation's wildcard: the
// wildcard (covering <machine>.<zone> and <service>.<zone>) plus its apex.
func reservationWildcardNames(r *SubdomainReservation) []string {
	zone := r.Zone()
	return []string{"*." + zone, zone}
}

// reservationCertID is the stable, blob-safe certificate id for a reservation.
func reservationCertID(domain, label string) string {
	return "sub-" + sanitizeDNSish(label+"."+domain)
}

func sanitizeDNSish(s string) string {
	return strings.Map(func(r rune) rune {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9', r == '-':
			return r
		default:
			return '-'
		}
	}, strings.ToLower(s))
}

// managedCertBlobName mints a fresh, write-once-safe basename per issuance. The
// epoch in the name means a renewal never collides with the blob store's
// write-once guard, and the old blob is GC'd after the record flips.
func managedCertBlobName(certID string, epoch int64) string {
	return fmt.Sprintf("mc-%s-%d.pem", sanitizeDNSish(certID), epoch)
}

// bundlePEM concatenates the private key and the cert chain into one blob.
func bundlePEM(c *webpki.Cert) []byte {
	out := make([]byte, 0, len(c.KeyPEM)+len(c.ChainPEM))
	out = append(out, c.KeyPEM...)
	return append(out, c.ChainPEM...)
}

// splitBundlePEM separates a stored bundle back into the cert chain and the
// private key. Private-key blocks (type ending in "PRIVATE KEY") go to keyPEM;
// CERTIFICATE blocks go to chainPEM, preserving order.
func splitBundlePEM(bundle []byte) (chainPEM, keyPEM []byte, err error) {
	rest := bundle
	for {
		var blk *pem.Block
		blk, rest = pem.Decode(rest)
		if blk == nil {
			break
		}
		enc := pem.EncodeToMemory(blk)
		if strings.HasSuffix(blk.Type, "PRIVATE KEY") {
			keyPEM = append(keyPEM, enc...)
		} else if blk.Type == "CERTIFICATE" {
			chainPEM = append(chainPEM, enc...)
		}
	}
	if len(chainPEM) == 0 || len(keyPEM) == 0 {
		return nil, nil, errors.New("managed cert bundle missing chain or key")
	}
	return chainPEM, keyPEM, nil
}

// --- issuance / renewal manager ---

// managedCertManager ensures every subdomain reservation has a current wildcard
// certificate, issuing missing ones, renewing those past ~2/3 of their lifetime,
// and GCing certs whose reservation was released. issuers is keyed by managed
// base domain, so a reservation is issued through its domain's DNS-01 provider.
// It is store-driven and idempotent, so it resumes cleanly after a restart and
// is safe to run leader-only on a tick.
type managedCertManager struct {
	store    Store
	blobs    blobStore
	issuers  map[string]webpki.Issuer // base domain -> issuer
	now      func() time.Time         // injectable for tests
	onChange func(workspaceID string) // re-push to a workspace's agents after a change (nil in tests)
	kick     chan struct{}            // nudge the controller to reconcile now (new reservation/funnel)
}

func newManagedCertManager(store Store, blobs blobStore, issuers map[string]webpki.Issuer) *managedCertManager {
	return &managedCertManager{store: store, blobs: blobs, issuers: issuers, now: time.Now, kick: make(chan struct{}, 1)}
}

// kickReconcile nudges the controller to reconcile promptly (e.g. after a new
// reservation or funnel) instead of waiting for the next tick. Non-blocking.
func (m *managedCertManager) kickReconcile() {
	if m == nil {
		return
	}
	select {
	case m.kick <- struct{}{}:
	default:
	}
}

func (m *managedCertManager) changed(workspaceID string) {
	if m.onChange != nil {
		m.onChange(workspaceID)
	}
}

// renewDue reports whether a cert is missing or within its final third of life.
func renewDue(rec *ManagedCertRecord, now time.Time) bool {
	if rec == nil {
		return true
	}
	lifetime := rec.NotAfter - rec.NotBefore
	if lifetime <= 0 {
		return true
	}
	return rec.NotAfter-now.Unix() < lifetime/3
}

// reconcile issues/renews a wildcard for every reservation and removes certs
// whose reservation is gone. A per-reservation failure is logged and does not
// abort the others.
func (m *managedCertManager) reconcile(ctx context.Context) error {
	res, err := m.store.ListSubdomainReservations()
	if err != nil {
		return err
	}
	want := make(map[string]bool, len(res))
	var firstErr error
	for _, r := range res {
		if err := ctx.Err(); err != nil {
			return err
		}
		want[reservationCertID(r.Domain, r.Label)] = true
		if err := m.ensureReservationCert(ctx, r); err != nil {
			slog.Warn("managed cert", "workspace", r.WorkspaceID, "zone", r.Zone(), "err", err)
			if firstErr == nil {
				firstErr = err
			}
		}
	}
	// Narrow leaves for funnel exposures.
	funnels, err := m.store.ListFunnelBindings()
	if err != nil {
		return err
	}
	for _, f := range funnels {
		if err := ctx.Err(); err != nil {
			return err
		}
		want[funnelCertID(f.Hostname)] = true
		if err := m.ensureFunnelCert(ctx, f); err != nil {
			slog.Warn("funnel cert", "workspace", f.WorkspaceID, "hostname", f.Hostname, "err", err)
			if firstErr == nil {
				firstErr = err
			}
		}
	}
	if err := m.gcOrphans(want); err != nil && firstErr == nil {
		firstErr = err
	}
	return firstErr
}

func (m *managedCertManager) ensureReservationCert(ctx context.Context, r *SubdomainReservation) error {
	issuer := m.issuers[r.Domain]
	if issuer == nil {
		return fmt.Errorf("no issuer for managed domain %q", r.Domain)
	}
	id := reservationCertID(r.Domain, r.Label)
	rec, err := m.store.GetManagedCert(id)
	if err != nil && !errors.Is(err, ErrNotFound) {
		return err
	}
	if err == nil && !renewDue(rec, m.now()) {
		return nil
	}
	cert, err := issuer.Issue(ctx, reservationWildcardNames(r))
	if err != nil {
		return err
	}
	return m.persist(id, r.WorkspaceID, r.Domain, r.Label, KindWorkspaceWildcard, cert, rec)
}

// domainFor returns the configured managed base domain a hostname falls under
// (longest match), or "" if none.
func (m *managedCertManager) domainFor(hostname string) string {
	var best string
	for base := range m.issuers {
		if (hostname == base || strings.HasSuffix(hostname, "."+base)) && len(base) > len(best) {
			best = base
		}
	}
	return best
}

func funnelCertID(hostname string) string { return "fnl-" + sanitizeDNSish(hostname) }

// ensureFunnelCert mints/renews the NARROW leaf for one funnel hostname (never
// the workspace wildcard — the leaf is what goes to public relays).
func (m *managedCertManager) ensureFunnelCert(ctx context.Context, f *FunnelBinding) error {
	domain := m.domainFor(f.Hostname)
	if domain == "" {
		return fmt.Errorf("funnel hostname %q is under no managed domain", f.Hostname)
	}
	issuer := m.issuers[domain]
	if issuer == nil {
		return fmt.Errorf("no issuer for managed domain %q", domain)
	}
	id := funnelCertID(f.Hostname)
	rec, err := m.store.GetManagedCert(id)
	if err != nil && !errors.Is(err, ErrNotFound) {
		return err
	}
	if err == nil && !renewDue(rec, m.now()) {
		return nil
	}
	cert, err := issuer.Issue(ctx, []string{f.Hostname})
	if err != nil {
		return err
	}
	label := strings.TrimSuffix(f.Hostname, "."+domain)
	return m.persist(id, f.WorkspaceID, domain, label, KindFunnelLeaf, cert, rec)
}

// gcOrphans removes cert records (and their blobs) that no live reservation
// wants — e.g. after an admin releases a subdomain.
func (m *managedCertManager) gcOrphans(want map[string]bool) error {
	certs, err := m.store.ListManagedCerts()
	if err != nil {
		return err
	}
	var firstErr error
	for _, c := range certs {
		if want[c.ID] {
			continue
		}
		if err := m.store.DeleteManagedCert(c.ID); err != nil {
			if firstErr == nil {
				firstErr = err
			}
			continue
		}
		if c.Ref != "" {
			_ = m.blobs.remove(c.Ref)
		}
		slog.Info("managed cert released", "id", c.ID, "zone", c.Label+"."+c.Domain)
		m.changed(c.WorkspaceID)
	}
	return firstErr
}

// persist writes the new bundle to a fresh blob, flips the index record, and
// GCs the previous blob. The record flip is the commit point: if the process
// dies before it, the orphaned blob is harmless and the next tick re-issues.
func (m *managedCertManager) persist(id, workspaceID, domain, label, kind string, cert *webpki.Cert, prev *ManagedCertRecord) error {
	epoch := int64(1)
	if prev != nil {
		epoch = prev.Epoch + 1
	}
	ref := m.blobs.newRef(managedCertBlobName(id, epoch))
	w, err := m.blobs.create(ref)
	if err != nil {
		return fmt.Errorf("create cert blob: %w", err)
	}
	if _, err := w.Write(bundlePEM(cert)); err != nil {
		w.Abort()
		return fmt.Errorf("write cert blob: %w", err)
	}
	if err := w.Commit(); err != nil {
		return fmt.Errorf("commit cert blob: %w", err)
	}
	sum := sha256.Sum256(cert.ChainPEM)
	rec := &ManagedCertRecord{
		ID:          id,
		WorkspaceID: workspaceID,
		Domain:      domain,
		Label:       label,
		Kind:        kind,
		Names:       cert.Names,
		Ref:         ref,
		NotBefore:   cert.NotBefore.Unix(),
		NotAfter:    cert.NotAfter.Unix(),
		Epoch:       epoch,
		Sha256:      hex.EncodeToString(sum[:]),
		IssuedUnix:  m.now().Unix(),
	}
	if err := m.store.PutManagedCert(rec); err != nil {
		return err
	}
	if prev != nil && prev.Ref != "" && prev.Ref != ref {
		_ = m.blobs.remove(prev.Ref)
	}
	slog.Info("managed cert issued", "id", id, "kind", kind, "names", cert.Names, "epoch", epoch, "not_after", cert.NotAfter)
	m.changed(workspaceID)
	return nil
}

// --- server wiring ---

// managedCertTickInterval is how often the renewal reconcile runs by default.
// Each cert only re-issues at ~2/3 of its lifetime, so a frequent tick is cheap;
// it mainly bounds how fast a newly-created workspace gets its first cert.
const managedCertTickInterval = 6 * time.Hour

// setupManagedCerts builds one ACME issuer per configured domain (through that
// domain's named DNS-01 provider, all under the shared account) and the renewal
// manager. It loads (or generates and persists) the stable ACME account key. A
// nil s.managedCerts means the feature is off.
func (s *Server) setupManagedCerts() error {
	md := s.cfg.ManagedDomain
	if !md.enabled() {
		return nil
	}
	keyPEM, err := loadOrCreateAccountKey(s.cfg.managedAccountKeyPath())
	if err != nil {
		return err
	}
	acct := md.ACME
	acct.AccountKeyPEM = keyPEM
	if err := acct.Validate(); err != nil {
		return err
	}
	issuers := make(map[string]webpki.Issuer, len(md.Domains))
	for _, d := range md.Domains {
		dns01, ok := md.DNSProviders[d.DNSProvider]
		if !ok {
			return fmt.Errorf("domain %q references unknown dns_provider %q", d.Base, d.DNSProvider)
		}
		issuer, err := webpki.New(acct, dns01)
		if err != nil {
			return fmt.Errorf("domain %q: %w", d.Base, err)
		}
		issuers[d.Base] = issuer
		slog.Info("managed domain enabled", "base", d.Base, "dns01", dns01.Provider,
			"production", acct.Production, "directory", acct.DirectoryURL)
	}
	s.managedCerts = newManagedCertManager(s.store, s.recordingBlobs, issuers)
	s.managedCerts.onChange = s.repushWorkspaceCerts

	// Funnel-DNS: an A-record manager per domain (skipped, logged, where the
	// provider can't yet manage A records — funnel DNS is then static).
	managers := make(map[string]webpki.RecordManager, len(md.Domains))
	for _, d := range md.Domains {
		rm, err := webpki.NewRecordManager(md.DNSProviders[d.DNSProvider])
		if err != nil {
			slog.Info("managed domain: funnel DNS unmanaged (set A records statically)", "base", d.Base, "reason", err)
			continue
		}
		managers[d.Base] = rm
	}
	s.funnelDNS = newFunnelDNSReconciler(s.store, managers)
	return nil
}

// loadOrCreateAccountKey reads the ACME account key, generating and persisting a
// fresh one (0600) on first start so the key — and thus the ACME account — is
// stable across restarts.
func loadOrCreateAccountKey(path string) ([]byte, error) {
	if b, err := os.ReadFile(path); err == nil {
		return b, nil
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, fmt.Errorf("read account key: %w", err)
	}
	key, err := webpki.GenerateAccountKey()
	if err != nil {
		return nil, err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, err
	}
	if err := os.WriteFile(path, key, 0o600); err != nil {
		return nil, fmt.Errorf("persist account key: %w", err)
	}
	return key, nil
}

// runManagedCertController drives issuance/renewal on a tick. It runs leader-only
// under a dedicated advisory lock (so the slow DNS-01 loop never contends with
// the fleet-map rebuild) and is fully store-driven, so it resumes after a
// restart. Inert when the feature is disabled.
func (s *Server) runManagedCertController(ctx context.Context, interval time.Duration) {
	if s.managedCerts == nil {
		return
	}
	if interval <= 0 {
		interval = managedCertTickInterval
	}
	tick := func() {
		held, release, err := s.store.TryManagedCertLock(ctx)
		if err != nil || !held {
			return
		}
		defer release()
		if err := s.managedCerts.reconcile(ctx); err != nil {
			slog.Warn("managed cert reconcile", "err", err)
		}
		if s.funnelDNS != nil {
			s.funnelDNS.reconcile(ctx) // publish/withdraw public A records for funnels
		}
	}
	tick() // issue promptly on startup, not only after the first interval
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			tick()
		case <-s.managedCerts.kick:
			tick() // a new reservation/funnel wants its cert now
		}
	}
}

// --- bbolt store ---

func (s *bboltStore) PutManagedCert(rec *ManagedCertRecord) error {
	return s.db.Update(func(tx *bbolt.Tx) error {
		return putJSON(tx, bucketManagedCerts, rec.ID, rec)
	})
}

func (s *bboltStore) GetManagedCert(id string) (*ManagedCertRecord, error) {
	var rec ManagedCertRecord
	err := s.db.View(func(tx *bbolt.Tx) error {
		return getJSON(tx, bucketManagedCerts, id, &rec)
	})
	if err != nil {
		return nil, err
	}
	return &rec, nil
}

func (s *bboltStore) ListManagedCerts() ([]*ManagedCertRecord, error) {
	var out []*ManagedCertRecord
	err := s.db.View(func(tx *bbolt.Tx) error {
		b := tx.Bucket(bucketManagedCerts)
		if b == nil {
			return nil
		}
		return b.ForEach(func(_, v []byte) error {
			var rec ManagedCertRecord
			if err := json.Unmarshal(v, &rec); err != nil {
				return err
			}
			out = append(out, &rec)
			return nil
		})
	})
	return out, err
}

func (s *bboltStore) DeleteManagedCert(id string) error {
	return s.db.Update(func(tx *bbolt.Tx) error {
		b := tx.Bucket(bucketManagedCerts)
		if b == nil {
			return nil
		}
		return b.Delete([]byte(id))
	})
}

// TryManagedCertLock: a single-node bbolt controller is the only writer, so it
// always grants the lock; the store-driven, idempotent reconcile is the
// correctness backstop if two ever slip through.
func (s *bboltStore) TryManagedCertLock(context.Context) (bool, func(), error) {
	return true, func() {}, nil
}

// --- sql store ---

func (s *sqlStore) PutManagedCert(rec *ManagedCertRecord) error {
	doc, err := marshalDoc(rec)
	if err != nil {
		return err
	}
	_, err = s.exec(s.ctx(), s.db, `INSERT INTO managed_certs (id, workspace_id, notafter_unix, doc) VALUES ($1, $2, $3, $4::jsonb)
		 ON CONFLICT (id) DO UPDATE SET workspace_id = EXCLUDED.workspace_id, notafter_unix = EXCLUDED.notafter_unix, doc = EXCLUDED.doc`,
		rec.ID, rec.WorkspaceID, rec.NotAfter, doc)
	return err
}

func (s *sqlStore) GetManagedCert(id string) (*ManagedCertRecord, error) {
	return sqlGetDoc[ManagedCertRecord](s.ctx(), s, s.db, `SELECT doc FROM managed_certs WHERE id = $1`, id)
}

func (s *sqlStore) ListManagedCerts() ([]*ManagedCertRecord, error) {
	return sqlListDocs[ManagedCertRecord](s.ctx(), s, s.db, `SELECT doc FROM managed_certs ORDER BY id`)
}

func (s *sqlStore) DeleteManagedCert(id string) error {
	_, err := s.exec(s.ctx(), s.db, `DELETE FROM managed_certs WHERE id = $1`, id)
	return err
}

// TryManagedCertLock is the same transient, non-blocking advisory lock as
// TryReconcileLock but on a distinct key, so the slow ACME issuance loop (DNS-01
// propagation runs minutes) never contends with the fleet-map rebuild.
func (s *sqlStore) TryManagedCertLock(ctx context.Context) (held bool, release func(), err error) {
	conn, err := s.db.Conn(ctx)
	if err != nil {
		return false, nil, err
	}
	ok, err := s.dialect.tryAdvisoryLock(ctx, conn, managedCertLockKey)
	if err != nil {
		_ = conn.Close()
		return false, nil, err
	}
	if !ok {
		_ = conn.Close()
		return false, nil, nil
	}
	return true, func() {
		_ = s.dialect.advisoryUnlock(context.Background(), conn, managedCertLockKey)
		_ = conn.Close()
	}, nil
}
