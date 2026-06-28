package agentd

import (
	"crypto/tls"
	"encoding/pem"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"geneza.io/internal/nodeseal"
	genezav1 "geneza.io/internal/pb/geneza/v1"
)

// certManager holds the node's managed-domain certificates. The controller pushes
// the full desired set (each cert's PEM bundle age-sealed to this node's Noise
// key); the manager unseals with the node's Noise private key, persists the
// bundle, and serves it via GetCertificate for a TLS listener. It reconciles
// declaratively — new/renewed certs are installed, released ones dropped — so a
// push is idempotent and a reconnect re-converges the set.
type certManager struct {
	log     *slog.Logger
	dir     string // where bundles are written (<data>/managed-certs)
	privKey []byte // node Noise X25519 private key (unseal)

	mu    sync.RWMutex
	certs map[string]*heldCert // zone -> held
	ver   int64
}

type heldCert struct {
	zone  string // "<label>.<domain>"; the cert covers *.zone and the apex
	epoch int64
	cert  *tls.Certificate
}

func newCertManager(log *slog.Logger, dir string, noisePriv []byte) *certManager {
	return &certManager{log: log, dir: dir, privKey: noisePriv, certs: map[string]*heldCert{}}
}

// reconcile applies a pushed bundle as the complete desired set.
func (m *certManager) reconcile(b *genezav1.CertBundle) {
	if b == nil {
		return
	}
	desired := make(map[string]bool, len(b.GetCerts()))
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, sc := range b.GetCerts() {
		zone := strings.ToLower(sc.GetZone())
		desired[zone] = true
		if h, ok := m.certs[zone]; ok && h.epoch == sc.GetEpoch() {
			continue // unchanged
		}
		bundle, err := nodeseal.Open(sc.GetSealed(), m.privKey)
		if err != nil {
			m.log.Warn("unseal managed cert", "zone", zone, "err", err)
			continue
		}
		crt, err := tlsCertFromBundle(bundle)
		if err != nil {
			m.log.Warn("parse managed cert", "zone", zone, "err", err)
			continue
		}
		if err := m.persist(zone, bundle); err != nil {
			m.log.Warn("persist managed cert", "zone", zone, "err", err)
		}
		m.certs[zone] = &heldCert{zone: zone, epoch: sc.GetEpoch(), cert: crt}
		m.log.Info("managed cert installed", "zone", zone, "epoch", sc.GetEpoch())
	}
	for zone := range m.certs {
		if !desired[zone] {
			delete(m.certs, zone)
			_ = os.Remove(m.bundlePath(zone))
			m.log.Info("managed cert removed", "zone", zone)
		}
	}
	m.ver = b.GetVersion()
}

// GetCertificate selects the managed cert for a TLS handshake's SNI. A held cert
// covers its apex zone and exactly one label below it (the wildcard), matching
// what was issued.
func (m *certManager) GetCertificate(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
	name := strings.ToLower(strings.TrimSuffix(hello.ServerName, "."))
	m.mu.RLock()
	defer m.mu.RUnlock()
	for _, h := range m.certs {
		if name == h.zone || singleLabelUnder(name, h.zone) {
			return h.cert, nil
		}
	}
	return nil, fmt.Errorf("no managed cert for %q", name)
}

// zones returns the zones currently held (test/observability).
func (m *certManager) zones() []string {
	m.mu.RLock()
	defer m.mu.RUnlock()
	out := make([]string, 0, len(m.certs))
	for z := range m.certs {
		out = append(out, z)
	}
	return out
}

func (m *certManager) bundlePath(zone string) string {
	safe := strings.Map(func(r rune) rune {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9', r == '.', r == '-':
			return r
		default:
			return '-'
		}
	}, strings.ToLower(zone))
	return filepath.Join(m.dir, safe+".pem")
}

func (m *certManager) persist(zone string, bundle []byte) error {
	if err := os.MkdirAll(m.dir, 0o700); err != nil {
		return err
	}
	return atomicWrite(m.bundlePath(zone), bundle, 0o600)
}

// singleLabelUnder reports whether name is exactly one DNS label below zone
// (what "*.zone" covers): "app.zone" yes, "a.b.zone" no, "zone" no.
func singleLabelUnder(name, zone string) bool {
	rest, ok := strings.CutSuffix(name, "."+zone)
	return ok && rest != "" && !strings.Contains(rest, ".")
}

// tlsCertFromBundle parses a PEM bundle (private key + cert chain in any order)
// into a tls.Certificate.
func tlsCertFromBundle(bundle []byte) (*tls.Certificate, error) {
	var chain, key []byte
	rest := bundle
	for {
		var blk *pem.Block
		blk, rest = pem.Decode(rest)
		if blk == nil {
			break
		}
		enc := pem.EncodeToMemory(blk)
		if strings.HasSuffix(blk.Type, "PRIVATE KEY") {
			key = append(key, enc...)
		} else if blk.Type == "CERTIFICATE" {
			chain = append(chain, enc...)
		}
	}
	if len(chain) == 0 || len(key) == 0 {
		return nil, fmt.Errorf("bundle missing chain or key")
	}
	crt, err := tls.X509KeyPair(chain, key)
	if err != nil {
		return nil, err
	}
	return &crt, nil
}
