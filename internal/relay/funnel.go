package relay

import (
	"crypto/rand"
	"crypto/subtle"
	"crypto/tls"
	"fmt"
	"log/slog"
	"strings"
	"sync"

	"golang.org/x/crypto/curve25519"

	"geneza.io/internal/certbundle"
	"geneza.io/internal/nodeseal"
	genezav1 "geneza.io/internal/pb/geneza/v1"
)

func subtleConstantTimeEqual(a, b string) bool {
	return subtle.ConstantTimeCompare([]byte(a), []byte(b)) == 1
}

// funnelCerts holds the narrow leaf certs this relay terminates public TLS for,
// keyed by funnel hostname, hot-swappable. The controller pushes them sealed to the
// relay's ephemeral X25519 key over the watch stream; the relay unseals them
// here. The public funnel listener selects a cert by SNI via GetCertificate. The
// key material is opaque on the wire and in memory until unsealed, and the
// private X25519 key is regenerated per process (never persisted).
type funnelCerts struct {
	log  *slog.Logger
	priv []byte // relay X25519 private key (unseal)
	pub  []byte // advertised in the heartbeat for the controller to seal to

	mu    sync.RWMutex
	certs map[string]*funnelCert // hostname -> held
}

type funnelCert struct {
	epoch    int64
	cert     *tls.Certificate
	regToken string // the controller-authorized registration secret for this host
}

func newFunnelCerts(log *slog.Logger) (*funnelCerts, error) {
	priv := make([]byte, 32)
	if _, err := rand.Read(priv); err != nil {
		return nil, err
	}
	pub, err := curve25519.X25519(priv, curve25519.Basepoint)
	if err != nil {
		return nil, err
	}
	return &funnelCerts{log: log, priv: priv, pub: pub, certs: map[string]*funnelCert{}}, nil
}

func (f *funnelCerts) sealPub() []byte { return f.pub }

// apply reconciles to the pushed sealed set declaratively (the controller sends the
// full current set each push): new/renewed certs are installed, released ones
// dropped.
func (f *funnelCerts) apply(sealed []*genezav1.SealedCert) {
	desired := make(map[string]bool, len(sealed))
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, sc := range sealed {
		host := strings.ToLower(sc.GetZone())
		desired[host] = true
		if h, ok := f.certs[host]; ok && h.epoch == sc.GetEpoch() {
			h.regToken = sc.GetRegToken() // token may rotate without a cert epoch bump
			continue
		}
		bundle, err := nodeseal.Open(sc.GetSealed(), f.priv)
		if err != nil {
			f.log.Warn("unseal funnel cert", "host", host, "err", err)
			continue
		}
		crt, err := certbundle.TLSCertificate(bundle)
		if err != nil {
			f.log.Warn("parse funnel cert", "host", host, "err", err)
			continue
		}
		f.certs[host] = &funnelCert{epoch: sc.GetEpoch(), cert: crt, regToken: sc.GetRegToken()}
		f.log.Info("funnel cert installed", "host", host, "epoch", sc.GetEpoch())
	}
	for host := range f.certs {
		if !desired[host] {
			delete(f.certs, host)
			f.log.Info("funnel cert removed", "host", host)
		}
	}
}

// GetCertificate selects the funnel cert for a TLS handshake's SNI — an exact
// match, since each leaf covers exactly one hostname.
func (f *funnelCerts) GetCertificate(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
	host := strings.ToLower(strings.TrimSuffix(hello.ServerName, "."))
	f.mu.RLock()
	defer f.mu.RUnlock()
	if h, ok := f.certs[host]; ok {
		return h.cert, nil
	}
	return nil, fmt.Errorf("no funnel cert for %q", host)
}

// authorizeReg reports whether the relay holds a funnel cert for host AND the
// presented registration token matches the controller-authorized one. An empty
// stored token (the controller didn't authorize anyone) denies all registrations.
func (f *funnelCerts) authorizeReg(host, token string) bool {
	f.mu.RLock()
	defer f.mu.RUnlock()
	h, ok := f.certs[host]
	return ok && h.regToken != "" && subtleConstantTimeEqual(h.regToken, token)
}

// hosts returns the funnel hostnames currently served (test/observability).
func (f *funnelCerts) hosts() []string {
	f.mu.RLock()
	defer f.mu.RUnlock()
	out := make([]string, 0, len(f.certs))
	for h := range f.certs {
		out = append(out, h)
	}
	return out
}
