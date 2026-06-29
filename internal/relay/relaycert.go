package relay

import (
	"bytes"
	"crypto"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"geneza.io/internal/ca"
)

// ensureIDCert loads the identity keypair into the holder once, whichever of the
// listener or registrar reaches it first.
func (r *Relay) ensureIDCert() error {
	r.certOnce.Do(func() {
		cert, err := tls.LoadX509KeyPair(r.cfg.CertFile, r.cfg.KeyFile)
		if err != nil {
			r.certLoadErr = fmt.Errorf("relay: load TLS keypair: %w", err)
			return
		}
		if cert.Leaf == nil && len(cert.Certificate) > 0 {
			cert.Leaf, _ = x509.ParseCertificate(cert.Certificate[0])
		}
		r.idCert.Store(&cert)
	})
	return r.certLoadErr
}

// getServerCert and getClientCert hand the live cert to the listener and the
// registrar dial, so a renewal applies without rebuilding either TLS config.
func (r *Relay) getServerCert(*tls.ClientHelloInfo) (*tls.Certificate, error) {
	return r.heldCert()
}

func (r *Relay) getClientCert(*tls.CertificateRequestInfo) (*tls.Certificate, error) {
	return r.heldCert()
}

func (r *Relay) heldCert() (*tls.Certificate, error) {
	if c := r.idCert.Load(); c != nil {
		return c, nil
	}
	return nil, fmt.Errorf("relay: no identity certificate loaded")
}

// renewalDue reports whether the held cert is past ~2/3 of its life. Cheap (no CSR
// build), so the registrar can poll it to break a long-lived watch when renewal
// comes due.
func (r *Relay) renewalDue() bool {
	cert := r.idCert.Load()
	return cert != nil && cert.Leaf != nil && ca.NeedsRenewal(cert.Leaf.NotBefore, cert.Leaf.NotAfter, time.Now())
}

// renewalCSR returns a CSR over the relay's existing key (so the agent-held
// relay_cert_pub pin survives the renewal) once renewal is due, else nil.
func (r *Relay) renewalCSR() []byte {
	if !r.renewalDue() {
		return nil
	}
	cert := r.idCert.Load()
	signer, ok := cert.PrivateKey.(crypto.Signer)
	if !ok {
		return nil
	}
	csr, err := ca.MakeCSR(signer, r.cfg.RelayID)
	if err != nil {
		r.log.Warn("relay: build renewal CSR", "err", err)
		return nil
	}
	return csr
}

// installRenewedCert hot-swaps the holder with the renewed cert (same key) and
// best-effort persists it. A read-only cert dir is fine: the in-memory swap holds,
// and on restart the relay falls back to the still-valid on-disk cert and renews again.
func (r *Relay) installRenewedCert(certPEM, caRoots []byte) {
	cur := r.idCert.Load()
	if cur == nil {
		return
	}
	chain := pemChainDER(certPEM)
	if len(chain) == 0 {
		r.log.Warn("relay: renewed cert had no PEM chain")
		return
	}
	leaf, err := x509.ParseCertificate(chain[0])
	if err != nil {
		r.log.Warn("relay: renewed cert did not parse", "err", err)
		return
	}
	// The renewed cert must bind our existing key (it always does — the CSR was over
	// that key). Refuse a mismatch rather than install a cert/key pair that would fail
	// every handshake; the still-valid old cert stays live.
	if signer, ok := cur.PrivateKey.(crypto.Signer); ok {
		want, _ := x509.MarshalPKIXPublicKey(signer.Public())
		got, _ := x509.MarshalPKIXPublicKey(leaf.PublicKey)
		if !bytes.Equal(want, got) {
			r.log.Warn("relay: renewed cert key mismatch; keeping current cert")
			return
		}
	}
	r.idCert.Store(&tls.Certificate{Certificate: chain, PrivateKey: cur.PrivateKey, Leaf: leaf})
	r.log.Info("relay: identity cert renewed", "not_after", leaf.NotAfter.Format(time.RFC3339))

	if err := atomicWrite(r.cfg.CertFile, certPEM, 0o600); err != nil {
		r.log.Warn("relay: persist renewed cert (in-memory swap still applied)", "err", err)
	}
	if len(caRoots) > 0 && r.cfg.ControllerCAFile != "" {
		if err := atomicWrite(r.cfg.ControllerCAFile, caRoots, 0o644); err != nil {
			r.log.Warn("relay: persist renewed CA roots", "err", err)
		}
	}
}

func pemChainDER(pemBytes []byte) [][]byte {
	var out [][]byte
	for rest := pemBytes; ; {
		blk, r := pem.Decode(rest)
		if blk == nil {
			break
		}
		if blk.Type == "CERTIFICATE" {
			out = append(out, blk.Bytes)
		}
		rest = r
	}
	return out
}

// atomicWrite writes via a temp file + rename so a reader never sees a half write.
func atomicWrite(path string, data []byte, perm os.FileMode) error {
	if path == "" {
		return nil
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), ".relaycert-*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Chmod(perm); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), path)
}
