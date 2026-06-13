// Package ca implements the Geneza certificate authority: a root CA
// (kept aside, "offline" in spirit) plus an issuing CA used online by the
// gateway. Leaf identities are encoded as URIs:
//
//	geneza://node/<node-id>     agent (client cert on the control channel)
//	geneza://user/<username>    operator (client cert on the user/admin API)
//	geneza://gateway/<name>     gateway TLS server cert
//	geneza://relay/<name>       relay TLS server cert
//
// User roles/provider ride in a custom extension (OIDRolesExt, JSON).
// The issuing key is held behind crypto.Signer so an HSM/KMS can replace the
// on-disk key without touching call sites.
package ca

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// OIDRolesExt carries JSON IdentityClaims in user certs (lab-private arc).
var OIDRolesExt = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 57534, 1}

const (
	KindNode    = "node"
	KindUser    = "user"
	KindGateway = "gateway"
	KindRelay   = "relay"
)

// Identity is what a verified peer certificate asserts.
type Identity struct {
	Kind string // node|user|gateway|relay
	// Workspace is the tenant the node/user belongs to (multi-tenancy). It is
	// encoded in the cert URI (geneza://user/<ws>/<name>) and is the SOLE source
	// of a peer's workspace — never client-supplied. Empty/legacy 2-segment certs
	// resolve to "default" for node/user kinds; gateway/relay carry no workspace.
	Workspace string
	Name      string // node id / username / service name
	Roles     []string
	Provider  string // identity provider that authenticated the user
}

// IdentityClaims is the JSON payload of OIDRolesExt.
type IdentityClaims struct {
	Roles    []string `json:"roles,omitempty"`
	Provider string   `json:"provider,omitempty"`
}

// CA wraps the issuing certificate and its signer.
type CA struct {
	Cert   *x509.Certificate
	Signer crypto.Signer
	// Roots is the PEM bundle agents/clients should trust (root cert(s)).
	RootsPEM []byte
	// chainPEM is the issuing cert PEM, served alongside leaves.
	IssuingPEM []byte
}

// ---------------------------------------------------------------------------
// Creation / loading
// ---------------------------------------------------------------------------

func newSerial() (*big.Int, error) {
	return rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 127))
}

func keyPEM(k *ecdsa.PrivateKey) ([]byte, error) {
	der, err := x509.MarshalECPrivateKey(k)
	if err != nil {
		return nil, err
	}
	return pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: der}), nil
}

func certPEM(der []byte) []byte {
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}

// Init creates a fresh two-tier CA under dir:
//
//	dir/root-ca.{key,crt}      — root (keep offline; only needed for rotation)
//	dir/issuing-ca.{key,crt}   — loaded by the gateway at runtime
//	dir/ca-roots.pem           — trust bundle distributed to the fleet
func Init(dir, clusterName string) error {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	if _, err := os.Stat(filepath.Join(dir, "issuing-ca.key")); err == nil {
		return errors.New("CA already initialized: " + dir)
	}

	rootKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return err
	}
	rootSerial, err := newSerial()
	if err != nil {
		return err
	}
	now := time.Now()
	rootTmpl := &x509.Certificate{
		SerialNumber:          rootSerial,
		Subject:               pkix.Name{CommonName: "Geneza Root CA " + clusterName, Organization: []string{"Geneza"}},
		NotBefore:             now.Add(-5 * time.Minute),
		NotAfter:              now.AddDate(10, 0, 0),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		MaxPathLen:            1,
	}
	rootDER, err := x509.CreateCertificate(rand.Reader, rootTmpl, rootTmpl, &rootKey.PublicKey, rootKey)
	if err != nil {
		return err
	}
	rootCert, err := x509.ParseCertificate(rootDER)
	if err != nil {
		return err
	}

	issKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return err
	}
	issSerial, err := newSerial()
	if err != nil {
		return err
	}
	issTmpl := &x509.Certificate{
		SerialNumber:          issSerial,
		Subject:               pkix.Name{CommonName: "Geneza Issuing CA " + clusterName, Organization: []string{"Geneza"}},
		NotBefore:             now.Add(-5 * time.Minute),
		NotAfter:              now.AddDate(5, 0, 0),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		MaxPathLenZero:        true,
	}
	issDER, err := x509.CreateCertificate(rand.Reader, issTmpl, rootCert, &issKey.PublicKey, rootKey)
	if err != nil {
		return err
	}

	rk, err := keyPEM(rootKey)
	if err != nil {
		return err
	}
	ik, err := keyPEM(issKey)
	if err != nil {
		return err
	}
	// Runtime files the gateway actually loads (Load reads only these): the
	// issuing key/cert and the public root trust bundle. The root cert is also
	// public; only the root PRIVATE key is the crown jewel.
	writes := []struct {
		name string
		data []byte
		mode os.FileMode
	}{
		{"root-ca.crt", certPEM(rootDER), 0o644},
		{"issuing-ca.key", ik, 0o600},
		{"issuing-ca.crt", certPEM(issDER), 0o644},
		{"ca-roots.pem", certPEM(rootDER), 0o644},
	}
	for _, w := range writes {
		if err := os.WriteFile(filepath.Join(dir, w.name), w.data, w.mode); err != nil {
			return err
		}
	}

	// The ROOT PRIVATE KEY must not live next to the running gateway: filesystem
	// compromise of the gateway would otherwise become fleet-wide identity
	// takeover (the root can mint any issuing CA). Write it into a separate
	// offline-root/ directory with a relocation notice; the operator/deploy is
	// responsible for moving offline-root/ off this host (HSM/KMS/air-gapped
	// store) and deleting it here. Load() never reads it — the gateway runs on
	// the issuing key alone, and the root is needed only for CA rotation.
	offlineDir := filepath.Join(dir, "offline-root")
	if err := os.MkdirAll(offlineDir, 0o700); err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(offlineDir, "root-ca.key"), rk, 0o600); err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(offlineDir, "root-ca.crt"), certPEM(rootDER), 0o644); err != nil {
		return err
	}
	notice := "SECURITY: this directory holds the Geneza ROOT CA PRIVATE KEY.\n" +
		"Move it OFF this gateway host (HSM / KMS / air-gapped store) and delete it here.\n" +
		"The gateway runs on issuing-ca.key alone; the root is needed only to rotate the CA.\n"
	if err := os.WriteFile(filepath.Join(offlineDir, "MOVE-OFFLINE-AND-DELETE.txt"), []byte(notice), 0o644); err != nil {
		return err
	}
	return nil
}

// Load opens the issuing CA from dir (as written by Init).
func Load(dir string) (*CA, error) {
	keyB, err := os.ReadFile(filepath.Join(dir, "issuing-ca.key"))
	if err != nil {
		return nil, err
	}
	blk, _ := pem.Decode(keyB)
	if blk == nil {
		return nil, errors.New("issuing-ca.key: no PEM block")
	}
	key, err := x509.ParseECPrivateKey(blk.Bytes)
	if err != nil {
		return nil, fmt.Errorf("issuing-ca.key: %w", err)
	}
	certB, err := os.ReadFile(filepath.Join(dir, "issuing-ca.crt"))
	if err != nil {
		return nil, err
	}
	cblk, _ := pem.Decode(certB)
	if cblk == nil {
		return nil, errors.New("issuing-ca.crt: no PEM block")
	}
	cert, err := x509.ParseCertificate(cblk.Bytes)
	if err != nil {
		return nil, err
	}
	roots, err := os.ReadFile(filepath.Join(dir, "ca-roots.pem"))
	if err != nil {
		return nil, err
	}
	return &CA{Cert: cert, Signer: key, RootsPEM: roots, IssuingPEM: certPEM(cblk.Bytes)}, nil
}

// ---------------------------------------------------------------------------
// Issuance
// ---------------------------------------------------------------------------

// Profile describes a leaf certificate to issue.
type Profile struct {
	Kind      string // node|user|gateway|relay
	Workspace string // tenant for node/user certs; empty for gateway/relay
	Name      string
	TTL       time.Duration
	Claims    *IdentityClaims // user certs
	DNSNames  []string        // server certs
	IPs       []net.IP        // server certs
}

// identityURI builds geneza://<kind>/<workspace>/<name> for tenant-scoped
// node/user certs, or geneza://<kind>/<name> when workspace is empty
// (gateway/relay server certs).
func identityURI(kind, workspace, name string) *url.URL {
	p := "/" + name
	if workspace != "" {
		p = "/" + workspace + "/" + name
	}
	return &url.URL{Scheme: "geneza", Host: kind, Path: p}
}

// IssueFromCSR verifies the CSR signature and issues a leaf for profile.
// The CSR only contributes the public key; all naming comes from profile.
// Returns leaf PEM with the issuing cert appended (chain to the root).
func (c *CA) IssueFromCSR(csrPEM []byte, p Profile) ([]byte, error) {
	blk, _ := pem.Decode(csrPEM)
	if blk == nil {
		return nil, errors.New("no PEM block in CSR")
	}
	csr, err := x509.ParseCertificateRequest(blk.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse CSR: %w", err)
	}
	if err := csr.CheckSignature(); err != nil {
		return nil, fmt.Errorf("CSR signature: %w", err)
	}
	return c.issue(csr.PublicKey, p)
}

func (c *CA) issue(pub any, p Profile) ([]byte, error) {
	serial, err := newSerial()
	if err != nil {
		return nil, err
	}
	now := time.Now()
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: p.Kind + ":" + p.Name, Organization: []string{"Geneza"}},
		NotBefore:    now.Add(-2 * time.Minute), // small skew tolerance
		NotAfter:     now.Add(p.TTL),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		URIs:         []*url.URL{identityURI(p.Kind, p.Workspace, p.Name)},
	}
	switch p.Kind {
	case KindNode, KindUser:
		tmpl.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}
	case KindGateway, KindRelay:
		tmpl.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}
		tmpl.DNSNames = p.DNSNames
		tmpl.IPAddresses = p.IPs
	default:
		return nil, fmt.Errorf("unknown cert kind %q", p.Kind)
	}
	if p.Claims != nil {
		j, err := json.Marshal(p.Claims)
		if err != nil {
			return nil, err
		}
		tmpl.ExtraExtensions = append(tmpl.ExtraExtensions, pkix.Extension{Id: OIDRolesExt, Value: j})
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, c.Cert, pub, c.Signer)
	if err != nil {
		return nil, err
	}
	return append(certPEM(der), c.IssuingPEM...), nil
}

// IssueServerKeypair generates a fresh key and server cert (gateway/relay
// provisioning convenience). Returns certPEM (with chain) and keyPEM.
func (c *CA) IssueServerKeypair(p Profile) (cert []byte, key []byte, err error) {
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	cert, err = c.issue(&k.PublicKey, p)
	if err != nil {
		return nil, nil, err
	}
	key, err = keyPEM(k)
	if err != nil {
		return nil, nil, err
	}
	return cert, key, nil
}

// ---------------------------------------------------------------------------
// Verification helpers
// ---------------------------------------------------------------------------

// PoolFromPEM builds a CertPool from a PEM bundle.
func PoolFromPEM(pemBytes []byte) (*x509.CertPool, error) {
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(pemBytes) {
		return nil, errors.New("no certificates in PEM bundle")
	}
	return pool, nil
}

// PeerIdentity extracts the Geneza identity from a verified leaf cert.
func PeerIdentity(cert *x509.Certificate) (*Identity, error) {
	for _, u := range cert.URIs {
		if u.Scheme != "geneza" {
			continue
		}
		// Path is /<name> (gateway/relay, legacy) or /<workspace>/<name>
		// (tenant-scoped node/user). node/user with no workspace segment resolve
		// to "default" for backward compatibility.
		var ws, name string
		if parts := strings.SplitN(strings.TrimPrefix(u.Path, "/"), "/", 2); len(parts) == 2 {
			ws, name = parts[0], parts[1]
		} else {
			name = parts[0]
		}
		if ws == "" && (u.Host == KindNode || u.Host == KindUser) {
			ws = "default"
		}
		id := &Identity{Kind: u.Host, Workspace: ws, Name: name}
		for _, ext := range cert.Extensions {
			if ext.Id.Equal(OIDRolesExt) {
				var claims IdentityClaims
				if err := json.Unmarshal(ext.Value, &claims); err != nil {
					return nil, fmt.Errorf("identity claims extension: %w", err)
				}
				id.Roles = claims.Roles
				id.Provider = claims.Provider
			}
		}
		if id.Name == "" {
			return nil, errors.New("empty identity name in certificate URI")
		}
		return id, nil
	}
	return nil, errors.New("no geneza identity URI in certificate")
}

// ---------------------------------------------------------------------------
// Client-side key + CSR helpers (used by agent and CLI)
// ---------------------------------------------------------------------------

// GenerateKey creates a P-256 key for a node/user identity.
func GenerateKey() (*ecdsa.PrivateKey, error) {
	return ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
}

func MarshalKeyPEM(k *ecdsa.PrivateKey) ([]byte, error) { return keyPEM(k) }

func ParseKeyPEM(b []byte) (*ecdsa.PrivateKey, error) {
	blk, _ := pem.Decode(b)
	if blk == nil {
		return nil, errors.New("no PEM block in key")
	}
	return x509.ParseECPrivateKey(blk.Bytes)
}

// MakeCSR builds a PKCS10 CSR for key (subject is informational only).
func MakeCSR(key crypto.Signer, cn string) ([]byte, error) {
	der, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
		Subject: pkix.Name{CommonName: cn},
	}, key)
	if err != nil {
		return nil, err
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der}), nil
}
