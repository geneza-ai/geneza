package controller

import (
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"

	"geneza.io/internal/ca"
	"geneza.io/internal/types"
)

// Server TLS certs are long-lived infrastructure certs (unlike the
// short-TTL node/user leaves); ~2 years, rotated by re-running issuance.
const serverCertTTL = 2 * 365 * 24 * time.Hour

// InitDataDir provisions a fresh controller data_dir: CA hierarchy, grant
// signing key, controller+relay TLS server keypairs, and the initial signed
// ClusterConfig (config_version 1). Refuses to touch an initialized dir.
func InitDataDir(cfg *Config) error {
	for _, p := range []string{
		filepath.Join(cfg.CADir(), "issuing-ca.key"),
		cfg.GrantKeyPath(),
		cfg.StatePath(),
	} {
		if _, err := os.Stat(p); err == nil {
			return fmt.Errorf("already initialized: %s exists", p)
		}
	}
	for _, d := range []string{cfg.DataDir, cfg.TLSDir(), cfg.ArtifactsDir(), cfg.RecordingsDir()} {
		if err := os.MkdirAll(d, 0o700); err != nil {
			return err
		}
	}

	if err := ca.Init(cfg.CADir(), cfg.ClusterName); err != nil {
		return err
	}
	caInst, err := ca.Load(cfg.CADir())
	if err != nil {
		return err
	}

	pub, priv, keyID, err := types.GenerateSigningKey()
	if err != nil {
		return err
	}
	if err := types.SavePrivateKeyPEM(cfg.GrantKeyPath(), priv); err != nil {
		return err
	}
	if err := os.WriteFile(cfg.GrantKeyIDPath(), []byte(keyID+"\n"), 0o644); err != nil {
		return err
	}

	// localhost/loopback SANs are always included so on-box tooling and
	// health checks work without the public name.
	dnsNames := append([]string{}, cfg.Advertise.DNSNames...)
	if !contains(dnsNames, "localhost") {
		dnsNames = append(dnsNames, "localhost")
	}
	ips := cfg.advertiseIPs()
	ips = append(ips, net.ParseIP("127.0.0.1"), net.ParseIP("::1"))

	type pair struct{ name, certPath, keyPath, kind string }
	for _, p := range []pair{
		{cfg.ClusterName, cfg.controllerCertPath(), cfg.controllerKeyPath(), ca.KindController},
		{cfg.ClusterName, cfg.relayCertPath(), cfg.relayKeyPath(), ca.KindRelay},
	} {
		cert, key, err := caInst.IssueServerKeypair(ca.Profile{
			Kind:     p.kind,
			Name:     p.name,
			TTL:      serverCertTTL,
			DNSNames: dnsNames,
			IPs:      ips,
		})
		if err != nil {
			return fmt.Errorf("issue %s keypair: %w", p.kind, err)
		}
		if err := os.WriteFile(p.certPath, cert, 0o644); err != nil {
			return err
		}
		if err := os.WriteFile(p.keyPath, key, 0o600); err != nil {
			return err
		}
	}

	cc := buildClusterConfig(1, caInst.RootsPEM, keyID, pub, cfg, synthesizeRelays(cfg), nil, nil)
	signed, err := signClusterConfig(cc, priv, keyID)
	if err != nil {
		return fmt.Errorf("sign cluster config: %w", err)
	}
	store, err := OpenStoreFor(cfg)
	if err != nil {
		return err
	}
	defer store.Close()
	if err := store.SetSignedClusterConfig(1, signed); err != nil {
		return err
	}
	return nil
}

// ReissueServerCerts re-issues the controller and relay TLS server keypairs from
// the current advertise config (DNS names + IPs) using the EXISTING CA, without
// touching the CA, grant key, or state. Used to add a public hostname/IP SAN to
// an already-initialized controller (e.g. when exposing it for self-hosting).
func ReissueServerCerts(cfg *Config) error {
	caInst, err := ca.Load(cfg.CADir())
	if err != nil {
		return fmt.Errorf("load CA: %w", err)
	}
	dnsNames := append([]string{}, cfg.Advertise.DNSNames...)
	if !contains(dnsNames, "localhost") {
		dnsNames = append(dnsNames, "localhost")
	}
	ips := cfg.advertiseIPs()
	ips = append(ips, net.ParseIP("127.0.0.1"), net.ParseIP("::1"))

	type pair struct{ certPath, keyPath, kind string }
	for _, p := range []pair{
		{cfg.controllerCertPath(), cfg.controllerKeyPath(), ca.KindController},
		{cfg.relayCertPath(), cfg.relayKeyPath(), ca.KindRelay},
	} {
		cert, key, err := caInst.IssueServerKeypair(ca.Profile{
			Kind: p.kind, Name: cfg.ClusterName, TTL: serverCertTTL,
			DNSNames: dnsNames, IPs: ips,
		})
		if err != nil {
			return fmt.Errorf("issue %s keypair: %w", p.kind, err)
		}
		if err := os.WriteFile(p.certPath, cert, 0o644); err != nil {
			return err
		}
		if err := os.WriteFile(p.keyPath, key, 0o600); err != nil {
			return err
		}
	}
	return nil
}

func contains(list []string, s string) bool {
	for _, v := range list {
		if v == s {
			return true
		}
	}
	return false
}

// IssueRelayCert mints a per-relay TLS server keypair whose Geneza identity
// Name is the operator-chosen relay id (URI SAN geneza://relay/<name>). A fleet
// relay needs this because the registrar binds the heartbeat's relay_id to the
// caller's certificate Name, so each relay must present a cert named for its own
// id — unlike the genesis relay cert, whose Name is the cluster name. localhost
// and loopback SANs are always added so on-box health checks work.
func IssueRelayCert(cfg *Config, name string, dnsNames []string, ips []net.IP, ttl time.Duration, outDir string) error {
	if name == "" {
		return fmt.Errorf("--name is required")
	}
	caInst, err := ca.Load(cfg.CADir())
	if err != nil {
		return fmt.Errorf("load CA: %w", err)
	}
	dnsNames = append(append([]string{}, dnsNames...), "localhost")
	ips = append(ips, net.ParseIP("127.0.0.1"), net.ParseIP("::1"))
	if ttl == 0 {
		ttl = serverCertTTL
	}
	cert, key, err := caInst.IssueServerKeypair(ca.Profile{
		Kind: ca.KindRelay, Name: name, TTL: ttl, DNSNames: dnsNames, IPs: ips,
	})
	if err != nil {
		return fmt.Errorf("issue relay keypair: %w", err)
	}
	if err := os.MkdirAll(outDir, 0o700); err != nil {
		return err
	}
	writes := []struct {
		name string
		data []byte
		mode os.FileMode
	}{
		{name + ".crt", cert, 0o644},
		{name + ".key", key, 0o600},
		{"ca.pem", caInst.RootsPEM, 0o644},
	}
	for _, w := range writes {
		if err := os.WriteFile(filepath.Join(outDir, w.name), w.data, w.mode); err != nil {
			return err
		}
	}
	return nil
}

// IssueUserCert is the break-glass path: a local admin cert minted straight
// from the CA files, bypassing login (and so working with the daemon down).
// It does not need the grant key — only the CA directory.
func IssueUserCert(cfg *Config, name string, roles []string, ttl time.Duration, outDir string) error {
	if name == "" {
		return fmt.Errorf("--name is required")
	}
	if len(roles) == 0 {
		return fmt.Errorf("--roles is required")
	}
	caInst, err := ca.Load(cfg.CADir())
	if err != nil {
		return fmt.Errorf("load CA: %w", err)
	}
	key, err := ca.GenerateKey()
	if err != nil {
		return err
	}
	csr, err := ca.MakeCSR(key, name)
	if err != nil {
		return err
	}
	certPEM, err := caInst.IssueFromCSR(csr, ca.Profile{
		Kind:   ca.KindUser,
		Name:   name,
		TTL:    ttl,
		Claims: &ca.IdentityClaims{Roles: roles, Provider: "breakglass"},
	})
	if err != nil {
		return err
	}
	keyPEM, err := ca.MarshalKeyPEM(key)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(outDir, 0o700); err != nil {
		return err
	}
	writes := []struct {
		name string
		data []byte
		mode os.FileMode
	}{
		{"user.key", keyPEM, 0o600},
		{"user.crt", certPEM, 0o644},
		{"ca.pem", caInst.RootsPEM, 0o644},
	}
	for _, w := range writes {
		if err := os.WriteFile(filepath.Join(outDir, w.name), w.data, w.mode); err != nil {
			return err
		}
	}
	return nil
}

// FormatRoles normalizes a comma-separated role flag.
func FormatRoles(arg string) []string {
	var out []string
	for _, r := range strings.Split(arg, ",") {
		if r = strings.TrimSpace(r); r != "" {
			out = append(out, r)
		}
	}
	return out
}
