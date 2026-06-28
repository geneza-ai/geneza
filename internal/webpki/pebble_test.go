//go:build pebble

// This battle-test drives the real ACME DNS-01 flow against a local pebble (a
// miniature ACME CA) + pebble-challtestsrv (a mock authoritative DNS with a
// management API). It proves the shipped issuance path — lego ordering, the
// DNS-01 challenge, TXT publish, validation, and certificate retrieval — that
// the unit tests can only stub. It is gated behind the `pebble` build tag and
// needs the pebble + pebble-challtestsrv binaries on GOPATH/bin:
//
//	go install github.com/letsencrypt/pebble/v2/cmd/pebble@latest
//	go install github.com/letsencrypt/pebble/v2/cmd/pebble-challtestsrv@latest
//	go test -tags pebble -run TestPebbleIssuance -v ./internal/webpki/
package webpki

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/go-acme/lego/v4/challenge/dns01"
)

// challtestsrvProvider solves DNS-01 by setting/clearing TXT records through
// pebble-challtestsrv's management API.
type challtestsrvProvider struct{ mgmt string }

func (p *challtestsrvProvider) Present(domain, token, keyAuth string) error {
	info := dns01.GetChallengeInfo(domain, keyAuth)
	return p.post("/set-txt", map[string]string{"host": info.FQDN, "value": info.Value})
}

func (p *challtestsrvProvider) CleanUp(domain, token, keyAuth string) error {
	info := dns01.GetChallengeInfo(domain, keyAuth)
	return p.post("/clear-txt", map[string]string{"host": info.FQDN})
}

func (p *challtestsrvProvider) post(path string, body map[string]string) error {
	b, _ := json.Marshal(body)
	resp, err := http.Post(p.mgmt+path, "application/json", bytes.NewReader(b))
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("challtestsrv %s: %s", path, resp.Status)
	}
	return nil
}

func gopathBin(t *testing.T, name string) string {
	t.Helper()
	out, err := exec.Command("go", "env", "GOPATH").Output()
	if err != nil {
		t.Fatalf("go env GOPATH: %v", err)
	}
	p := filepath.Join(strings.TrimSpace(string(out)), "bin", name)
	if _, err := os.Stat(p); err != nil {
		t.Skipf("%s not installed (%v); go install it to run this test", name, err)
	}
	return p
}

func startProc(t *testing.T, env []string, name string, args ...string) {
	t.Helper()
	cmd := exec.Command(name, args...)
	cmd.Env = append(os.Environ(), env...)
	var buf bytes.Buffer
	cmd.Stdout, cmd.Stderr = &buf, &buf
	if err := cmd.Start(); err != nil {
		t.Fatalf("start %s: %v", name, err)
	}
	t.Cleanup(func() {
		_ = cmd.Process.Kill()
		_, _ = cmd.Process.Wait()
		if t.Failed() {
			t.Logf("%s output:\n%s", filepath.Base(name), buf.String())
		}
	})
}

// pebbleFrontCert mints the self-signed cert pebble serves its ACME API with,
// plus a RootCAs pool trusting it so the lego client can connect.
func pebbleFrontCert(t *testing.T, dir string) *x509.CertPool {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "pebble"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		IPAddresses:           []net.IP{net.ParseIP("127.0.0.1")},
		DNSNames:              []string{"localhost"},
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyDER, _ := x509.MarshalPKCS8PrivateKey(key)
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})
	if err := os.WriteFile(filepath.Join(dir, "cert.pem"), certPEM, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "key.pem"), keyPEM, 0o600); err != nil {
		t.Fatal(err)
	}
	pool := x509.NewCertPool()
	pool.AppendCertsFromPEM(certPEM)
	return pool
}

func TestPebbleIssuance(t *testing.T) {
	pebble := gopathBin(t, "pebble")
	challtestsrv := gopathBin(t, "pebble-challtestsrv")
	dir := t.TempDir()
	pool := pebbleFrontCert(t, dir)

	cfg := `{"pebble":{"listenAddress":"127.0.0.1:14000","managementListenAddress":"127.0.0.1:15000",` +
		`"certificate":"` + filepath.Join(dir, "cert.pem") + `","privateKey":"` + filepath.Join(dir, "key.pem") + `",` +
		`"httpPort":5002,"tlsPort":5001,"ocspResponderURL":""}}`
	cfgPath := filepath.Join(dir, "pebble.json")
	if err := os.WriteFile(cfgPath, []byte(cfg), 0o600); err != nil {
		t.Fatal(err)
	}

	// challtestsrv: only DNS (:8053) + management (:8055); pebble resolves DNS-01
	// against it and we publish the TXT through its management API.
	startProc(t, nil, challtestsrv,
		"-dnsserver", ":8053", "-management", ":8055",
		"-http01", "", "-https01", "", "-tlsalpn01", "", "-doh", "")
	// pebble: deterministic (no random nonce rejects), no artificial VA delay.
	startProc(t, []string{"PEBBLE_VA_NOSLEEP=1", "PEBBLE_WFE_NONCEREJECT=0"},
		pebble, "-config", cfgPath, "-dnsserver", "127.0.0.1:8053")

	client := &http.Client{
		Timeout:   30 * time.Second,
		Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: pool}},
	}
	const dirURL = "https://127.0.0.1:14000/dir"
	waitReachable(t, client, dirURL)

	key, err := GenerateAccountKey()
	if err != nil {
		t.Fatal(err)
	}
	acct := Account{
		Email:         "ops@example.test",
		DirectoryURL:  dirURL,
		AccountKeyPEM: key,
		httpClient:    client,
	}
	// Point lego's DNS-01 self-check at challtestsrv (where we publish the TXT)
	// and relax propagation gating, since the record lives only in the mock DNS.
	iss, err := newWithProvider(acct, &challtestsrvProvider{mgmt: "http://127.0.0.1:8055"},
		dns01.AddRecursiveNameservers([]string{"127.0.0.1:8053"}),
		dns01.DisableCompletePropagationRequirement())
	if err != nil {
		t.Fatalf("issuer: %v", err)
	}

	names := []string{"*.acme.example.test", "acme.example.test"}
	cert, err := iss.Issue(context.Background(), names)
	if err != nil {
		t.Fatalf("issue: %v", err)
	}

	// The returned bundle is a real, parseable wildcard cert covering our names.
	blk, _ := pem.Decode(cert.ChainPEM)
	if blk == nil {
		t.Fatal("no PEM in chain")
	}
	leaf, err := x509.ParseCertificate(blk.Bytes)
	if err != nil {
		t.Fatalf("parse leaf: %v", err)
	}
	if !contains(leaf.DNSNames, "*.acme.example.test") {
		t.Fatalf("leaf SANs %v missing the wildcard", leaf.DNSNames)
	}
	if !cert.NotAfter.After(time.Now()) {
		t.Fatalf("cert already expired: %v", cert.NotAfter)
	}
	if len(cert.KeyPEM) == 0 {
		t.Fatal("no private key returned")
	}
	t.Logf("issued %v valid until %s", leaf.DNSNames, cert.NotAfter.Format(time.RFC3339))
}

func waitReachable(t *testing.T, client *http.Client, url string) {
	t.Helper()
	deadline := time.Now().Add(15 * time.Second)
	for time.Now().Before(deadline) {
		resp, err := client.Get(url)
		if err == nil {
			resp.Body.Close()
			if resp.StatusCode == http.StatusOK {
				return
			}
		}
		time.Sleep(200 * time.Millisecond)
	}
	t.Fatalf("pebble directory never came up at %s", url)
}

func contains(ss []string, s string) bool {
	for _, x := range ss {
		if x == s {
			return true
		}
	}
	return false
}
