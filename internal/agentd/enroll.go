package agentd

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"time"

	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"

	"osie.cloud/geneza/internal/ca"
	"osie.cloud/geneza/internal/defaults"
	genezav1 "osie.cloud/geneza/internal/pb/geneza/v1"
	"osie.cloud/geneza/internal/tunnel"
	"osie.cloud/geneza/internal/version"
)

// EnrollOptions are the flag overrides for 'geneza-agent enroll'.
type EnrollOptions struct {
	Provider string // "token" (default) | "openstack-metadata" (PoC seam)
	Token    string
	Gateway  string // host:port; overrides config gateway_grpc_addr
	Name     string
	Labels   map[string]string
	Force    bool
}

// Enroll performs the one-time machine-identity bootstrap: generate node key
// + CSR + Noise static keypair, obtain CA roots (pre-placed file or TOFU
// fetch), call Enrollment.Enroll over TLS without a client cert, verify the
// returned signed cluster config, and persist everything to the state dir.
//
// Nothing is persisted unless every verification step succeeds; node-id is
// written last and is the idempotence marker.
func Enroll(ctx context.Context, log *slog.Logger, cfg *Config, opts EnrollOptions) error {
	provider := opts.Provider
	if provider == "" {
		provider = "token"
	}
	switch provider {
	case "token":
		if opts.Token == "" {
			return errors.New("--token is required for provider=token")
		}
	case "openstack-metadata":
		// The instance authenticates with its own identity document; no token.
		// Server-side this provider is the reserved PoC seam (Unimplemented)
		// until wired — see docs/openstack-integration.md.
	default:
		return fmt.Errorf("unknown enrollment provider %q (token|openstack-metadata)", provider)
	}
	gateway := opts.Gateway
	if gateway == "" {
		gateway = cfg.GatewayGRPCAddr
	}
	if gateway == "" {
		return errors.New("gateway address required (--gateway or gateway_grpc_addr in config)")
	}
	name := opts.Name
	if name == "" {
		name = cfg.Name
	}
	if name == "" {
		name, _ = os.Hostname()
	}
	labels := map[string]string{}
	for k, v := range cfg.Labels {
		labels[k] = v
	}
	for k, v := range opts.Labels {
		labels[k] = v
	}

	if err := os.MkdirAll(cfg.StateDir, 0o700); err != nil {
		return err
	}
	if Enrolled(cfg.StateDir) && !opts.Force {
		return fmt.Errorf("already enrolled (node-id exists in %s); use --force to re-enroll", cfg.StateDir)
	}

	rootsPEM, err := obtainCARoots(ctx, log, cfg, gateway)
	if err != nil {
		return err
	}
	rootPool, err := ca.PoolFromPEM(rootsPEM)
	if err != nil {
		return fmt.Errorf("CA roots bundle: %w", err)
	}

	// Fresh identity material.
	nodeKey, err := ca.GenerateKey()
	if err != nil {
		return err
	}
	csrPEM, err := ca.MakeCSR(nodeKey, name)
	if err != nil {
		return err
	}
	noiseKey, err := tunnel.GenerateKeypair()
	if err != nil {
		return err
	}
	// Dedicated per-node WireGuard data-plane keypair (clamped by wgtypes),
	// distinct from the Noise control/SSH key for clean protocol separation.
	wgKey, err := wgtypes.GeneratePrivateKey()
	if err != nil {
		return fmt.Errorf("generate wireguard key: %w", err)
	}
	wgPub := wgKey.PublicKey()

	// Enrollment uses server-auth TLS only: identity is the one-time token.
	creds := credentials.NewTLS(&tls.Config{RootCAs: rootPool, MinVersion: tls.VersionTLS12})
	conn, err := grpc.NewClient(gateway, grpc.WithTransportCredentials(creds))
	if err != nil {
		return fmt.Errorf("dial gateway %s: %w", gateway, err)
	}
	defer conn.Close()

	hostname, _ := os.Hostname()
	rctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	resp, err := genezav1.NewEnrollmentClient(conn).Enroll(rctx, &genezav1.EnrollRequest{
		Provider:       provider,
		Token:          opts.Token,
		RequestedName:  name,
		CsrPem:         csrPEM,
		NoiseStaticPub: noiseKey.Public,
		WgStaticPub:    wgPub[:],
		Labels:         labels,
		Platform: &genezav1.PlatformInfo{
			Os:           runtime.GOOS,
			Arch:         runtime.GOARCH,
			Hostname:     hostname,
			AgentVersion: version.Version,
		},
	})
	if err != nil {
		return fmt.Errorf("enroll: %w", err)
	}
	if resp.NodeId == "" || len(resp.NodeCertPem) == 0 || len(resp.SignedClusterConfig) == 0 {
		return errors.New("enroll: gateway returned incomplete response")
	}

	// The first cluster config is trusted via this (CA-verified) channel; its
	// grant keys become the offline trust root from now on. Verify the
	// envelope against its own keys before persisting anything.
	clusterCfg, _, err := parseAndCheckClusterConfig(resp.SignedClusterConfig, 0)
	if err != nil {
		return fmt.Errorf("enroll: signed cluster config rejected: %w", err)
	}

	finalRoots := resp.CaRootsPem
	if len(finalRoots) == 0 {
		finalRoots = rootsPEM // fall back to the bundle that verified the gateway
	}
	keyPEM, err := ca.MarshalKeyPEM(nodeKey)
	if err != nil {
		return err
	}
	noiseJSON, err := json.Marshal(noiseFile{
		Priv: hex.EncodeToString(noiseKey.Private),
		Pub:  hex.EncodeToString(noiseKey.Public),
	})
	if err != nil {
		return err
	}
	wgJSON, err := json.Marshal(wgFile{
		Priv: wgKey.String(), // base64 (wgtypes canonical)
		Pub:  wgPub.String(),
	})
	if err != nil {
		return err
	}

	writes := []struct {
		name string
		data []byte
		mode os.FileMode
	}{
		{fileCARoots, finalRoots, 0o600},
		{fileNodeKey, keyPEM, 0o600},
		{fileNodeCert, resp.NodeCertPem, 0o600},
		{fileNoise, noiseJSON, 0o600},
		{fileWG, wgJSON, 0o600},
		{fileClusterConfig, resp.SignedClusterConfig, 0o600},
		{fileGatewayAddr, []byte(gateway + "\n"), 0o600},
		{fileNodeID, []byte(resp.NodeId + "\n"), 0o600}, // last: enrollment marker
	}
	for _, w := range writes {
		if err := atomicWrite(filepath.Join(cfg.StateDir, w.name), w.data, w.mode); err != nil {
			return fmt.Errorf("persist %s: %w", w.name, err)
		}
	}

	log.Info("enrolled",
		"node_id", resp.NodeId,
		"name", name,
		"gateway", gateway,
		"cluster_config_version", clusterCfg.ConfigVersion,
		"grant_keys", len(clusterCfg.GrantKeys),
		"state_dir", cfg.StateDir)
	return nil
}

// obtainCARoots returns the trust bundle for the gateway TLS handshake:
// the pre-placed state_dir/ca-roots.pem if present (the secure path), else a
// TOFU fetch from the gateway's HTTPS endpoint with a loudly-logged
// fingerprint so the operator can verify it out of band.
func obtainCARoots(ctx context.Context, log *slog.Logger, cfg *Config, gateway string) ([]byte, error) {
	pre := filepath.Join(cfg.StateDir, fileCARoots)
	if b, err := os.ReadFile(pre); err == nil && len(b) > 0 {
		log.Info("using pre-placed CA roots", "path", pre)
		return b, nil
	}

	url := cfg.GatewayHTTPURL
	if url == "" {
		host, _, err := net.SplitHostPort(gateway)
		if err != nil {
			host = gateway
		}
		url = "https://" + net.JoinHostPort(host, strconv.Itoa(defaults.GatewayHTTPPort))
	}
	url += "/v1/ca-roots"

	// TOFU: there is no trust anchor yet, so this fetch is deliberately
	// unverified. The fingerprint below is the operator's only check.
	client := &http.Client{
		Timeout: 15 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, // #nosec G402 -- TOFU bootstrap, fingerprint logged
		},
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("fetch CA roots from %s: %w", url, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("fetch CA roots from %s: HTTP %s", url, resp.Status)
	}
	b, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, err
	}
	if len(b) == 0 {
		return nil, errors.New("gateway returned empty CA roots bundle")
	}
	sum := sha256.Sum256(b)
	log.Warn("TOFU: fetched CA roots WITHOUT verification — confirm this fingerprint against the gateway out of band",
		"url", url,
		"sha256", hex.EncodeToString(sum[:]))
	return b, nil
}
