package agentd

import (
	"context"
	"crypto"
	"crypto/ecdsa"
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

	"geneza.io/internal/agentd/platform"
	"geneza.io/internal/ca"
	"geneza.io/internal/defaults"
	"geneza.io/internal/keysource"
	genezav1 "geneza.io/internal/pb/geneza/v1"
	"geneza.io/internal/tunnel"
	"geneza.io/internal/types"
	"geneza.io/internal/version"
)

// EnrollOptions are the flag overrides for 'geneza-agent enroll'.
type EnrollOptions struct {
	Provider string // "token" (default) | "openstack-metadata" (PoC seam)
	Token    string
	Controller  string // host:port; overrides config controller_grpc_addr
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
	controller := opts.Controller
	if controller == "" {
		controller = cfg.ControllerGRPCAddr
	}
	if controller == "" {
		return errors.New("controller address required (--controller or controller_grpc_addr in config)")
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

	rootsPEM, err := obtainCARoots(ctx, log, cfg, controller)
	if err != nil {
		return err
	}
	rootPool, err := ca.PoolFromPEM(rootsPEM)
	if err != nil {
		return fmt.Errorf("CA roots bundle: %w", err)
	}

	// Fresh identity material. The node signer is either a freshly generated
	// in-memory ECDSA key (file backend, persisted below) or a token-resident
	// signer found by label (pkcs11 backend) whose private bytes never enter this
	// process. The CSR is built from the signer either way.
	nodeSigner, fileKey, err := newNodeSigner(cfg)
	if err != nil {
		return err
	}
	csrPEM, err := ca.MakeCSR(nodeSigner, name)
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
	conn, err := grpc.NewClient(controller, grpc.WithTransportCredentials(creds))
	if err != nil {
		return fmt.Errorf("dial controller %s: %w", controller, err)
	}
	defer conn.Close()

	hostname, _ := os.Hostname()
	plat := platform.Detect()
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
			Os:            runtime.GOOS,
			Arch:          runtime.GOARCH,
			Hostname:      hostname,
			AgentVersion:  version.Version,
			Distro:        plat.Distro,
			DistroVersion: plat.Version,
			OsPretty:      plat.Pretty,
			HostUuid:      hostUUID(),
		},
	})
	if err != nil {
		return fmt.Errorf("enroll: %w", err)
	}
	splitAnchors, splitMap := resp.GetTrustAnchors(), resp.GetRoutineMap()
	hasLegacy := len(resp.SignedClusterConfig) > 0
	hasSplit := len(splitAnchors) > 0 && len(splitMap) > 0
	if resp.NodeId == "" || len(resp.NodeCertPem) == 0 || (!hasLegacy && !hasSplit) {
		return errors.New("enroll: controller returned incomplete response")
	}

	// The first config is trusted via this (CA-verified) channel; its keys become the
	// node's trust root from now on. Verify whatever was delivered against its own keys
	// before persisting anything: the legacy config (when present) against its grant/
	// trust keys, and — when the controller delivered the trust-anchor + routine-map pair —
	// the split pair against the anchors' own pinned trust keys (TOFU over this mTLS
	// channel). A require-split fleet may send only the split pair; an un-split cluster
	// sends only the legacy config, leaving enrollment byte-for-byte unchanged.
	var clusterCfg *types.ClusterConfig
	if hasLegacy {
		cc, _, cerr := parseAndCheckClusterConfig(resp.SignedClusterConfig, 0)
		if cerr != nil {
			return fmt.Errorf("enroll: signed cluster config rejected: %w", cerr)
		}
		clusterCfg = cc
	}
	switch {
	case hasSplit:
		if _, ferr := parseAndCheckFleetState(splitAnchors, splitMap, 0, 0); ferr != nil {
			return fmt.Errorf("enroll: split fleet state rejected: %w", ferr)
		}
	case len(splitAnchors) > 0 || len(splitMap) > 0:
		return errors.New("enroll: controller returned a partial split fleet state")
	}

	finalRoots := resp.CaRootsPem
	if len(finalRoots) == 0 {
		finalRoots = rootsPEM // fall back to the bundle that verified the controller
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
		{fileNodeCert, resp.NodeCertPem, 0o600},
		{fileNoise, noiseJSON, 0o600},
		{fileWG, wgJSON, 0o600},
		{fileControllerAddr, []byte(controller + "\n"), 0o600},
	}
	// The legacy cluster config is written only when the controller delivered one (a
	// require-split fleet may send only the split pair).
	if hasLegacy {
		writes = append(writes, struct {
			name string
			data []byte
			mode os.FileMode
		}{fileClusterConfig, resp.SignedClusterConfig, 0o600})
	}
	// The split documents are written before the node-id marker (appended last below)
	// so an enrolled node — one whose node-id exists — always has its fleet state on
	// first load, never a half-written enrollment.
	if hasSplit {
		writes = append(writes,
			struct {
				name string
				data []byte
				mode os.FileMode
			}{fileTrustAnchors, splitAnchors, 0o600},
			struct {
				name string
				data []byte
				mode os.FileMode
			}{fileRoutineMap, splitMap, 0o600},
		)
	}
	// node-id is the enrollment marker: written last so its presence means every other
	// artifact is already on disk.
	writes = append(writes, struct {
		name string
		data []byte
		mode os.FileMode
	}{fileNodeID, []byte(resp.NodeId + "\n"), 0o600})
	// The node key is written only for the file backend; with a token backend the
	// private key stays on the token and there is no node.key to persist.
	if fileKey != nil {
		keyPEM, err := ca.MarshalKeyPEM(fileKey)
		if err != nil {
			return err
		}
		writes = append([]struct {
			name string
			data []byte
			mode os.FileMode
		}{{fileNodeKey, keyPEM, 0o600}}, writes...)
	}
	for _, w := range writes {
		if err := atomicWrite(filepath.Join(cfg.StateDir, w.name), w.data, w.mode); err != nil {
			return fmt.Errorf("persist %s: %w", w.name, err)
		}
	}

	configVersion, grantKeys := int64(0), 0
	if clusterCfg != nil {
		configVersion, grantKeys = clusterCfg.ConfigVersion, len(clusterCfg.GrantKeys)
	}
	log.Info("enrolled",
		"node_id", resp.NodeId,
		"name", name,
		"controller", controller,
		"cluster_config_version", configVersion,
		"grant_keys", grantKeys,
		"split", hasSplit,
		"state_dir", cfg.StateDir)
	return nil
}

// newNodeSigner resolves the node identity signer used to build the enrollment
// CSR. With the file backend it generates a fresh in-memory ECDSA P-256 key and
// returns it as fileKey so the caller persists it as node.key (today's behavior,
// byte-for-byte). With the pkcs11 backend it opens the token-resident key found
// by label/id and returns a nil fileKey: the private bytes never enter the
// agent, so the CSR — and later the mTLS handshake and manifest signatures — are
// all produced on the token. The token key is expected to be provisioned ahead of
// enrollment (generate-on-token is a possible future convenience, but finding a
// pre-provisioned key keeps the agent free of token-administration logic).
func newNodeSigner(cfg *Config) (signer crypto.Signer, fileKey *ecdsa.PrivateKey, err error) {
	if cfg.NodeKeySource.usesPKCS11() {
		s, err := keysource.Open(cfg.nodeKeySource())
		if err != nil {
			return nil, nil, fmt.Errorf("node key source: %w", err)
		}
		if _, ok := s.Public().(*ecdsa.PublicKey); !ok {
			return nil, nil, fmt.Errorf("node key source: token key is %T, want an ECDSA key", s.Public())
		}
		return s, nil, nil
	}
	k, err := ca.GenerateKey()
	if err != nil {
		return nil, nil, err
	}
	return k, k, nil
}

// obtainCARoots returns the trust bundle for the controller TLS handshake:
// the pre-placed state_dir/ca-roots.pem if present (the secure path), else a
// TOFU fetch from the controller's HTTPS endpoint with a loudly-logged
// fingerprint so the operator can verify it out of band.
func obtainCARoots(ctx context.Context, log *slog.Logger, cfg *Config, controller string) ([]byte, error) {
	pre := filepath.Join(cfg.StateDir, fileCARoots)
	if b, err := os.ReadFile(pre); err == nil && len(b) > 0 {
		log.Info("using pre-placed CA roots", "path", pre)
		return b, nil
	}

	url := cfg.ControllerHTTPURL
	if url == "" {
		host, _, err := net.SplitHostPort(controller)
		if err != nil {
			host = controller
		}
		url = "https://" + net.JoinHostPort(host, strconv.Itoa(defaults.ControllerHTTPPort))
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
		return nil, errors.New("controller returned empty CA roots bundle")
	}
	sum := sha256.Sum256(b)
	log.Warn("TOFU: fetched CA roots WITHOUT verification — confirm this fingerprint against the controller out of band",
		"url", url,
		"sha256", hex.EncodeToString(sum[:]))
	return b, nil
}
