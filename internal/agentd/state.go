package agentd

import (
	"crypto"
	"crypto/ed25519"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/flynn/noise"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"

	"geneza.io/internal/ca"
	"geneza.io/internal/keysource"
	"geneza.io/internal/types"
)

// State-dir file names. node-id is written last during enrollment and acts
// as the "enrolled" marker.
const (
	fileNodeKey       = "node.key"
	fileNodeCert      = "node.crt"
	fileCARoots       = "ca-roots.pem"
	fileNoise         = "noise.json"
	fileWG            = "wg.json"
	fileNodeID        = "node-id"
	fileClusterConfig = "cluster-config.json"
	fileControllerAddr   = "controller-addr"
	// Split-mode trust documents (absent on a legacy/un-split enrollment): the
	// offline/threshold-signed trust anchors and the grant-key-signed routine map.
	// Their presence in the state dir is what makes the node a "pinned" split node on
	// reload — it re-derives its pinned trust set from the held anchors.
	fileTrustAnchors = "trust-anchors.json"
	fileRoutineMap   = "routine-map.json"
)

// State is the agent's persisted identity, loaded from the state dir. The
// trust root after enrollment is the grant-key set inside ClusterRaw; the
// directory itself is protected by file permissions (0700/0600).
type State struct {
	Dir    string
	NodeID string
	// Key is the node identity signer. With the file backend it is the on-disk
	// ECDSA private key (an *ecdsa.PrivateKey, which satisfies crypto.Signer); with
	// a pkcs11 backend it is a token-bound signer whose private bytes never enter
	// the process. It signs the mTLS client handshake and recording manifests.
	Key         crypto.Signer
	NodeCertPEM []byte
	CARootsPEM  []byte
	Noise       noise.DHKey
	WGPriv      wgtypes.Key // WireGuard data-plane static private key
	HasWG       bool        // false for agents enrolled before the data plane
	ClusterRaw  []byte      // types.Signed envelope bytes (legacy ClusterConfig)
	ControllerAddr string      // recorded at enroll time; config may override
	// Split-mode held documents: nil on a legacy node. AnchorRaw is the MultiSigned
	// trust-anchor envelope (its TrustKeys/Threshold are the node's pinned trust root);
	// RoutineMapRaw is the Signed RoutineMap bound to it. Persisted alongside ClusterRaw
	// so a restart re-pins from the held anchors, never from the channel.
	AnchorRaw     []byte
	RoutineMapRaw []byte
}

// SplitMode reports whether the node holds split trust documents (an anchor and a
// routine map). A legacy node holds neither and stays on the legacy verify path.
func (s *State) SplitMode() bool {
	return len(s.AnchorRaw) > 0 && len(s.RoutineMapRaw) > 0
}

type noiseFile struct {
	Priv string `json:"priv"`
	Pub  string `json:"pub"`
}

// wgFile persists the agent's dedicated WireGuard static keypair (hex). The
// public key is redundant (derivable from priv) but stored for symmetry with
// noise.json and easy inspection.
type wgFile struct {
	Priv string `json:"priv"`
	Pub  string `json:"pub"`
}

// atomicWrite writes via temp-file + rename so readers never see a torn file
// and a crash never leaves a half-written credential.
func atomicWrite(path string, data []byte, mode os.FileMode) error {
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, "."+filepath.Base(path)+".tmp-*")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName) // no-op after successful rename
	if err := tmp.Chmod(mode); err != nil {
		tmp.Close()
		return err
	}
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmpName, path)
}

// Enrolled reports whether the state dir contains a completed enrollment.
func Enrolled(dir string) bool {
	_, err := os.Stat(filepath.Join(dir, fileNodeID))
	return err == nil
}

// LoadState loads and sanity-checks all enrollment artifacts. The node key is
// resolved through keySrc: the default (empty/file) Spec reads node.key under
// dir, while a pkcs11 Spec binds the signer to a token. The persisted cluster
// config is re-verified against its own embedded grant keys: that is only an
// integrity check (trust comes from the verified write path), but it catches
// corruption before anything is trusted.
func LoadState(dir string, keySrc keysource.Spec) (*State, error) {
	st := &State{Dir: dir}

	id, err := os.ReadFile(filepath.Join(dir, fileNodeID))
	if err != nil {
		return nil, fmt.Errorf("agent is not enrolled (missing %s): run 'geneza-agent enroll' first: %w",
			filepath.Join(dir, fileNodeID), err)
	}
	st.NodeID = strings.TrimSpace(string(id))
	if st.NodeID == "" {
		return nil, errors.New("empty node-id in state dir")
	}

	if keySrc.Backend == "" || keySrc.Backend == keysource.BackendFile {
		if keySrc.Path == "" {
			keySrc.Path = filepath.Join(dir, fileNodeKey)
		}
	}
	st.Key, err = keysource.Open(keySrc)
	if err != nil {
		return nil, fmt.Errorf("node key source: %w", err)
	}

	st.NodeCertPEM, err = os.ReadFile(filepath.Join(dir, fileNodeCert))
	if err != nil {
		return nil, err
	}
	st.CARootsPEM, err = os.ReadFile(filepath.Join(dir, fileCARoots))
	if err != nil {
		return nil, err
	}

	nb, err := os.ReadFile(filepath.Join(dir, fileNoise))
	if err != nil {
		return nil, err
	}
	var nf noiseFile
	if err := json.Unmarshal(nb, &nf); err != nil {
		return nil, fmt.Errorf("%s: %w", fileNoise, err)
	}
	st.Noise.Private, err = hex.DecodeString(nf.Priv)
	if err != nil {
		return nil, fmt.Errorf("%s: bad priv hex: %w", fileNoise, err)
	}
	st.Noise.Public, err = hex.DecodeString(nf.Pub)
	if err != nil {
		return nil, fmt.Errorf("%s: bad pub hex: %w", fileNoise, err)
	}
	if len(st.Noise.Private) != 32 || len(st.Noise.Public) != 32 {
		return nil, fmt.Errorf("%s: keys must be 32 bytes", fileNoise)
	}

	// WireGuard data-plane key is optional: agents enrolled before the data plane
	// have no wg.json and simply run without overlay interfaces.
	if wb, err := os.ReadFile(filepath.Join(dir, fileWG)); err == nil {
		var wf wgFile
		if err := json.Unmarshal(wb, &wf); err != nil {
			return nil, fmt.Errorf("%s: %w", fileWG, err)
		}
		key, err := wgtypes.ParseKey(wf.Priv)
		if err != nil {
			return nil, fmt.Errorf("%s: bad priv key: %w", fileWG, err)
		}
		st.WGPriv = key
		st.HasWG = true
	}

	// The legacy cluster config is mandatory unless the node holds the split pair: a
	// require-split fleet may have dropped the legacy fallback, in which case the node
	// runs purely off the anchor + routine map below. A node with neither is unenrolled.
	if b, cerr := os.ReadFile(filepath.Join(dir, fileClusterConfig)); cerr == nil {
		st.ClusterRaw = b
		if _, _, perr := parseAndCheckClusterConfig(st.ClusterRaw, 0); perr != nil {
			return nil, fmt.Errorf("persisted cluster config: %w", perr)
		}
	} else if _, serr := os.Stat(filepath.Join(dir, fileTrustAnchors)); serr != nil {
		return nil, cerr // no legacy config AND no split anchor: incomplete state
	}

	// Split-mode documents are optional: a legacy node has neither. When present, both
	// must be present and must self-verify (the anchors against their OWN pinned trust
	// keys, the routine map bound to them) — an integrity check on reload, mirroring the
	// cluster-config self-check; trust comes from the verified write path, this only
	// catches a corrupt or half-written pair before anything is trusted.
	if b, rerr := os.ReadFile(filepath.Join(dir, fileTrustAnchors)); rerr == nil {
		st.AnchorRaw = b
		rm, merr := os.ReadFile(filepath.Join(dir, fileRoutineMap))
		if merr != nil {
			return nil, fmt.Errorf("held trust anchors without a routine map: %w", merr)
		}
		st.RoutineMapRaw = rm
		if _, cerr := parseAndCheckFleetState(st.AnchorRaw, st.RoutineMapRaw, 0, 0); cerr != nil {
			return nil, fmt.Errorf("persisted fleet state: %w", cerr)
		}
	}

	if b, err := os.ReadFile(filepath.Join(dir, fileControllerAddr)); err == nil {
		st.ControllerAddr = strings.TrimSpace(string(b))
	}
	return st, nil
}

// parseAndCheckClusterConfig decodes a signed cluster-config envelope and
// verifies it against the grant keys embedded in its own payload (internal
// consistency). Callers that already hold a trusted key set must use
// types.VerifyClusterConfig with that set instead — this self-check is only
// valid for the first config (trusted channel) and for reloading local state.
func parseAndCheckClusterConfig(raw []byte, minVersion int64) (*types.ClusterConfig, map[string]ed25519.PublicKey, error) {
	env, err := types.DecodeSigned(raw)
	if err != nil {
		return nil, nil, err
	}
	var unverified types.ClusterConfig
	if err := json.Unmarshal(env.Payload, &unverified); err != nil {
		return nil, nil, fmt.Errorf("cluster config payload: %w", err)
	}
	// Self-check: verify the ENVELOPE against the config's own trust set (its
	// TrustKeys, or its GrantKeys when TrustKeys is absent). Valid only for a
	// pinned config — one delivered over the enrollment channel or reloaded from
	// the trusted state dir; runtime push updates verify against the HELD trust
	// set instead (worker.handleClusterConfig), never the incoming config's own.
	trust, err := unverified.TrustedConfigKeys()
	if err != nil {
		return nil, nil, err
	}
	cfg, err := types.VerifyClusterConfig(trust, env, minVersion)
	if err != nil {
		return nil, nil, err
	}
	// Return the GRANT key set (used to verify session grants), not the trust set.
	grantKeys, err := cfg.TrustedKeys()
	if err != nil {
		return nil, nil, err
	}
	return cfg, grantKeys, nil
}

// parseAndCheckFleetState decodes the split trust-anchor + routine-map pair and
// verifies it against the anchors' OWN pinned trust keys + threshold (internal
// consistency). Like parseAndCheckClusterConfig this self-check is valid only for a
// pinned pair — one delivered over the enrollment channel or reloaded from the trusted
// state dir; a runtime push verifies against the HELD pinned set instead (never the
// incoming document's own). minAnchor/minConfig are the rollback floors (0 on reload).
func parseAndCheckFleetState(anchorRaw, mapRaw []byte, minAnchor, minConfig int64) (*types.FleetState, error) {
	anchorEnv, err := types.DecodeMultiSigned(anchorRaw)
	if err != nil {
		return nil, fmt.Errorf("trust anchors envelope: %w", err)
	}
	var anchors types.TrustAnchors
	if err := json.Unmarshal(anchorEnv.Payload, &anchors); err != nil {
		return nil, fmt.Errorf("trust anchors payload: %w", err)
	}
	pinned, err := anchors.PinnedTrustKeys()
	if err != nil {
		return nil, err
	}
	mapEnv, err := types.DecodeSigned(mapRaw)
	if err != nil {
		return nil, fmt.Errorf("routine map envelope: %w", err)
	}
	// time.Time{} as "now" would trip a non-zero ExpiresAt; use the real clock for the
	// reload integrity check so an expired held anchor surfaces honestly.
	return types.VerifyFleetState(pinned, anchors.Threshold, minAnchor, minConfig, anchorEnv, mapEnv, time.Now())
}

// TLSCertificate assembles the node's client certificate for mTLS. The private
// key is the node Signer: a file-backed *ecdsa.PrivateKey or a token-bound
// signer (the Go TLS stack signs the handshake via crypto.Signer either way, so
// a pkcs11 node key never exposes its private bytes to the process).
func (s *State) TLSCertificate() (tls.Certificate, error) {
	var chain [][]byte
	rest := s.NodeCertPEM
	for {
		var blk *pem.Block
		blk, rest = pem.Decode(rest)
		if blk == nil {
			break
		}
		if blk.Type == "CERTIFICATE" {
			chain = append(chain, blk.Bytes)
		}
	}
	if len(chain) == 0 {
		return tls.Certificate{}, errors.New("node.crt: no certificate PEM block")
	}
	leaf, err := x509.ParseCertificate(chain[0])
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("node.crt leaf: %w", err)
	}
	// Guard against a key/cert mismatch (the same safety check tls.X509KeyPair
	// makes): the signer's public key must match the leaf certificate.
	if signerPub, ok := s.Key.Public().(interface{ Equal(crypto.PublicKey) bool }); ok {
		if !signerPub.Equal(leaf.PublicKey) {
			return tls.Certificate{}, errors.New("node key does not match node.crt public key")
		}
	}
	return tls.Certificate{Certificate: chain, PrivateKey: s.Key, Leaf: leaf}, nil
}

// LeafCert parses the first certificate in node.crt (the leaf).
func (s *State) LeafCert() (*x509.Certificate, error) {
	blk, _ := pem.Decode(s.NodeCertPEM)
	if blk == nil {
		return nil, errors.New("node.crt: no PEM block")
	}
	return x509.ParseCertificate(blk.Bytes)
}

// Workspace returns the agent's enrolled workspace, derived from its OWN node
// cert URI (geneza://node/<ws>/<name>; legacy 2-segment => "default"). This is
// the never-client-supplied source the scoped-grant floor enforces a grant's
// WorkspaceID against. Empty on a parse error (the floor then degrades to the
// key-scope check only).
func (s *State) Workspace() string {
	leaf, err := s.LeafCert()
	if err != nil {
		return ""
	}
	id, err := ca.PeerIdentity(leaf)
	if err != nil {
		return ""
	}
	return id.Workspace
}

func (s *State) SaveNodeCert(certPEM []byte) error {
	if err := atomicWrite(filepath.Join(s.Dir, fileNodeCert), certPEM, 0o600); err != nil {
		return err
	}
	s.NodeCertPEM = certPEM
	return nil
}

func (s *State) SaveCARoots(rootsPEM []byte) error {
	if len(rootsPEM) == 0 {
		return nil // never clobber the trust bundle with nothing
	}
	if err := atomicWrite(filepath.Join(s.Dir, fileCARoots), rootsPEM, 0o600); err != nil {
		return err
	}
	s.CARootsPEM = rootsPEM
	return nil
}

func (s *State) SaveClusterConfig(raw []byte) error {
	if err := atomicWrite(filepath.Join(s.Dir, fileClusterConfig), raw, 0o600); err != nil {
		return err
	}
	s.ClusterRaw = raw
	return nil
}

// SaveFleetState persists the verified split trust-anchor + routine-map pair. The
// anchor is written first so a crash between the two writes leaves an anchor without a
// map (caught on reload) rather than a map with no anchor to bind it. Caller passes the
// EXACT verified envelope bytes, so the held documents are the ones a node re-pins from.
func (s *State) SaveFleetState(anchorRaw, mapRaw []byte) error {
	if err := atomicWrite(filepath.Join(s.Dir, fileTrustAnchors), anchorRaw, 0o600); err != nil {
		return err
	}
	if err := atomicWrite(filepath.Join(s.Dir, fileRoutineMap), mapRaw, 0o600); err != nil {
		return err
	}
	s.AnchorRaw = anchorRaw
	s.RoutineMapRaw = mapRaw
	return nil
}
