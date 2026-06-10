package agentd

import (
	"crypto/ecdsa"
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

	"github.com/flynn/noise"

	"osie.cloud/geneza/internal/ca"
	"osie.cloud/geneza/internal/types"
)

// State-dir file names. node-id is written last during enrollment and acts
// as the "enrolled" marker.
const (
	fileNodeKey       = "node.key"
	fileNodeCert      = "node.crt"
	fileCARoots       = "ca-roots.pem"
	fileNoise         = "noise.json"
	fileNodeID        = "node-id"
	fileClusterConfig = "cluster-config.json"
	fileGatewayAddr   = "gateway-addr"
)

// State is the agent's persisted identity, loaded from the state dir. The
// trust root after enrollment is the grant-key set inside ClusterRaw; the
// directory itself is protected by file permissions (0700/0600).
type State struct {
	Dir         string
	NodeID      string
	Key         *ecdsa.PrivateKey
	NodeCertPEM []byte
	CARootsPEM  []byte
	Noise       noise.DHKey
	ClusterRaw  []byte // types.Signed envelope bytes
	GatewayAddr string // recorded at enroll time; config may override
}

type noiseFile struct {
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

// LoadState loads and sanity-checks all enrollment artifacts. The persisted
// cluster config is re-verified against its own embedded grant keys: that is
// only an integrity check (trust comes from the verified write path), but it
// catches corruption before anything is trusted.
func LoadState(dir string) (*State, error) {
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

	keyPEM, err := os.ReadFile(filepath.Join(dir, fileNodeKey))
	if err != nil {
		return nil, err
	}
	st.Key, err = ca.ParseKeyPEM(keyPEM)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", fileNodeKey, err)
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

	st.ClusterRaw, err = os.ReadFile(filepath.Join(dir, fileClusterConfig))
	if err != nil {
		return nil, err
	}
	if _, _, err := parseAndCheckClusterConfig(st.ClusterRaw, 0); err != nil {
		return nil, fmt.Errorf("persisted cluster config: %w", err)
	}

	if b, err := os.ReadFile(filepath.Join(dir, fileGatewayAddr)); err == nil {
		st.GatewayAddr = strings.TrimSpace(string(b))
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
	keys, err := unverified.TrustedKeys()
	if err != nil {
		return nil, nil, err
	}
	cfg, err := types.VerifyClusterConfig(keys, env, minVersion)
	if err != nil {
		return nil, nil, err
	}
	return cfg, keys, nil
}

// TLSCertificate assembles the node's client certificate for mTLS.
func (s *State) TLSCertificate() (tls.Certificate, error) {
	keyPEM, err := ca.MarshalKeyPEM(s.Key)
	if err != nil {
		return tls.Certificate{}, err
	}
	return tls.X509KeyPair(s.NodeCertPEM, keyPEM)
}

// LeafCert parses the first certificate in node.crt (the leaf).
func (s *State) LeafCert() (*x509.Certificate, error) {
	blk, _ := pem.Decode(s.NodeCertPEM)
	if blk == nil {
		return nil, errors.New("node.crt: no PEM block")
	}
	return x509.ParseCertificate(blk.Bytes)
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
