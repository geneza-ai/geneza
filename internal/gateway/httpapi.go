package gateway

import (
	"crypto/ed25519"
	"encoding/json"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"strconv"

	"osie.cloud/geneza/internal/types"
)

// The HTTPS listener is deliberately unauthenticated: it serves only public
// material (CA roots, auth bootstrap hints) and signed artifacts whose trust
// derives from the offline artifact signature, not from who fetched them.

// loadSignedRootKeys reads and decodes the configured root-keys.json (the
// offline-signed TUF-lite trust root). It is read fresh on every call so a file
// swap rotates fleet trust without a restart. Any error (unset, missing,
// unreadable, corrupt) yields nil — the gateway then simply omits the doc and
// agents fall back to their single pinned key; trust is never forged by the
// gateway, so failing open here only foregoes rotation, it cannot weaken trust.
func (s *Server) loadSignedRootKeys() *types.Signed {
	if s.cfg.RootKeysFile == "" {
		return nil
	}
	b, err := os.ReadFile(s.cfg.RootKeysFile)
	if err != nil {
		return nil
	}
	signed, err := types.DecodeSigned(b)
	if err != nil {
		return nil
	}
	return signed
}

// publishTrustSet is the gateway's DEFENSE-IN-DEPTH publish gate — NOT the trust
// boundary (agents verify the full chain against their pinned root before
// installing anything). It accepts a manifest signed by the single pinned
// artifact key OR by any signing key the locally-configured root-keys doc lists,
// so rotating the release-signing key does not break `admin publish`. The
// root-keys payload is read unverified here on purpose: the gateway has no root
// public key (it only serves root-keys), and this gate is a sanity check, not
// the security decision. Empty set = no key configured (publish accepted with a
// metadata-only parse, exactly as before).
func (s *Server) publishTrustSet() map[string]ed25519.PublicKey {
	set := map[string]ed25519.PublicKey{}
	if s.artifactPub != nil {
		set[types.KeyIDFor(s.artifactPub)] = s.artifactPub
	}
	if signed := s.loadSignedRootKeys(); signed != nil {
		var rk types.RootKeys
		if err := json.Unmarshal(signed.Payload, &rk); err == nil {
			if m, err := rk.SigningKeys(); err == nil {
				for id, pub := range m {
					set[id] = pub
				}
			}
		}
	}
	return set
}

func resolveDesired(stable, canary string, canaryNodes []string, nodeID string) string {
	if canary != "" {
		for _, n := range canaryNodes {
			if n == nodeID {
				return canary
			}
		}
	}
	return stable
}

type authConfigOIDC struct {
	Issuer   string `json:"issuer"`
	ClientID string `json:"client_id"`
}

type authConfigResponse struct {
	OIDC         *authConfigOIDC `json:"oidc"`
	LocalEnabled bool            `json:"local_enabled"`
}

func (s *Server) httpHandler() http.Handler {
	mux := http.NewServeMux()

	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		_, _ = w.Write([]byte("ok"))
	})

	mux.HandleFunc("GET /v1/ca-roots", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		_, _ = w.Write(s.ca.RootsPEM)
	})

	mux.HandleFunc("GET /v1/auth-config", func(w http.ResponseWriter, _ *http.Request) {
		resp := authConfigResponse{LocalEnabled: s.identity.localEnabled()}
		if s.cfg.OIDC != nil {
			resp.OIDC = &authConfigOIDC{Issuer: s.cfg.OIDC.Issuer, ClientID: s.cfg.OIDC.ClientID}
		}
		writeJSON(w, resp)
	})

	// Bootstrap reconcile loop: which worker version should this node run,
	// and the signed manifest proving what that version is.
	mux.HandleFunc("GET /v1/updates/desired", func(w http.ResponseWriter, r *http.Request) {
		nodeID := r.URL.Query().Get("node")
		if nodeID == "" {
			http.Error(w, "missing node parameter", http.StatusBadRequest)
			return
		}
		stable, err := s.store.StableVersion()
		if err != nil {
			http.Error(w, "settings unavailable", http.StatusInternalServerError)
			return
		}
		canary, err := s.store.CanaryVersion()
		if err != nil {
			http.Error(w, "settings unavailable", http.StatusInternalServerError)
			return
		}
		canaryNodes, err := s.store.CanaryNodes()
		if err != nil {
			http.Error(w, "settings unavailable", http.StatusInternalServerError)
			return
		}
		desired := resolveDesired(stable, canary, canaryNodes, nodeID)
		if desired == "" {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		// Resolve the artifact for the NODE's own platform, not a hardcoded
		// linux/amd64 — otherwise self-update silently breaks for macOS and
		// linux/arm64 nodes (their reconcile loop 404s forever).
		os, arch := "linux", "amd64"
		if rec, err := s.store.GetNode(nodeID); err == nil {
			if rec.Platform.OS != "" {
				os = rec.Platform.OS
			}
			if rec.Platform.Arch != "" {
				arch = rec.Platform.Arch
			}
		}
		manifestBytes, err := s.store.GetManifest(ManifestKey("geneza-agent", os, arch, desired))
		if err != nil {
			http.Error(w, "no artifact for desired version "+desired+" ("+os+"/"+arch+")", http.StatusNotFound)
			return
		}
		signed, err := types.DecodeSigned(manifestBytes)
		if err != nil {
			http.Error(w, "stored manifest corrupt", http.StatusInternalServerError)
			return
		}
		resp := types.DesiredVersionResponse{Version: desired, SignedManifest: signed}
		// Attach the offline-signed root-keys doc (TUF-lite) when configured, so
		// the agent verifies the manifest against the rotatable signing-key set
		// anchored to its pinned root. Read per-request: a file swap rotates the
		// fleet's trust with no gateway restart. A missing/corrupt file is not
		// fatal — we simply omit it and the agent falls back to its single pinned
		// key (legacy mode); the gateway cannot forge trust either way.
		if rk := s.loadSignedRootKeys(); rk != nil {
			resp.SignedRootKeys = rk
		}
		writeJSON(w, resp)
	})

	// Artifact blobs are public by design: they are signed binaries the
	// bootstrap verifies offline. The strict hash check is also the path
	// sanitizer.
	mux.HandleFunc("GET /v1/artifacts/{sha256}", func(w http.ResponseWriter, r *http.Request) {
		sha := r.PathValue("sha256")
		if !sha256HexRe.MatchString(sha) {
			http.Error(w, "invalid artifact hash", http.StatusBadRequest)
			return
		}
		path := filepath.Join(s.cfg.ArtifactsDir(), sha)
		f, err := os.Open(path)
		if err != nil {
			http.Error(w, "artifact not found", http.StatusNotFound)
			return
		}
		defer f.Close()
		st, err := f.Stat()
		if err != nil {
			http.Error(w, "artifact not readable", http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/octet-stream")
		w.Header().Set("Content-Length", strconv.FormatInt(st.Size(), 10))
		http.ServeContent(w, r, sha, st.ModTime(), f)
	})

	// curl|bash installer (install.sh, root-pubkey, stage-1 binaries).
	s.registerInstallerRoutes(mux)

	return mux
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(v); err != nil {
		slog.Warn("write json response", "err", err)
	}
}
