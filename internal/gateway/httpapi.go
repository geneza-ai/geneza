package gateway

import (
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
		manifestBytes, err := s.store.GetManifest(ManifestKey("geneza-agent", "linux", "amd64", desired))
		if err != nil {
			http.Error(w, "no artifact for desired version "+desired, http.StatusNotFound)
			return
		}
		signed, err := types.DecodeSigned(manifestBytes)
		if err != nil {
			http.Error(w, "stored manifest corrupt", http.StatusInternalServerError)
			return
		}
		writeJSON(w, types.DesiredVersionResponse{Version: desired, SignedManifest: signed})
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

	return mux
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(v); err != nil {
		slog.Warn("write json response", "err", err)
	}
}
