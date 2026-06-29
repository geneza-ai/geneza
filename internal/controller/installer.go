package controller

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"geneza.io/internal/releasetrust"
)

// The curl|bash installer. Convenience for "stand up a new node", built so
// the convenience never costs security:
//   - the script is served over TLS, but trust does NOT rest on TLS: the script
//     fingerprint-checks the TUF-lite root key it downloads against the --root-fp
//     the operator pasted (printed next to the join token by `tokens new`), so a
//     compromised/MITM controller cannot swap the trust anchor at bootstrap;
//   - the join token gates WHO may enroll (one-time, short-TTL, label-scoped);
//   - the enrolled node lands PENDING (zero authority) until an admin
//     approves it — a leaked token alone yields nothing usable;
//   - the FIRST worker binary is pulled by the bootstrap through the full rooted
//     update chain (the agent copy fetched here is used only to run `enroll`).

// installBinRe allowlists the stage-1 binaries the installer may fetch. The
// name is interpolated into a filesystem path, so it must be strictly bounded.
var installBinRe = regexp.MustCompile(`^geneza-(agent|bootstrap)-(linux|darwin)-(amd64|arm64)$`)

// rootPubkeyPEM is the root public-key PEM the controller serves at /v1/root-pubkey
// and fingerprints into the enroll one-liner. By default it is the key compiled into
// this binary (releasetrust, injected at build) — the controller already carries the
// root it signs releases under, so no file or config is needed. An explicit
// root_pubkey_file overrides it (a private deployment pinning its own root). Nil only
// in an uninjected dev build with no file set.
func (s *Server) rootPubkeyPEM() []byte {
	if s.cfg.RootPubkeyFile != "" {
		b, err := os.ReadFile(s.cfg.RootPubkeyFile)
		if err != nil {
			return nil
		}
		return b
	}
	return releasetrust.RootPubPEM
}

// rootFingerprint is sha256 of the served root public key PEM bytes, formatted
// "sha256:<hex>". Empty when this build pins no root and none is configured. The
// installer recomputes the same hash over the bytes it downloads and compares.
func (s *Server) rootFingerprint() string {
	b := s.rootPubkeyPEM()
	if len(b) == 0 {
		return ""
	}
	sum := sha256.Sum256(b)
	return "sha256:" + hex.EncodeToString(sum[:])
}

// stage1SHA256 returns "sha256:<hex>" of a served stage-1 binary (e.g.
// "geneza-bootstrap-linux-amd64"), or "" if InstallDir is unset / the file is
// missing. The OpenStack vendordata path pins these into the cloud-init so
// install.sh verifies the binaries before exec. Because that cloud-init travels
// over the controller's TLS listener, the pin arrives authenticated rather than
// over an unsigned channel.
func (s *Server) stage1SHA256(name string) string {
	if s.cfg.InstallDir == "" || !installBinRe.MatchString(name) {
		return ""
	}
	b, err := os.ReadFile(filepath.Join(s.cfg.InstallDir, name))
	if err != nil {
		return ""
	}
	sum := sha256.Sum256(b)
	return "sha256:" + hex.EncodeToString(sum[:])
}

// registerInstallerRoutes wires the installer endpoints onto the public HTTP mux
// (same listener as artifacts/desired — everything here is public material whose
// trust derives from the fingerprint + token + signed update chain, not the
// channel). All are no-ops behavior-wise when InstallDir/RootPubkeyFile is unset.
func (s *Server) registerInstallerRoutes(mux *http.ServeMux) {
	mux.HandleFunc("GET /install.sh", func(w http.ResponseWriter, r *http.Request) {
		if s.cfg.InstallDir == "" {
			http.Error(w, "installer not enabled on this controller", http.StatusNotFound)
			return
		}
		// The HTTP base the operator reached us on becomes the script's default
		// controller, so the one-liner works verbatim whether internal or public.
		base := externalBase(r)
		w.Header().Set("Content-Type", "text/x-shellscript; charset=utf-8")
		_, _ = w.Write([]byte(strings.ReplaceAll(installScript, "__CONTROLLER_HTTP__", base)))
	})

	mux.HandleFunc("GET /v1/root-pubkey", func(w http.ResponseWriter, _ *http.Request) {
		b := s.rootPubkeyPEM()
		if len(b) == 0 {
			http.Error(w, "no root pubkey configured", http.StatusNotFound)
			return
		}
		w.Header().Set("Content-Type", "application/x-pem-file")
		_, _ = w.Write(b)
	})

	mux.HandleFunc("GET /v1/install/bin/{name}", func(w http.ResponseWriter, r *http.Request) {
		if s.cfg.InstallDir == "" {
			http.Error(w, "installer not enabled", http.StatusNotFound)
			return
		}
		name := r.PathValue("name")
		if !installBinRe.MatchString(name) {
			http.Error(w, "unknown install binary", http.StatusBadRequest)
			return
		}
		path := filepath.Join(s.cfg.InstallDir, name)
		f, err := os.Open(path)
		if err != nil {
			http.Error(w, "binary not found (controller install_dir not populated for this platform)", http.StatusNotFound)
			return
		}
		defer f.Close()
		var mod time.Time
		if st, err := f.Stat(); err == nil {
			mod = st.ModTime()
		}
		w.Header().Set("Content-Type", "application/octet-stream")
		http.ServeContent(w, r, name, mod, f)
	})
}

// externalBase reconstructs scheme://host as the client reached it. The controller
// HTTPS listener terminates TLS itself in the lab; behind a proxy the standard
// X-Forwarded-* headers win so the printed one-liner uses the public origin.
func externalBase(r *http.Request) string {
	scheme := "https"
	if xf := r.Header.Get("X-Forwarded-Proto"); xf != "" {
		scheme = xf
	} else if r.TLS == nil {
		scheme = "http"
	}
	host := r.Host
	if xh := r.Header.Get("X-Forwarded-Host"); xh != "" {
		host = xh
	}
	return fmt.Sprintf("%s://%s", scheme, host)
}
