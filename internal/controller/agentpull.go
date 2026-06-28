package controller

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"geneza.io/internal/releasetrust"
	"geneza.io/internal/selfupdate"
)

// nodeArchs are the Linux CPU architectures the controller serves agent binaries
// for. The agent is Linux-only; both arches enroll against one controller, so a
// containerized controller pulls both regardless of its own arch.
var nodeArchs = []string{"amd64", "arm64"}

// startAgentPull keeps InstallDir populated with the signed geneza-node binaries
// from GitHub Releases. It runs one pull on startup and, if a refresh interval
// is configured, re-pulls on a ticker — so the served agent tracks the latest
// signed release independent of the controller's own version. Failures are logged,
// never fatal: the controller keeps serving whatever is already in InstallDir
// (e.g. the binaries baked into its image).
func (s *Server) startAgentPull(ctx context.Context) {
	cfg := s.cfg.AgentRelease
	if !cfg.Pull || s.cfg.InstallDir == "" {
		return
	}
	pull := func() {
		pctx, cancel := context.WithTimeout(ctx, 3*time.Minute)
		defer cancel()
		if err := s.pullNodeBinaries(pctx, s.cfg.InstallDir, cfg.Tag); err != nil {
			slog.Warn("agent-pull failed; serving existing install_dir binaries", "err", err)
		}
	}
	pull()
	refresh := cfg.Refresh.D()
	if refresh <= 0 {
		return
	}
	t := time.NewTicker(refresh)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			pull()
		}
	}
}

// pullNodeBinaries fetches the geneza-node release archives (agent + bootstrap)
// for each Linux arch, verifies them against the release signature chain (the
// controller's pinned root, when present), and writes them into installDir under
// the names the curl|bash installer serves: geneza-{agent,bootstrap}-linux-<arch>.
// tag empty = latest release.
func (s *Server) pullNodeBinaries(ctx context.Context, installDir, tag string) error {
	if installDir == "" {
		return fmt.Errorf("install_dir not set")
	}
	if err := os.MkdirAll(installDir, 0o755); err != nil {
		return fmt.Errorf("mkdir %s: %w", installDir, err)
	}

	dl := selfupdate.NewHTTPClient(2 * time.Minute)
	var (
		rel *selfupdate.Release
		err error
	)
	if tag != "" {
		rel, err = selfupdate.ReleaseByTag(ctx, tag)
	} else {
		rel, err = selfupdate.LatestRelease(ctx)
	}
	if err != nil {
		return fmt.Errorf("fetch release: %w", err)
	}
	// Verify SHA256SUMS (and its offline-signed chain when the controller pins a
	// root) once; every per-arch archive digest is then checked against it. The
	// anti-rollback floor (highest root-keys version served) lives beside the
	// served binaries.
	floorPath := filepath.Join(installDir, ".release-rootkeys-version")
	sums, rkVersion, err := selfupdate.VerifiedSums(ctx, dl, rel, releasetrust.LoadVersionFloor(floorPath))
	if err != nil {
		return fmt.Errorf("verify release %s: %w", rel.TagName, err)
	}

	pulled := 0
	for _, arch := range nodeArchs {
		if err := pullOneArch(ctx, dl, rel, sums, installDir, arch); err != nil {
			slog.Warn("agent-pull: skipping arch", "arch", arch, "release", rel.TagName, "err", err)
			continue
		}
		pulled++
	}
	if pulled == 0 {
		return fmt.Errorf("no node archives pulled from %s", rel.TagName)
	}
	if rkVersion > 0 {
		_ = releasetrust.SaveVersionFloor(floorPath, rkVersion)
	}
	slog.Info("agent-pull: served node binaries", "release", rel.TagName, "arches", pulled, "dir", installDir)
	return nil
}

func pullOneArch(ctx context.Context, dl *http.Client, rel *selfupdate.Release, sums []byte, installDir, arch string) error {
	archive := fmt.Sprintf("geneza-node_linux_%s.tar.gz", arch)
	asset := selfupdate.FindAsset(rel, archive)
	if asset == nil {
		return fmt.Errorf("release has no %s", archive)
	}
	want, err := selfupdate.ExpectedDigest(sums, archive)
	if err != nil {
		return err
	}
	data, err := selfupdate.Fetch(ctx, dl, asset.URL, 256<<20)
	if err != nil {
		return fmt.Errorf("download %s: %w", archive, err)
	}
	if err := selfupdate.VerifyDigest(data, want, archive); err != nil {
		return err
	}
	// Extract both binaries before writing either, so a partial archive doesn't
	// leave a mismatched agent/bootstrap pair in InstallDir.
	out := map[string][]byte{}
	for _, bin := range []string{"geneza-agent", "geneza-bootstrap"} {
		inner := fmt.Sprintf("geneza-node_linux_%s/%s", arch, bin)
		b, err := selfupdate.ExtractTarGzFile(data, inner)
		if err != nil {
			return fmt.Errorf("extract %s: %w", inner, err)
		}
		out[bin] = b
	}
	for _, bin := range []string{"geneza-agent", "geneza-bootstrap"} {
		target := filepath.Join(installDir, fmt.Sprintf("%s-linux-%s", bin, arch))
		if err := writeFileAtomic(target, out[bin], 0o755); err != nil {
			return fmt.Errorf("write %s: %w", target, err)
		}
	}
	return nil
}

// writeFileAtomic writes data to path via a temp file + rename in the same dir,
// so a concurrent installer read never sees a half-written binary.
func writeFileAtomic(path string, data []byte, mode os.FileMode) error {
	tmp, err := os.CreateTemp(filepath.Dir(path), ".geneza-pull-*")
	if err != nil {
		return err
	}
	tmpPath := tmp.Name()
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		_ = os.Remove(tmpPath)
		return err
	}
	if err := tmp.Close(); err != nil {
		_ = os.Remove(tmpPath)
		return err
	}
	if err := os.Chmod(tmpPath, mode); err != nil {
		_ = os.Remove(tmpPath)
		return err
	}
	return os.Rename(tmpPath, path)
}
