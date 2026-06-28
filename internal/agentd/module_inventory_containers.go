package agentd

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/google/osv-scalibr/artifact/image/layerscanning/image"
	"github.com/google/osv-scalibr/extractor/filesystem"
	scalibrfs "github.com/google/osv-scalibr/fs"
	"github.com/google/osv-scalibr/stats"

	"geneza.io/internal/sbom"
)

// commandRunner runs an external command and returns its stdout. It is the single seam
// the container path shells out through — the runtime CLI (`ps`/`inspect`, and `save`
// to export an image's layers) — so a test injects fixtures without a live docker.
type commandRunner func(ctx context.Context, name string, args ...string) ([]byte, error)

// execRunner is the production commandRunner: it runs the binary and returns its
// stdout, surfacing a non-zero exit (with any stderr) as the error so a missing
// runtime degrades to the documented fallback rather than a silent empty set.
func execRunner(ctx context.Context, name string, args ...string) ([]byte, error) {
	cmd := exec.CommandContext(ctx, name, args...)
	var stderr strings.Builder
	cmd.Stderr = &stderr
	out, err := cmd.Output()
	if err != nil {
		if msg := strings.TrimSpace(stderr.String()); msg != "" {
			return nil, fmt.Errorf("%s: %w: %s", name, err, msg)
		}
		return nil, fmt.Errorf("%s: %w", name, err)
	}
	return out, nil
}

// runningContainer is one container the runtime reports running: its id, the image
// reference it was started from, the content-addressable image digest, and the host
// pid of its init process (for the /proc/<pid>/root fallback scan). digest is the
// dedup key — many containers sharing an image resolve to one digest and are scanned
// once.
type runningContainer struct {
	id     string
	image  string
	digest string
	pid    int
}

// containerRuntime enumerates the running containers on the node and unpacks an image's
// layers for scanning. The docker/nerdctl implementation shells out to its CLI through
// the injected runner; crictl enumerates but cannot export layers, so it leaves
// imageFS to the caller's /proc/<pid>/root fallback.
type containerRuntime interface {
	name() string
	list(ctx context.Context, run commandRunner) ([]runningContainer, error)
	// imageFS unpacks the image's layers into a scannable filesystem and returns it with
	// a cleanup. ok is false when this runtime cannot export the image (crictl), so the
	// caller falls back to the merged-rootfs scan. ref is the reference to export.
	imageFS(ctx context.Context, run commandRunner, ref string) (fsys scalibrfs.FS, cleanup func(), ok bool, err error)
}

// dockerRuntime drives the docker/nerdctl CLI, whose `ps`/`inspect`/`save` surface is
// identical. nerdctl is a drop-in for docker, so one type covers both, selected by
// the binary name.
type dockerRuntime struct{ bin string }

func (d dockerRuntime) name() string { return d.bin }

// list enumerates running containers and resolves each one's image digest. `docker ps`
// gives the id and image ref; the digest and pid come from `inspect` since `ps` does
// not carry them. A container whose digest cannot be resolved still reports with an
// empty digest (it is scanned by ref, just not deduped against other refs).
func (d dockerRuntime) list(ctx context.Context, run commandRunner) ([]runningContainer, error) {
	// One JSON object per line ({{json .}} is the per-container record); parse line by
	// line so a partial output still yields the containers that did print.
	out, err := run(ctx, d.bin, "ps", "--no-trunc", "--format", "{{json .}}")
	if err != nil {
		return nil, err
	}
	var cs []runningContainer
	for _, line := range strings.Split(string(out), "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		var rec struct {
			ID    string `json:"ID"`
			Image string `json:"Image"`
		}
		if err := json.Unmarshal([]byte(line), &rec); err != nil {
			continue
		}
		if rec.ID == "" {
			continue
		}
		cs = append(cs, runningContainer{id: rec.ID, image: rec.Image})
	}
	for i := range cs {
		cs[i].digest, cs[i].pid = d.inspect(ctx, run, cs[i].id)
	}
	return cs, nil
}

// inspect resolves a container's image digest and init pid from `inspect`. A failed
// inspect (the container exited between ps and inspect) yields an empty digest and a
// zero pid; the caller scans by ref and skips the /proc fallback.
func (d dockerRuntime) inspect(ctx context.Context, run commandRunner, id string) (digest string, pid int) {
	out, err := run(ctx, d.bin, "inspect", id)
	if err != nil {
		return "", 0
	}
	var recs []struct {
		Image string `json:"Image"`
		State struct {
			Pid int `json:"Pid"`
		} `json:"State"`
	}
	if err := json.Unmarshal(out, &recs); err != nil || len(recs) == 0 {
		return "", 0
	}
	return recs[0].Image, recs[0].State.Pid
}

// imageFS exports the image to a temp tarball with `<runtime> save` and unpacks its
// layers in-process. `save` is the uniform export for docker and nerdctl alike and
// needs no daemon-client library — the runner already speaks the CLI — and the tarball
// is the format scalibr's FromTarball consumes directly. The temp file is removed once
// it is unpacked (FromTarball reads it eagerly); the returned cleanup releases the
// unpacked filesystem.
func (d dockerRuntime) imageFS(ctx context.Context, run commandRunner, ref string) (scalibrfs.FS, func(), bool, error) {
	tar, err := os.CreateTemp("", "geneza-image-*.tar")
	if err != nil {
		return nil, nil, true, fmt.Errorf("create image tarball: %w", err)
	}
	tarPath := tar.Name()
	tar.Close()
	defer os.Remove(tarPath)

	out, err := run(ctx, d.bin, "save", "-o", tarPath, ref)
	if err != nil {
		return nil, nil, true, fmt.Errorf("%s save %s: %w", d.bin, ref, err)
	}
	// Some runtimes write the stream to stdout when -o is unsupported; tolerate that by
	// writing it to the file ourselves so FromTarball always has a file to read.
	if len(out) > 0 {
		if werr := os.WriteFile(tarPath, out, 0o600); werr != nil {
			return nil, nil, true, fmt.Errorf("write image tarball: %w", werr)
		}
	}
	return fsFromTarball(tarPath)
}

// fsFromTarball unpacks a docker-save / OCI image tarball into a scannable filesystem.
// Split from imageFS so the unpack path is exercised against a fixture tarball without a
// live runtime. The returned cleanup releases the unpacked layers' backing storage.
func fsFromTarball(tarPath string) (scalibrfs.FS, func(), bool, error) {
	img, err := image.FromTarball(tarPath, image.DefaultConfig())
	if err != nil {
		return nil, nil, true, fmt.Errorf("unpack image tarball: %w", err)
	}
	cleanup := func() {
		if cerr := img.CleanUp(); cerr != nil {
			// best-effort: the temp storage is reclaimed on process exit regardless.
			_ = cerr
		}
	}
	return img.FS(), cleanup, true, nil
}

// crictlRuntime drives crictl (the CRI runtimes: containerd/CRI-O on Kubernetes
// nodes), whose `ps -o json` carries the id, image ref, and image digest directly.
type crictlRuntime struct{ bin string }

func (c crictlRuntime) name() string { return c.bin }

func (c crictlRuntime) list(ctx context.Context, run commandRunner) ([]runningContainer, error) {
	out, err := run(ctx, c.bin, "ps", "-o", "json")
	if err != nil {
		return nil, err
	}
	var doc struct {
		Containers []struct {
			ID    string `json:"id"`
			Image struct {
				Image string `json:"image"`
			} `json:"image"`
			ImageRef string `json:"imageRef"`
		} `json:"containers"`
	}
	if err := json.Unmarshal(out, &doc); err != nil {
		return nil, fmt.Errorf("%s ps: %w", c.bin, err)
	}
	var cs []runningContainer
	for _, ct := range doc.Containers {
		if ct.ID == "" {
			continue
		}
		// imageRef is the digest-pinned reference (image@sha256:...); the digest is the
		// part after the @, the content-addressable dedup key.
		digest := ct.ImageRef
		if _, d, ok := strings.Cut(ct.ImageRef, "@"); ok {
			digest = d
		}
		cs = append(cs, runningContainer{id: ct.ID, image: ct.Image.Image, digest: digest})
	}
	return cs, nil
}

// imageFS reports unsupported: crictl has no `save`, so a CRI image cannot be exported
// to a tarball here. The caller falls back to the /proc/<pid>/root scan of the merged
// rootfs, which needs no runtime export.
func (c crictlRuntime) imageFS(ctx context.Context, run commandRunner, ref string) (scalibrfs.FS, func(), bool, error) {
	return nil, nil, false, nil
}

// detectRuntime returns the first container runtime CLI present on the node, in
// preference order docker -> nerdctl -> crictl, or nil when none is on PATH. With no
// runtime the container collector is a clean no-op.
func detectRuntime(run commandRunner, lookPath func(string) (string, error)) containerRuntime {
	if _, err := lookPath("docker"); err == nil {
		return dockerRuntime{bin: "docker"}
	}
	if _, err := lookPath("nerdctl"); err == nil {
		return dockerRuntime{bin: "nerdctl"}
	}
	if _, err := lookPath("crictl"); err == nil {
		return crictlRuntime{bin: "crictl"}
	}
	return nil
}

// imageSource is the component Source for a container image's packages. It carries the
// image ref AND the content-addressable digest, so a verdict points at the exact image
// and the controller can dedup fleet-wide by digest: two nodes running the same digest
// report the same Source and key to the same component identity. When the digest is
// unknown only the ref is carried.
func imageSource(ref, digest string) string {
	if digest == "" {
		return "image:" + ref
	}
	return "image:" + ref + "@" + digest
}

// collectContainers enumerates running containers, resolves each one's image digest,
// and produces the image's components — scanning each unique digest at most once. Each
// image's layers are unpacked in-process (no external scanner binary) and walked with
// the same osv-scalibr extractors the host scan uses, so the ecosystems and PURLs match
// the matcher's expectations. With no runtime it returns nothing. The components are
// tagged source "image:<ref>@<digest>" so the controller keys them apart from host
// packages and can dedup by digest.
func (m *inventoryModule) collectContainers(ctx context.Context) ([]sbom.Component, error) {
	m.mu.Lock()
	run := m.run
	lookPath := m.lookPath
	m.mu.Unlock()
	if run == nil {
		run = execRunner
	}
	if lookPath == nil {
		lookPath = exec.LookPath
	}

	rt := detectRuntime(run, lookPath)
	if rt == nil {
		return nil, nil
	}
	containers, err := rt.list(ctx, run)
	if err != nil {
		return nil, fmt.Errorf("list containers (%s): %w", rt.name(), err)
	}
	if len(containers) == 0 {
		return nil, nil
	}

	// Dedup by digest: a digest is content-addressable, so its component set is a
	// property of the digest, not of each container running it. Scan each unique digest
	// once and attribute the result to every container on it. Containers with no
	// resolvable digest fall back to a per-id scan so they are not silently dropped.
	seen := map[string][]sbom.Component{}
	var out []sbom.Component
	for _, ct := range containers {
		key := ct.digest
		if key == "" {
			key = "id:" + ct.id
		}
		comps, ok := seen[key]
		if !ok {
			comps = m.scanContainerImage(ctx, run, rt, ct)
			seen[key] = comps
		}
		out = append(out, comps...)
	}
	return out, nil
}

// scanContainerImage produces the components for one container's image, tagging each
// with the image source (ref@digest). It unpacks the image's layers in-process and
// walks them with the OS + language extractors; if the runtime cannot export the image
// or the unpack fails, it falls back to the /proc/<pid>/root scan of the merged rootfs
// rather than dropping the image. A failure on both paths logs and yields nothing for
// this image rather than failing the whole collection.
func (m *inventoryModule) scanContainerImage(ctx context.Context, run commandRunner, rt containerRuntime, ct runningContainer) []sbom.Component {
	source := imageSource(ct.image, ct.digest)

	fsys, cleanup, ok, err := rt.imageFS(ctx, run, ct.image)
	if err != nil {
		m.log.Warn("image unpack failed, falling back to rootfs scan", "runtime", rt.name(), "image", ct.image, "err", err)
	} else if ok {
		defer cleanup()
		comps, serr := scanImageFS(ctx, fsys)
		if serr != nil {
			m.log.Warn("image scan failed, falling back to rootfs scan", "runtime", rt.name(), "image", ct.image, "err", serr)
		} else {
			return retagComponents(comps, source)
		}
	}

	// In-process image scan unavailable or failed: fall back to the in-process
	// extractors over the container's merged rootfs (the running filesystem, not the
	// layered image) via /proc/<pid>/root. This degrades gracefully but sees only the
	// merged view, so it is the lesser path.
	if ct.pid <= 0 {
		return nil
	}
	comps, err := m.scanContainerRootfs(ctx, ct.pid)
	if err != nil {
		m.log.Warn("container rootfs scan failed", "container", ct.id, "err", err)
		return nil
	}
	return retagComponents(comps, source)
}

// retagComponents stamps every component with the image source so host and image
// packages stay distinct in the index and a verdict points at the image. The extractors
// emit no geneza source property, so the collector sets it authoritatively.
func retagComponents(comps []sbom.Component, source string) []sbom.Component {
	out := make([]sbom.Component, 0, len(comps))
	for _, c := range comps {
		c.Source = source
		out = append(out, c)
	}
	return out
}

// scanContainerRootfs runs the OS-package and language extractors over a container's
// merged rootfs via /proc/<pid>/root, the fallback when the image cannot be unpacked.
// It reuses the same in-process extractors the image and host scans use so the
// ecosystems and PURLs match the matcher's expectations.
func (m *inventoryModule) scanContainerRootfs(ctx context.Context, pid int) ([]sbom.Component, error) {
	return scanRootfs(ctx, filepath.Join("/proc", strconv.Itoa(pid), "root"))
}

// scanRootfs runs the container OS+language extractors over an arbitrary root and maps
// the found packages into components. Split from scanContainerRootfs so the extraction
// is testable against a fixture directory without a live /proc/<pid>/root.
func scanRootfs(ctx context.Context, root string) ([]sbom.Component, error) {
	exts, err := containerExtractors()
	if err != nil {
		return nil, err
	}

	inv, _, err := filesystem.Run(ctx, &filesystem.Config{
		Extractors: exts,
		ScanRoots:  scalibrfs.RealFSScanRoots(root),
		Stats:      stats.NoopCollector{},
		DirsToSkip: skipDirsUnder(root),
	})
	if err != nil {
		return nil, fmt.Errorf("scan container rootfs %s: %w", root, err)
	}
	// Source is overwritten by the caller's retag; "image" here is a placeholder the
	// retag replaces with the ref@digest-qualified value.
	return componentsFromPackages(inv.Packages, "image"), nil
}

// scanImageFS walks an unpacked image's filesystem with the container OS+language
// extractors and maps the found packages into components. The filesystem is virtual
// (scalibr's layer-unpacked view), so it is scanned through a virtual scan root; the
// synthetic kernel directories never appear in an image but are passed as skip hints to
// stay uniform with the rootfs path.
func scanImageFS(ctx context.Context, fsys scalibrfs.FS) ([]sbom.Component, error) {
	exts, err := containerExtractors()
	if err != nil {
		return nil, err
	}
	inv, _, err := filesystem.Run(ctx, &filesystem.Config{
		Extractors: exts,
		ScanRoots:  []*scalibrfs.ScanRoot{{FS: fsys}},
		Stats:      stats.NoopCollector{},
		DirsToSkip: dirsToSkip,
	})
	if err != nil {
		return nil, fmt.Errorf("scan image filesystem: %w", err)
	}
	// Source is overwritten by the caller's retag; "image" here is a placeholder the
	// retag replaces with the ref@digest-qualified value.
	return componentsFromPackages(inv.Packages, "image"), nil
}

// containerExtractors builds the OS-package and language extractor set the image and
// rootfs scans run. It reuses the host scan's OS extractors (dpkg/rpm/apk, so a Debian,
// RPM, or Alpine image is covered) and the language extractors, so an image SBOM
// produces the same ecosystem strings the host SBOM and the matcher expect.
func containerExtractors() ([]filesystem.Extractor, error) {
	osExts, err := osPackageExtractors()
	if err != nil {
		return nil, err
	}
	langExts, err := languageExtractors()
	if err != nil {
		return nil, fmt.Errorf("build language extractors: %w", err)
	}
	return append(osExts, langExts...), nil
}
