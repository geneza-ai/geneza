package gateway

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"time"

	"osie.cloud/geneza/internal/types"
)

// The OpenStack vendordata endpoint (§10). Nova calls it during instance build
// with its service token; Geneza validates the token, reads the AUTHORITATIVE
// project from Nova (security #1 — never the body), maps it to a workspace
// (binding or auto-provision, §6), mints ONE idempotent join token (security
// #15), and returns a cloud-init that installs + enrols the agent. It is mounted
// on the gateway's existing HTTPS listener, so it inherits server-auth TLS
// (security #3): a join token / cloud-init never crosses the wire in cleartext.
//
// The response is a JSON STRING (the #cloud-config text), so Nova stores it as
// vendor_data2.json = {"cloud-init": "<#cloud-config>"} — the nesting cloud-init
// requires (§4 gotcha 3). Returning an object here would double-nest and break.

// maxVendordataBody bounds the request body (Nova's is a few KB).
const maxVendordataBody = 1 << 20

// vendordataBody is Nova's dynamic-vendordata request (hyphenated keys, §4). Note
// project-id is present but DELIBERATELY NOT TRUSTED — the authoritative project
// comes from the Nova server callback (security #1).
type vendordataBody struct {
	ProjectID  string            `json:"project-id"`
	InstanceID string            `json:"instance-id"`
	ImageID    string            `json:"image-id"`
	Hostname   string            `json:"hostname"`
	BootRoles  string            `json:"boot-roles"`
	Metadata   map[string]string `json:"metadata"`
}

func (s *Server) registerVendordataRoutes(mux *http.ServeMux) {
	mux.HandleFunc("POST /openstack/vendordata/{service_uid}", s.handleVendordata)
}

// osAudit appends an OpenStack-enrollment audit record with standardized detail
// fields (security #31): always the service-uid, decision, reason.
func (s *Server) osAudit(svcUID, decision, reason string, extra map[string]string) {
	detail := map[string]string{"service_uid": svcUID, "decision": decision}
	if reason != "" {
		detail["reason"] = reason
	}
	for k, v := range extra {
		detail[k] = v
	}
	if err := s.audit.Append("openstack_vendordata", "nova:"+svcUID, extra["node"], "", detail); err != nil {
		slog.Error("audit append failed (openstack vendordata)", "err", err)
	}
}

func (s *Server) handleVendordata(w http.ResponseWriter, r *http.Request) {
	svcUID := r.PathValue("service_uid")
	ctx := r.Context()

	// 1. ROUTE: the suffix selects a clouds-registry entry. It is a routing key,
	// not an auth grant (§7): an unknown uid is a 404 and grants nothing.
	cl, ok := s.cfg.Clouds[svcUID]
	if !ok {
		http.Error(w, "unknown cloud", http.StatusNotFound)
		return
	}
	verifier := s.clouds[svcUID]
	if verifier == nil {
		http.Error(w, "cloud not initialized", http.StatusInternalServerError)
		return
	}

	token := r.Header.Get("X-Auth-Token")
	if token == "" {
		s.osAudit(svcUID, "deny", "missing X-Auth-Token", nil)
		http.Error(w, "missing X-Auth-Token", http.StatusUnauthorized)
		return
	}

	body, err := io.ReadAll(io.LimitReader(r.Body, maxVendordataBody))
	if err != nil {
		http.Error(w, "read body", http.StatusBadRequest)
		return
	}
	var vd vendordataBody
	if err := json.Unmarshal(body, &vd); err != nil {
		http.Error(w, "bad body", http.StatusBadRequest)
		return
	}
	if vd.InstanceID == "" {
		s.osAudit(svcUID, "deny", "missing instance-id", nil)
		http.Error(w, "missing instance-id", http.StatusBadRequest)
		return
	}

	// 2. AUTH: validate the presented token against THIS cloud's Keystone.
	sess, err := verifier.Validate(ctx, token)
	if err != nil {
		s.osAudit(svcUID, "deny", "token validation failed: "+redactErr(err), map[string]string{"instance": vd.InstanceID})
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	caller := sess.Caller()

	// 2b. Require a Nova SERVICE-scoped token (security #4, non-overridable):
	// the enrollment plane never accepts an arbitrary tenant token.
	if caller.ProjectName != cl.serviceProject() {
		s.osAudit(svcUID, "deny", fmt.Sprintf("caller not service-scoped (project=%q want %q)", caller.ProjectName, cl.serviceProject()), map[string]string{"instance": vd.InstanceID})
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}

	// 3. AUTHORITATIVE project (security #1): read Nova's server record and use
	// its tenant_id. The body's project-id is IGNORED — it is attacker-shaped.
	srv, err := sess.GetServer(ctx, vd.InstanceID)
	if err != nil {
		if isOSNotFound(err) {
			s.osAudit(svcUID, "deny", "instance not found in Nova", map[string]string{"instance": vd.InstanceID})
			http.Error(w, "instance not found", http.StatusNotFound)
			return
		}
		s.osAudit(svcUID, "error", "nova callback failed: "+redactErr(err), map[string]string{"instance": vd.InstanceID})
		http.Error(w, "nova callback failed", http.StatusBadGateway)
		return
	}
	projectID := srv.TenantID
	if projectID == "" {
		s.osAudit(svcUID, "error", "nova returned empty tenant_id", map[string]string{"instance": vd.InstanceID})
		http.Error(w, "nova returned no tenant", http.StatusBadGateway)
		return
	}
	if vd.ProjectID != "" && vd.ProjectID != projectID {
		// Not fatal (we trust Nova), but a mismatch is exactly the confused-deputy
		// signal — record it loudly.
		s.osAudit(svcUID, "warn", "body project-id != nova tenant_id (ignored body, used nova)",
			map[string]string{"instance": vd.InstanceID, "body_project": vd.ProjectID, "nova_project": projectID})
	}

	// 4. BIND / AUTO-PROVISION: resolve the workspace for this project (§6).
	bindingKey := osProjectBindingKey(svcUID, projectID)
	ws, provisioned, err := s.resolveOSWorkspace(ctx, svcUID, cl, bindingKey, projectID, sess)
	if err != nil {
		if err == errUnboundProject {
			s.osAudit(svcUID, "pending", "unbound project (auto_provision off)",
				map[string]string{"instance": vd.InstanceID, "project": projectID})
			// Surface, never silently misroute: return an empty cloud-init so the
			// VM boots without Geneza rather than landing in the wrong tenant.
			writeVendordataString(w, "#cloud-config\n{}\n")
			return
		}
		s.osAudit(svcUID, "error", "resolve workspace: "+redactErr(err), map[string]string{"instance": vd.InstanceID, "project": projectID})
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	// 5. LABELS (§8 / security #7): operator-trusted facts under "os:", launcher-
	// and tenant-asserted hints under "os.claim:" so they can never collide with
	// or impersonate an operator label, and a policy author can grep grants off
	// the untrusted namespace.
	labels := deriveOSLabels(svcUID, projectID, vd, cl.DefaultLabels)

	// 6. IDEMPOTENT MINT (security #15,#22): keyed by (service-uid, instance).
	ttl := cl.joinTokenTTL()
	now := time.Now()
	tok := &TokenRecord{
		WorkspaceID: ws,
		Labels:      labels,
		ExpiresUnix: now.Add(ttl).Unix(),
		MaxUses:     1,
		AutoApprove: cl.AutoApprove,
	}
	joinTok, reused, err := s.store.OSMintOnce(osEnrollKey(svcUID, vd.InstanceID), now, ttl, tok, types.NewToken)
	if err != nil {
		s.osAudit(svcUID, "error", "mint join token: "+redactErr(err), map[string]string{"instance": vd.InstanceID, "project": projectID})
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	s.osAudit(svcUID, "allow", "", map[string]string{
		"instance":     vd.InstanceID,
		"project":      projectID,
		"workspace":    ws,
		"reused_token": boolStr(reused),
		"provisioned":  boolStr(provisioned),
		"auto_approve": boolStr(cl.AutoApprove),
	})
	slog.Info("openstack vendordata enroll",
		"cloud", svcUID, "instance", vd.InstanceID, "project", projectID,
		"workspace", ws, "reused", reused, "provisioned", provisioned)

	// 7. RETURN cloud-init (as a JSON string — §4 nesting trap).
	cfg, err := s.renderOSCloudInit(r, cl, joinTok, vd.Hostname)
	if err != nil {
		http.Error(w, "render cloud-init", http.StatusInternalServerError)
		return
	}
	writeVendordataString(w, cfg)
}

// errUnboundProject signals a project with no binding under a cloud whose
// auto_provision is off (§6 / §10 step 4).
var errUnboundProject = fmt.Errorf("unbound project")

// resolveOSWorkspace returns the workspace for a project: an existing binding,
// or — when auto_provision is on — a freshly created per-project isolated
// workspace (§6). provisioned reports whether a new workspace was created.
func (s *Server) resolveOSWorkspace(ctx context.Context, svcUID string, cl CloudConfig, bindingKey, projectID string, sess cloudSession) (ws string, provisioned bool, err error) {
	if b, gerr := s.store.GetSourceBinding(bindingKey); gerr == nil {
		return b.WorkspaceID, false, nil
	} else if gerr != ErrNotFound {
		return "", false, gerr
	}
	if !cl.AutoProvision {
		return "", false, errUnboundProject
	}
	// Auto-provision: SAFE without a whitelist because (a) the token validated
	// against a trusted Keystone and (b) each project gets its OWN isolated
	// workspace keyed by the exact (service-uid, project) Nova attested.
	slug := autoWorkspaceSlug(svcUID, projectID, sess, ctx)
	overlay := defaultOverlayCIDR
	name := slug
	if err := s.ensureWorkspace(slug, name, overlay); err != nil {
		return "", false, fmt.Errorf("provision workspace: %w", err)
	}
	if err := s.store.PutSourceBinding(&SourceBinding{
		Key:             bindingKey,
		WorkspaceID:     slug,
		CreatedUnix:     time.Now().Unix(),
		CreatedBy:       "auto:openstack",
		AutoProvisioned: true,
	}); err != nil {
		return "", false, fmt.Errorf("record binding: %w", err)
	}
	// Mirror config-driven workspaces into the policy engine + membership map so
	// the broker can authorize sessions into the auto-provisioned tenant.
	s.registerDynamicWorkspace(slug)
	return slug, true, nil
}

// autoWorkspaceSlug builds a stable, collision-resistant workspace id for a
// project: <project-name>-<short-uuid> (project name fetched best-effort), else
// os-<service-uid>-<short-uuid>. Deterministic in the project UUID so the ~5
// concurrent Nova hits converge on one workspace.
func autoWorkspaceSlug(svcUID, projectID string, sess cloudSession, ctx context.Context) string {
	short := projectID
	if len(short) > 8 {
		short = short[:8]
	}
	name := ""
	if p, err := sess.ResolveProject(ctx, projectID); err == nil {
		name = p.Name
	}
	base := slugify(name)
	if base == "" {
		base = "os-" + slugify(svcUID)
	}
	return base + "-" + short
}

// slugify lowercases and reduces a string to [a-z0-9-], the workspace-id charset.
func slugify(s string) string {
	s = strings.ToLower(strings.TrimSpace(s))
	var b strings.Builder
	prevDash := false
	for _, r := range s {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9':
			b.WriteRune(r)
			prevDash = false
		default:
			if !prevDash && b.Len() > 0 {
				b.WriteByte('-')
				prevDash = true
			}
		}
	}
	return strings.Trim(b.String(), "-")
}

func osProjectBindingKey(svcUID, projectID string) string {
	return "openstack:project:" + svcUID + ":" + projectID
}

func osEnrollKey(svcUID, instanceID string) string { return svcUID + "#" + instanceID }

// deriveOSLabels separates trusted facts from tenant-asserted hints (§8 / #7).
func deriveOSLabels(svcUID, projectID string, vd vendordataBody, defaults map[string]string) map[string]string {
	out := map[string]string{}
	// Operator-configured defaults (trusted).
	for k, v := range defaults {
		out[k] = v
	}
	// Operator/Nova-verified facts — reserved "os:" namespace.
	out["os:cloud"] = svcUID
	out["os:project"] = projectID
	out["os:instance"] = vd.InstanceID
	// Launcher's boot-roles: ADVISORY hints, never grants. Namespaced "os.claim:"
	// so they cannot impersonate an operator label.
	for _, role := range splitCSV(vd.BootRoles) {
		out["os.claim:boot-role:"+role] = "1"
	}
	// Tenant-set instance metadata under geneza.*: also advisory, also namespaced.
	for k, v := range vd.Metadata {
		if strings.HasPrefix(k, "geneza.") {
			out["os.claim:"+strings.TrimPrefix(k, "geneza.")] = v
		}
	}
	return out
}

func splitCSV(s string) []string {
	var out []string
	for _, p := range strings.Split(s, ",") {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}

// renderOSCloudInit builds the #cloud-config that installs + enrols the agent.
// The install.sh one-liner carries the pinned root fingerprint AND the stage-1
// binary hashes (security #2/#26): over the TLS listener these arrive
// authenticated, and install.sh verifies the binaries before exec.
func (s *Server) renderOSCloudInit(r *http.Request, cl CloudConfig, joinTok, hostname string) (string, error) {
	base := cl.GatewayURL
	if base == "" {
		base = externalBase(r)
	}
	base = strings.TrimRight(base, "/")
	grpc := cl.GatewayGRPC
	if grpc == "" {
		grpc = hostOf(base) + ":7401"
	}
	rootFP := s.rootFingerprint()
	bootstrapSHA := s.stage1SHA256("geneza-bootstrap-linux-amd64")
	agentSHA := s.stage1SHA256("geneza-agent-linux-amd64")

	args := []string{
		"--token", shellQuote(joinTok),
		"--gateway-http", shellQuote(base),
		"--gateway-grpc", shellQuote(grpc),
	}
	if cl.GatewayRuntimeURL != "" {
		args = append(args, "--gateway-http-runtime", shellQuote(strings.TrimRight(cl.GatewayRuntimeURL, "/")))
	}
	if rootFP != "" {
		args = append(args, "--root-fp", shellQuote(rootFP))
	}
	if bootstrapSHA != "" {
		args = append(args, "--bootstrap-sha256", shellQuote(bootstrapSHA))
	}
	if agentSHA != "" {
		args = append(args, "--agent-sha256", shellQuote(agentSHA))
	}
	if hostname != "" {
		args = append(args, "--name", shellQuote(hostname))
	}

	var sb strings.Builder
	sb.WriteString("#cloud-config\n")
	sb.WriteString("runcmd:\n")
	sb.WriteString("  - curl -fsSL " + shellQuote(base+"/install.sh") + " | sh -s -- " + strings.Join(args, " ") + "\n")
	return sb.String(), nil
}

// writeVendordataString writes the cloud-config as a JSON string so Nova nests
// it as {"cloud-init": "<text>"} (§4 gotcha 3).
func writeVendordataString(w http.ResponseWriter, cloudConfig string) {
	w.Header().Set("Content-Type", "application/json")
	enc, _ := json.Marshal(cloudConfig)
	_, _ = w.Write(enc)
}

func hostOf(rawURL string) string {
	u, err := url.Parse(rawURL)
	if err != nil || u.Host == "" {
		return rawURL
	}
	return u.Hostname()
}

// shellQuote single-quotes a value for safe interpolation into the sh one-liner.
func shellQuote(s string) string {
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}

func boolStr(b bool) string {
	if b {
		return "true"
	}
	return "false"
}

// redactErr trims an error to a short, log-safe string (no token material).
func redactErr(err error) string {
	if err == nil {
		return ""
	}
	m := err.Error()
	if len(m) > 200 {
		m = m[:200]
	}
	return m
}
