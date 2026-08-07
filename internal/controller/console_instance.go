package controller

import (
	"encoding/json"
	"net/http"
	"time"

	"geneza.io/internal/enrollcode"
	"geneza.io/internal/types"
)

// Tenant-driven enrollment for an instance that predates Geneza.
//
// vendordata only fires at instance BUILD, so a VM that already existed can never
// acquire the trusted os:instance that way, and its portal shell button stays dead.
// The agent's own metadata read cannot substitute: unsigned metadata proves nothing
// to anyone but the reader (docs/openstack-integration.md §3), which is why it
// lands in the untrusted os.claim: namespace.
//
// This closes the gap without an operator in the loop, because the tenant's own
// Keystone token IS the credential Nova needs. The portal presents it together with
// an instance id, and the controller asks Nova — with THAT token — whether the
// instance exists and which project owns it. Nova's own authorization does the
// tenancy check, so no operator credential is required and none is stored.
//
// The instance id is therefore a REQUEST, never an assertion: it is only ever
// believed after Nova answers, and the project stamped is the caller's own
// authoritative one, never anything the caller sent. That is residual risk #1's
// prescribed fix ("read tenant_id from Nova's server record and discard the body's
// project-id") applied to a tenant-driven path.
//
// What remains, and is unavoidable without a per-instance secret: a member of a
// project can request a token for a co-member's VM in the SAME project, because
// Nova cannot distinguish them — they are the same tenancy. The one-live-node-per-
// instance rule bounds it to VMs that have not enrolled yet.

type instanceRequest struct {
	Token      string `json:"token"`
	InstanceID string `json:"instance_id"`
}

type instanceStatusResponse struct {
	Enrolled bool   `json:"enrolled"`
	Online   bool   `json:"online"`
	NodeID   string `json:"node_id,omitempty"`
	NodeName string `json:"node_name,omitempty"`
	Instance string `json:"instance"`
	Project  string `json:"project"`
}

type enrollTokenResponse struct {
	EnrollCode     string `json:"enroll_code"`
	InstallCommand string `json:"install_command,omitempty"`
	ExpiresUnix    int64  `json:"expires_unix"`
	Workspace      string `json:"workspace"`
	Instance       string `json:"instance"`
	Project        string `json:"project"`
	AutoApprove    bool   `json:"auto_approve"`
}

// verifiedInstance is what the shared preamble established: nothing in it came
// from the caller unchecked.
type verifiedInstance struct {
	SvcUID    string
	Workspace string
	Project   string // the CALLER's authoritative project, never anything they sent
	Instance  string // Nova-confirmed to exist and to be owned by Project
}

// verifyInstanceOwnership authenticates the human, resolves their workspace, then
// asks NOVA who owns the instance — with the caller's own token, so Nova's
// authorization does the tenancy check for us.
func (c *consoleAPI) verifyInstanceOwnership(w http.ResponseWriter, r *http.Request) (verifiedInstance, bool) {
	var zero verifiedInstance
	svcUID := r.PathValue("svc")
	cl, exists := c.s.cfg.Clouds[svcUID]
	if !exists {
		writeErr(w, http.StatusNotFound, "unknown cloud") // routing-only, never auth
		return zero, false
	}
	// Same gate as the launch plane: this exists so a portal can make an instance
	// launchable in the first place, and is meaningless without it.
	if !cl.Launch.Allow {
		writeErr(w, http.StatusForbidden, "hosted-UI launch is not enabled for this cloud")
		return zero, false
	}
	if r.URL.Query().Has("token") {
		writeErr(w, http.StatusBadRequest, "the keystone token must be POSTed in the body, not the query string")
		return zero, false
	}
	var req instanceRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeErr(w, http.StatusBadRequest, "bad request body")
		return zero, false
	}
	if req.Token == "" || req.InstanceID == "" {
		writeErr(w, http.StatusBadRequest, "token and instance_id are required")
		return zero, false
	}

	verifier := c.s.clouds[svcUID]
	if verifier == nil {
		writeErr(w, http.StatusInternalServerError, "cloud verifier unavailable")
		return zero, false
	}
	sess, err := verifier.Validate(r.Context(), req.Token)
	if err != nil {
		c.auditLoginDenied("", providerKeystone, "instance: validate token: "+err.Error())
		writeErr(w, http.StatusUnauthorized, "invalid keystone token")
		return zero, false
	}
	caller := sess.Caller()
	if err := validateHumanKeystoneToken(caller, cl); err != nil {
		c.auditLoginDenied(caller.UserName, providerKeystone, "instance: "+err.Error())
		writeErr(w, http.StatusForbidden, err.Error())
		return zero, false
	}
	join, err := c.s.resolveAccessWorkspace(r.Context(), svcUID, cl, caller)
	if err != nil {
		if err == errUnboundProject {
			writeErr(w, http.StatusForbidden, "your OpenStack project is not bound to a Geneza workspace")
			return zero, false
		}
		writeErr(w, http.StatusInternalServerError, "could not resolve workspace")
		return zero, false
	}

	// THE check. Asked with the CALLER's token, so Nova refuses an instance outside
	// their project before we even compare — and the comparison then rules out an
	// admin-scoped token that can see everything.
	srv, err := sess.GetServer(r.Context(), req.InstanceID)
	if err != nil {
		if isOSNotFound(err) {
			writeErr(w, http.StatusNotFound, "no such instance in your project")
			return zero, false
		}
		writeErr(w, http.StatusBadGateway, "could not reach OpenStack to verify the instance")
		return zero, false
	}
	if srv.TenantID == "" || srv.TenantID != caller.ProjectID {
		writeErr(w, http.StatusForbidden, "that instance belongs to a different project")
		return zero, false
	}
	return verifiedInstance{
		SvcUID: svcUID, Workspace: join.Workspace,
		Project: caller.ProjectID, Instance: req.InstanceID,
	}, true
}

func (c *consoleAPI) handleInstanceStatus(w http.ResponseWriter, r *http.Request) {
	v, ok := c.verifyInstanceOwnership(w, r)
	if !ok {
		return
	}
	out := instanceStatusResponse{Instance: v.Instance, Project: v.Project}
	sums, err := c.s.nodeSummaries(v.Workspace)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "list nodes")
		return
	}
	for _, n := range sums {
		if n.GetLabels()[launchInstanceLabel] != v.Instance {
			continue
		}
		if n.GetLabels()[launchProjectLabel] != v.Project {
			continue // a co-bound project's node is not this caller's
		}
		out.Enrolled, out.Online = true, n.GetOnline()
		out.NodeID, out.NodeName = n.GetNodeId(), n.GetName()
		break
	}
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, out)
}

func (c *consoleAPI) handleInstanceEnrollToken(w http.ResponseWriter, r *http.Request) {
	v, ok := c.verifyInstanceOwnership(w, r)
	if !ok {
		return
	}
	cl := c.s.cfg.Clouds[v.SvcUID]

	// Nova-verified, so these are evidence rather than assertion — the same three
	// keys vendordata stamps, derived the same way.
	labels := map[string]string{
		launchInstanceLabel: v.Instance,
		launchProjectLabel:  v.Project,
		osCloudLabel:        v.SvcUID,
	}
	// Operator-configured defaults fill in around them, never over them.
	for k, dv := range cl.DefaultLabels {
		if _, taken := labels[k]; !taken {
			labels[k] = dv
		}
	}
	// Minting for an instance that already has a node would hand out a credential
	// whose enrollment is guaranteed to be refused, so say so now with the reason.
	if err := c.s.enforceInstanceUniqueness(v.Workspace, labels); err != nil {
		writeErr(w, http.StatusConflict, err.Error())
		return
	}

	token, err := types.NewToken()
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "token")
		return
	}
	ttl := cl.JoinTokenTTL.D()
	if ttl <= 0 {
		ttl = time.Hour
	}
	expires := time.Now().Add(ttl).Unix()
	// Auto-approve, unlike the plain operator-minted token that inherits the cloud's
	// setting. The evidence here is stronger than a bearer token: Nova confirmed,
	// against the caller's own credential, that this instance exists and is theirs.
	// Requiring an operator to then approve their own VM would leave the customer
	// having run the command and still unable to open a shell, which is the whole
	// point of the flow.
	//
	// It is not unconditional: the enroll path downgrades this to PENDING unless the
	// machine redeeming the token proves it is the instance the token names (see
	// the auto-approve gate in Enroll). So the admission decision follows how well
	// the redeemer can prove possession, not merely who minted it.
	if err := c.s.store.PutToken(token, &TokenRecord{
		WorkspaceID: v.Workspace, Labels: labels, ExpiresUnix: expires,
		MaxUses: 1, AutoApprove: true,
	}); err != nil {
		writeErr(w, http.StatusInternalServerError, "store token")
		return
	}
	_ = c.s.audit.AppendWS(v.Workspace, "instance_enroll_token", "keystone:"+v.Project, "", "", map[string]string{
		"cloud": v.SvcUID, "instance": v.Instance, "project": v.Project,
		"auto_approve": boolStr(cl.AutoApprove), "portal_ip": remoteIP(r),
	})

	out := enrollTokenResponse{
		ExpiresUnix: expires, Workspace: v.Workspace, Instance: v.Instance,
		Project: v.Project, AutoApprove: cl.AutoApprove,
	}
	// The code binds the token to the pinned root fingerprint and the runtime
	// endpoints, which is what makes the curl|sh verifiable rather than blind.
	if fp := c.s.rootFingerprint(); fp != "" {
		base := c.s.consoleExternalURL()
		if base == "" {
			base = c.s.controllerRuntimeBase()
		}
		out.EnrollCode = enrollcode.Encode(enrollcode.Fields{
			Token: token, RootFP: fp, HTTP: base,
			Runtime: c.s.controllerRuntimeBase(),
			GRPC:    c.s.controllerGRPCEndpoint(),
		})
		// Only advertise the one-liner when this controller actually serves
		// /install.sh: with install_dir unset the URL 404s, or worse an SPA
		// catch-all answers it with index.html — HTML piped into sudo sh.
		if c.s.cfg.InstallDir != "" && base != "" {
			out.InstallCommand = "curl -fsSL " + base + "/install.sh | sudo sh -s -- " + out.EnrollCode
		}
	}
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, out)
}
