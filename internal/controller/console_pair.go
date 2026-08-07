package controller

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
)

// Operator pairing: promote a node's SELF-REPORTED OpenStack identity to the
// trusted one, so a VM that predates Geneza becomes launchable.
//
// The gap this fills: vendordata only ever fires at instance BUILD, so a VM that
// already existed when Geneza arrived can never acquire os:instance that way, and
// its portal "remote shell" button stays dead forever. The agent does read the
// local metadata and report what it believes it is — but in the untrusted os.claim:
// namespace, because an unsigned metadata read proves nothing to anyone but the
// reader (docs/openstack-integration.md §3). Something has to bridge that, and a
// human operator deciding "yes, this node really is that VM" is the same kind of
// judgement the node admission gate already asks for.
//
// Three properties keep the bridge narrow:
//
//  1. OPERATOR ONLY. A keystone session is a tenant, and Fleet management makes the
//     first human in a project a ws-admin — letting them pair would hand back
//     exactly the co-member impersonation that refusing tenant-set os: labels
//     closed. The operator signs in locally or by OIDC.
//  2. ONLY WHAT THE NODE CLAIMS. The instance is taken from the node's own
//     os.claim:instance, never from the request. An operator cannot pair a node to
//     an arbitrary VM by typing its uuid — including by accident, which matters
//     more, because getting it wrong silently redirects someone's shell.
//  3. PROJECT FROM THE BINDING, NOT THE CLAIM. os:project is derived from the
//     workspace's OpenStack binding, which an operator established. The node's
//     claimed project is only checked for agreement. So a node can never be paired
//     into a project its workspace is not already bound to, whatever it claims.
//
// Uniqueness still applies: pairing an instance another node already holds is
// refused, so this cannot be used to take over an enrolled VM's identity.
type pairInstanceResponse struct {
	OK       bool   `json:"ok"`
	NodeID   string `json:"nodeId"`
	Instance string `json:"instance"`
	Project  string `json:"project"`
	Cloud    string `json:"cloud"`
}

func (c *consoleAPI) handlePairInstance(w http.ResponseWriter, r *http.Request, u *consoleUser) {
	if u.Provider == providerKeystone {
		writeErr(w, http.StatusForbidden,
			"pairing is an operator action: a tenant may not decide which VM a node answers for")
		return
	}
	node, err := c.s.store.FindNode(u.Workspace, r.PathValue("id"))
	if err != nil {
		writeErr(w, http.StatusNotFound, "node not found")
		return
	}

	claimed := node.Labels[claimedInstanceLabel]
	if claimed == "" {
		writeErr(w, http.StatusBadRequest,
			"this node reports no OpenStack instance ("+claimedInstanceLabel+"); "+
				"it is not an OpenStack VM, or its agent predates metadata discovery")
		return
	}
	// Confirming the uuid is a deliberate acknowledgement of WHICH VM is being
	// wired up, not an input: it must equal what the node already claims.
	var body struct {
		Instance string `json:"instance"`
	}
	_ = json.NewDecoder(r.Body).Decode(&body)
	if body.Instance != "" && body.Instance != claimed {
		writeErr(w, http.StatusBadRequest,
			fmt.Sprintf("this node reports instance %s, not %s; a node may only be paired with the instance it reports",
				claimed, body.Instance))
		return
	}

	svcUID, project, err := c.s.workspaceOpenStackBinding(u.Workspace)
	if err != nil {
		writeErr(w, http.StatusBadRequest,
			"this workspace is not bound to an OpenStack project, so there is no project to pair into")
		return
	}
	// The node's claimed project is advisory, but disagreeing with the binding means
	// the machine believes it lives somewhere this workspace does not reach — pairing
	// it would create a node whose labels contradict each other.
	if cp := node.Labels[claimedProjectLabel]; cp != "" && cp != project {
		writeErr(w, http.StatusConflict,
			fmt.Sprintf("this node reports project %s but the workspace is bound to %s", cp, project))
		return
	}

	labels := map[string]string{}
	for k, v := range node.Labels {
		labels[k] = v
	}
	labels[launchInstanceLabel] = claimed
	labels[launchProjectLabel] = project
	labels[osCloudLabel] = svcUID

	// One live node per instance, same rule enrollment enforces — otherwise pairing
	// would be a way around it.
	if err := c.s.enforceInstanceUniqueness(u.Workspace, labels); err != nil {
		writeErr(w, http.StatusConflict, err.Error())
		return
	}

	node.Labels = labels
	if err := c.s.store.PutNode(u.Workspace, node); err != nil {
		writeErr(w, http.StatusInternalServerError, "store node")
		return
	}
	_ = c.s.audit.AppendWS(u.Workspace, "node_instance_paired", "console:"+u.Name, node.ID, "", map[string]string{
		"instance": claimed, "project": project, "cloud": svcUID, "provider": u.Provider,
	})
	writeJSON(w, pairInstanceResponse{
		OK: true, NodeID: node.ID, Instance: claimed, Project: project, Cloud: svcUID,
	})
}

// workspaceOpenStackBinding returns the (service-uid, project) this workspace is
// bound to. A workspace may bind several projects; pairing needs exactly one to be
// unambiguous, so more than one is an error rather than a guess.
func (s *Server) workspaceOpenStackBinding(ws string) (svcUID, projectID string, err error) {
	all, err := s.store.ListSourceBindings()
	if err != nil {
		return "", "", err
	}
	const prefix = "openstack:project:"
	var found []string
	for _, b := range all {
		if b.WorkspaceID != ws || !strings.HasPrefix(b.Key, prefix) {
			continue
		}
		found = append(found, strings.TrimPrefix(b.Key, prefix))
	}
	switch len(found) {
	case 0:
		return "", "", fmt.Errorf("workspace %q has no OpenStack project binding", ws)
	case 1:
		svc, proj, ok := strings.Cut(found[0], ":")
		if !ok || svc == "" || proj == "" {
			return "", "", fmt.Errorf("malformed binding %q", found[0])
		}
		return svc, proj, nil
	default:
		return "", "", fmt.Errorf("workspace %q binds %d OpenStack projects; pairing needs one", ws, len(found))
	}
}
