package agentd

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"time"
)

// The OpenStack metadata service. Link-local and answered by the hypervisor, so it
// is only ever reachable from inside an instance — but it is unsigned plaintext
// (docs/openstack-integration.md §3), so what it says is a CLAIM, not a proof.
const (
	osMetadataURL     = "http://169.254.169.254/openstack/latest/meta_data.json"
	osMetadataTimeout = 2 * time.Second

	// ClaimedInstanceLabel / ClaimedProjectLabel live in the untrusted os.claim:
	// namespace the controller reserves for tenant-asserted hints. The controller
	// drops any os: label an agent sends, so these can never become the trusted
	// os:instance / os:project — they exist to be CROSS-CHECKED against enrollment
	// evidence, and to be visible to an operator diagnosing a mislabelled node.
	ClaimedInstanceLabel = "os.claim:instance"
	ClaimedProjectLabel  = "os.claim:project"
)

type osMetadata struct {
	UUID      string `json:"uuid"`
	ProjectID string `json:"project_id"`
}

// OpenStackClaims returns what the local metadata service says this machine is, or
// nil when there is none — bare metal, another cloud, or a network that does not
// route link-local. That is the common case on a mixed fleet, so it is silent
// rather than an error: enrollment must not depend on being an OpenStack VM.
//
// The short timeout matters. 169.254.169.254 is routable-looking but frequently
// blackholed rather than refused, so without one this would stall every enrollment
// on every non-OpenStack host until the default dial timeout expired.
func OpenStackClaims(ctx context.Context) map[string]string {
	ctx, cancel := context.WithTimeout(ctx, osMetadataTimeout)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, osMetadataURL, nil)
	if err != nil {
		return nil
	}
	resp, err := (&http.Client{Timeout: osMetadataTimeout}).Do(req)
	if err != nil {
		return nil
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil
	}
	// Cap the read: this endpoint is unauthenticated, and a hostile or broken one
	// on the same link should not be able to make the agent allocate without bound.
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil
	}
	var md osMetadata
	if err := json.Unmarshal(body, &md); err != nil || md.UUID == "" {
		return nil
	}
	out := map[string]string{ClaimedInstanceLabel: md.UUID}
	if md.ProjectID != "" {
		out[ClaimedProjectLabel] = md.ProjectID
	}
	return out
}
