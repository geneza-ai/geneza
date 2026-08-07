package agentd

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"os"
	"strings"
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

// OpenStackClaims returns what this machine says it is, or nil when nothing says
// anything — bare metal, another cloud, or a network that does not route
// link-local. That is the common case on a mixed fleet, so it is silent rather than
// an error: enrollment must not depend on being an OpenStack VM.
//
// Two sources, because a VM may have only one of them. The HTTP metadata service is
// tried first; where it is absent the VM was very likely given a CONFIG DRIVE
// instead, which is the usual arrangement when the 169.254.169.254 path is
// unreachable (no DHCP isolated-metadata, no router — see
// docs/openstack-integration.md §4 gotcha 2). Rather than mount config-2 from the
// agent, read what cloud-init already normalised out of whichever datasource it
// used: that covers config drive, the metadata service, and anything else, without
// touching a block device.
func OpenStackClaims(ctx context.Context) map[string]string {
	if c := openStackClaimsHTTP(ctx); c != nil {
		return c
	}
	return openStackClaimsCloudInit()
}

// openStackClaimsHTTP reads the link-local metadata service.
//
// The short timeout matters. 169.254.169.254 is routable-looking but frequently
// blackholed rather than refused, so without one this would stall every enrollment
// on every non-OpenStack host until the default dial timeout expired.
func openStackClaimsHTTP(ctx context.Context) map[string]string {
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

// cloudInitInstanceData is where cloud-init writes what it learned from whichever
// datasource it used, normalised. Present regardless of whether the instance was
// given a config drive or the HTTP metadata service, which is exactly why it is the
// fallback: it makes config-drive-only VMs work without the agent mounting config-2.
//
// Not the -sensitive variant: that is 0600 and carries vendordata (including, on
// the zero-touch path, a join token). Nothing here needs it.
const cloudInitInstanceData = "/run/cloud-init/instance-data.json"

type cloudInitData struct {
	V1 struct {
		InstanceID string `json:"instance_id"`
		CloudName  string `json:"cloud_name"`
		Platform   string `json:"platform"`
	} `json:"v1"`
	DS struct {
		MetaData osMetadata `json:"meta_data"`
	} `json:"ds"`
}

func openStackClaimsCloudInit() map[string]string {
	f, err := os.Open(cloudInitInstanceData)
	if err != nil {
		return nil // no cloud-init, or it has not run: nothing to claim
	}
	defer f.Close()
	body, err := io.ReadAll(io.LimitReader(f, 4<<20))
	if err != nil {
		return nil
	}
	return parseCloudInitClaims(body)
}

// parseCloudInitClaims is split out so the shape can be tested against real
// instance-data.json bodies without a filesystem.
func parseCloudInitClaims(body []byte) map[string]string {
	var d cloudInitData
	if err := json.Unmarshal(body, &d); err != nil {
		return nil
	}
	// Only claim an OpenStack identity on OpenStack. cloud-init writes this file on
	// EC2, Azure and the rest too, and an instance id from one of those is not a
	// Nova instance uuid — labelling it as one would be a lie in the same namespace.
	if !strings.EqualFold(d.V1.CloudName, "openstack") && !strings.EqualFold(d.V1.Platform, "openstack") {
		return nil
	}
	uuid, project := d.DS.MetaData.UUID, d.DS.MetaData.ProjectID
	if uuid == "" {
		uuid = d.V1.InstanceID
	}
	if uuid == "" {
		return nil
	}
	out := map[string]string{ClaimedInstanceLabel: uuid}
	if project != "" {
		out[ClaimedProjectLabel] = project
	}
	return out
}
