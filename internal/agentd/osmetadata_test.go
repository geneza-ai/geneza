package agentd

import (
	"context"
	"testing"
	"time"
)

// A mixed fleet is the normal case: bare metal, other clouds, and networks that
// blackhole link-local all have no metadata service. Enrollment must not depend on
// being an OpenStack VM, and — because 169.254.169.254 is far more often dropped
// than refused — it must not stall either.
func TestOpenStackClaimsIsSilentAndPromptWithoutAMetadataService(t *testing.T) {
	start := time.Now()
	got := OpenStackClaims(context.Background())
	elapsed := time.Since(start)

	// A CI runner has no OpenStack metadata service. If one somehow answers, the
	// only thing to assert is that the shape is right.
	if got != nil {
		if got[ClaimedInstanceLabel] == "" {
			t.Fatalf("returned claims without an instance: %v", got)
		}
		return
	}
	if elapsed > 10*time.Second {
		t.Fatalf("took %v with no metadata service; every non-OpenStack enrollment would stall", elapsed)
	}
}

// The claim must land in the untrusted namespace. The controller drops anything
// starting with "os:", so a claim named os:instance would be silently discarded and
// the cross-check would never fire.
func TestClaimLabelsUseTheUntrustedNamespace(t *testing.T) {
	for _, k := range []string{ClaimedInstanceLabel, ClaimedProjectLabel} {
		if len(k) < 3 || k[:3] != "os." {
			t.Errorf("%q is not in the os.claim: namespace", k)
		}
		if len(k) >= 3 && k[:3] == "os:" {
			t.Errorf("%q is in the reserved trusted namespace and would be dropped", k)
		}
	}
}

// A cancelled context must not leave the caller waiting on the dial.
func TestOpenStackClaimsRespectsContext(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if got := OpenStackClaims(ctx); got != nil {
		t.Fatalf("expected no claims from a cancelled context, got %v", got)
	}
}

// A VM whose 169.254.169.254 path is unreachable is very likely on a CONFIG DRIVE
// instead (docs/openstack-integration.md §4 gotcha 2). cloud-init normalises both
// into one file, so reading that covers config drive without the agent mounting
// config-2. Shape below is taken verbatim from a real OpenStack VM.
func TestCloudInitFallbackCoversConfigDrive(t *testing.T) {
	const real = `{
      "v1": {"instance_id": "af78268f-32e9-4a96-b9c0-92fee3fe286f",
             "cloud_name": "openstack", "platform": "openstack"},
      "ds": {"meta_data": {"uuid": "af78268f-32e9-4a96-b9c0-92fee3fe286f",
                           "project_id": "71f5edaa1c1d4ffb88406b608e052cb3"}}}`

	for _, tc := range []struct {
		name         string
		body         string
		wantInstance string
		wantProject  string
	}{
		{"real OpenStack VM", real,
			"af78268f-32e9-4a96-b9c0-92fee3fe286f", "71f5edaa1c1d4ffb88406b608e052cb3"},
		// Older cloud-init, or a datasource that exposes less, still yields the id.
		{"falls back to v1.instance_id",
			`{"v1":{"instance_id":"abc-123","cloud_name":"openstack"}}`, "abc-123", ""},
		// cloud-init writes this file on every cloud. An EC2 instance id is not a Nova
		// uuid, and claiming it in the OpenStack namespace would be a lie.
		{"other clouds claim nothing",
			`{"v1":{"instance_id":"i-0abc","cloud_name":"aws","platform":"ec2"},
              "ds":{"meta_data":{"uuid":"i-0abc"}}}`, "", ""},
		{"no identity at all", `{"v1":{"cloud_name":"openstack"}}`, "", ""},
		{"malformed", `not json`, "", ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := parseCloudInitClaims([]byte(tc.body))
			if tc.wantInstance == "" {
				if got != nil {
					t.Fatalf("expected no claims, got %v", got)
				}
				return
			}
			if got[ClaimedInstanceLabel] != tc.wantInstance {
				t.Errorf("instance = %q, want %q", got[ClaimedInstanceLabel], tc.wantInstance)
			}
			if got[ClaimedProjectLabel] != tc.wantProject {
				t.Errorf("project = %q, want %q", got[ClaimedProjectLabel], tc.wantProject)
			}
		})
	}
}
