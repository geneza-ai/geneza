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
