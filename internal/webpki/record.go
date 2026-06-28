package webpki

import (
	"context"
	"errors"
	"fmt"
	"os/exec"
	"strings"
)

// RecordManager publishes durable public DNS A records — distinct from the DNS-01
// challenge solver (which writes transient TXT). The funnel-DNS reconciler uses it
// to point funnel hostnames at the healthy relay pool, and to withdraw them on
// drain/release.
type RecordManager interface {
	// SetA publishes fqdn's A-record set, replacing any existing.
	SetA(ctx context.Context, fqdn string, ips []string) error
	// RemoveA deletes fqdn's A records.
	RemoveA(ctx context.Context, fqdn string) error
}

// NewRecordManager builds an A-record manager from the same provider config used
// for DNS-01. v1 implements the "exec" provider (a script, fully pluggable and
// testable); native cloudflare A-record management is a follow — until then a
// cloudflare deployment manages funnel A records statically (the reconciler skips
// the domain and logs it).
func NewRecordManager(d DNS01Config) (RecordManager, error) {
	switch d.Provider {
	case "exec":
		if d.Exec.Program == "" {
			return nil, errors.New("webpki: dns01.exec requires program")
		}
		return &execRecordManager{program: d.Exec.Program}, nil
	case "cloudflare":
		return newCloudflareRecordManager(d.Cloudflare)
	default:
		return nil, fmt.Errorf("webpki: no A-record manager for provider %q", d.Provider)
	}
}

// execRecordManager runs the operator's DNS script:
//
//	program set-a    <fqdn> <ip,ip,...>
//	program remove-a <fqdn>
type execRecordManager struct{ program string }

func (e *execRecordManager) SetA(ctx context.Context, fqdn string, ips []string) error {
	return e.run(ctx, "set-a", fqdn, strings.Join(ips, ","))
}

func (e *execRecordManager) RemoveA(ctx context.Context, fqdn string) error {
	return e.run(ctx, "remove-a", fqdn, "")
}

func (e *execRecordManager) run(ctx context.Context, verb, fqdn, ips string) error {
	args := []string{verb, fqdn}
	if ips != "" {
		args = append(args, ips)
	}
	cmd := exec.CommandContext(ctx, e.program, args...)
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("exec dns %s %s: %w (%s)", verb, fqdn, err, strings.TrimSpace(string(out)))
	}
	return nil
}
