package agentd

import (
	"crypto/sha256"
	"io"
	"os"
	"strings"
)

// measureSelf returns the SHA-256 of the agent's own running executable, which the
// agent reports on its heartbeat so the controller can detect a swapped binary (the
// controller pins the first measurement after approval and quarantines on a later
// mismatch). It prefers /proc/self/exe — the kernel's authoritative handle to the
// RUNNING image, so the measurement reflects what is actually executing rather than
// whatever bytes currently sit at the on-disk path — and falls back to os.Executable
// on platforms without procfs. Returns nil on any error; a heartbeat with no
// measurement just leaves the controller holding the last value (the controller treats a
// genuinely absent-but-required measurement, for an online node, as its own signal).
//
// The running image cannot change for the life of a process, so a caller measures
// once at startup and reuses the value; a binary swap only takes effect on restart,
// and the new process then measures the new (untrusted) image.
func measureSelf() []byte {
	f, err := os.Open("/proc/self/exe")
	if err != nil {
		exe, eerr := os.Executable()
		if eerr != nil {
			return nil
		}
		if f, err = os.Open(exe); err != nil {
			return nil
		}
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return nil
	}
	return h.Sum(nil)
}

// hostUUID returns the machine's stable hardware identifier — the DMI product UUID
// on Linux — reported once at enroll. The controller uses it ONLY as stable evidence
// for the quarantine re-enroll gate (a quarantined host that wipes its state and
// re-enrolls is recognized and held for admin review). Best-effort: empty when
// unreadable (non-Linux, unprivileged — the file is root-only — or no DMI). Never
// fabricated; an empty value just degrades the gate to node-id scope.
func hostUUID() string {
	b, err := os.ReadFile("/sys/class/dmi/id/product_uuid")
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(b))
}
