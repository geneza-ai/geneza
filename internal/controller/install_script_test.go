package controller

import (
	"os/exec"
	"strings"
	"testing"
)

// Re-running the installer is how a node is re-enrolled after being retired: the
// enroll rewrites the identity and certs under /var/lib/geneza/agent. But
// `systemctl enable --now` only STARTS a unit, so it does nothing when one is
// already running — the supervisor keeps presenting the retired identity, the node
// never connects, and it shows offline until someone restarts it by hand.
//
// The unit must therefore be restarted, not merely started.
func TestInstallScriptRestartsTheSupervisorOnReEnrollment(t *testing.T) {
	// Match the command, not prose: the comment above it names the anti-pattern.
	if strings.Contains(installScript, "systemctl enable --now") {
		t.Error("install.sh uses `systemctl enable --now`, which is a no-op for an " +
			"already-running unit: a re-enrolled node keeps its retired identity and stays offline")
	}
	if !strings.Contains(installScript, "systemctl restart geneza-bootstrap") {
		t.Error("install.sh must restart geneza-bootstrap so a re-enrollment takes effect")
	}
	// Enabling is still required, or the node does not come back after a reboot.
	if !strings.Contains(installScript, "systemctl enable geneza-bootstrap") {
		t.Error("install.sh must still enable geneza-bootstrap so it survives a reboot")
	}
	// The restart has to come after the enroll rewrites the identity, otherwise it
	// restarts onto the old one and the bug survives in a subtler form.
	enroll := strings.Index(installScript, "geneza-agent enroll")
	restart := strings.Index(installScript, "systemctl restart geneza-bootstrap")
	if enroll < 0 || restart < 0 || restart < enroll {
		t.Errorf("the restart must follow the enroll (enroll=%d restart=%d)", enroll, restart)
	}
}

// The script is piped straight into `sh` on a fresh host, so a syntax error is a
// broken install for every node, not a test failure someone notices later.
func TestInstallScriptIsValidShell(t *testing.T) {
	sh, err := exec.LookPath("sh")
	if err != nil {
		t.Skip("no sh available")
	}
	body := strings.ReplaceAll(installScript, "__CONTROLLER_HTTP__", "https://geneza.example.com")
	cmd := exec.Command(sh, "-n")
	cmd.Stdin = strings.NewReader(body)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("install.sh is not valid shell: %v\n%s", err, out)
	}
}
