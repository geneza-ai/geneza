package vpn

import (
	"fmt"
	"os/exec"
	"strings"
)

// SetLinkResolver points the system resolver at the local DNS stub for the
// tenant zone only (split DNS, MagicDNS-style), preferring systemd-resolved so
// teardown is a clean per-link revert and all other DNS is untouched. dnsIP is
// the stub's address (e.g. "127.0.0.54"); zone is the tenant suffix (e.g.
// "geneza"). Returns a revert func to push onto the VPN cleanup stack.
func SetLinkResolver(link, dnsIP, zone string) (revert func(), err error) {
	if _, e := exec.LookPath("resolvectl"); e == nil {
		// dns: send the link's queries to the stub. domain <zone> (no '~') makes
		// it both a SEARCH domain (so `host node1` -> node1.<zone>) and a routing
		// domain (so only *.<zone> goes to the stub).
		if out, e := exec.Command("resolvectl", "dns", link, dnsIP).CombinedOutput(); e != nil {
			return nil, fmt.Errorf("resolvectl dns: %v: %s", e, strings.TrimSpace(string(out)))
		}
		if out, e := exec.Command("resolvectl", "domain", link, zone).CombinedOutput(); e != nil {
			return nil, fmt.Errorf("resolvectl domain: %v: %s", e, strings.TrimSpace(string(out)))
		}
		return func() { _ = exec.Command("resolvectl", "revert", link).Run() }, nil
	}
	// No systemd-resolved: we deliberately do NOT rewrite global /etc/resolv.conf
	// from here (too blunt / racy to restore safely in a lab). Report it so the
	// caller can tell the user to point DNS at the stub manually.
	return nil, fmt.Errorf("systemd-resolved (resolvectl) not found; tenant DNS not auto-configured — query %s directly", dnsIP)
}
