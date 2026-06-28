//go:build !linux

package vpn

import "fmt"

// SetLinkResolver is Linux-only for now (systemd-resolved split DNS). macOS
// (scutil / /etc/resolver/<zone>) and Windows are future work.
func SetLinkResolver(link, dnsIP, zone string) (revert func(), err error) {
	return nil, fmt.Errorf("tenant DNS auto-config is only implemented on Linux; query %s directly", dnsIP)
}
