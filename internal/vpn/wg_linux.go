//go:build linux

package vpn

import (
	"fmt"
	"os/exec"
	"strings"

	"golang.zx2c4.com/wireguard/wgctrl"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

// wg_linux.go is the kernel-WireGuard backend for the per-Network data plane.
// One interface per Network (VNI); peers + keys come from the gateway's
// NetworkConfig push. Link lifecycle uses the same `ip` shell-out as the TUN
// path (ipCmd) for in-repo consistency; device configuration uses wgctrl
// (pure-Go netlink, CGO-free). Requires the `wireguard` kernel module + root.

// WGCreate adds a WireGuard link of the given name. Idempotent: an existing link
// of the same name is treated as success (reconcile re-applies config).
func WGCreate(name string) error {
	if wgLinkExists(name) {
		return nil
	}
	out, err := exec.Command("ip", "link", "add", name, "type", "wireguard").CombinedOutput()
	if err != nil {
		s := strings.TrimSpace(string(out))
		if strings.Contains(s, "File exists") {
			return nil
		}
		return fmt.Errorf("ip link add %s type wireguard (need root + wireguard module): %v: %s", name, err, s)
	}
	return nil
}

// WGConfigure sets the interface private key, listen port and the full peer set
// (ReplacePeers: the pushed set is authoritative — peers dropped by the gateway
// disappear from the device, which is how tag-removal severs access).
func WGConfigure(name string, priv wgtypes.Key, listenPort int, peers []wgtypes.PeerConfig) error {
	cl, err := wgctrl.New()
	if err != nil {
		return fmt.Errorf("wgctrl: %w", err)
	}
	defer cl.Close()
	cfg := wgtypes.Config{
		PrivateKey:   &priv,
		ReplacePeers: true,
		Peers:        peers,
	}
	if listenPort > 0 {
		cfg.ListenPort = &listenPort
	}
	if err := cl.ConfigureDevice(name, cfg); err != nil {
		return fmt.Errorf("configure wg device %s: %w", name, err)
	}
	return nil
}

// WGListenPort returns the kernel-assigned UDP listen port for a wg device (when
// configured with listenPort 0, the kernel picks one; the gateway needs it for
// endpoint discovery).
func WGListenPort(name string) (int, error) {
	cl, err := wgctrl.New()
	if err != nil {
		return 0, fmt.Errorf("wgctrl: %w", err)
	}
	defer cl.Close()
	dev, err := cl.Device(name)
	if err != nil {
		return 0, fmt.Errorf("wg device %s: %w", name, err)
	}
	return dev.ListenPort, nil
}

// WGSetAddr (re)assigns the interface overlay address and brings it up. Flushes
// first so a changed overlay IP is replaced cleanly; idempotent for an unchanged
// address. The connected route created by the /prefix carries same-subnet peer
// traffic to the device (out-of-subnet allowedIPs need explicit routes later).
func WGSetAddr(name, cidr string) error {
	_ = ipCmd("addr", "flush", "dev", name)
	if cidr != "" {
		if err := ipCmd("addr", "add", cidr, "dev", name); err != nil {
			return err
		}
	}
	return ipCmd("link", "set", "dev", name, "up")
}

// WGDelete removes a WireGuard link (best effort idempotent).
func WGDelete(name string) error {
	if !wgLinkExists(name) {
		return nil
	}
	return ipCmd("link", "del", name)
}

func wgLinkExists(name string) bool {
	return exec.Command("ip", "link", "show", name).Run() == nil
}
