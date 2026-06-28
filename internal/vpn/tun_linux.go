//go:build linux

package vpn

import (
	"fmt"
	"os"
	"os/exec"
	"strings"
	"unsafe"

	"golang.org/x/sys/unix"
)

type linuxTUN struct {
	f    *os.File
	name string
}

// ifreq layout for TUNSETIFF.
type ifreqFlags struct {
	name  [unix.IFNAMSIZ]byte
	flags uint16
	_     [22]byte
}

// OpenTUN creates a TUN device (IFF_TUN | IFF_NO_PI -> raw IP packets). nameHint
// is a desired interface name (the kernel may pick a suffix). Requires
// CAP_NET_ADMIN (root).
//
// The fd is opened raw, the TUNSETIFF ioctl runs on it, and then it is set
// non-blocking BEFORE being wrapped in an *os.File. This is the wireguard-go
// pattern and is load-bearing: if a blocking fd is handed to os.OpenFile the Go
// runtime registers it with the netpoller in an inconsistent state and Read
// fails intermittently with "/dev/net/tun: not pollable" whenever no packet is
// already queued — which silently kills idle VPN tunnels. SetNonblock first
// makes the poller manage the fd correctly (and Close cleanly unblocks reads).
func OpenTUN(nameHint string) (TUN, error) {
	fd, err := unix.Open("/dev/net/tun", unix.O_RDWR|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, fmt.Errorf("open /dev/net/tun (need root/CAP_NET_ADMIN): %w", err)
	}
	var req ifreqFlags
	copy(req.name[:], nameHint)
	req.flags = unix.IFF_TUN | unix.IFF_NO_PI
	if _, _, errno := unix.Syscall(unix.SYS_IOCTL, uintptr(fd), unix.TUNSETIFF, uintptr(unsafe.Pointer(&req))); errno != 0 {
		unix.Close(fd)
		return nil, fmt.Errorf("TUNSETIFF: %w", errno)
	}
	if err := unix.SetNonblock(fd, true); err != nil {
		unix.Close(fd)
		return nil, fmt.Errorf("set tun non-blocking: %w", err)
	}
	name := strings.TrimRight(string(req.name[:]), "\x00")
	t := &linuxTUN{f: os.NewFile(uintptr(fd), "/dev/net/tun"), name: name}
	if err := ipCmd("link", "set", "dev", name, "mtu", fmt.Sprint(MTU)); err != nil {
		t.Close()
		return nil, err
	}
	return t, nil
}

func (t *linuxTUN) Read(p []byte) (int, error)  { return t.f.Read(p) }
func (t *linuxTUN) Write(p []byte) (int, error) { return t.f.Write(p) }
func (t *linuxTUN) Name() string                { return t.name }
func (t *linuxTUN) Close() error                { return t.f.Close() }

func ipCmd(args ...string) error {
	out, err := exec.Command("ip", args...).CombinedOutput()
	if err != nil {
		return fmt.Errorf("ip %s: %v: %s", strings.Join(args, " "), err, strings.TrimSpace(string(out)))
	}
	return nil
}

func sysctl(key, val string) error {
	return os.WriteFile("/proc/sys/"+strings.ReplaceAll(key, ".", "/"), []byte(val), 0o644)
}

func iptables(args ...string) error {
	out, err := exec.Command("iptables", args...).CombinedOutput()
	if err != nil {
		return fmt.Errorf("iptables %s: %v: %s", strings.Join(args, " "), err, strings.TrimSpace(string(out)))
	}
	return nil
}

// LinkUpAddr brings a TUN up with an optional /32 address.
func LinkUpAddr(name, addrCIDR string) error {
	if addrCIDR != "" {
		if err := ipCmd("addr", "add", addrCIDR, "dev", name); err != nil {
			return err
		}
	}
	return ipCmd("link", "set", "dev", name, "up")
}

// AddRoute routes cidr through the named device.
func AddRoute(cidr, dev string) error { return ipCmd("route", "add", cidr, "dev", dev) }

// RouteVia pins a host/cidr to a specific controller (used to keep the tunnel's
// own traffic off the tunnel when installing a default route via an exit node).
func RouteVia(cidr, gw string) error { return ipCmd("route", "add", cidr, "via", gw) }

// DelRoute removes a route (best effort).
func DelRoute(cidr, dev string) { _ = ipCmd("route", "del", cidr, "dev", dev) }

// RemoveRoute removes a route by destination only (best effort) — used for the
// exit-node relay pin that was installed "via <gw>" with no device.
func RemoveRoute(cidr string) { _ = ipCmd("route", "del", cidr) }

// DefaultGateway returns the current default gateway IP (for exit-node split).
func DefaultGateway() (string, error) {
	out, err := exec.Command("ip", "route", "show", "default").Output()
	if err != nil {
		return "", err
	}
	fields := strings.Fields(string(out))
	for i, f := range fields {
		if f == "via" && i+1 < len(fields) {
			return fields[i+1], nil
		}
	}
	return "", fmt.Errorf("no default gateway")
}

// EnableForwarding turns on IPv4 forwarding (node/subnet-router side).
func EnableForwarding() error { return sysctl("net.ipv4.ip_forward", "1") }

// EgressInterface returns the interface used to reach addr (e.g. the route to a
// subnet CIDR's first host, or to the internet for an exit node).
func EgressInterface(probeIP string) (string, error) {
	out, err := exec.Command("ip", "route", "get", probeIP).Output()
	if err != nil {
		return "", err
	}
	fields := strings.Fields(string(out))
	for i, f := range fields {
		if f == "dev" && i+1 < len(fields) {
			return fields[i+1], nil
		}
	}
	return "", fmt.Errorf("no egress interface for %s", probeIP)
}

// NodeRouteFor wires the node side for one VPN client: route the client's
// overlay IP back to the TUN, enable forwarding, and SNAT/masquerade the
// client's packets out each egress interface so replies return. egressIfs is
// the set of interfaces used to reach the advertised routes (deduplicated by
// the caller). Returns a cleanup func that removes every rule it installed.
func NodeRouteFor(tunName, clientOverlayIP string, egressIfs []string) (func(), error) {
	if err := EnableForwarding(); err != nil {
		return nil, err
	}
	if err := AddRoute(clientOverlayIP+"/32", tunName); err != nil {
		return nil, err
	}
	var installed [][]string
	cleanup := func() {
		for _, masq := range installed {
			del := append([]string{"-t", "nat", "-D", "POSTROUTING"}, masq[4:]...)
			_ = iptables(del...)
		}
		DelRoute(clientOverlayIP+"/32", tunName)
	}
	for _, egressIf := range egressIfs {
		masq := []string{"-t", "nat", "-A", "POSTROUTING", "-s", clientOverlayIP + "/32", "-o", egressIf, "-j", "MASQUERADE"}
		if err := iptables(masq...); err != nil {
			cleanup()
			return nil, err
		}
		installed = append(installed, masq)
	}
	return cleanup, nil
}
