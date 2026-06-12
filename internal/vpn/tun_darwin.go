//go:build darwin

package vpn

import (
	"encoding/binary"
	"fmt"
	"os/exec"
	"strings"

	"golang.org/x/sys/unix"
)

// macOS utun backend for the CLIENT side of the overlay (a Mac laptop joining a
// node's subnet route or exit node). Node-side operations (forwarding,
// masquerade) are Linux-only — a Mac is never a Geneza subnet router/exit node
// in this product — so those return ErrUnsupported here.
//
// utun framing differs from Linux: every packet on the kernel interface is
// prefixed with a 4-byte protocol family (AF_INET / AF_INET6). darwinTUN strips
// it on Read and prepends it on Write so the rest of the stack (vpn.Pump) sees
// raw IP packets exactly like the Linux IFF_NO_PI device.

var ErrUnsupported = fmt.Errorf("geneza vpn: operation is Linux-only (node side)")

// Fixed kernel constants not exported by x/sys/unix on darwin (from
// <sys/sys_domain.h> and <net/if_utun.h>).
const (
	sysprotoControl = 2 // SYSPROTO_CONTROL
	utunOptIfname   = 2 // UTUN_OPT_IFNAME
)

type darwinTUN struct {
	fd   int
	name string
}

// OpenTUN opens a utun device via the PF_SYSTEM control socket. nameHint is
// ignored (macOS assigns utunN); requires root. Returns a TUN whose Read/Write
// move raw IP packets (the 4-byte AF header is handled internally).
func OpenTUN(string) (TUN, error) {
	fd, err := unix.Socket(unix.AF_SYSTEM, unix.SOCK_DGRAM, sysprotoControl)
	if err != nil {
		return nil, fmt.Errorf("utun socket (need root): %w", err)
	}
	ctlInfo := &unix.CtlInfo{}
	copy(ctlInfo.Name[:], "com.apple.net.utun_control")
	if err := unix.IoctlCtlInfo(fd, ctlInfo); err != nil {
		unix.Close(fd)
		return nil, fmt.Errorf("utun CTLIOCGINFO: %w", err)
	}
	// sc_unit 0 lets the kernel pick the next free utunN.
	if err := unix.Connect(fd, &unix.SockaddrCtl{ID: ctlInfo.Id, Unit: 0}); err != nil {
		unix.Close(fd)
		return nil, fmt.Errorf("utun connect: %w", err)
	}
	name, err := unix.GetsockoptString(fd, sysprotoControl, utunOptIfname)
	if err != nil {
		unix.Close(fd)
		return nil, fmt.Errorf("utun ifname: %w", err)
	}
	return &darwinTUN{fd: fd, name: name}, nil
}

func (t *darwinTUN) Read(p []byte) (int, error) {
	buf := make([]byte, len(p)+4)
	n, err := unix.Read(t.fd, buf)
	if err != nil {
		return 0, err
	}
	if n < 4 {
		return 0, nil
	}
	return copy(p, buf[4:n]), nil
}

func (t *darwinTUN) Write(p []byte) (int, error) {
	// Prepend the 4-byte address family (AF_INET / AF_INET6) the kernel expects.
	af := uint32(unix.AF_INET)
	if len(p) > 0 && p[0]>>4 == 6 {
		af = uint32(unix.AF_INET6)
	}
	buf := make([]byte, len(p)+4)
	binary.BigEndian.PutUint32(buf[:4], af)
	copy(buf[4:], p)
	if _, err := unix.Write(t.fd, buf); err != nil {
		return 0, err
	}
	return len(p), nil
}

func (t *darwinTUN) Name() string { return t.name }
func (t *darwinTUN) Close() error { return unix.Close(t.fd) }

func ifconfig(args ...string) error {
	out, err := exec.Command("ifconfig", args...).CombinedOutput()
	if err != nil {
		return fmt.Errorf("ifconfig %s: %v: %s", strings.Join(args, " "), err, strings.TrimSpace(string(out)))
	}
	return nil
}

func routeCmd(args ...string) error {
	out, err := exec.Command("route", args...).CombinedOutput()
	if err != nil {
		return fmt.Errorf("route %s: %v: %s", strings.Join(args, " "), err, strings.TrimSpace(string(out)))
	}
	return nil
}

// LinkUpAddr brings the utun up with a point-to-point overlay address. addrCIDR
// is "<ip>/<prefix>"; macOS utun wants `ifconfig utunN inet <ip> <ip> up`.
func LinkUpAddr(name, addrCIDR string) error {
	if addrCIDR == "" {
		return ifconfig(name, "up")
	}
	ip := addrCIDR
	if i := strings.IndexByte(addrCIDR, '/'); i >= 0 {
		ip = addrCIDR[:i]
	}
	return ifconfig(name, "inet", ip, ip, "up")
}

// AddRoute routes cidr through the named utun device.
func AddRoute(cidr, dev string) error { return routeCmd("-n", "add", "-net", cidr, "-interface", dev) }

// RouteVia pins a host/cidr to a specific gateway (keeps the encrypted tunnel
// off the overlay when installing a default route via an exit node).
func RouteVia(cidr, gw string) error { return routeCmd("-n", "add", "-net", cidr, gw) }

// DelRoute removes a route through a device (best effort).
func DelRoute(cidr, dev string) { _ = routeCmd("-n", "delete", "-net", cidr, "-interface", dev) }

// RemoveRoute removes a route by destination only (best effort).
func RemoveRoute(cidr string) { _ = routeCmd("-n", "delete", "-net", cidr) }

// DefaultGateway returns the current default gateway IP (for the exit-node split).
func DefaultGateway() (string, error) {
	out, err := exec.Command("route", "-n", "get", "default").Output()
	if err != nil {
		return "", err
	}
	for _, line := range strings.Split(string(out), "\n") {
		f := strings.Fields(line)
		if len(f) == 2 && f[0] == "gateway:" {
			return f[1], nil
		}
	}
	return "", fmt.Errorf("no default gateway")
}

// ---- node-side ops: Linux-only, not reachable from a macOS client ----

func EnableForwarding() error                              { return ErrUnsupported }
func EgressInterface(string) (string, error)               { return "", ErrUnsupported }
func NodeRouteFor(string, string, []string) (func(), error) { return nil, ErrUnsupported }
