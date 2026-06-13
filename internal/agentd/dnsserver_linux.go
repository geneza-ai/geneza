//go:build linux

package agentd

import (
	"context"
	"net"
	"os/exec"
	"syscall"

	"golang.org/x/sys/unix"
)

// bindResolverSocket assigns the resolver IP host-locally (a /32 on lo) and binds
// the UDP:53 socket to the loopback device via SO_BINDTODEVICE — so host apps reach
// it (queries to 100.64.0.53 route to lo) but a packet arriving on a gnzw overlay
// interface for .53 is NOT delivered to it: a peer cannot query another node's
// resolver. Requires CAP_NET_ADMIN/root (the agent already has it for TUN/WG).
func bindResolverSocket() (net.PacketConn, error) {
	// Idempotent: ignore "RTNETLINK answers: File exists".
	_ = exec.Command("ip", "addr", "add", dnsResolverIP+"/32", "dev", "lo").Run()
	lc := net.ListenConfig{
		Control: func(_, _ string, c syscall.RawConn) error {
			var serr error
			if err := c.Control(func(fd uintptr) {
				serr = unix.SetsockoptString(int(fd), unix.SOL_SOCKET, unix.SO_BINDTODEVICE, "lo")
			}); err != nil {
				return err
			}
			return serr
		},
	}
	return lc.ListenPacket(context.Background(), "udp", dnsResolverListen)
}

func releaseResolverAddr() {
	_ = exec.Command("ip", "addr", "del", dnsResolverIP+"/32", "dev", "lo").Run()
}
