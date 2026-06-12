// Package vpn implements Geneza's L3 overlay: subnet-route and exit-node
// services that carry raw IP packets over the existing Noise tunnel between a
// client TUN and a node (the "subnet router" / "exit node"). It is the
// Tailscale-style mesh-VPN layer riding the same identity-aware, policy-gated,
// relay-or-direct data path as shells and service forwards.
//
// Platform support: the TUN device is Linux-first (the v1 server platform and
// the lab); macOS (utun) and Windows (wintun) are later backends behind the
// same TUN interface. The packet pump and framing are platform-independent.
package vpn

import (
	"io"
	"log/slog"

	"osie.cloud/geneza/internal/wire"
)

// MTU for the overlay TUN. Kept well under the tunnel's per-frame ceiling so a
// full IP packet always fits in a single encrypted frame.
const MTU = 1280

// TUN is a layer-3 packet device: Read/Write move whole IP packets (no
// platform packet-info header — configured with IFF_NO_PI on Linux).
type TUN interface {
	io.ReadWriteCloser
	Name() string
}

// Pump shuttles IP packets between a TUN device and a framed byte stream (the
// Noise tunnel): every TUN packet becomes one length-prefixed wire frame and
// vice versa. It runs until either side errors/closes, then returns. closeBoth
// is invoked once to tear down both ends so the second direction unblocks.
func Pump(tun TUN, conn io.ReadWriter, closeBoth func()) {
	done := make(chan struct{}, 2)
	// TUN -> tunnel
	go func() {
		buf := make([]byte, 65535)
		for {
			n, err := tun.Read(buf)
			if n > 0 {
				if werr := wire.WriteFrame(conn, buf[:n]); werr != nil {
					slog.Debug("vpn pump: tun->tunnel write err", "err", werr)
					break
				}
			}
			if err != nil {
				slog.Debug("vpn pump: tun read err", "err", err)
				break
			}
		}
		done <- struct{}{}
		closeBoth()
	}()
	// tunnel -> TUN
	go func() {
		for {
			pkt, err := wire.ReadFrameLimit(conn, 65535)
			if err != nil {
				slog.Debug("vpn pump: tunnel read err", "err", err)
				break
			}
			if _, werr := tun.Write(pkt); werr != nil {
				slog.Debug("vpn pump: tun write err", "err", werr)
				break
			}
		}
		done <- struct{}{}
		closeBoth()
	}()
	<-done
}
