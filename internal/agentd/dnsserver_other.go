//go:build !linux

package agentd

import (
	"errors"
	"net"
)

// bindResolverSocket is Linux-only for now. The macOS (/etc/resolver) + Windows
// (NRPT) resolver wiring is the cross-platform follow-up; the agent itself runs
// on Linux today.
func bindResolverSocket() (net.PacketConn, error) {
	return nil, errors.New("in-network DNS resolver: Linux only for now")
}

func releaseResolverAddr() {}
