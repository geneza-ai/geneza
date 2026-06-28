//go:build !linux

package vpn

import (
	"errors"

	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

// ErrWGUnsupported is returned by the WireGuard data-plane operations off Linux.
// The kernel-WG per-Network data plane is Linux-only in this build; macOS-utun
// WireGuard is the documented follow-up.
var ErrWGUnsupported = errors.New("geneza wireguard data plane: implemented on Linux only in this build")

func WGCreate(string) error                                            { return ErrWGUnsupported }
func WGConfigure(string, wgtypes.Key, int, []wgtypes.PeerConfig) error { return ErrWGUnsupported }
func WGListenPort(string) (int, error)                                 { return 0, ErrWGUnsupported }
func WGSetAddr(string, string) error                                   { return ErrWGUnsupported }
func WGDelete(string) error                                            { return ErrWGUnsupported }
