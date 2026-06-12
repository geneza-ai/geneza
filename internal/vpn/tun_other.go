//go:build !linux && !darwin

package vpn

import "errors"

// ErrUnsupported is returned by the TUN operations on platforms whose backend
// is not yet wired (Linux and macOS are implemented; Windows wintun is a later
// phase).
var ErrUnsupported = errors.New("geneza vpn: TUN devices are implemented on Linux and macOS only in this build")

func OpenTUN(string) (TUN, error)                         { return nil, ErrUnsupported }
func LinkUpAddr(string, string) error                     { return ErrUnsupported }
func AddRoute(string, string) error                       { return ErrUnsupported }
func RouteVia(string, string) error                       { return ErrUnsupported }
func DelRoute(string, string)                             {}
func RemoveRoute(string)                                  {}
func DefaultGateway() (string, error)                     { return "", ErrUnsupported }
func EnableForwarding() error                             { return ErrUnsupported }
func EgressInterface(string) (string, error)              { return "", ErrUnsupported }
func NodeRouteFor(string, string, []string) (func(), error) { return nil, ErrUnsupported }
