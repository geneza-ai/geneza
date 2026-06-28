//go:build windows

package platform

import (
	"strconv"
	"strings"

	"golang.org/x/sys/windows/registry"
)

// detect reads the canonical Windows version keys from the registry. Windows 11
// still reports a "Windows 10" ProductName on many builds, so we correct it from
// the build number (11 starts at build 22000).
func detect() Info {
	k, err := registry.OpenKey(
		registry.LOCAL_MACHINE,
		`SOFTWARE\Microsoft\Windows NT\CurrentVersion`,
		registry.QUERY_VALUE,
	)
	if err != nil {
		return Info{Distro: "windows"}
	}
	defer k.Close()

	product, _, _ := k.GetStringValue("ProductName") // "Windows 10 Pro"
	display, _, _ := k.GetStringValue("DisplayVersion")
	if display == "" {
		display, _, _ = k.GetStringValue("ReleaseId") // older builds
	}
	build, _, _ := k.GetStringValue("CurrentBuild")

	if n, err := strconv.Atoi(build); err == nil && n >= 22000 {
		product = strings.Replace(product, "Windows 10", "Windows 11", 1)
	}

	ver := display
	if ver == "" {
		ver = build
	}
	pretty := product
	if display != "" {
		pretty = strings.TrimSpace(product + " " + display)
	}
	return Info{Distro: "windows", Version: ver, Pretty: pretty}
}
