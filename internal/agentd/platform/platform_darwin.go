//go:build darwin

package platform

import (
	"os"
	"regexp"
)

// detect reads the system version plist directly (no exec, no plist dependency)
// and pulls the product name/version/build keys.
func detect() Info {
	const plist = "/System/Library/CoreServices/SystemVersion.plist"
	data, err := os.ReadFile(plist)
	if err != nil {
		return Info{Distro: "macos"}
	}
	name := plistString(data, "ProductName") // "macOS" (or "Mac OS X" on old releases)
	ver := plistString(data, "ProductVersion")
	build := plistString(data, "ProductBuildVersion")
	if name == "" {
		name = "macOS"
	}
	pretty := name
	if ver != "" {
		pretty += " " + ver
	}
	if build != "" {
		pretty += " (" + build + ")"
	}
	return Info{Distro: "macos", Version: ver, Pretty: pretty}
}

// plistString extracts the <string> value following a given <key> in an Apple
// XML plist. The system version plist is flat, so a positional match is enough.
func plistString(b []byte, key string) string {
	re := regexp.MustCompile(`(?s)<key>` + regexp.QuoteMeta(key) + `</key>\s*<string>(.*?)</string>`)
	m := re.FindSubmatch(b)
	if m == nil {
		return ""
	}
	return string(m[1])
}
