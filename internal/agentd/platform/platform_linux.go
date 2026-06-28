//go:build linux

package platform

import (
	"bufio"
	"os"
	"strings"
)

// detect reads os-release (the freedesktop standard present on essentially every
// modern Linux), preferring /etc/os-release and falling back to the stateless
// /usr/lib copy.
func detect() Info {
	for _, p := range []string{"/etc/os-release", "/usr/lib/os-release"} {
		if info, ok := parseOSRelease(p); ok {
			return info
		}
	}
	return Info{}
}

func parseOSRelease(path string) (Info, bool) {
	f, err := os.Open(path)
	if err != nil {
		return Info{}, false
	}
	defer f.Close()

	kv := map[string]string{}
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		k, v, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		// Values may be shell-quoted with single or double quotes.
		kv[k] = strings.Trim(strings.TrimSpace(v), `"'`)
	}

	id := kv["ID"]
	if id == "" {
		return Info{}, false
	}
	return Info{
		Distro:  strings.ToLower(id),
		Version: kv["VERSION_ID"],
		Pretty:  kv["PRETTY_NAME"],
	}, true
}
