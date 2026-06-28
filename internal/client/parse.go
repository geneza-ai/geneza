package client

import (
	"fmt"
	"net"
	"strconv"
	"strings"
)

// SplitRemote parses scp-style "NODE:PATH" specs. A spec is remote when it
// contains a ':' and the part before the first ':' is a plausible node name —
// non-empty and without '/' (so "./weird:file" and "/tmp/a:b" stay local).
func SplitRemote(spec string) (node, path string, remote bool) {
	i := strings.IndexByte(spec, ':')
	if i <= 0 {
		return "", spec, false
	}
	prefix := spec[:i]
	if strings.ContainsAny(prefix, "/\\") {
		return "", spec, false
	}
	return prefix, spec[i+1:], true
}

// ParseForwardSpec parses "LOCAL_PORT:TARGET_HOST:TARGET_PORT" and returns
// the local port plus the normalized (net.JoinHostPort) target. IPv6 target
// hosts use brackets: "8080:[::1]:80".
func ParseForwardSpec(spec string) (localPort int, target string, err error) {
	i := strings.IndexByte(spec, ':')
	if i < 0 {
		return 0, "", fmt.Errorf("forward spec %q: want LOCAL_PORT:TARGET_HOST:TARGET_PORT", spec)
	}
	localPort, err = strconv.Atoi(spec[:i])
	if err != nil || localPort < 1 || localPort > 65535 {
		return 0, "", fmt.Errorf("forward spec %q: bad local port %q", spec, spec[:i])
	}
	host, portStr, err := net.SplitHostPort(spec[i+1:])
	if err != nil {
		return 0, "", fmt.Errorf("forward spec %q: bad target: %v", spec, err)
	}
	if host == "" {
		return 0, "", fmt.Errorf("forward spec %q: empty target host", spec)
	}
	port, err := strconv.Atoi(portStr)
	if err != nil || port < 1 || port > 65535 {
		return 0, "", fmt.Errorf("forward spec %q: bad target port %q", spec, portStr)
	}
	return localPort, net.JoinHostPort(host, portStr), nil
}

// shellSafe matches argv words that need no quoting in POSIX sh.
func shellSafe(s string) bool {
	if s == "" {
		return false
	}
	for _, r := range s {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9':
		case strings.ContainsRune("@%+=:,./_-", r):
		default:
			return false
		}
	}
	return true
}

// ShellJoin joins argv into a single sh -c command line, single-quoting any
// word the shell would otherwise interpret. This is what 'geneza exec' sends
// as the session command (the agent runs commands through the user's shell).
func ShellJoin(argv []string) string {
	parts := make([]string, len(argv))
	for i, a := range argv {
		if shellSafe(a) {
			parts[i] = a
			continue
		}
		// In single quotes everything is literal except ' itself: close,
		// emit an escaped quote, reopen.
		parts[i] = "'" + strings.ReplaceAll(a, "'", `'\''`) + "'"
	}
	return strings.Join(parts, " ")
}
