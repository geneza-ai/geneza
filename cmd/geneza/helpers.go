package main

import (
	"fmt"
	"strings"
)

// orDash renders an empty string as "-" in tables.
func orDash(s string) string {
	if s == "" {
		return "-"
	}
	return s
}

// orStr returns a, or b when a is empty.
func orStr(a, b string) string {
	if a != "" {
		return a
	}
	return b
}

// parseLabels parses a k=v,k2=v2 label string into a map.
func parseLabels(s string) (map[string]string, error) {
	if s == "" {
		return nil, nil
	}
	out := map[string]string{}
	for _, kv := range strings.Split(s, ",") {
		k, v, ok := strings.Cut(strings.TrimSpace(kv), "=")
		if !ok || k == "" {
			return nil, fmt.Errorf("bad label %q (want k=v,...)", kv)
		}
		out[k] = v
	}
	return out, nil
}
