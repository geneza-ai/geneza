package client

import (
	"fmt"
	"io"
	"sort"
	"strings"
	"time"
)

// visibleLen is the column width of s ignoring ANSI SGR sequences, so a
// colored cell still aligns.
func visibleLen(s string) int {
	n, esc := 0, false
	for i := 0; i < len(s); i++ {
		switch {
		case esc:
			if s[i] == 'm' {
				esc = false
			}
		case s[i] == '\x1b':
			esc = true
		default:
			n++
		}
	}
	return n
}

// PrintTable writes a left-aligned, two-space-gapped column table.
func PrintTable(w io.Writer, header []string, rows [][]string) {
	widths := make([]int, len(header))
	for i, h := range header {
		widths[i] = visibleLen(h)
	}
	for _, r := range rows {
		for i, c := range r {
			if l := visibleLen(c); i < len(widths) && l > widths[i] {
				widths[i] = l
			}
		}
	}
	line := func(cells []string) {
		var b strings.Builder
		for i, c := range cells {
			if i > 0 {
				b.WriteString("  ")
			}
			if i == len(cells)-1 {
				b.WriteString(c) // no trailing padding
			} else {
				b.WriteString(c + strings.Repeat(" ", widths[i]-visibleLen(c)))
			}
		}
		fmt.Fprintln(w, b.String())
	}
	line(header)
	for _, r := range rows {
		line(r)
	}
}

// FormatLabels renders a label map as sorted k=v,k=v (or "-" when empty).
func FormatLabels(labels map[string]string) string {
	if len(labels) == 0 {
		return "-"
	}
	keys := make([]string, 0, len(labels))
	for k := range labels {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	parts := make([]string, len(keys))
	for i, k := range keys {
		parts[i] = k + "=" + labels[k]
	}
	return strings.Join(parts, ",")
}

// Ago humanizes a unix timestamp as a relative age ("42s", "5m", "3h", "2d").
func Ago(unix int64) string {
	if unix <= 0 {
		return "-"
	}
	d := time.Since(time.Unix(unix, 0))
	if d < 0 {
		d = 0
	}
	switch {
	case d < time.Minute:
		return fmt.Sprintf("%ds", int(d.Seconds()))
	case d < time.Hour:
		return fmt.Sprintf("%dm", int(d.Minutes()))
	case d < 48*time.Hour:
		return fmt.Sprintf("%dh", int(d.Hours()))
	default:
		return fmt.Sprintf("%dd", int(d.Hours()/24))
	}
}
