package main

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"geneza.io/internal/defaults"
)

// detect-public-ip helps the operator set the relay's funnel public IP. There is
// no automatic source that reliably yields the public INGRESS address (the
// controller↔relay path may be a management VLAN; even a public egress probe differs
// from the ingress IP behind an LB; the address may live in the cloud's NAT table,
// not on a local NIC). So this gathers CANDIDATES and the operator CONFIRMS — the
// authoritative choice is theirs. The result is written to relay.yaml's public_ip;
// a relay with no public_ip simply cannot serve funnel.

type ipCandidate struct {
	ip    string
	label string
}

// localIPv4s returns the machine's non-loopback, non-link-local IPv4 interface
// addresses (the directly-attached / bare-metal case).
func localIPv4s() []string {
	ifaces, err := net.Interfaces()
	if err != nil {
		return nil
	}
	var out []string
	for _, ifc := range ifaces {
		if ifc.Flags&net.FlagUp == 0 || ifc.Flags&net.FlagLoopback != 0 {
			continue
		}
		addrs, _ := ifc.Addrs()
		for _, a := range addrs {
			var ip net.IP
			switch v := a.(type) {
			case *net.IPNet:
				ip = v.IP
			case *net.IPAddr:
				ip = v.IP
			}
			v4 := ip.To4()
			if v4 == nil || ip.IsLoopback() || ip.IsLinkLocalUnicast() {
				continue
			}
			out = append(out, v4.String())
		}
	}
	return out
}

// ipClass labels an address "public" or "private" (RFC-1918/ULA + CGNAT 100.64/10,
// which is Geneza's overlay space).
func ipClass(s string) string {
	ip := net.ParseIP(s)
	if ip == nil {
		return ""
	}
	if ip.IsPrivate() {
		return "private"
	}
	if v4 := ip.To4(); v4 != nil && v4[0] == 100 && v4[1] >= 64 && v4[1] <= 127 {
		return "private" // CGNAT / overlay
	}
	return "public"
}

// discoverEgressIP calls a public whoami service and parses the IP it reports
// (JSON {"ip":...} or a bare address). This is the relay's EGRESS IP — only equal
// to the ingress IP for symmetric (elastic-IP / 1:1-NAT) relays.
func discoverEgressIP(ctx context.Context, client *http.Client, url string) (string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return "", err
	}
	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
	var j struct {
		IP string `json:"ip"`
	}
	if json.Unmarshal(body, &j) == nil {
		if ip := strings.TrimSpace(j.IP); net.ParseIP(ip) != nil {
			return ip, nil
		}
	}
	if s := strings.TrimSpace(string(body)); net.ParseIP(s) != nil {
		return s, nil
	}
	return "", fmt.Errorf("no IP in response from %s", url)
}

// buildCandidates orders the choices: the public egress hint first (recommended
// for the common case), then public local interfaces, then private ones.
func buildCandidates(local []string, egress string) []ipCandidate {
	var out []ipCandidate
	seen := map[string]bool{}
	add := func(ip, label string) {
		if ip == "" || seen[ip] || net.ParseIP(ip) == nil {
			return
		}
		seen[ip] = true
		out = append(out, ipCandidate{ip, label})
	}
	if ipClass(egress) == "public" {
		add(egress, "public egress IP (from the whoami service) — correct UNLESS your relay is behind a separate ingress/LB")
	} else if egress != "" {
		add(egress, "egress IP (looks private — likely not your public address)")
	}
	for _, ip := range local {
		if ipClass(ip) == "public" {
			add(ip, "local interface (public)")
		}
	}
	for _, ip := range local {
		if ipClass(ip) == "private" {
			add(ip, "local interface (private — only if a 1:1 NAT / elastic IP maps it publicly)")
		}
	}
	return out
}

// promptSelect presents candidates and reads the operator's choice (a number, a
// typed IP, or "c" to enter a custom one). Empty input takes the first candidate.
func promptSelect(out io.Writer, in io.Reader, candidates []ipCandidate) (string, error) {
	fmt.Fprintln(out, "Select the relay's PUBLIC IP — the address funnel clients resolve to.")
	fmt.Fprintln(out, "Only you know this for sure; the entries below are candidates, not guarantees.")
	for i, c := range candidates {
		fmt.Fprintf(out, "  [%d] %-15s  %s\n", i+1, c.ip, c.label)
	}
	fmt.Fprintln(out, "  [c] enter a custom IP")
	def := ""
	if len(candidates) > 0 {
		def = candidates[0].ip
		fmt.Fprint(out, "Choice [1]: ")
	} else {
		fmt.Fprint(out, "Enter the public IP: ")
	}
	sc := bufio.NewScanner(in)
	if !sc.Scan() {
		if def != "" {
			return def, nil
		}
		return "", errors.New("a public IP is required")
	}
	line := strings.TrimSpace(sc.Text())
	switch {
	case line == "" && def != "":
		return def, nil
	case line == "":
		return "", errors.New("a public IP is required")
	case line == "c" || line == "C":
		fmt.Fprint(out, "Enter IP: ")
		if !sc.Scan() {
			return "", errors.New("no input")
		}
		ip := strings.TrimSpace(sc.Text())
		if net.ParseIP(ip) == nil {
			return "", fmt.Errorf("invalid IP %q", ip)
		}
		return ip, nil
	case net.ParseIP(line) != nil:
		return line, nil
	}
	n, err := strconv.Atoi(line)
	if err != nil || n < 1 || n > len(candidates) {
		return "", fmt.Errorf("invalid choice %q", line)
	}
	return candidates[n-1].ip, nil
}

// writePublicIP sets relay.yaml's public_ip line (replacing or appending),
// preserving the rest of the file.
func writePublicIP(path, ip string) error {
	b, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	lines := strings.Split(string(b), "\n")
	for i, l := range lines {
		trimmed := strings.TrimLeft(l, " \t")
		if strings.HasPrefix(trimmed, "public_ip:") {
			indent := l[:len(l)-len(trimmed)]
			lines[i] = indent + "public_ip: " + ip
			return os.WriteFile(path, []byte(strings.Join(lines, "\n")), 0o644)
		}
	}
	content := string(b)
	if content != "" && !strings.HasSuffix(content, "\n") {
		content += "\n"
	}
	content += "public_ip: " + ip + "\n"
	return os.WriteFile(path, []byte(content), 0o644)
}

func newDetectPublicIPCmd() *cobra.Command {
	var configPath, publicIP, service string
	var printOnly bool
	cmd := &cobra.Command{
		Use:   "detect-public-ip",
		Short: "Choose and record the relay's public IP for funnel (operator-confirmed)",
		Long: "Gathers candidate addresses (local interfaces, and an optional public " +
			"egress probe) and asks you to confirm the relay's public ingress IP — the " +
			"address funnel clients resolve to. There is no fully reliable automatic " +
			"source, so the choice is yours. The result is written to relay.yaml's " +
			"public_ip; a relay without one cannot serve funnel.",
		RunE: func(cmd *cobra.Command, _ []string) error {
			var chosen string
			if publicIP != "" {
				if net.ParseIP(publicIP) == nil {
					return fmt.Errorf("invalid --public-ip %q", publicIP)
				}
				chosen = publicIP
			} else {
				var egress string
				if service != "" {
					ctx, cancel := context.WithTimeout(cmd.Context(), 10*time.Second)
					if ip, err := discoverEgressIP(ctx, http.DefaultClient, service); err == nil {
						egress = ip
					} else {
						fmt.Fprintln(os.Stderr, "warning: egress probe failed:", err)
					}
					cancel()
				}
				ip, err := promptSelect(os.Stdout, os.Stdin, buildCandidates(localIPv4s(), egress))
				if err != nil {
					return err
				}
				chosen = ip
			}
			if printOnly {
				fmt.Println(chosen)
				return nil
			}
			if err := writePublicIP(configPath, chosen); err != nil {
				return fmt.Errorf("write %s: %w", configPath, err)
			}
			fmt.Printf("public_ip: %s written to %s\n", chosen, configPath)
			return nil
		},
	}
	cmd.Flags().StringVar(&configPath, "config", filepath.Join(defaults.EtcDir, "relay.yaml"), "relay.yaml to update")
	cmd.Flags().StringVar(&publicIP, "public-ip", "", "set this IP non-interactively (skips the prompt)")
	cmd.Flags().StringVar(&service, "public-service", "", "optional public whoami URL for an egress-IP hint (e.g. https://api.ipify.org)")
	cmd.Flags().BoolVar(&printOnly, "print", false, "print the chosen IP instead of writing the config")
	return cmd
}
