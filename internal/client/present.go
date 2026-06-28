package client

import (
	"fmt"
	"os"

	"golang.org/x/term"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"
)

// PrintJSON renders a proto message for --json scripting output.
func PrintJSON(m proto.Message) error {
	b, err := protojson.MarshalOptions{Multiline: true, Indent: "  "}.Marshal(m)
	if err != nil {
		return err
	}
	fmt.Println(string(b))
	return nil
}

// ColorsEnabled honors NO_COLOR and only colors a real terminal.
func ColorsEnabled() bool {
	if os.Getenv("NO_COLOR") != "" {
		return false
	}
	return term.IsTerminal(int(os.Stdout.Fd()))
}

// Colorize wraps s in an ANSI SGR code when stdout is a color terminal.
func Colorize(s, code string) string {
	if !ColorsEnabled() {
		return s
	}
	return "\x1b[" + code + "m" + s + "\x1b[0m"
}

// OnlineStr renders an online flag green (yes) / red (no).
func OnlineStr(online bool) string {
	if online {
		return Colorize("yes", "32")
	}
	return Colorize("no", "31")
}

// AdmissionStr renders the zero-trust admission gate: approved machines can
// have sessions brokered to them; pending ones cannot until an admin approves.
func AdmissionStr(approved bool) string {
	if approved {
		return Colorize("approved", "32")
	}
	return Colorize("PENDING", "33")
}

// BoolStr renders a plain yes/no.
func BoolStr(b bool) string {
	if b {
		return "yes"
	}
	return "no"
}
