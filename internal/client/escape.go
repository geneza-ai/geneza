package client

// EscapeAction is what an escape sequence asks the client to do.
type EscapeAction int

const (
	EscNone   EscapeAction = iota
	EscDetach              // <newline> ~ d  — detach, leave the session running
	EscClose               // <newline> ~ .  — hard-close the connection
)

// EscapeDetector recognizes ssh-style escape sequences in the raw stdin
// stream: a '~' at the start of a line introduces an escape; '~d' detaches,
// '~.' closes, '~~' sends a literal tilde. State persists across Feed calls
// because terminal reads split byte sequences arbitrarily (the '~' may arrive
// in one read and the 'd' in the next).
type EscapeDetector struct {
	state escState
}

type escState int

const (
	escLineStart escState = iota // start of input or just after CR/LF
	escMidLine
	escTilde // saw '~' at line start; holding it back
)

func isNewline(b byte) bool { return b == '\r' || b == '\n' }

// Feed consumes raw input bytes and returns the bytes to forward to the
// remote plus the first action triggered. When an action fires, bytes after
// the escape sequence are discarded (the connection is about to go away).
func (d *EscapeDetector) Feed(p []byte) ([]byte, EscapeAction) {
	out := make([]byte, 0, len(p)+1)
	for _, b := range p {
		switch d.state {
		case escTilde:
			switch {
			case b == 'd':
				d.state = escLineStart
				return out, EscDetach
			case b == '.':
				d.state = escLineStart
				return out, EscClose
			case b == '~': // literal tilde
				out = append(out, '~')
				d.state = escMidLine
			default:
				// Not an escape after all: release the held tilde + this byte.
				out = append(out, '~', b)
				if isNewline(b) {
					d.state = escLineStart
				} else {
					d.state = escMidLine
				}
			}
		case escLineStart:
			if b == '~' {
				d.state = escTilde // hold it back until resolved
				continue
			}
			out = append(out, b)
			if !isNewline(b) {
				d.state = escMidLine
			}
		case escMidLine:
			out = append(out, b)
			if isNewline(b) {
				d.state = escLineStart
			}
		}
	}
	return out, EscNone
}
