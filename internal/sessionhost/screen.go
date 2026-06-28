package sessionhost

import (
	"bytes"
	"fmt"

	"github.com/hinshun/vt10x"
)

// vt10x keeps its attribute bits unexported; these mirror the constant block
// in state.go of the pinned version (attrReverse=1<<0, attrUnderline=1<<1,
// attrBold=1<<2). The dependency is pinned in go.mod, so the values are
// stable.
const (
	vtAttrReverse   = 1 << 0
	vtAttrUnderline = 1 << 1
	vtAttrBold      = 1 << 2
)

// sgr is the subset of cell attributes we repaint. Correct-enough beats
// perfect: a full-screen app must come back legible and a prompt exact.
type sgr struct {
	fg, bg          vt10x.Color
	bold, underline bool
	reverse         bool
}

var sgrDefault = sgr{fg: vt10x.DefaultFG, bg: vt10x.DefaultBG}

func sgrOf(g vt10x.Glyph) sgr {
	return sgr{
		fg:        g.FG,
		bg:        g.BG,
		bold:      g.Mode&vtAttrBold != 0,
		underline: g.Mode&vtAttrUnderline != 0,
		reverse:   g.Mode&vtAttrReverse != 0,
	}
}

// writeSGR emits a full attribute set (starting from reset) so the previous
// state never leaks into the new one. The caller only invokes it on change to
// minimize churn.
func writeSGR(b *bytes.Buffer, s sgr) {
	b.WriteString("\x1b[0")
	if s.bold {
		b.WriteString(";1")
	}
	if s.underline {
		b.WriteString(";4")
	}
	if s.reverse {
		b.WriteString(";7")
	}
	writeColor(b, s.fg, true)
	writeColor(b, s.bg, false)
	b.WriteByte('m')
}

func writeColor(b *bytes.Buffer, c vt10x.Color, fg bool) {
	switch {
	case c == vt10x.DefaultFG || c == vt10x.DefaultBG || c == vt10x.DefaultCursor:
		// defaults are already in effect after the leading reset
	case c < 8:
		if fg {
			fmt.Fprintf(b, ";%d", 30+c)
		} else {
			fmt.Fprintf(b, ";%d", 40+c)
		}
	case c < 256:
		if fg {
			fmt.Fprintf(b, ";38;5;%d", c)
		} else {
			fmt.Fprintf(b, ";48;5;%d", c)
		}
	case c < 1<<24:
		// vt10x packs truecolor as r<<16|g<<8|b below the default sentinels.
		r, g, bl := (c>>16)&0xff, (c>>8)&0xff, c&0xff
		if fg {
			fmt.Fprintf(b, ";38;2;%d;%d;%d", r, g, bl)
		} else {
			fmt.Fprintf(b, ";48;2;%d;%d;%d", r, g, bl)
		}
	}
}

// blankCell reports whether a cell needs no painting on a freshly cleared
// screen: a space with default background and no underline/reverse.
func blankCell(g vt10x.Glyph) bool {
	if g.Mode&(vtAttrUnderline|vtAttrReverse) != 0 {
		return false
	}
	if g.BG != vt10x.DefaultBG {
		return false
	}
	return g.Char == ' ' || g.Char == 0
}

// renderSnapshot serializes the current screen of a vt10x terminal into an
// ANSI byte stream that repaints it on a blank client terminal: clear+home,
// per-row cell runs with SGR emitted only on change, final SGR reset, cursor
// position, and cursor visibility. The View lock orders after session.mu
// everywhere (pump writes also happen under session.mu), so callers holding
// session.mu may call this without deadlock.
func renderSnapshot(term vt10x.Terminal) []byte {
	term.Lock()
	defer term.Unlock()
	cols, rows := term.Size()
	var b bytes.Buffer
	b.Grow(cols*rows + 256)
	b.WriteString("\x1b[2J\x1b[H\x1b[0m")
	cur := sgrDefault
	for y := 0; y < rows; y++ {
		end := cols
		for end > 0 && blankCell(term.Cell(end-1, y)) {
			end--
		}
		if end == 0 {
			continue // row is blank; the clear already painted it
		}
		fmt.Fprintf(&b, "\x1b[%d;1H", y+1)
		for x := 0; x < end; x++ {
			g := term.Cell(x, y)
			if st := sgrOf(g); st != cur {
				writeSGR(&b, st)
				cur = st
			}
			ch := g.Char
			if ch == 0 {
				ch = ' '
			}
			b.WriteRune(ch)
		}
	}
	b.WriteString("\x1b[0m")
	c := term.Cursor()
	fmt.Fprintf(&b, "\x1b[%d;%dH", c.Y+1, c.X+1)
	if term.CursorVisible() {
		b.WriteString("\x1b[?25h")
	} else {
		b.WriteString("\x1b[?25l")
	}
	return b.Bytes()
}
