package main

import (
	"fmt"
	"io"
)

// printPageHint notes when a list view was truncated to a page, so a user is not
// misled into thinking a bounded result is the whole set.
func printPageHint(w io.Writer, shown, total, offset int) {
	if shown > 0 && offset+shown < total {
		fmt.Fprintf(w, "\nshowing %d-%d of %d (use --offset/--limit to page)\n", offset+1, offset+shown, total)
	}
}
