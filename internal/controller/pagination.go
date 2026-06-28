package controller

import (
	"net/http"
	"strconv"
)

// Pagination for the controller's list views. Every list endpoint accepts ?limit=
// and ?offset= and returns the page under its original array key plus total/
// limit/offset, so a client can render controls and a view never has to load or
// transfer an unbounded list.
const (
	defaultPageLimit = 100
	maxPageLimit     = 1000
)

// Page bounds a list query. Limit <= 0 selects the default; it is capped at
// maxPageLimit. Offset < 0 is treated as 0.
type Page struct {
	Limit  int
	Offset int
}

// normalize returns the effective (limit, offset) the stores and the response
// envelope use, applying the default and the cap.
func (p Page) normalize() (limit, offset int) {
	limit = p.Limit
	if limit <= 0 {
		limit = defaultPageLimit
	}
	if limit > maxPageLimit {
		limit = maxPageLimit
	}
	offset = p.Offset
	if offset < 0 {
		offset = 0
	}
	return limit, offset
}

// bounds returns the [lo, hi) slice range into a list of the given length —
// the in-memory paging the bbolt store and small handler-side lists use.
func (p Page) bounds(total int) (lo, hi int) {
	limit, offset := p.normalize()
	lo = offset
	if lo > total {
		lo = total
	}
	hi = lo + limit
	if hi > total {
		hi = total
	}
	return lo, hi
}

// pageParams reads ?limit=&offset= from a request.
func pageParams(r *http.Request) Page {
	q := r.URL.Query()
	limit, _ := strconv.Atoi(q.Get("limit"))
	offset, _ := strconv.Atoi(q.Get("offset"))
	return Page{Limit: limit, Offset: offset}
}

// pageEnvelope wraps a page of items under key with the paging metadata, keeping
// the original array key so existing clients still read it.
func pageEnvelope(key string, items any, total int, p Page) map[string]any {
	limit, offset := p.normalize()
	return map[string]any{key: items, "total": total, "limit": limit, "offset": offset}
}
