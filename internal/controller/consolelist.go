package controller

import (
	"sort"
	"strings"
)

// SessionQuery is the filter + sort + page a list view asks the store for. Every
// field is applied in the store (SQL or bbolt), never in the controller over a
// fully-loaded list, so the views scale.
type SessionQuery struct {
	State  string // exact session state ("" / "all" = any)
	User   string // exact user ("" = any) — the mine-only path
	Search string // free-text substring over user / node / action / id
	Sort   string // started | user | node | action | state
	Order  string // asc | desc (default: desc)
	Page   Page
}

// bbolt fallback (single-node): filter + sort + page in memory. The SQL store
// does the same work in the database; these helpers keep the bbolt path correct.

func filterSessions(in []*SessionRecord, q SessionQuery) []*SessionRecord {
	state := strings.ToLower(strings.TrimSpace(q.State))
	search := strings.ToLower(strings.TrimSpace(q.Search))
	if (state == "" || state == "all") && search == "" && q.User == "" {
		return in
	}
	out := make([]*SessionRecord, 0, len(in))
	for _, s := range in {
		if state != "" && state != "all" && strings.ToLower(s.State) != state {
			continue
		}
		if q.User != "" && s.User != q.User {
			continue
		}
		if search != "" && !sessionMatches(s, search) {
			continue
		}
		out = append(out, s)
	}
	return out
}

func sessionMatches(s *SessionRecord, q string) bool {
	return strings.Contains(strings.ToLower(s.User), q) ||
		strings.Contains(strings.ToLower(s.NodeName), q) ||
		strings.Contains(strings.ToLower(s.NodeID), q) ||
		strings.Contains(strings.ToLower(s.Action), q) ||
		strings.Contains(strings.ToLower(s.ID), q)
}

func sortSessions(s []*SessionRecord, key, order string) {
	asc := func(i, j int) bool {
		switch strings.ToLower(key) {
		case "user":
			return s[i].User < s[j].User
		case "node":
			return sessionNodeLabel(s[i]) < sessionNodeLabel(s[j])
		case "action":
			return s[i].Action < s[j].Action
		case "state":
			return s[i].State < s[j].State
		default: // started / unknown
			return s[i].StartedUnix < s[j].StartedUnix
		}
	}
	desc := strings.ToLower(order) != "asc"
	sort.SliceStable(s, func(i, j int) bool {
		if desc {
			return asc(j, i)
		}
		return asc(i, j)
	})
}

func sessionNodeLabel(s *SessionRecord) string {
	if s.NodeName != "" {
		return s.NodeName
	}
	return s.NodeID
}
