package controller

import (
	"fmt"
	"testing"
)

func TestListSessionsPage(t *testing.T) {
	st := testStore(t)
	ws := defaultWorkspace
	const n = 250
	for i := 0; i < n; i++ {
		state := "active"
		if i%5 == 0 {
			state = "ended"
		}
		if err := st.PutSession(ws, &SessionRecord{
			ID: fmt.Sprintf("s-%03d", i), StartedUnix: int64(i), State: state,
			User: fmt.Sprintf("u%d", i%3), NodeName: fmt.Sprintf("node%d", i),
		}); err != nil {
			t.Fatal(err)
		}
	}

	// Default page: capped at defaultPageLimit, newest first, correct total.
	items, total, err := st.QuerySessions(ws, SessionQuery{Page: Page{}})
	if err != nil {
		t.Fatal(err)
	}
	if total != n {
		t.Fatalf("total = %d, want %d", total, n)
	}
	if len(items) != defaultPageLimit {
		t.Fatalf("default page len = %d, want %d", len(items), defaultPageLimit)
	}
	if items[0].StartedUnix != n-1 {
		t.Fatalf("first item started = %d, want %d (newest first)", items[0].StartedUnix, n-1)
	}

	// limit + offset window.
	items, _, err = st.QuerySessions(ws, SessionQuery{Page: Page{Limit: 10, Offset: 5}})
	if err != nil {
		t.Fatal(err)
	}
	if len(items) != 10 {
		t.Fatalf("windowed len = %d, want 10", len(items))
	}
	if items[0].StartedUnix != n-1-5 {
		t.Fatalf("windowed first = %d, want %d", items[0].StartedUnix, n-1-5)
	}

	// Filter by state: only the ended ones (i%5==0 => 50 of 250).
	_, total, err = st.QuerySessions(ws, SessionQuery{State: "ended", Page: Page{}})
	if err != nil {
		t.Fatal(err)
	}
	if total != n/5 {
		t.Fatalf("ended total = %d, want %d", total, n/5)
	}

	// Sort ascending by started.
	items, _, _ = st.QuerySessions(ws, SessionQuery{Sort: "started", Order: "asc", Page: Page{Limit: 3}})
	if items[0].StartedUnix != 0 {
		t.Fatalf("asc first = %d, want 0", items[0].StartedUnix)
	}

	// Free-text search narrows the total.
	_, total, _ = st.QuerySessions(ws, SessionQuery{Search: "node7", Page: Page{}})
	if total == 0 || total >= n {
		t.Fatalf("search total = %d, want a strict subset of %d", total, n)
	}

	// Over-cap limit is capped; offset past the end is empty (not an error).
	if items, _, _ = st.QuerySessions(ws, SessionQuery{Page: Page{Limit: 1 << 20}}); len(items) != n {
		t.Fatalf("over-cap page len = %d, want %d", len(items), n)
	}
	if items, _, _ = st.QuerySessions(ws, SessionQuery{Page: Page{Offset: 10_000}}); len(items) != 0 {
		t.Fatalf("past-end page len = %d, want 0", len(items))
	}
}

func TestPageNormalizeAndBounds(t *testing.T) {
	// defaults + cap
	if l, o := (Page{}).normalize(); l != defaultPageLimit || o != 0 {
		t.Fatalf("zero Page normalize = (%d,%d)", l, o)
	}
	if l, _ := (Page{Limit: 1 << 20}).normalize(); l != maxPageLimit {
		t.Fatalf("over-cap limit = %d, want %d", l, maxPageLimit)
	}
	if _, o := (Page{Offset: -5}).normalize(); o != 0 {
		t.Fatalf("negative offset = %d, want 0", o)
	}
	// bounds clamp to total
	if lo, hi := (Page{Limit: 10, Offset: 95}).bounds(100); lo != 95 || hi != 100 {
		t.Fatalf("bounds = (%d,%d), want (95,100)", lo, hi)
	}
}
