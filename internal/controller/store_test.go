package controller

import (
	"errors"
	"path/filepath"
	"testing"
	"time"
)

func testStore(t *testing.T) *bboltStore {
	t.Helper()
	s, err := OpenStore(filepath.Join(t.TempDir(), "state.db"))
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	t.Cleanup(func() { s.Close() })
	return s.(*bboltStore)
}

func TestTokenSingleUse(t *testing.T) {
	s := testStore(t)
	now := time.Now()
	if err := s.PutToken("gz-aaaa", &TokenRecord{
		Labels:      map[string]string{"env": "prod"},
		ExpiresUnix: now.Add(time.Hour).Unix(),
		MaxUses:     1,
	}); err != nil {
		t.Fatal(err)
	}

	rec, err := s.UseToken("gz-aaaa", now)
	if err != nil {
		t.Fatalf("first use: %v", err)
	}
	if rec.Labels["env"] != "prod" {
		t.Fatalf("labels lost: %+v", rec.Labels)
	}
	if _, err := s.UseToken("gz-aaaa", now); !errors.Is(err, ErrTokenExhausted) {
		t.Fatalf("second use: want ErrTokenExhausted, got %v", err)
	}
}

func TestTokenMultiUse(t *testing.T) {
	s := testStore(t)
	now := time.Now()
	if err := s.PutToken("gz-bbbb", &TokenRecord{ExpiresUnix: now.Add(time.Hour).Unix(), MaxUses: 2}); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 2; i++ {
		if _, err := s.UseToken("gz-bbbb", now); err != nil {
			t.Fatalf("use %d: %v", i+1, err)
		}
	}
	if _, err := s.UseToken("gz-bbbb", now); !errors.Is(err, ErrTokenExhausted) {
		t.Fatalf("third use: want ErrTokenExhausted, got %v", err)
	}
}

func TestTokenExpiry(t *testing.T) {
	s := testStore(t)
	now := time.Now()
	if err := s.PutToken("gz-cccc", &TokenRecord{ExpiresUnix: now.Add(-time.Minute).Unix(), MaxUses: 1}); err != nil {
		t.Fatal(err)
	}
	if _, err := s.UseToken("gz-cccc", now); !errors.Is(err, ErrTokenExpired) {
		t.Fatalf("want ErrTokenExpired, got %v", err)
	}
	if _, err := s.UseToken("gz-missing", now); !errors.Is(err, ErrTokenUnknown) {
		t.Fatalf("want ErrTokenUnknown, got %v", err)
	}
}

func TestFindNodeAmbiguity(t *testing.T) {
	s := testStore(t)
	for _, id := range []string{"n-000000000001", "n-000000000002"} {
		if err := s.PutNode(defaultWorkspace, &NodeRecord{ID: id, Name: "dup"}); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := s.FindNode(defaultWorkspace, "n-000000000001"); err != nil {
		t.Fatalf("by id: %v", err)
	}
	if _, err := s.FindNode(defaultWorkspace, "dup"); err == nil {
		t.Fatal("ambiguous name must fail closed")
	}
}
