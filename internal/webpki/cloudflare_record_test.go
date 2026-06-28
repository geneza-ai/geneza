package webpki

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sort"
	"strings"
	"sync"
	"testing"
)

// mockCloudflare is a minimal in-memory Cloudflare API v4: one zone and a set of
// A records, enough to exercise the record manager's zone lookup + reconcile.
type mockCloudflare struct {
	mu      sync.Mutex
	zone    string
	zoneID  string
	records map[string]cfDNSRecord // record id -> record
	nextID  int
}

func newMockCF(zone string) *mockCloudflare {
	return &mockCloudflare{zone: zone, zoneID: "zone1", records: map[string]cfDNSRecord{}}
}

func (m *mockCloudflare) ips(name string) []string {
	m.mu.Lock()
	defer m.mu.Unlock()
	var out []string
	for _, r := range m.records {
		if r.Name == name {
			out = append(out, r.Content)
		}
	}
	sort.Strings(out)
	return out
}

func (m *mockCloudflare) server() *httptest.Server {
	mux := http.NewServeMux()
	ok := func(w http.ResponseWriter, result any) {
		raw, _ := json.Marshal(result)
		json.NewEncoder(w).Encode(cfEnvelope{Success: true, Result: raw})
	}
	mux.HandleFunc("/zones", func(w http.ResponseWriter, r *http.Request) {
		ok(w, []cfZone{{ID: m.zoneID, Name: m.zone}})
	})
	mux.HandleFunc("/zones/"+m.zoneID+"/dns_records", func(w http.ResponseWriter, r *http.Request) {
		m.mu.Lock()
		defer m.mu.Unlock()
		switch r.Method {
		case http.MethodGet:
			name := r.URL.Query().Get("name")
			var recs []cfDNSRecord
			for _, rec := range m.records {
				if rec.Name == name && rec.Type == "A" {
					recs = append(recs, rec)
				}
			}
			ok(w, recs)
		case http.MethodPost:
			var body map[string]any
			json.NewDecoder(r.Body).Decode(&body)
			m.nextID++
			id := "rec" + strings.Repeat("x", m.nextID%3) + string(rune('a'+m.nextID))
			m.records[id] = cfDNSRecord{ID: id, Type: "A", Name: body["name"].(string), Content: body["content"].(string)}
			ok(w, m.records[id])
		}
	})
	mux.HandleFunc("/zones/"+m.zoneID+"/dns_records/", func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodDelete {
			id := strings.TrimPrefix(r.URL.Path, "/zones/"+m.zoneID+"/dns_records/")
			m.mu.Lock()
			delete(m.records, id)
			m.mu.Unlock()
			ok(w, map[string]string{"id": id})
		}
	})
	return httptest.NewServer(mux)
}

func TestCloudflareRecordManager(t *testing.T) {
	mock := newMockCF("geneza.app")
	srv := mock.server()
	defer srv.Close()

	rm, err := NewRecordManager(DNS01Config{Provider: "cloudflare", Cloudflare: CloudflareConfig{APIToken: "tok", BaseURL: srv.URL}})
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	const fqdn = "app.acme.geneza.app"

	// Publish a 2-IP set.
	if err := rm.SetA(ctx, fqdn, []string{"1.1.1.1", "2.2.2.2"}); err != nil {
		t.Fatalf("set-a: %v", err)
	}
	if got := mock.ips(fqdn); len(got) != 2 || got[0] != "1.1.1.1" || got[1] != "2.2.2.2" {
		t.Fatalf("after SetA: %v", got)
	}

	// Failover to a single IP: the extra is deleted, the kept one is untouched.
	if err := rm.SetA(ctx, fqdn, []string{"2.2.2.2"}); err != nil {
		t.Fatalf("set-a failover: %v", err)
	}
	if got := mock.ips(fqdn); len(got) != 1 || got[0] != "2.2.2.2" {
		t.Fatalf("after failover SetA: %v", got)
	}

	// Withdraw.
	if err := rm.RemoveA(ctx, fqdn); err != nil {
		t.Fatalf("remove-a: %v", err)
	}
	if got := mock.ips(fqdn); len(got) != 0 {
		t.Fatalf("after RemoveA: %v", got)
	}
}
