package controller

import (
	"context"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sync/atomic"
	"testing"
	"time"
)

// TestMetricsBackendIngest verifies the controller forwards exposition text to
// VictoriaMetrics' import endpoint with the node identity carried as extra_label
// query params and the push timestamp stamped on the batch.
func TestMetricsBackendIngest(t *testing.T) {
	var gotPath string
	var gotQuery url.Values
	var gotBody string
	var gotCT string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		gotQuery = r.URL.Query()
		gotCT = r.Header.Get("Content-Type")
		b, _ := io.ReadAll(r.Body)
		gotBody = string(b)
		w.WriteHeader(http.StatusNoContent)
	}))
	defer srv.Close()

	mb, err := newMetricsBackend(srv.URL, slog.Default())
	if err != nil {
		t.Fatalf("newMetricsBackend: %v", err)
	}
	defer mb.Close()
	exposition := []byte("node_load1 1.5\n")
	if err := mb.Ingest(context.Background(),
		map[string]string{"instance": "node1", "node_id": "n-abc", "job": "node-exporter"},
		exposition, 1_700_000_000_000); err != nil {
		t.Fatalf("Ingest: %v", err)
	}

	if gotPath != "/api/v1/import/prometheus" {
		t.Fatalf("import path = %q", gotPath)
	}
	if gotBody != string(exposition) {
		t.Fatalf("body = %q, want %q", gotBody, exposition)
	}
	if gotCT != "text/plain" {
		t.Fatalf("content-type = %q", gotCT)
	}
	if ts := gotQuery.Get("timestamp"); ts != "1700000000000" {
		t.Fatalf("timestamp = %q", ts)
	}
	labels := map[string]bool{}
	for _, el := range gotQuery["extra_label"] {
		labels[el] = true
	}
	for _, want := range []string{"instance=node1", "node_id=n-abc", "job=node-exporter"} {
		if !labels[want] {
			t.Fatalf("missing extra_label %q in %v", want, gotQuery["extra_label"])
		}
	}
}

// TestMetricsBackendIngestEmptyLabels: an empty-valued identity label is skipped
// rather than emitted as `extra_label=name=` (which silently un-keys the series).
func TestMetricsBackendIngestEmptyLabels(t *testing.T) {
	var gotQuery url.Values
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotQuery = r.URL.Query()
		w.WriteHeader(http.StatusNoContent)
	}))
	defer srv.Close()
	mb, _ := newMetricsBackend(srv.URL, slog.Default())
	defer mb.Close()
	if err := mb.Ingest(context.Background(),
		map[string]string{"instance": "node1", "job": ""}, []byte("x 1\n"), 0); err != nil {
		t.Fatalf("Ingest: %v", err)
	}
	for _, el := range gotQuery["extra_label"] {
		if el == "job=" {
			t.Fatalf("emitted empty-valued extra_label %q", el)
		}
	}
	if gotQuery.Get("timestamp") != "" {
		t.Fatalf("timestamp set despite tsMs=0: %q", gotQuery.Get("timestamp"))
	}
}

// TestMetricsBackendIngestErrorStatus surfaces a non-2xx import as an error.
func TestMetricsBackendIngestErrorStatus(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "boom", http.StatusBadRequest)
	}))
	defer srv.Close()
	mb, _ := newMetricsBackend(srv.URL, slog.Default())
	defer mb.Close()
	if err := mb.Ingest(context.Background(), nil, []byte("x 1\n"), 0); err == nil {
		t.Fatal("expected error on 400 import, got nil")
	}
}

// TestMetricsBackendEnqueueIngest verifies the async path actually POSTs to VM
// off the caller's goroutine.
func TestMetricsBackendEnqueueIngest(t *testing.T) {
	var hits int32
	done := make(chan struct{}, 1)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&hits, 1)
		w.WriteHeader(http.StatusNoContent)
		select {
		case done <- struct{}{}:
		default:
		}
	}))
	defer srv.Close()
	mb, _ := newMetricsBackend(srv.URL, slog.Default())
	defer mb.Close()

	mb.EnqueueIngest(map[string]string{"node": "node1"}, []byte("x 1\n"), 0)
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("EnqueueIngest never reached the backend")
	}
	if got := atomic.LoadInt32(&hits); got != 1 {
		t.Fatalf("hits = %d, want 1", got)
	}
	// An empty exposition is a no-op (never enqueued, never POSTed).
	mb.EnqueueIngest(map[string]string{"node": "node1"}, nil, 0)
}

// TestMetricsBackendQuery verifies instant/range queries hit the right VM
// endpoints with the right params and unwrap the {status,data} envelope.
func TestMetricsBackendQuery(t *testing.T) {
	var lastPath string
	var lastQuery url.Values
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		lastPath = r.URL.Path
		lastQuery = r.URL.Query()
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"status":"success","data":{"resultType":"vector","result":[{"metric":{"__name__":"node_load1"},"value":[1700000000,"1.5"]}]}}`)
	}))
	defer srv.Close()

	mb, _ := newMetricsBackend(srv.URL, slog.Default())
	defer mb.Close()

	data, err := mb.QueryInstant(context.Background(), "", "node_load1", time.Unix(1_700_000_000, 0))
	if err != nil {
		t.Fatalf("QueryInstant: %v", err)
	}
	if lastPath != "/api/v1/query" {
		t.Fatalf("instant path = %q", lastPath)
	}
	if lastQuery.Get("query") != "node_load1" || lastQuery.Get("time") != "1700000000" {
		t.Fatalf("instant params = %v", lastQuery)
	}
	m, ok := data.(map[string]any)
	if !ok || m["resultType"] != "vector" {
		t.Fatalf("instant data = %#v", data)
	}

	_, err = mb.QueryRange(context.Background(), "", "node_load1",
		time.Unix(1_700_000_000, 0), time.Unix(1_700_000_300, 0), 15*time.Second)
	if err != nil {
		t.Fatalf("QueryRange: %v", err)
	}
	if lastPath != "/api/v1/query_range" {
		t.Fatalf("range path = %q", lastPath)
	}
	if lastQuery.Get("start") != "1700000000" || lastQuery.Get("end") != "1700000300" || lastQuery.Get("step") != "15" {
		t.Fatalf("range params = %v", lastQuery)
	}
}

// TestMetricsBackendQueryError maps a VM error envelope to a Go error carrying
// the upstream message.
func TestMetricsBackendQueryError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"status":"error","error":"parse error: unexpected character"}`)
	}))
	defer srv.Close()
	mb, _ := newMetricsBackend(srv.URL, slog.Default())
	defer mb.Close()
	_, err := mb.QueryInstant(context.Background(), "", "node_load1{", time.Now())
	if err == nil || err.Error() != "parse error: unexpected character" {
		t.Fatalf("err = %v, want upstream parse error", err)
	}
}

// TestMetricsBackendDisabled: an empty URL yields a nil backend (metrics off).
func TestMetricsBackendDisabled(t *testing.T) {
	mb, err := newMetricsBackend("", slog.Default())
	if err != nil || mb != nil {
		t.Fatalf("newMetricsBackend(\"\") = %v, %v; want nil, nil", mb, err)
	}
}

// TestMetricsBackendBadURL rejects a non-http(s) URL at construction.
func TestMetricsBackendBadURL(t *testing.T) {
	if _, err := newMetricsBackend("not-a-url", slog.Default()); err == nil {
		t.Fatal("expected error for invalid metrics_url, got nil")
	}
}
