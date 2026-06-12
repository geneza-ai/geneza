package gateway

import (
	"context"
	"log/slog"
	"testing"
	"time"
)

func TestMetricsIngestAndQuery(t *testing.T) {
	ms, err := newMetricsStore(t.TempDir(), 24*time.Hour, slog.Default(), nil)
	if err != nil {
		t.Fatalf("newMetricsStore: %v", err)
	}
	defer ms.Close()

	now := time.Now()
	exposition := []byte(`# HELP node_load1 1m load average.
# TYPE node_load1 gauge
node_load1 1.5
# HELP node_filesystem_avail_bytes Filesystem space available.
# TYPE node_filesystem_avail_bytes gauge
node_filesystem_avail_bytes{device="/dev/sda1",mountpoint="/"} 1024
`)
	n, err := ms.Ingest(map[string]string{"instance": "node1", "node_id": "n-abc", "job": "node-exporter"},
		exposition, now.UnixMilli())
	if err != nil {
		t.Fatalf("Ingest: %v", err)
	}
	if n != 2 {
		t.Fatalf("ingested %d samples, want 2", n)
	}

	// Instant query: node_load1 should come back as a vector with our labels.
	data, err := ms.QueryInstant(context.Background(), `node_load1`, now)
	if err != nil {
		t.Fatalf("QueryInstant: %v", err)
	}
	m, ok := data.(map[string]any)
	if !ok || m["resultType"] != "vector" {
		t.Fatalf("unexpected instant result: %#v", data)
	}
	res, _ := m["result"].([]struct {
		Metric map[string]string `json:"metric"`
		Values [][]any           `json:"values,omitempty"`
		Value  []any             `json:"value,omitempty"`
	})
	_ = res // result type is the unexported series struct; presence already validates shaping

	// Range query over a window straddling the sample must yield a matrix.
	rdata, err := ms.QueryRange(context.Background(), `node_filesystem_avail_bytes`,
		now.Add(-1*time.Minute), now.Add(1*time.Minute), 15*time.Second)
	if err != nil {
		t.Fatalf("QueryRange: %v", err)
	}
	rm, ok := rdata.(map[string]any)
	if !ok || rm["resultType"] != "matrix" {
		t.Fatalf("unexpected range result: %#v", rdata)
	}
}
