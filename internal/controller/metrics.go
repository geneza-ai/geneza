package controller

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"
)

// metricsBackend is the controller's proxy to an external VictoriaMetrics — a
// single-binary, Prometheus-compatible time-series database. The controller holds
// no series state itself: agent-pushed exposition text is forwarded to VM's
// import endpoint, and console PromQL is proxied to VM's query API. Keeping the
// controller stateless for metrics is what makes the HA story trivial — every
// controller replica talks to the same VM, so a series is queryable regardless of
// which replica ingested it (no per-replica fragmentation, no cross-replica
// scrape coordination).
type metricsBackend struct {
	base   string
	client *http.Client
	log    *slog.Logger

	// Ingest runs off the agent control-stream loop: a slow or down VM must
	// never stall an agent's heartbeats/session events. Pushes queue to a fixed
	// worker pool and are dropped under sustained backpressure (metrics are
	// lossy-tolerant observability, not authorization state).
	queue  chan ingestJob
	ctx    context.Context
	cancel context.CancelFunc
	wg     sync.WaitGroup
}

type ingestJob struct {
	extra map[string]string
	body  []byte
	tsMs  int64
}

const (
	ingestWorkers  = 4
	ingestQueueLen = 256
	// queryBodyLimit caps a query response read; a wide query_range that exceeds
	// it surfaces a clear error rather than a truncated-JSON parse failure.
	queryBodyLimit = 64 << 20
)

// newMetricsBackend returns nil (metrics disabled) when rawURL is empty, so a
// deployment without a metrics backend simply serves no metrics rather than
// failing to start.
func newMetricsBackend(rawURL string, log *slog.Logger) (*metricsBackend, error) {
	if rawURL == "" {
		return nil, nil
	}
	u, err := url.Parse(rawURL)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
		return nil, fmt.Errorf("metrics_url %q is not a valid http(s) URL", rawURL)
	}
	ctx, cancel := context.WithCancel(context.Background())
	b := &metricsBackend{
		base:   strings.TrimRight(rawURL, "/"),
		client: &http.Client{Timeout: 30 * time.Second},
		log:    log.With("component", "metrics"),
		queue:  make(chan ingestJob, ingestQueueLen),
		ctx:    ctx,
		cancel: cancel,
	}
	for i := 0; i < ingestWorkers; i++ {
		b.wg.Add(1)
		go b.ingestWorker()
	}
	return b, nil
}

// Close stops the ingest workers (cancelling any in-flight import) and waits for
// them to drain.
func (b *metricsBackend) Close() error {
	if b == nil {
		return nil
	}
	b.cancel()
	b.wg.Wait()
	return nil
}

func (b *metricsBackend) ingestWorker() {
	defer b.wg.Done()
	for {
		select {
		case <-b.ctx.Done():
			return
		case job := <-b.queue:
			if err := b.Ingest(b.ctx, job.extra, job.body, job.tsMs); err != nil {
				b.log.Warn("metrics ingest failed", "err", err)
			}
		}
	}
}

// EnqueueIngest hands one node's push to the async workers without blocking the
// caller (the agent control-stream loop). On a full queue — backend slow or
// down — the push is dropped: the control plane must not stall on observability.
func (b *metricsBackend) EnqueueIngest(extra map[string]string, exposition []byte, tsMs int64) {
	if len(exposition) == 0 {
		return
	}
	select {
	case b.queue <- ingestJob{extra: extra, body: exposition, tsMs: tsMs}:
	default:
		b.log.Warn("metrics ingest queue full; dropping push", "node", extra["node"])
	}
}

// Ingest forwards one node's Prometheus exposition text to VictoriaMetrics'
// import endpoint, tagging every series with the node's identity labels
// (instance/node/node_id/job) via extra_label so series stay per-node queryable.
// tsMs stamps the whole batch (VM applies it to rows without an inline
// timestamp), so a delayed reconnect burst lands at scrape time, not receive
// time.
func (b *metricsBackend) Ingest(ctx context.Context, extra map[string]string, exposition []byte, tsMs int64) error {
	if len(exposition) == 0 {
		return nil
	}
	q := url.Values{}
	for k, v := range extra {
		if v == "" {
			continue // an empty-valued extra_label silently un-keys the series in VM
		}
		q.Add("extra_label", k+"="+v)
	}
	if tsMs > 0 {
		q.Set("timestamp", strconv.FormatInt(tsMs, 10))
	}
	u := b.base + "/api/v1/import/prometheus?" + q.Encode()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, u, bytes.NewReader(exposition))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "text/plain")
	resp, err := b.client.Do(req)
	if err != nil {
		return fmt.Errorf("metrics import: %w", err)
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 1<<16))
	if resp.StatusCode/100 != 2 {
		return fmt.Errorf("metrics import: %s", resp.Status)
	}
	return nil
}

// QueryInstant proxies a PromQL instant query to VictoriaMetrics' /api/v1/query
// and returns the Prometheus-API "data" object ({resultType, result}) ready to
// marshal under {"status":"success"} — the console consumes it unchanged. The
// workspace is enforced as a server-side label matcher (see scopeWorkspace), so
// a tenant can never read another tenant's series regardless of its PromQL.
func (b *metricsBackend) QueryInstant(ctx context.Context, workspace, query string, ts time.Time) (any, error) {
	v := url.Values{
		"query": {query},
		"time":  {formatUnixSeconds(ts)},
	}
	scopeWorkspace(v, workspace)
	return b.query(ctx, "/api/v1/query", v)
}

// QueryRange proxies a PromQL range query to VictoriaMetrics' /api/v1/query_range.
func (b *metricsBackend) QueryRange(ctx context.Context, workspace, query string, start, end time.Time, step time.Duration) (any, error) {
	v := url.Values{
		"query": {query},
		"start": {formatUnixSeconds(start)},
		"end":   {formatUnixSeconds(end)},
		"step":  {strconv.FormatFloat(step.Seconds(), 'g', -1, 64)},
	}
	scopeWorkspace(v, workspace)
	return b.query(ctx, "/api/v1/query_range", v)
}

// scopeWorkspace forces VictoriaMetrics to restrict the query to one tenant's
// series. extra_label is applied server-side to every selector in the PromQL, so
// a client cannot widen it with its own matchers. An empty workspace is the
// cluster-operator path (no restriction); tenant callers always pass a non-empty
// one (the handlers derive it from the session, never the request).
func scopeWorkspace(v url.Values, workspace string) {
	if workspace != "" {
		v.Set("extra_label", "workspace="+workspace)
	}
}

// formatUnixSeconds renders a time as Unix seconds with its sub-second part
// preserved (the query handlers parse fractional-second time params, so don't
// truncate them on the way out).
func formatUnixSeconds(t time.Time) string {
	return strconv.FormatFloat(float64(t.Unix())+float64(t.Nanosecond())/1e9, 'f', -1, 64)
}

// query performs the GET against VM and unwraps its Prometheus-shaped envelope,
// returning just the inner "data" object (or the upstream error message). A
// transport failure or a non-success status surfaces as a Go error the handler
// renders back as a Prometheus-API error.
func (b *metricsBackend) query(ctx context.Context, path string, params url.Values) (any, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, b.base+path+"?"+params.Encode(), nil)
	if err != nil {
		return nil, err
	}
	resp, err := b.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("metrics backend unreachable: %w", err)
	}
	defer resp.Body.Close()
	// Read one byte past the cap so a truncated body is reported, not silently
	// fed to the JSON parser as a confusing syntax error.
	body, _ := io.ReadAll(io.LimitReader(resp.Body, queryBodyLimit+1))
	if len(body) > queryBodyLimit {
		return nil, fmt.Errorf("metrics response exceeded %d bytes — narrow the query", queryBodyLimit)
	}
	var out struct {
		Status string          `json:"status"`
		Data   json.RawMessage `json:"data"`
		Error  string          `json:"error"`
	}
	if err := json.Unmarshal(body, &out); err != nil {
		return nil, fmt.Errorf("metrics backend: unreadable response (%s)", resp.Status)
	}
	if out.Status != "success" {
		msg := out.Error
		if msg == "" {
			msg = resp.Status
		}
		return nil, fmt.Errorf("%s", msg)
	}
	var data any
	if err := json.Unmarshal(out.Data, &data); err != nil {
		return nil, err
	}
	return data, nil
}
