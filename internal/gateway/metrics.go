package gateway

import (
	"bytes"
	"context"
	"fmt"
	"log/slog"
	"strconv"
	"time"

	dto "github.com/prometheus/client_model/go"
	"github.com/prometheus/common/expfmt"
	"github.com/prometheus/common/model"
	"github.com/prometheus/prometheus/model/labels"
	"github.com/prometheus/prometheus/promql"
	"github.com/prometheus/prometheus/tsdb"
)

// MetricsSink is the extension seam for shipping samples beyond the gateway's
// embedded TSDB — e.g. Prometheus remote_write to Thanos Receive / Mimir /
// Cortex for long-term, horizontally-scalable storage. The default deployment
// uses only the local TSDB (sink == nil); wiring a remote sink needs no change
// to the agent, the scrape path, or the query API.
type MetricsSink interface {
	Write(samples []Sample) error
}

// Sample is one ingested point with its full label set (incl. __name__).
type Sample struct {
	Labels labels.Labels
	TimeMs int64
	Value  float64
}

// metricsStore is the gateway's embedded Prometheus: a local TSDB that ingests
// agent-pushed exposition text and a PromQL engine to query it. No separate
// Prometheus server is deployed.
type metricsStore struct {
	log    *slog.Logger
	db     *tsdb.DB
	engine *promql.Engine
	sink   MetricsSink // optional long-term sink (Thanos/Mimir); nil = local-only
}

func newMetricsStore(dir string, retention time.Duration, log *slog.Logger, sink MetricsSink) (*metricsStore, error) {
	// Embedding the prometheus libraries leaves the global metric/label name
	// validation scheme Unset (the upstream binaries set it from config), which
	// panics any parse/append. Pin it to UTF8 (a superset of classic node_exporter
	// names) so ingestion is deterministic.
	if model.NameValidationScheme == model.UnsetValidation {
		model.NameValidationScheme = model.UTF8Validation
	}
	opts := tsdb.DefaultOptions()
	opts.RetentionDuration = int64(retention / time.Millisecond)
	opts.MinBlockDuration = int64(2 * time.Hour / time.Millisecond)
	db, err := tsdb.Open(dir, log.With("component", "tsdb"), nil, opts, nil)
	if err != nil {
		return nil, fmt.Errorf("open tsdb at %s: %w", dir, err)
	}
	engine := promql.NewEngine(promql.EngineOpts{
		Logger:        log.With("component", "promql"),
		MaxSamples:    50_000_000,
		Timeout:       30 * time.Second,
		LookbackDelta: 5 * time.Minute,
	})
	return &metricsStore{log: log.With("component", "metrics"), db: db, engine: engine, sink: sink}, nil
}

func (s *metricsStore) Close() error {
	if s == nil || s.db == nil {
		return nil
	}
	return s.db.Close()
}

// Ingest parses one node's Prometheus exposition text and appends every sample
// to the TSDB (and the remote sink, if configured), stamping the node's
// identity labels (instance/node/node_id/job) so series are per-node queryable.
// defaultMs is the push timestamp used for samples that carry none.
func (s *metricsStore) Ingest(extra map[string]string, exposition []byte, defaultMs int64) (int, error) {
	// NewTextParser (not a zero-value TextParser) is required: a default-
	// constructed parser has an Unset validation scheme and panics on parse.
	parser := expfmt.NewTextParser(model.UTF8Validation)
	families, err := parser.TextToMetricFamilies(bytes.NewReader(exposition))
	if err != nil {
		// Tolerate a trailing partial line; ingest whatever parsed.
		s.log.Debug("exposition parse warning", "err", err)
	}
	samples := expandFamilies(families, extra, defaultMs)
	if len(samples) == 0 {
		return 0, nil
	}

	app := s.db.Appender(context.Background())
	appended := 0
	for _, smp := range samples {
		if _, aerr := app.Append(0, smp.Labels, smp.TimeMs, smp.Value); aerr != nil {
			// Out-of-order / duplicate samples are expected on reconnect bursts;
			// skip the bad one rather than aborting the whole batch.
			continue
		}
		appended++
	}
	if cErr := app.Commit(); cErr != nil {
		_ = app.Rollback()
		return 0, fmt.Errorf("tsdb commit: %w", cErr)
	}
	if s.sink != nil {
		if werr := s.sink.Write(samples); werr != nil {
			s.log.Warn("metrics sink write failed", "err", werr)
		}
	}
	return appended, nil
}

// expandFamilies flattens dto metric families into per-series samples, including
// the multi-series expansion of summaries (_sum/_count/{quantile}) and
// histograms (_sum/_count/_bucket{le}).
func expandFamilies(families map[string]*dto.MetricFamily, extra map[string]string, defaultMs int64) []Sample {
	var out []Sample
	add := func(name string, m *dto.Metric, val float64, extraPair ...string) {
		b := labels.NewBuilder(labels.EmptyLabels())
		b.Set(labels.MetricName, name)
		for _, lp := range m.GetLabel() {
			b.Set(lp.GetName(), lp.GetValue())
		}
		for i := 0; i+1 < len(extraPair); i += 2 {
			b.Set(extraPair[i], extraPair[i+1])
		}
		for k, v := range extra {
			b.Set(k, v)
		}
		ts := defaultMs
		if m.TimestampMs != nil && m.GetTimestampMs() != 0 {
			ts = m.GetTimestampMs()
		}
		out = append(out, Sample{Labels: b.Labels(), TimeMs: ts, Value: val})
	}
	for name, mf := range families {
		for _, m := range mf.GetMetric() {
			switch mf.GetType() {
			case dto.MetricType_COUNTER:
				add(name, m, m.GetCounter().GetValue())
			case dto.MetricType_GAUGE:
				add(name, m, m.GetGauge().GetValue())
			case dto.MetricType_UNTYPED:
				add(name, m, m.GetUntyped().GetValue())
			case dto.MetricType_SUMMARY:
				sum := m.GetSummary()
				add(name+"_sum", m, sum.GetSampleSum())
				add(name+"_count", m, float64(sum.GetSampleCount()))
				for _, q := range sum.GetQuantile() {
					add(name, m, q.GetValue(), "quantile", strconv.FormatFloat(q.GetQuantile(), 'g', -1, 64))
				}
			case dto.MetricType_HISTOGRAM:
				h := m.GetHistogram()
				add(name+"_sum", m, h.GetSampleSum())
				add(name+"_count", m, float64(h.GetSampleCount()))
				for _, bkt := range h.GetBucket() {
					add(name+"_bucket", m, float64(bkt.GetCumulativeCount()),
						"le", strconv.FormatFloat(bkt.GetUpperBound(), 'g', -1, 64))
				}
			}
		}
	}
	return out
}

// QueryRange runs a PromQL range query and returns the Prometheus-API-shaped
// data object ({resultType, result}) ready to marshal under {"status":"success"}.
func (s *metricsStore) QueryRange(ctx context.Context, qs string, start, end time.Time, step time.Duration) (any, error) {
	q, err := s.engine.NewRangeQuery(ctx, s.db, nil, qs, start, end, step)
	if err != nil {
		return nil, err
	}
	defer q.Close()
	return promResult(q.Exec(ctx))
}

// QueryInstant runs a PromQL instant query at ts.
func (s *metricsStore) QueryInstant(ctx context.Context, qs string, ts time.Time) (any, error) {
	q, err := s.engine.NewInstantQuery(ctx, s.db, nil, qs, ts)
	if err != nil {
		return nil, err
	}
	defer q.Close()
	return promResult(q.Exec(ctx))
}

// promResult converts a promql result into the Prometheus HTTP API JSON shape
// (matrix/vector/scalar), so the console — or any Prometheus-compatible client —
// consumes it unchanged.
func promResult(res *promql.Result) (any, error) {
	if res.Err != nil {
		return nil, res.Err
	}
	type series struct {
		Metric map[string]string `json:"metric"`
		Values [][]any           `json:"values,omitempty"`
		Value  []any             `json:"value,omitempty"`
	}
	lblMap := func(l labels.Labels) map[string]string {
		m := map[string]string{}
		l.Range(func(lb labels.Label) { m[lb.Name] = lb.Value })
		return m
	}
	switch v := res.Value.(type) {
	case promql.Matrix:
		result := make([]series, 0, len(v))
		for _, ss := range v {
			pts := make([][]any, 0, len(ss.Floats))
			for _, p := range ss.Floats {
				pts = append(pts, []any{float64(p.T) / 1000, strconv.FormatFloat(p.F, 'g', -1, 64)})
			}
			result = append(result, series{Metric: lblMap(ss.Metric), Values: pts})
		}
		return map[string]any{"resultType": "matrix", "result": result}, nil
	case promql.Vector:
		result := make([]series, 0, len(v))
		for _, smp := range v {
			result = append(result, series{
				Metric: lblMap(smp.Metric),
				Value:  []any{float64(smp.T) / 1000, strconv.FormatFloat(smp.F, 'g', -1, 64)},
			})
		}
		return map[string]any{"resultType": "vector", "result": result}, nil
	case promql.Scalar:
		return map[string]any{"resultType": "scalar",
			"result": []any{float64(v.T) / 1000, strconv.FormatFloat(v.V, 'g', -1, 64)}}, nil
	default:
		return nil, fmt.Errorf("unsupported promql result type %T", res.Value)
	}
}
