package gateway

import (
	"encoding/json"
	"net/http"
	"strconv"
	"time"
)

// promError writes a Prometheus-HTTP-API-shaped error so the same client code
// (and a real Grafana, if ever pointed here) handles failures uniformly.
func promError(w http.ResponseWriter, code int, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(map[string]any{"status": "error", "error": msg})
}

func promSuccess(w http.ResponseWriter, data any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{"status": "success", "data": data})
}

func parseUnixParam(s string) (time.Time, bool) {
	if s == "" {
		return time.Time{}, false
	}
	f, err := strconv.ParseFloat(s, 64)
	if err != nil {
		return time.Time{}, false
	}
	sec := int64(f)
	return time.Unix(sec, int64((f-float64(sec))*1e9)), true
}

// handleMetricsQuery is the Prometheus /api/v1/query (instant) equivalent.
func (c *consoleAPI) handleMetricsQuery(w http.ResponseWriter, r *http.Request, _ *consoleUser) {
	if c.s.metrics == nil {
		promError(w, http.StatusServiceUnavailable, "metrics store disabled")
		return
	}
	q := r.URL.Query().Get("query")
	if q == "" {
		promError(w, http.StatusBadRequest, "query required")
		return
	}
	ts := time.Now()
	if t, ok := parseUnixParam(r.URL.Query().Get("time")); ok {
		ts = t
	}
	data, err := c.s.metrics.QueryInstant(r.Context(), q, ts)
	if err != nil {
		promError(w, http.StatusBadRequest, err.Error())
		return
	}
	promSuccess(w, data)
}

// handleMetricsQueryRange is the Prometheus /api/v1/query_range equivalent.
func (c *consoleAPI) handleMetricsQueryRange(w http.ResponseWriter, r *http.Request, _ *consoleUser) {
	if c.s.metrics == nil {
		promError(w, http.StatusServiceUnavailable, "metrics store disabled")
		return
	}
	qv := r.URL.Query()
	q := qv.Get("query")
	if q == "" {
		promError(w, http.StatusBadRequest, "query required")
		return
	}
	start, ok1 := parseUnixParam(qv.Get("start"))
	end, ok2 := parseUnixParam(qv.Get("end"))
	if !ok1 || !ok2 {
		promError(w, http.StatusBadRequest, "start and end (unix seconds) required")
		return
	}
	step := 15 * time.Second
	if s := qv.Get("step"); s != "" {
		if secs, err := strconv.ParseFloat(s, 64); err == nil && secs > 0 {
			step = time.Duration(secs * float64(time.Second))
		}
	}
	if step < time.Second {
		step = time.Second
	}
	data, err := c.s.metrics.QueryRange(r.Context(), q, start, end, step)
	if err != nil {
		promError(w, http.StatusBadRequest, err.Error())
		return
	}
	promSuccess(w, data)
}

// handleGetNodeModules returns a node's desired agent-module set.
func (c *consoleAPI) handleGetNodeModules(w http.ResponseWriter, r *http.Request, u *consoleUser) {
	node, err := c.s.store.FindNode(u.Workspace, r.PathValue("id"))
	if err != nil {
		writeErr(w, http.StatusNotFound, "node not found")
		return
	}
	rec, err := c.s.store.GetNodeModules(u.Workspace, node.ID)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "load modules: "+err.Error())
		return
	}
	writeJSON(w, map[string]any{"nodeId": node.ID, "version": rec.Version, "modules": rec.Modules})
}

// handleSetNodeModules (admin) replaces a node's module set and pushes it live.
func (c *consoleAPI) handleSetNodeModules(w http.ResponseWriter, r *http.Request, u *consoleUser) {
	node, err := c.s.store.FindNode(u.Workspace, r.PathValue("id"))
	if err != nil {
		writeErr(w, http.StatusNotFound, "node not found")
		return
	}
	var body struct {
		Modules []NodeModule `json:"modules"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<16)).Decode(&body); err != nil {
		writeErr(w, http.StatusBadRequest, "bad json: "+err.Error())
		return
	}
	for _, m := range body.Modules {
		if m.Name == "" {
			writeErr(w, http.StatusBadRequest, "module name required")
			return
		}
	}
	rec, err := c.s.store.SetNodeModules(u.Workspace, node.ID, body.Modules)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "store modules: "+err.Error())
		return
	}
	c.s.pushNodeModules(u.Workspace, node.ID)
	if err := c.s.audit.Append("node_modules_set", u.Name, node.ID, "", map[string]string{
		"modules": strconv.Itoa(len(body.Modules)),
	}); err != nil {
		writeErr(w, http.StatusInternalServerError, "audit: "+err.Error())
		return
	}
	writeJSON(w, map[string]any{"ok": true, "version": rec.Version, "modules": rec.Modules})
}
