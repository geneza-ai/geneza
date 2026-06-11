// Package policy implements Geneza's policy-as-data engine: roles bound to
// users/groups, each role a set of allow rules over actions, node labels,
// and time windows (RBAC with ABAC-style conditions). The Engine interface
// is the seam where an OPA/Rego or Cedar evaluator can be swapped in.
package policy

import (
	"fmt"
	"os"
	"sort"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

// Engine evaluates an access request to a decision.
type Engine interface {
	Evaluate(in Input) Decision
	// RolesFor resolves the role set for an authenticated principal.
	RolesFor(user string, groups []string) []string
}

// Input is one access request.
type Input struct {
	User       string
	Groups     []string // from the IdP (e.g. OIDC groups claim)
	Roles      []string // pre-resolved roles (e.g. from a user cert); if empty, resolved via bindings
	NodeID     string
	NodeName   string
	NodeLabels map[string]string
	Action     string // shell|exec|sftp|forward|attach|vpn
	ClientPath string // native|web
	// Service access (empty for plain node access): the specific service the
	// request targets. Rules can gate by service name, kind, and labels — so an
	// admin can authorize "the postgres service" or "rdp on workstations" or "the
	// 10.0.0.0/24 subnet route" rather than a blanket forward/vpn action.
	Service       string
	ServiceKind   string
	ServiceLabels map[string]string
	Now           time.Time
}

// Decision is the result of evaluation.
type Decision struct {
	Allow         bool
	Reason        string // human-readable allow/deny explanation
	MatchedRole   string
	MaxSessionTTL time.Duration // 0 = engine default
	AllowDetach   bool
	Record        bool
}

// ---------------------------------------------------------------------------
// Policy document (YAML)
// ---------------------------------------------------------------------------

type Doc struct {
	Roles    map[string]Role `yaml:"roles"`
	Bindings []Binding       `yaml:"bindings"`
}

type Role struct {
	Allow []Rule `yaml:"allow"`
}

type Rule struct {
	// Actions: list of session actions, "*" for all.
	Actions []string `yaml:"actions"`
	// Services / ServiceKinds / ServiceLabels gate access to specific services
	// inside a node (rdp, postgres, an http app, a subnet route, an exit node,
	// ...). If any is set, the request MUST target a matching service; if none
	// are set the rule applies to plain node access (and to any service, by its
	// action). "*" matches any. This is what turns node-as-workload policy into
	// service-level zero-trust policy.
	Services      []string          `yaml:"services,omitempty"`
	ServiceKinds  []string          `yaml:"service_kinds,omitempty"`
	ServiceLabels map[string]string `yaml:"service_labels,omitempty"`
	// NodeLabels must all match the node's labels. Value "*" matches any
	// value; key "*" (with value "*") matches any node.
	NodeLabels map[string]string `yaml:"node_labels"`
	// Optional clock window (gateway-local time).
	TimeWindow *TimeWindow `yaml:"time_window,omitempty"`
	// Optional session TTL cap, e.g. "8h".
	MaxSessionTTL Duration `yaml:"max_session_ttl,omitempty"`
	// AllowDetach: nil = true (detachable sessions permitted).
	AllowDetach *bool `yaml:"allow_detach,omitempty"`
	// RequireNative restricts this rule to the native (true E2E) client path:
	// it will not match web-proxy sessions. The most sensitive targets should
	// set this (the web session proxy sees plaintext).
	RequireNative bool `yaml:"require_native,omitempty"`
}

type TimeWindow struct {
	Days  []string `yaml:"days,omitempty"` // Mon Tue ... ; empty = all days
	Start string   `yaml:"start"`          // "09:00"
	End   string   `yaml:"end"`            // "17:00"
}

type Binding struct {
	Role   string   `yaml:"role"`
	Users  []string `yaml:"users,omitempty"`
	Groups []string `yaml:"groups,omitempty"`
}

// Duration decodes YAML strings like "8h30m" via time.ParseDuration.
type Duration time.Duration

func (d *Duration) UnmarshalYAML(value *yaml.Node) error {
	var s string
	if err := value.Decode(&s); err != nil {
		return fmt.Errorf("duration must be a string like \"8h\": %w", err)
	}
	v, err := time.ParseDuration(s)
	if err != nil {
		return err
	}
	*d = Duration(v)
	return nil
}

// ---------------------------------------------------------------------------
// Static engine
// ---------------------------------------------------------------------------

type Static struct {
	doc Doc
}

func Load(path string) (*Static, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return Parse(b)
}

func Parse(b []byte) (*Static, error) {
	var d Doc
	if err := yaml.Unmarshal(b, &d); err != nil {
		return nil, fmt.Errorf("policy yaml: %w", err)
	}
	for _, bind := range d.Bindings {
		if _, ok := d.Roles[bind.Role]; !ok {
			return nil, fmt.Errorf("binding references unknown role %q", bind.Role)
		}
	}
	return &Static{doc: d}, nil
}

func (s *Static) RolesFor(user string, groups []string) []string {
	gset := make(map[string]bool, len(groups))
	for _, g := range groups {
		gset[g] = true
	}
	var roles []string
	seen := map[string]bool{}
	for _, b := range s.doc.Bindings {
		match := false
		for _, u := range b.Users {
			if u == user {
				match = true
			}
		}
		for _, g := range b.Groups {
			if gset[g] {
				match = true
			}
		}
		if match && !seen[b.Role] {
			seen[b.Role] = true
			roles = append(roles, b.Role)
		}
	}
	sort.Strings(roles)
	return roles
}

func (s *Static) Evaluate(in Input) Decision {
	roles := in.Roles
	if len(roles) == 0 {
		roles = s.RolesFor(in.User, in.Groups)
	}
	if len(roles) == 0 {
		return Decision{Allow: false, Reason: fmt.Sprintf("user %q has no roles", in.User)}
	}
	now := in.Now
	if now.IsZero() {
		now = time.Now()
	}

	best := Decision{Allow: false, Reason: fmt.Sprintf("no rule in roles %v allows %s on node %s", roles, in.Action, in.NodeName)}
	for _, rname := range roles {
		role, ok := s.doc.Roles[rname]
		if !ok {
			continue
		}
		for _, rule := range role.Allow {
			if !rule.matches(in, now) {
				continue
			}
			d := Decision{
				Allow:         true,
				MatchedRole:   rname,
				Reason:        fmt.Sprintf("role %q allows %s on node %s", rname, in.Action, in.NodeName),
				MaxSessionTTL: time.Duration(rule.MaxSessionTTL),
				AllowDetach:   rule.AllowDetach == nil || *rule.AllowDetach,
				Record:        true,
			}
			if !best.Allow {
				best = d
				continue
			}
			// Merge across matching rules: most permissive wins.
			if d.AllowDetach {
				best.AllowDetach = true
			}
			if d.MaxSessionTTL == 0 || (best.MaxSessionTTL != 0 && d.MaxSessionTTL > best.MaxSessionTTL) {
				best.MaxSessionTTL = d.MaxSessionTTL
			}
		}
	}
	return best
}

// matchList reports whether v is in list, with "*" matching anything.
func matchList(list []string, v string) bool {
	for _, x := range list {
		if x == "*" || x == v {
			return true
		}
	}
	return false
}

func (r *Rule) matches(in Input, now time.Time) bool {
	// Fail closed: a require_native rule grants ONLY when the path is proven
	// native. An empty/unknown client_path must not satisfy it — otherwise the
	// most sensitive targets (those reserved for the true-E2E native client)
	// are reachable by any request that simply omits the field.
	if r.RequireNative && in.ClientPath != "native" {
		return false
	}
	// An empty actions list means "any action" (the rule is scoped by its other
	// constraints, e.g. service_kinds or node_labels).
	actionOK := len(r.Actions) == 0
	for _, a := range r.Actions {
		if a == "*" || a == in.Action {
			actionOK = true
			break
		}
		// "shell" implies permission to reattach to one's own shells.
		if a == "shell" && in.Action == "attach" {
			actionOK = true
			break
		}
	}
	if !actionOK {
		return false
	}
	// Service constraints: if a rule names services/kinds/labels, the request
	// MUST target a matching service (so a service-scoped rule never grants
	// plain node access, and vice versa).
	if len(r.Services) > 0 && !matchList(r.Services, in.Service) {
		return false
	}
	if len(r.ServiceKinds) > 0 && !matchList(r.ServiceKinds, in.ServiceKind) {
		return false
	}
	for k, v := range r.ServiceLabels {
		if k == "*" {
			continue
		}
		got, ok := in.ServiceLabels[k]
		if !ok {
			return false
		}
		if v != "*" && got != v {
			return false
		}
	}
	for k, v := range r.NodeLabels {
		if k == "*" {
			continue
		}
		got, ok := in.NodeLabels[k]
		if !ok {
			return false
		}
		if v != "*" && got != v {
			return false
		}
	}
	if r.TimeWindow != nil && !r.TimeWindow.contains(now) {
		return false
	}
	return true
}

func (w *TimeWindow) contains(now time.Time) bool {
	if len(w.Days) > 0 {
		day := now.Weekday().String()[:3] // Mon, Tue, ...
		ok := false
		for _, d := range w.Days {
			dd := strings.TrimSpace(d)
			if len(dd) < 3 {
				continue // malformed day entry must not panic evaluation (DoS)
			}
			if strings.EqualFold(dd[:3], day) {
				ok = true
				break
			}
		}
		if !ok {
			return false
		}
	}
	parse := func(s string) (int, bool) {
		var h, m int
		if _, err := fmt.Sscanf(s, "%d:%d", &h, &m); err != nil {
			return 0, false
		}
		return h*60 + m, true
	}
	start, ok1 := parse(w.Start)
	end, ok2 := parse(w.End)
	if !ok1 || !ok2 {
		return false // malformed window fails closed
	}
	cur := now.Hour()*60 + now.Minute()
	if start <= end {
		return cur >= start && cur < end
	}
	return cur >= start || cur < end // overnight window
}
