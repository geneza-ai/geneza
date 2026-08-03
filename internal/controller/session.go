package controller

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"strings"
	"time"

	bbolt "go.etcd.io/bbolt"
)

// Controller-minted browser session. After authenticating a human by ANY
// provider (local/oidc/keystone) the controller mints an OPAQUE 256-bit token and
// hands it to the browser, which carries it as a Bearer header (sessionStorage,
// not a cookie → no CSRF surface). The token is stored hashed: the bucket key is
// sha256(token), so a DB/backup leak cannot resurrect a live session. The record
// is the SOLE console authority — workspace/roles/admin come only from it, never
// from a re-verified upstream token (which is discarded after mint), and never
// from a client-supplied value.
//
// Storage mirrors the join-token primitive (a single global bucket, atomic
// redeem/delete) but is semantically distinct from the brokered remote-access
// SessionRecord — do not conflate them.

var (
	bucketAuthSessions = []byte("sessions_auth") // global: sha256(token) hex -> AuthSession
	bucketWSTickets    = []byte("ws_tickets")    // global: sha256(ticket) -> WSTicket (one-time WS auth)
)

// WSTicket is a short-lived, single-use credential for a browser WebSocket
// (the remote shell). A WS handshake cannot carry a Bearer header, so the URL
// carries a ?ticket= — but it must NOT be the session token (it would leak into
// access logs / Referer). Instead the SPA mints a node-scoped ticket that
// points at its session; handleShell redeems it once and re-reads the session.
type WSTicket struct {
	TicketHash       string `json:"ticket_hash"`
	SessionTokenHash string `json:"session_token_hash"` // links to the AuthSession (for the live watchdog)
	NodeID           string `json:"node_id"`
	ExpiresUnix      int64  `json:"expires_unix"`
}

// MintWSTicket creates a one-time ticket bound to a session + node.
func (s *bboltStore) MintWSTicket(sessionTokenHash, nodeID string, ttl time.Duration) (string, error) {
	ticket, err := randToken(32)
	if err != nil {
		return "", err
	}
	rec := &WSTicket{
		TicketHash: hashToken(ticket), SessionTokenHash: sessionTokenHash,
		NodeID: nodeID, ExpiresUnix: time.Now().Add(ttl).Unix(),
	}
	err = s.db.Update(func(tx *bbolt.Tx) error {
		return putJSON(tx, bucketWSTickets, rec.TicketHash, rec)
	})
	if err != nil {
		return "", err
	}
	return ticket, nil
}

// RedeemWSTicket consumes a ticket once (single bbolt Update) and returns its
// session token hash + node. Expired/unknown/used tickets fail closed.
func (s *bboltStore) RedeemWSTicket(ticket string, now int64) (sessionTokenHash, nodeID string, err error) {
	th := hashToken(ticket)
	err = s.db.Update(func(tx *bbolt.Tx) error {
		var rec WSTicket
		if gerr := getJSON(tx, bucketWSTickets, th, &rec); gerr != nil {
			return errInvalidTicket
		}
		_ = tx.Bucket(bucketWSTickets).Delete([]byte(th)) // single-use
		if now >= rec.ExpiresUnix {
			return errInvalidTicket
		}
		sessionTokenHash = rec.SessionTokenHash
		nodeID = rec.NodeID
		return nil
	})
	return sessionTokenHash, nodeID, err
}

var errInvalidTicket = errors.New("invalid or expired ticket")

// session kinds discriminate the disjoint browser-session namespaces stored in
// the one auth-session bucket: a tenant console session (the default, empty/legacy
// value), a cluster-operator console session, and a hosted-UI launch session. Each
// console resolves ONLY its own kind, so a tenant session can never authenticate the
// cluster console, nor a cluster session the tenant console. A launch session is a
// tenant session narrowed by a SessionScope: it authenticates the same console but
// is admitted ONLY on the routes that explicitly opt in (authScoped).
const (
	sessionKindTenant  = "tenant"
	sessionKindCluster = "cluster"
	sessionKindLaunch  = "launch"
)

// SessionScope pins a hosted-UI launch session to exactly what the launch
// authorized: one node, one set of actions. It is written at mint time from the
// server-resolved launch and never from anything the browser sends, so the
// scope cannot be widened by editing a URL. Nil scope = an ordinary full
// console session.
//
// The containment rule is intersection, never union: effective authority is
// policy(user's roles) ∩ scope. A scope can only ever make a session LESS
// capable than the same human logging into the console directly.
type SessionScope struct {
	NodeID   string   `json:"node_id"`             // the single node this session may address
	NodeName string   `json:"node_name,omitempty"` // display only
	Actions  []string `json:"actions"`             // e.g. ["shell"]; empty = nothing
	Cloud    string   `json:"cloud,omitempty"`     // svc-uid the launch was authenticated against
	Instance string   `json:"instance,omitempty"`  // the cloud instance id the portal named (audit)
	Embed    bool     `json:"embed,omitempty"`     // launched to be framed (§7 frame-ancestors applies)
}

// allowsNode reports whether a scoped session may address this node. An
// unscoped session (nil receiver) may address any node in its workspace.
func (sc *SessionScope) allowsNode(nodeID string) bool {
	if sc == nil {
		return true
	}
	return sc.NodeID != "" && sc.NodeID == nodeID
}

// allowsAction reports whether a scoped session may broker this action. An
// unscoped session (nil receiver) is bounded by policy alone.
func (sc *SessionScope) allowsAction(action string) bool {
	if sc == nil {
		return true
	}
	return contains(sc.Actions, action)
}

// AuthSession is one logged-in browser session.
type AuthSession struct {
	TokenHash   string   `json:"token_hash"`              // sha256(token) hex — also the bucket key
	Kind        string   `json:"kind,omitempty"`          // "" / "tenant" (tenant console) | "cluster" (cluster console)
	User        string   `json:"user"`                    // canonical display name
	Provider    string   `json:"provider"`                // keystone|oidc|local
	Source      string   `json:"source,omitempty"`        // keystone svc-uid / oidc issuer / "" local
	Subject     string   `json:"subject"`                 // stable provider id (authz key)
	Workspace   string   `json:"workspace"`               // resolved server-side; SOLE console authority
	Roles       []string `json:"roles"`                   // stripReservedRoles'd at mint
	Groups      []string `json:"groups,omitempty"`        // IdP/keystone groups (audit + re-resolution)
	Admin       bool     `json:"admin"`                   // isWorkspaceAdmin(Roles)
	KSTokenHash string   `json:"ks_token_hash,omitempty"` // keystone token sha256 — for a future revocation reaper
	// Scope narrows a launch session to one node + action set. Non-nil implies
	// Kind == sessionKindLaunch and Admin == false, both forced at mint.
	Scope *SessionScope `json:"scope,omitempty"`

	CreatedUnix int64 `json:"created_unix"`
	ExpiresUnix int64 `json:"expires_unix"` // min(now+ConsoleSessionTTL, UpstreamExp)
	// MaxExpiresUnix is the ABSOLUTE ceiling for a renewable (launch) session.
	// Renewal slides ExpiresUnix forward but can never pass this, so an
	// indefinitely-held shell still ends. Zero = not renewable.
	MaxExpiresUnix int64  `json:"max_expires_unix,omitempty"`
	UpstreamExp    int64  `json:"upstream_exp,omitempty"` // keystone expires_at / oidc exp / 0 local
	LastSeenUnix   int64  `json:"last_seen_unix"`         // sliding-idle bookkeeping (reserved)
	UserAgent      string `json:"user_agent,omitempty"`   // soft fingerprint (reserved)
	Revoked        bool   `json:"revoked,omitempty"`
	// Continuous presence for a presence-required browser session;
	// the SPA beacon (POST /api/v1/session/heartbeat) stamps these and the web-shell
	// watchdog drops the session when they go stale. Zero values = presence-off.
	RequirePresence       bool   `json:"require_presence,omitempty"`
	LastPresenceUnix      int64  `json:"last_presence_unix,omitempty"`
	PresenceChallenge     []byte `json:"presence_challenge,omitempty"`
	PrevPresenceChallenge []byte `json:"prev_presence_challenge,omitempty"`
	PrevChallengeUnix     int64  `json:"prev_challenge_unix,omitempty"`
}

// hashToken is the at-rest key for any opaque secret (session/device/handoff):
// the raw secret lives only on the client; the controller stores sha256(secret).
func hashToken(token string) string {
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:])
}

// randToken returns a fresh URL-safe random secret of nBytes of entropy as hex.
func randToken(nBytes int) (string, error) {
	b := make([]byte, nBytes)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

func (s *bboltStore) PutAuthSession(rec *AuthSession) error {
	return s.db.Update(func(tx *bbolt.Tx) error {
		return putJSON(tx, bucketAuthSessions, rec.TokenHash, rec)
	})
}

// GetAuthSession looks up a session by the RAW token's hash. Returns ErrNotFound
// for unknown/deleted tokens.
func (s *bboltStore) GetAuthSession(tokenHash string) (*AuthSession, error) {
	var rec AuthSession
	err := s.db.View(func(tx *bbolt.Tx) error {
		return getJSON(tx, bucketAuthSessions, tokenHash, &rec)
	})
	if err != nil {
		return nil, err
	}
	return &rec, nil
}

func (s *bboltStore) DeleteAuthSession(tokenHash string) error {
	return s.db.Update(func(tx *bbolt.Tx) error {
		return tx.Bucket(bucketAuthSessions).Delete([]byte(tokenHash))
	})
}

func (s *bboltStore) ListAuthSessions() ([]*AuthSession, error) {
	var out []*AuthSession
	err := s.db.View(func(tx *bbolt.Tx) error {
		return tx.Bucket(bucketAuthSessions).ForEach(func(_, v []byte) error {
			var rec AuthSession
			if err := json.Unmarshal(v, &rec); err != nil {
				return err
			}
			out = append(out, &rec)
			return nil
		})
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}

// RevokeAuthSessionsForUser deletes every browser session owned by a display
// name (the RevokeUser fan-out: web + CLI revocation are uniform). It is
// coarse by design — admin "kick this user" should drop all their sessions.
func (s *bboltStore) RevokeAuthSessionsForUser(user string) (int, error) {
	n := 0
	err := s.db.Update(func(tx *bbolt.Tx) error {
		b := tx.Bucket(bucketAuthSessions)
		var kill [][]byte
		if err := b.ForEach(func(k, v []byte) error {
			var rec AuthSession
			if err := json.Unmarshal(v, &rec); err != nil {
				return err
			}
			if rec.User == user {
				kill = append(kill, append([]byte(nil), k...))
			}
			return nil
		}); err != nil {
			return err
		}
		for _, k := range kill {
			if err := b.Delete(k); err != nil {
				return err
			}
			n++
		}
		return nil
	})
	return n, err
}

// RevokeAuthSessionsForSubject deletes every browser session owned by a
// principal (provider+subject) — the precise suspension key, not the mutable
// display name.
func (s *bboltStore) RevokeAuthSessionsForSubject(provider, subject string) (int, error) {
	if subject == "" {
		return 0, nil
	}
	want := strings.TrimPrefix(provider, "device:")
	n := 0
	err := s.db.Update(func(tx *bbolt.Tx) error {
		b := tx.Bucket(bucketAuthSessions)
		var kill [][]byte
		if err := b.ForEach(func(k, v []byte) error {
			var rec AuthSession
			if err := json.Unmarshal(v, &rec); err != nil {
				return err
			}
			if strings.TrimPrefix(rec.Provider, "device:") == want && rec.Subject == subject {
				kill = append(kill, append([]byte(nil), k...))
			}
			return nil
		}); err != nil {
			return err
		}
		for _, k := range kill {
			if err := b.Delete(k); err != nil {
				return err
			}
			n++
		}
		return nil
	})
	return n, err
}

// SweepExpiredAuthSessions deletes sessions past their expiry. Returns the count.
func (s *bboltStore) SweepExpiredAuthSessions(now int64) (int, error) {
	n := 0
	err := s.db.Update(func(tx *bbolt.Tx) error {
		b := tx.Bucket(bucketAuthSessions)
		var dead [][]byte
		if err := b.ForEach(func(k, v []byte) error {
			var rec AuthSession
			if err := json.Unmarshal(v, &rec); err != nil {
				return err
			}
			if rec.ExpiresUnix > 0 && now >= rec.ExpiresUnix {
				dead = append(dead, append([]byte(nil), k...))
			}
			return nil
		}); err != nil {
			return err
		}
		for _, k := range dead {
			if err := b.Delete(k); err != nil {
				return err
			}
			n++
		}
		return nil
	})
	return n, err
}

// sessionInput is the authenticated, workspace-resolved result of a login,
// ready to be sealed into a session.
type sessionInput struct {
	Provider    string
	Source      string
	User        string
	Subject     string
	Workspace   string
	Roles       []string
	Groups      []string
	UpstreamExp int64 // upstream credential expiry (keystone expires_at / oidc exp); 0 = none
	KSTokenHash string
	UserAgent   string
	// Scope, when set, mints a NARROWED launch session instead of a full console
	// one (§6 of docs/hosted-ui-launch-spec.md). MaxTTL caps this session below
	// the console default; 0 means use the default. AbsoluteTTL is the ceiling
	// renewal may never slide past; 0 means the session is not renewable.
	Scope       *SessionScope
	MaxTTL      time.Duration
	AbsoluteTTL time.Duration
}

// mintAuthSession seals a sessionInput into a stored AuthSession and returns the
// RAW token (the only place it ever exists outside the browser). The session TTL
// is capped by the upstream credential's expiry: a session can never
// outlive the keystone/oidc token that authorized it.
//
// A scoped input mints a launch session: the kind flips, the TTL is capped
// further, and Admin is forced false — a one-click hosted-UI launch is never a
// console admin, even when the human behind it is a ws-admin.
func (s *Server) mintAuthSession(in sessionInput) (string, *AuthSession, error) {
	token, err := randToken(32) // 256-bit
	if err != nil {
		return "", nil, err
	}
	now := time.Now()
	ttl := s.cfg.consoleSessionTTL()
	if in.MaxTTL > 0 && in.MaxTTL < ttl {
		ttl = in.MaxTTL
	}
	exp := now.Add(ttl)
	if in.UpstreamExp > 0 && in.UpstreamExp < exp.Unix() {
		exp = time.Unix(in.UpstreamExp, 0)
	}
	roles := stripReservedRoles(in.Roles)
	rec := &AuthSession{
		TokenHash:    hashToken(token),
		User:         in.User,
		Provider:     in.Provider,
		Source:       in.Source,
		Subject:      in.Subject,
		Workspace:    in.Workspace,
		Roles:        roles,
		Groups:       in.Groups,
		Admin:        isWorkspaceAdmin(roles),
		KSTokenHash:  in.KSTokenHash,
		CreatedUnix:  now.Unix(),
		ExpiresUnix:  exp.Unix(),
		UpstreamExp:  in.UpstreamExp,
		LastSeenUnix: now.Unix(),
		UserAgent:    in.UserAgent,
	}
	rec.Kind = sessionKindTenant
	if in.Scope != nil {
		rec.Kind = sessionKindLaunch
		rec.Scope = in.Scope
		rec.Admin = false // structural: a scope only ever narrows
		if in.AbsoluteTTL > 0 {
			max := now.Add(in.AbsoluteTTL).Unix()
			if in.UpstreamExp > 0 && in.UpstreamExp < max {
				max = in.UpstreamExp
			}
			rec.MaxExpiresUnix = max
		}
	}
	if err := s.store.PutAuthSession(rec); err != nil {
		return "", nil, err
	}
	return token, rec, nil
}

// renewSession slides a renewable session's expiry forward by its idle window,
// bounded by the absolute ceiling stamped at mint (which already folds in the
// upstream credential's expiry). It is NOT a blind extension: revocation,
// expiry, and suspension are all re-checked first, so a renew can never
// resurrect a session that policy has already turned off.
//
// window is the idle allowance — each renewal buys that much more time from
// now, so an attended shell stays alive and an abandoned one still dies.
func (s *Server) renewSession(tokenHash string, window time.Duration) (*AuthSession, error) {
	rec, err := s.store.GetAuthSession(tokenHash)
	if err != nil {
		return nil, errors.New("invalid session")
	}
	if rec.MaxExpiresUnix == 0 {
		return nil, errors.New("session is not renewable")
	}
	now := time.Now()
	if rec.Revoked || (rec.ExpiresUnix > 0 && now.Unix() >= rec.ExpiresUnix) {
		return nil, errors.New("session is no longer valid")
	}
	if s.store.IsSuspended(rec.Workspace, rec.Provider, rec.Subject) {
		return nil, errors.New("authorization suspended")
	}
	next := now.Add(window).Unix()
	if next > rec.MaxExpiresUnix {
		next = rec.MaxExpiresUnix
	}
	if next <= rec.ExpiresUnix {
		return rec, nil // already at the ceiling; nothing to extend
	}
	rec.ExpiresUnix = next
	rec.LastSeenUnix = now.Unix()
	if err := s.store.PutAuthSession(rec); err != nil {
		return nil, err
	}
	return rec, nil
}

// clusterSessionInput is the verified, group-gated identity of a cluster-console
// OIDC login, ready to be sealed into a cluster session.
type clusterSessionInput struct {
	Source      string // oidc issuer
	User        string
	Subject     string
	Groups      []string
	UpstreamExp int64 // id_token exp; caps the session TTL
	UserAgent   string
}

// mintClusterSession seals a verified cluster-admin OIDC login into a SEPARATE
// cluster-kind session and returns the raw bearer. It is deliberately NOT
// mintAuthSession: a cluster session carries no tenant workspace/roles (the cluster
// console gates on the kind + the required group, not on tenant roles), and it is
// stamped sessionKindCluster so the tenant console can never resolve it. The TTL is
// capped by the id_token's expiry exactly like a tenant session.
func (s *Server) mintClusterSession(in clusterSessionInput) (string, *AuthSession, error) {
	token, err := randToken(32) // 256-bit
	if err != nil {
		return "", nil, err
	}
	now := time.Now()
	exp := now.Add(s.cfg.consoleSessionTTL())
	if in.UpstreamExp > 0 && in.UpstreamExp < exp.Unix() {
		exp = time.Unix(in.UpstreamExp, 0)
	}
	rec := &AuthSession{
		TokenHash:    hashToken(token),
		Kind:         sessionKindCluster,
		User:         in.User,
		Provider:     providerOIDC,
		Source:       in.Source,
		Subject:      in.Subject,
		Groups:       in.Groups,
		CreatedUnix:  now.Unix(),
		ExpiresUnix:  exp.Unix(),
		UpstreamExp:  in.UpstreamExp,
		LastSeenUnix: now.Unix(),
		UserAgent:    in.UserAgent,
	}
	if err := s.store.PutAuthSession(rec); err != nil {
		return "", nil, err
	}
	return token, rec, nil
}

// clusterSessionByToken resolves a raw bearer to a live CLUSTER session. It fails
// closed for an unknown/revoked/expired token AND for any session that is not of the
// cluster kind — so a tenant session presented here is rejected as if absent.
func (s *Server) clusterSessionByToken(tok string) (*AuthSession, error) {
	if tok == "" {
		return nil, errors.New("missing session token")
	}
	rec, err := s.store.GetAuthSession(hashToken(tok))
	if err != nil {
		return nil, errors.New("invalid session")
	}
	if rec.Kind != sessionKindCluster {
		return nil, errors.New("not a cluster session")
	}
	if rec.Revoked {
		return nil, errors.New("session revoked")
	}
	if rec.ExpiresUnix > 0 && time.Now().Unix() >= rec.ExpiresUnix {
		_ = s.store.DeleteAuthSession(rec.TokenHash)
		return nil, errors.New("session expired")
	}
	return rec, nil
}
