package controller

import (
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"net"
	"net/http"
	"strings"
	"time"
)

// RFC 8628 device-grant HTTP endpoints. The anonymous authorize+token endpoints
// run on the main :7402 listener (so the CLI logs in even with the console
// disabled) AND on the console; the session-authed lookup/approve/deny
// run on the console (the human approves there). The CLI never touches the
// console; the human never touches the token endpoint.

const maxPendingDeviceGrants = 256 // global DoS backstop (RT-DoS)

// clientIP extracts the real client IP behind the nginx terminator.
func clientIP(r *http.Request) string {
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		if i := strings.IndexByte(xff, ','); i > 0 {
			return strings.TrimSpace(xff[:i])
		}
		return strings.TrimSpace(xff)
	}
	if host, _, err := net.SplitHostPort(r.RemoteAddr); err == nil {
		return host
	}
	return r.RemoteAddr
}

// handleDeviceAuthorize mints a device+user code for a CLI login (anonymous).
func (s *Server) handleDeviceAuthorize(w http.ResponseWriter, r *http.Request) {
	var req struct {
		CSRPem     string `json:"csrPem"`
		ClientName string `json:"clientName"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid request")
		return
	}
	// Validate the CSR up front (PUBLIC material only; the controller signs it at
	// approval). A malformed CSR never enters the store.
	blk, _ := pem.Decode([]byte(req.CSRPem))
	if blk == nil {
		writeErr(w, http.StatusBadRequest, "csrPem is not a PEM block")
		return
	}
	if _, err := x509.ParseCertificateRequest(blk.Bytes); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid CSR")
		return
	}
	if n, err := s.store.countDeviceGrants(); err == nil && n >= maxPendingDeviceGrants {
		writeErr(w, http.StatusTooManyRequests, "too many pending device logins; try again shortly")
		return
	}
	deviceCode, err := randToken(32)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "internal error")
		return
	}
	userCode, err := newUserCode()
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "internal error")
		return
	}
	ttl := s.cfg.deviceCodeTTL()
	interval := int32(s.cfg.devicePollInterval().Seconds())
	if interval < 1 {
		interval = 5
	}
	now := time.Now()
	clientName := req.ClientName
	if clientName == "" {
		clientName = "geneza-cli"
	}
	g := &DeviceGrant{
		DeviceHash:   hashToken(deviceCode),
		UserCodeHash: hashToken(normalizeUserCode(userCode)),
		CSRPem:       []byte(req.CSRPem),
		ClientName:   clientName,
		SourceIP:     clientIP(r),
		State:        deviceStatePending,
		CreatedUnix:  now.Unix(),
		ExpiresUnix:  now.Add(ttl).Unix(),
		Interval:     interval,
	}
	if err := s.store.PutDeviceGrant(g); err != nil {
		writeErr(w, http.StatusInternalServerError, "could not start device login")
		return
	}
	base := s.consoleExternalURL()
	writeJSON(w, map[string]any{
		"deviceCode":              deviceCode,
		"userCode":                userCode,
		"verificationUri":         base + "/activate",
		"verificationUriComplete": base + "/activate?user_code=" + userCode,
		"expiresIn":               int(ttl.Seconds()),
		"interval":                interval,
	})
}

// handleDeviceToken is the RFC 8628 polling endpoint (anonymous). It returns the
// issued cert on success or an RFC 8628 error (authorization_pending /
// slow_down / access_denied / expired_token) with HTTP 400.
func (s *Server) handleDeviceToken(w http.ResponseWriter, r *http.Request) {
	var req struct {
		DeviceCode string `json:"deviceCode"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.DeviceCode == "" {
		writeErr(w, http.StatusBadRequest, "invalid request")
		return
	}
	certPEM, err := s.store.PollDeviceGrant(req.DeviceCode, time.Now().Unix(), func(g *DeviceGrant) ([]byte, error) {
		// The SUSPENDED-principal gate (authn != authz) now runs INSIDE
		// PollDeviceGrant's redeem txn so the Store interface stays backend-
		// agnostic; this callback just mints the cert.
		// Cert TTL is capped by the approving session's upstream expiry.
		ttl := s.cfg.CertTTL.User.D()
		if g.UpstreamExp > 0 {
			if d := time.Until(time.Unix(g.UpstreamExp, 0)); d < ttl {
				ttl = d
			}
		}
		pem, _, ierr := s.issueUserCert("device:"+g.ApprovedProvider, g.ApprovedUser, g.ApprovedSubject, g.ApprovedWS, g.ApprovedRoles, g.CSRPem, ttl)
		return pem, ierr
	})
	if err != nil {
		if de, ok := err.(deviceTokenError); ok {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusBadRequest)
			_ = json.NewEncoder(w).Encode(map[string]string{"error": de.code})
			return
		}
		writeErr(w, http.StatusInternalServerError, "device token error")
		return
	}
	exp, _ := leafNotAfter(certPEM)
	writeJSON(w, map[string]any{
		"userCertPem": string(certPEM),
		"caRootsPem":  string(s.ca.RootsPEM),
		"expiresUnix": exp,
	})
}

// ---- console (session-authed) approval surface ----

// handleDeviceLookup returns the pending grant's metadata for the approval page
// (the human verifies client name + source IP before approving).
func (c *consoleAPI) handleDeviceLookup(w http.ResponseWriter, r *http.Request, _ *consoleUser) {
	code := r.PathValue("code")
	g, err := c.s.store.GetDeviceGrantByUserCode(code)
	if err != nil || g.State != deviceStatePending || time.Now().Unix() >= g.ExpiresUnix {
		writeErr(w, http.StatusNotFound, "no such pending device login")
		return
	}
	writeJSON(w, map[string]any{
		"clientName": g.ClientName, "sourceIp": g.SourceIP, "requestedUnix": g.CreatedUnix,
	})
}

// handleDeviceApprove binds a pending grant to the approving console user. The
// human MUST type the user_code (it is the request body — no one-click from the
// verification_uri_complete). Workspace + roles are recomputed
// server-side from the approver and asserted: the CLI receives exactly
// the approver's access in their current workspace, never more.
func (c *consoleAPI) handleDeviceApprove(w http.ResponseWriter, r *http.Request, u *consoleUser) {
	var req struct {
		UserCode string `json:"userCode"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.UserCode == "" {
		writeErr(w, http.StatusBadRequest, "userCode is required")
		return
	}
	// Recompute the approver's roles in their session workspace — never trust a
	// client-supplied workspace/roles. Assert membership.
	roles := c.s.rolesForMember(u.Workspace, u.Provider, u.Name, u.Subject, u.Groups)
	if len(roles) == 0 {
		writeErr(w, http.StatusForbidden, "you have no roles to delegate")
		return
	}
	err := c.s.store.ApproveDeviceGrant(req.UserCode, func(g *DeviceGrant) error {
		g.State = deviceStateApproved
		g.ApprovedUser = u.Name
		g.ApprovedSubject = u.Subject
		g.ApprovedProvider = u.Provider
		g.ApprovedWS = u.Workspace
		g.ApprovedRoles = roles
		g.ApprovedBy = u.Name
		g.UpstreamExp = u.ExpiresUnix // the CLI cert can't outlive the approver's session
		return nil
	})
	if err != nil {
		writeErr(w, http.StatusNotFound, "no such pending device login")
		return
	}
	_ = c.s.audit.AppendWS(u.Workspace, "device_approve", u.Name, "", "", map[string]string{
		"workspace": u.Workspace, "roles": strings.Join(roles, ","),
	})
	writeJSON(w, map[string]any{"ok": true})
}

func (c *consoleAPI) handleDeviceDeny(w http.ResponseWriter, r *http.Request, u *consoleUser) {
	var req struct {
		UserCode string `json:"userCode"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.UserCode == "" {
		writeErr(w, http.StatusBadRequest, "userCode is required")
		return
	}
	if err := c.s.store.DenyDeviceGrant(req.UserCode); err != nil {
		writeErr(w, http.StatusNotFound, "no such pending device login")
		return
	}
	_ = c.s.audit.AppendWS(u.Workspace, "device_deny", u.Name, "", "", nil)
	writeJSON(w, map[string]any{"ok": true})
}

// consoleExternalURL is the public origin the CLI sends the human to.
func (s *Server) consoleExternalURL() string {
	return strings.TrimRight(s.cfg.Console.ExternalURL, "/")
}
