package controller

import (
	"encoding/base64"
	"encoding/json"
	"net/http"
)

// presence_enroll.go is the hardware presence-factor ENROLL seam.
// It wires the full enroll path — begin (issue a challenge) -> finish (store an
// EnrolledCredential on the member) -> the registry's software-stub safety gate
// then refuses Kind=="software" for that principal. The WebAuthn crypto itself is
// the documented drop-in (webauthnFactor.Verify in presence.go); these handlers
// store the credential the SPA + go-webauthn would produce. Bearer-authed; the
// user enrolls a factor for THEIR OWN principal (Provider+Subject from the cert).

// handleEnrollBegin issues a single-use enroll challenge plus the relying-party +
// user info a WebAuthn `navigator.credentials.create` call needs. Stub: the SPA
// frontend drives the authenticator; here we mint the challenge and the
// user binding (the durable Subject, never the mutable display name).
func (c *consoleAPI) handleEnrollBegin(w http.ResponseWriter, r *http.Request, u *consoleUser) {
	ch := newPresenceChallenge()
	writeJSON(w, map[string]any{
		"challenge":        base64.StdEncoding.EncodeToString(ch),
		"rp":               map[string]string{"id": "geneza", "name": "Geneza"},
		"user":             map[string]string{"id": u.Subject, "name": u.Name},
		"userVerification": "required",
	})
}

// handleEnrollFinish stores the attested credential. Stub: it persists the public
// key + AAGUID the authenticator returned (the SPA forwards the attestation
// object; real verification of that object is the go-webauthn drop-in). Once
// stored, software presence beats for this principal are refused (the gate).
func (c *consoleAPI) handleEnrollFinish(w http.ResponseWriter, r *http.Request, u *consoleUser) {
	var body struct {
		Kind      string `json:"kind"`       // "webauthn" | "fido2"
		PublicKey string `json:"public_key"` // base64
		AAGUID    string `json:"aaguid"`     // base64
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<16)).Decode(&body); err != nil {
		writeErr(w, http.StatusBadRequest, "bad enroll body")
		return
	}
	kind := body.Kind
	if kind == "" {
		kind = "webauthn"
	}
	if kind == "software" { // a hardware enroll must never register the stub kind
		writeErr(w, http.StatusBadRequest, "enroll requires a hardware factor kind")
		return
	}
	pub, _ := base64.StdEncoding.DecodeString(body.PublicKey)
	aaguid, _ := base64.StdEncoding.DecodeString(body.AAGUID)
	cred := EnrolledCredential{Kind: kind, PublicKey: pub, AAGUID: aaguid}
	if err := c.s.store.AddPresenceCredential(u.Workspace, u.Provider, u.Subject, cred); err != nil {
		writeErr(w, http.StatusInternalServerError, "store credential")
		return
	}
	_ = c.s.audit.Append("presence_factor_enrolled", u.Name, "", "", map[string]string{
		"workspace": u.Workspace, "provider": normProvider(u.Provider), "subject": u.Subject, "kind": kind,
	})
	writeJSON(w, map[string]any{"ok": true, "kind": kind})
}

// handleEnrollList returns the kinds of presence factors enrolled for the caller,
// so the console can show "presence factor: SOFTWARE" vs hardware: a software-only
// "present" must be visibly distinct from a hardware-attested one in the audit surface.
func (c *consoleAPI) handleEnrollList(w http.ResponseWriter, r *http.Request, u *consoleUser) {
	kinds := []string{}
	if m, err := c.s.store.GetMember(u.Workspace, u.Provider, u.Subject); err == nil && m != nil {
		for _, cr := range m.PresenceCredentials {
			kinds = append(kinds, cr.Kind)
		}
	}
	hasHardware := len(kinds) > 0
	writeJSON(w, map[string]any{"credentials": kinds, "hasHardware": hasHardware, "softwareAllowed": c.s.cfg.Presence.SoftwareAllowed() && !hasHardware})
}
