package controller

import (
	"testing"
	"time"
)

func TestSoftwareFactorVerify(t *testing.T) {
	f := softwareFactor{}
	ch := []byte("challenge-bytes")
	good := Attestation{Kind: "software", SessionID: "s-1", Counter: 1, ClientData: ch}

	if _, err := f.Verify(good, ch, EnrolledCredential{}, "s-1"); err != nil {
		t.Fatalf("valid beat should verify: %v", err)
	}
	// challenge mismatch (replay of an old/empty challenge)
	bad := good
	bad.ClientData = []byte("wrong")
	if _, err := f.Verify(bad, ch, EnrolledCredential{}, "s-1"); err == nil {
		t.Fatal("challenge mismatch must fail")
	}
	if _, err := f.Verify(good, nil, EnrolledCredential{}, "s-1"); err == nil {
		t.Fatal("empty server challenge must fail closed")
	}
	// cross-session replay: same attestation, different session id
	if _, err := f.Verify(good, ch, EnrolledCredential{}, "s-2"); err == nil {
		t.Fatal("session-id mismatch must fail (cross-session replay)")
	}
	// counter must start at 1
	zero := good
	zero.Counter = 0
	if _, err := f.Verify(zero, ch, EnrolledCredential{}, "s-1"); err == nil {
		t.Fatal("counter 0 must fail")
	}
}

func TestPresenceRegistryGate(t *testing.T) {
	// allow_software=true, no hardware enrolled -> software allowed.
	r := newPresenceRegistry(true)
	if _, err := r.Get("software", nil); err != nil {
		t.Fatalf("software should be allowed when no hardware enrolled: %v", err)
	}
	// once a hardware credential is enrolled, software is refused.
	if _, err := r.Get("software", []EnrolledCredential{{Kind: "webauthn"}}); err == nil {
		t.Fatal("software must be refused once a hardware credential is enrolled")
	}
	// allow_software=false refuses software even with no hardware.
	r2 := newPresenceRegistry(false)
	if _, err := r2.Get("software", nil); err == nil {
		t.Fatal("software must be refused when allow_software=false")
	}
	// unknown kind -> fail closed.
	if _, err := r.Get("fido2", nil); err == nil {
		t.Fatal("unknown factor kind must fail closed")
	}
}

func TestPresenceConfigValidation(t *testing.T) {
	dur := func(d time.Duration) Duration { return Duration(d) }
	base := func() *Config {
		return &Config{PolicyFile: "p", RelayAddrs: []string{"r:7403"}, ReauthInterval: dur(15 * time.Second)}
	}
	// valid: heartbeat 10s < ttl 30s, reauth 15s <= 30s
	c := base()
	c.Presence = PresenceConfig{HeartbeatInterval: dur(10 * time.Second), TTL: dur(30 * time.Second)}
	if err := c.validateForServe(); err != nil {
		t.Fatalf("valid presence config should pass: %v", err)
	}
	// heartbeat >= ttl -> hard error
	c = base()
	c.Presence = PresenceConfig{HeartbeatInterval: dur(30 * time.Second), TTL: dur(30 * time.Second)}
	if err := c.validateForServe(); err == nil {
		t.Fatal("heartbeat_interval >= ttl must be rejected")
	}
	// reauth > ttl -> hard error
	c = base()
	c.ReauthInterval = dur(60 * time.Second)
	c.Presence = PresenceConfig{HeartbeatInterval: dur(10 * time.Second), TTL: dur(30 * time.Second)}
	if err := c.validateForServe(); err == nil {
		t.Fatal("reauth_interval > ttl must be rejected")
	}
	// ttl == 0 (off) -> no presence validation
	c = base()
	c.Presence = PresenceConfig{HeartbeatInterval: dur(99 * time.Hour)}
	if err := c.validateForServe(); err != nil {
		t.Fatalf("presence off (ttl=0) should skip presence validation: %v", err)
	}
}

func TestEnrollGateAndWebauthnSeam(t *testing.T) {
	st, err := OpenStore(t.TempDir() + "/state.db")
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	ws := "default"
	if err := st.AddPresenceCredential(ws, "oidc", "subj-1", EnrolledCredential{Kind: "webauthn", PublicKey: []byte("pk")}); err != nil {
		t.Fatalf("enroll: %v", err)
	}
	m, err := st.GetMember(ws, "oidc", "subj-1")
	if err != nil || m == nil || len(m.PresenceCredentials) != 1 {
		t.Fatalf("credential not persisted: %v %+v", err, m)
	}
	// idempotent
	if err := st.AddPresenceCredential(ws, "oidc", "subj-1", EnrolledCredential{Kind: "webauthn", PublicKey: []byte("pk")}); err != nil {
		t.Fatal(err)
	}
	if m2, _ := st.GetMember(ws, "oidc", "subj-1"); len(m2.PresenceCredentials) != 1 {
		t.Fatal("AddPresenceCredential must be idempotent by pubkey")
	}
	// gate: once hardware is enrolled, software is refused for this principal
	r := newPresenceRegistry(true)
	if _, err := r.Get("software", m.PresenceCredentials); err == nil {
		t.Fatal("software must be refused after a hardware credential is enrolled")
	}
	// the webauthn factor seam is fail-closed until the crypto lands
	if _, err := (webauthnFactor{}).Verify(Attestation{Kind: "webauthn", SessionID: "s", Counter: 1, ClientData: []byte("c")}, []byte("c"), EnrolledCredential{}, "s"); err == nil {
		t.Fatal("webauthn factor must be fail-closed (not yet implemented)")
	}
}
