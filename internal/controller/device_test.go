package controller

import (
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"testing"

	"geneza.io/internal/ca"
)

// makeCSRPEM returns a valid PKCS10 CSR PEM for the device flow.
func makeCSRPEM(t *testing.T) string {
	t.Helper()
	key, err := ca.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	csr, err := ca.MakeCSR(key, "geneza-user")
	if err != nil {
		t.Fatal(err)
	}
	return string(csr)
}

// jsonStr JSON-quotes a string for inline request bodies.
func jsonStr(s string) string {
	b, _ := json.Marshal(s)
	return string(b)
}

// loginLocalToken logs a local user into the console and returns the session token.
func loginLocalToken(t *testing.T, h http.Handler, user, pass string) string {
	t.Helper()
	code, resp := doJSON(t, h, "POST", "/api/v1/session/local", "", `{"username":`+jsonStr(user)+`,"password":`+jsonStr(pass)+`}`)
	if code != 200 {
		t.Fatalf("local login (%s): %d %v", user, code, resp)
	}
	tok, _ := resp["token"].(string)
	if tok == "" {
		t.Fatalf("local login (%s) returned no token: %v", user, resp)
	}
	return tok
}

func TestDeviceFlowEndToEnd(t *testing.T) {
	_, api := testConsoleServer(t)
	h := api.handler()
	csr := makeCSRPEM(t)

	// 1. CLI starts the device flow (anonymous).
	code, da := doJSON(t, h, "POST", "/api/v1/device/authorize", "", `{"csrPem":`+jsonStr(csr)+`,"clientName":"laptop"}`)
	if code != 200 {
		t.Fatalf("authorize: %d %v", code, da)
	}
	deviceCode, _ := da["deviceCode"].(string)
	userCode, _ := da["userCode"].(string)
	if deviceCode == "" || userCode == "" {
		t.Fatalf("authorize missing codes: %v", da)
	}

	// 2. Before approval, the token endpoint says authorization_pending.
	code, errBody := doJSON(t, h, "POST", "/api/v1/device/token", "", `{"deviceCode":`+jsonStr(deviceCode)+`}`)
	if code != 400 || errBody["error"] != "authorization_pending" {
		t.Fatalf("pending poll: %d %v", code, errBody)
	}

	// 3. A human (alice) logs into the console and approves (typing the code).
	st := loginLocalToken(t, h, "alice", "hunter2")
	code, _ = doJSON(t, h, "GET", "/api/v1/device/"+userCode, st, "")
	if code != 200 {
		t.Fatalf("device lookup: %d", code)
	}
	code, _ = doJSON(t, h, "POST", "/api/v1/device/approve", st, `{"userCode":`+jsonStr(userCode)+`}`)
	if code != 200 {
		t.Fatalf("approve: %d", code)
	}

	// 4. The CLI poll now returns a cert bound to the approver's identity.
	code, tok := doJSON(t, h, "POST", "/api/v1/device/token", "", `{"deviceCode":`+jsonStr(deviceCode)+`}`)
	if code != 200 {
		t.Fatalf("token after approve: %d %v", code, tok)
	}
	certPEM, _ := tok["userCertPem"].(string)
	if certPEM == "" {
		t.Fatalf("no cert in token response: %v", tok)
	}
	blk, _ := pem.Decode([]byte(certPEM))
	crt, err := x509.ParseCertificate(blk.Bytes)
	if err != nil {
		t.Fatalf("parse cert: %v", err)
	}
	id, err := ca.PeerIdentity(crt)
	if err != nil {
		t.Fatalf("peer identity: %v", err)
	}
	// The issued cert carries the APPROVER's workspace+roles (alice -> ops), not the CLI's.
	if id.Name != "alice" || id.Workspace != defaultWorkspace || len(id.Roles) != 1 || id.Roles[0] != "ops" {
		t.Fatalf("device cert identity: %+v", id)
	}
	for _, r := range id.Roles {
		if reservedRoles[r] {
			t.Fatalf("device cert leaked reserved role: %v", id.Roles)
		}
	}

	// 5. Redeem-once: a second poll on the already-consumed code is rejected.
	code, errBody = doJSON(t, h, "POST", "/api/v1/device/token", "", `{"deviceCode":`+jsonStr(deviceCode)+`}`)
	if code != 400 || errBody["error"] != "expired_token" {
		t.Fatalf("second poll must be expired_token, got %d %v", code, errBody)
	}
}

func TestDeviceDenied(t *testing.T) {
	_, api := testConsoleServer(t)
	h := api.handler()
	csr := makeCSRPEM(t)
	_, da := doJSON(t, h, "POST", "/api/v1/device/authorize", "", `{"csrPem":`+jsonStr(csr)+`}`)
	deviceCode := da["deviceCode"].(string)
	userCode := da["userCode"].(string)
	st := loginLocalToken(t, h, "alice", "hunter2")
	if code, _ := doJSON(t, h, "POST", "/api/v1/device/deny", st, `{"userCode":`+jsonStr(userCode)+`}`); code != 200 {
		t.Fatalf("deny: %d", code)
	}
	code, errBody := doJSON(t, h, "POST", "/api/v1/device/token", "", `{"deviceCode":`+jsonStr(deviceCode)+`}`)
	if code != 400 || errBody["error"] != "access_denied" {
		t.Fatalf("denied poll: %d %v", code, errBody)
	}
}

func TestDeviceAuthorizeRejectsBadCSR(t *testing.T) {
	_, api := testConsoleServer(t)
	h := api.handler()
	if code, _ := doJSON(t, h, "POST", "/api/v1/device/authorize", "", `{"csrPem":"not a csr"}`); code != 400 {
		t.Fatalf("bad CSR must be 400, got %d", code)
	}
}
