package client

import (
	"bufio"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os/exec"
	"runtime"
	"strings"
	"time"

	"golang.org/x/oauth2"
)

// OIDCFlow obtains an ID token from the customer IdP. The gateway validates
// the token server-side; the CLI never inspects claims. Note the trust split:
// the IdP speaks public TLS (system roots), the gateway speaks the pinned
// geneza CA — this flow deliberately uses the default HTTP transport.
type OIDCFlow struct {
	Issuer    string
	ClientID  string
	NoBrowser bool
	// Manual selects the paste-the-callback flow: print the authorize URL, let
	// the user complete it in a browser on ANY machine, then paste the redirected
	// callback URL back in. Use when the CLI's loopback is unreachable from the
	// browser (SSH session, headless box, remote login).
	Manual bool
	Out    io.Writer // where to print the authorize URL / hints
	In     io.Reader // where to read the pasted callback URL (Manual mode)
	// Timeout bounds the interactive wait for the browser redirect.
	Timeout time.Duration
}

// manualRedirect is the redirect URI used in Manual mode. Nothing listens on it
// (the user copies the URL out of the address bar), but it must be an allowed
// redirect for the client — Keycloak permits any loopback (127.0.0.1) port/path.
const manualRedirect = "http://127.0.0.1/callback"

var oidcScopes = []string{"openid", "profile", "email"}

// PasswordGrant runs the OAuth2 resource-owner-password grant directly
// against the Keycloak-style token endpoint <issuer>/protocol/openid-connect/token.
// Headless path for CI/scripts; interactive logins should use AuthCodePKCE.
func (f *OIDCFlow) PasswordGrant(ctx context.Context, username, password string) (string, error) {
	tokenURL := strings.TrimRight(f.Issuer, "/") + "/protocol/openid-connect/token"
	form := url.Values{
		"grant_type": {"password"},
		"client_id":  {f.ClientID},
		"scope":      {strings.Join(oidcScopes, " ")},
		"username":   {username},
		"password":   {password},
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, tokenURL, strings.NewReader(form.Encode()))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := (&http.Client{Timeout: 30 * time.Second}).Do(req)
	if err != nil {
		return "", fmt.Errorf("IdP token endpoint: %w", err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxHTTPBody))
	if err != nil {
		return "", err
	}
	var tok struct {
		IDToken          string `json:"id_token"`
		Error            string `json:"error"`
		ErrorDescription string `json:"error_description"`
	}
	if err := json.Unmarshal(body, &tok); err != nil {
		return "", fmt.Errorf("IdP token response (%s): %w", resp.Status, err)
	}
	if resp.StatusCode != http.StatusOK || tok.Error != "" {
		msg := tok.ErrorDescription
		if msg == "" {
			msg = tok.Error
		}
		if msg == "" {
			msg = resp.Status
		}
		return "", fmt.Errorf("IdP rejected credentials: %s", msg)
	}
	if tok.IDToken == "" {
		return "", errors.New("IdP response had no id_token (is the 'openid' scope allowed for this client?)")
	}
	return tok.IDToken, nil
}

// discovery is the subset of <issuer>/.well-known/openid-configuration we use.
type discovery struct {
	AuthorizationEndpoint string `json:"authorization_endpoint"`
	TokenEndpoint         string `json:"token_endpoint"`
}

func (f *OIDCFlow) discover(ctx context.Context) (*discovery, error) {
	u := strings.TrimRight(f.Issuer, "/") + "/.well-known/openid-configuration"
	body, err := httpGet(ctx, &http.Client{Timeout: 15 * time.Second}, u)
	if err != nil {
		return nil, fmt.Errorf("OIDC discovery: %w", err)
	}
	var d discovery
	if err := json.Unmarshal(body, &d); err != nil {
		return nil, fmt.Errorf("OIDC discovery: %w", err)
	}
	if d.AuthorizationEndpoint == "" || d.TokenEndpoint == "" {
		return nil, errors.New("OIDC discovery: issuer metadata missing endpoints")
	}
	return &d, nil
}

// AuthCodePKCE runs the authorization-code flow with PKCE (S256) and a
// loopback redirect: we listen on 127.0.0.1:0, print (and try to open) the
// authorize URL, and exchange the returned code for an ID token.
func (f *OIDCFlow) AuthCodePKCE(ctx context.Context) (string, error) {
	d, err := f.discover(ctx)
	if err != nil {
		return "", err
	}
	if f.Manual {
		return f.manualPaste(ctx, d)
	}

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return "", fmt.Errorf("loopback listener: %w", err)
	}
	defer ln.Close()
	redirect := fmt.Sprintf("http://%s/callback", ln.Addr().String())

	cfg := &oauth2.Config{
		ClientID:    f.ClientID,
		Endpoint:    oauth2.Endpoint{AuthURL: d.AuthorizationEndpoint, TokenURL: d.TokenEndpoint},
		RedirectURL: redirect,
		Scopes:      oidcScopes,
	}
	state, err := randomToken()
	if err != nil {
		return "", err
	}
	verifier := oauth2.GenerateVerifier()
	authURL := cfg.AuthCodeURL(state, oauth2.S256ChallengeOption(verifier))

	type cbResult struct {
		code string
		err  error
	}
	resCh := make(chan cbResult, 1)
	srv := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/callback" {
			http.NotFound(w, r)
			return
		}
		q := r.URL.Query()
		// State mismatch = injected/replayed callback: fail closed.
		if q.Get("state") != state {
			http.Error(w, "state mismatch", http.StatusBadRequest)
			resCh <- cbResult{err: errors.New("OIDC callback state mismatch")}
			return
		}
		if e := q.Get("error"); e != "" {
			desc := q.Get("error_description")
			http.Error(w, "login failed: "+e, http.StatusBadRequest)
			resCh <- cbResult{err: fmt.Errorf("IdP returned %s: %s", e, desc)}
			return
		}
		code := q.Get("code")
		if code == "" {
			http.Error(w, "missing code", http.StatusBadRequest)
			resCh <- cbResult{err: errors.New("OIDC callback without code")}
			return
		}
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		fmt.Fprintln(w, "geneza: login complete - you can close this tab and return to the terminal.")
		resCh <- cbResult{code: code}
	})}
	go srv.Serve(ln)                         //nolint:errcheck // closed via Shutdown below
	defer srv.Shutdown(context.Background()) //nolint:errcheck

	out := f.Out
	if out == nil {
		out = io.Discard
	}
	fmt.Fprintf(out, "Open this URL in your browser to log in:\n\n  %s\n\n", authURL)
	if !f.NoBrowser {
		if err := openBrowser(authURL); err == nil {
			fmt.Fprintln(out, "(a browser window should have opened)")
		}
	}

	timeout := f.Timeout
	if timeout == 0 {
		timeout = 5 * time.Minute
	}
	waitCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	var code string
	select {
	case <-waitCtx.Done():
		return "", fmt.Errorf("timed out waiting for the browser login: %w", waitCtx.Err())
	case res := <-resCh:
		if res.err != nil {
			return "", res.err
		}
		code = res.code
	}

	tok, err := cfg.Exchange(ctx, code, oauth2.VerifierOption(verifier))
	if err != nil {
		return "", fmt.Errorf("OIDC code exchange: %w", err)
	}
	idToken, _ := tok.Extra("id_token").(string)
	if idToken == "" {
		return "", errors.New("token response had no id_token")
	}
	return idToken, nil
}

// manualPaste runs the headless/remote authorization-code flow: print the
// authorize URL, the user completes it in a browser anywhere, then pastes the
// redirected callback URL (or the bare code) back in. No loopback server.
func (f *OIDCFlow) manualPaste(ctx context.Context, d *discovery) (string, error) {
	cfg := &oauth2.Config{
		ClientID:    f.ClientID,
		Endpoint:    oauth2.Endpoint{AuthURL: d.AuthorizationEndpoint, TokenURL: d.TokenEndpoint},
		RedirectURL: manualRedirect,
		Scopes:      oidcScopes,
	}
	state, err := randomToken()
	if err != nil {
		return "", err
	}
	verifier := oauth2.GenerateVerifier()
	authURL := cfg.AuthCodeURL(state, oauth2.S256ChallengeOption(verifier))

	out := f.Out
	if out == nil {
		out = io.Discard
	}
	in := f.In
	if in == nil {
		return "", errors.New("manual login needs an input stream to read the pasted URL")
	}
	fmt.Fprintf(out, "\nOpen this URL in a browser on ANY machine and sign in:\n\n  %s\n\n", authURL)
	fmt.Fprintf(out, "Your browser will then be redirected to a URL that starts with\n  %s?...\n"+
		"and shows a \"can't connect\" / \"site can't be reached\" error — that is EXPECTED.\n"+
		"Copy that whole URL from the address bar and paste it below.\n\n", manualRedirect)
	fmt.Fprint(out, "Paste the callback URL (or just the code): ")

	line, err := bufio.NewReader(in).ReadString('\n')
	if err != nil && line == "" {
		return "", fmt.Errorf("reading pasted callback: %w", err)
	}
	code, err := parseManualCallback(strings.TrimSpace(line), state)
	if err != nil {
		return "", err
	}

	tok, err := cfg.Exchange(ctx, code, oauth2.VerifierOption(verifier))
	if err != nil {
		return "", fmt.Errorf("OIDC code exchange: %w", err)
	}
	idToken, _ := tok.Extra("id_token").(string)
	if idToken == "" {
		return "", errors.New("token response had no id_token")
	}
	return idToken, nil
}

// parseManualCallback accepts either the full redirected callback URL (whose
// state is verified against want) or a bare authorization code, and returns the
// code. A full URL is preferred because it lets us check the state (CSRF guard).
func parseManualCallback(input, want string) (string, error) {
	if input == "" {
		return "", errors.New("no callback pasted")
	}
	if strings.Contains(input, "?") || strings.HasPrefix(input, "http") {
		u, err := url.Parse(input)
		if err != nil {
			return "", fmt.Errorf("could not parse the pasted URL: %w", err)
		}
		q := u.Query()
		if e := q.Get("error"); e != "" {
			return "", fmt.Errorf("IdP returned %s: %s", e, q.Get("error_description"))
		}
		if st := q.Get("state"); st != want {
			return "", errors.New("state mismatch in the pasted callback (possible CSRF or wrong URL)")
		}
		code := q.Get("code")
		if code == "" {
			return "", errors.New("the pasted callback URL has no ?code= parameter")
		}
		return code, nil
	}
	// Bare code (no URL to verify state against): accept it as-is.
	return input, nil
}

func randomToken() (string, error) {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	return hex.EncodeToString(b[:]), nil
}

// openBrowser best-effort opens url in the default browser.
func openBrowser(url string) error {
	var name string
	switch runtime.GOOS {
	case "darwin":
		name = "open"
	default:
		name = "xdg-open"
	}
	path, err := exec.LookPath(name)
	if err != nil {
		return err
	}
	cmd := exec.Command(path, url)
	if err := cmd.Start(); err != nil {
		return err
	}
	go cmd.Wait() //nolint:errcheck // detach; outcome is irrelevant
	return nil
}
