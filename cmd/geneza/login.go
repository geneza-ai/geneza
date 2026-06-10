package main

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/spf13/cobra"
	"golang.org/x/term"

	"osie.cloud/geneza/internal/ca"
	"osie.cloud/geneza/internal/client"
	"osie.cloud/geneza/internal/defaults"

	genezav1 "osie.cloud/geneza/internal/pb/geneza/v1"
)

type loginOpts struct {
	gateway       string
	grpcPort      int
	httpPort      int
	provider      string
	user          string
	passwordEnv   string
	passwordStdin bool
	caFile        string
	noBrowser     bool
}

func newLoginCmd() *cobra.Command {
	var o loginOpts
	cmd := &cobra.Command{
		Use:   "login",
		Short: "Authenticate to the gateway and obtain a short-lived certificate",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runLogin(cmd.Context(), &o)
		},
	}
	f := cmd.Flags()
	f.StringVar(&o.gateway, "gateway", "", "gateway host (FQDN or IP)")
	f.IntVar(&o.grpcPort, "grpc-port", defaults.GatewayGRPCPort, "gateway gRPC port")
	f.IntVar(&o.httpPort, "http-port", defaults.GatewayHTTPPort, "gateway HTTPS port")
	f.StringVar(&o.provider, "provider", "", "identity provider: oidc|local (default: first offered)")
	f.StringVar(&o.user, "user", "", "username (local provider, or OIDC password grant)")
	f.StringVar(&o.passwordEnv, "password-env", "", "name of an environment variable holding the password (e.g. GENEZA_PASSWORD)")
	f.BoolVar(&o.passwordStdin, "password-stdin", false, "read the password from stdin (first line)")
	f.StringVar(&o.caFile, "ca-file", "", "trust this CA bundle instead of TOFU-fetching it")
	f.BoolVar(&o.noBrowser, "no-browser", false, "do not try to open a browser for the OIDC flow")
	return cmd
}

func runLogin(ctx context.Context, o *loginOpts) error {
	st, err := client.NewStore(flagProfile)
	if err != nil {
		return err
	}
	prev, err := st.LoadProfile()
	if err != nil && !errors.Is(err, client.ErrNoProfile) {
		return err
	}

	host := o.gateway
	if host == "" && prev != nil {
		if h, _, err := net.SplitHostPort(prev.GatewayGRPC); err == nil {
			host = h
		}
	}
	if host == "" {
		return errors.New("--gateway is required on first login")
	}
	if strings.Contains(host, "://") {
		return fmt.Errorf("--gateway %q: pass a bare host name or IP (no scheme)", host)
	}
	if _, _, err := net.SplitHostPort(host); err == nil {
		return fmt.Errorf("--gateway %q: pass the host only; set ports with --grpc-port/--http-port", host)
	}
	gatewayGRPC := net.JoinHostPort(host, strconv.Itoa(o.grpcPort))
	gatewayHTTP := "https://" + net.JoinHostPort(host, strconv.Itoa(o.httpPort))

	// --- 1. CA trust: --ca-file > existing ca.pem > TOFU fetch -------------
	caPEM, pin, err := establishCATrust(ctx, st, prev, o.caFile, gatewayHTTP)
	if err != nil {
		return err
	}
	pool, err := ca.PoolFromPEM(caPEM)
	if err != nil {
		return err
	}

	// --- 2. Provider selection (everything from here is CA-verified) -------
	ac, err := client.FetchAuthConfig(ctx, gatewayHTTP, pool)
	if err != nil {
		return err
	}
	provider := o.provider
	if provider == "" {
		switch {
		case len(ac.Providers) == 0:
			return errors.New("gateway offers no login providers")
		case slices.Contains(ac.Providers, "oidc"):
			provider = "oidc"
		default:
			provider = ac.Providers[0]
		}
	} else if !slices.Contains(ac.Providers, provider) {
		return fmt.Errorf("provider %q not offered by the gateway (available: %s)", provider, strings.Join(ac.Providers, ", "))
	}

	// --- 3. Authenticate with the provider ---------------------------------
	password, havePassword, err := readPassword(o)
	if err != nil {
		return err
	}

	req := &genezav1.LoginRequest{Provider: provider}
	switch provider {
	case "oidc":
		if ac.OIDCIssuer == "" || ac.OIDCClientID == "" {
			return errors.New("gateway auth-config is missing oidc_issuer/oidc_client_id")
		}
		flow := &client.OIDCFlow{
			Issuer:    ac.OIDCIssuer,
			ClientID:  ac.OIDCClientID,
			NoBrowser: o.noBrowser,
			Out:       os.Stderr,
		}
		var idToken string
		if havePassword {
			// Headless path (CI / scripts): resource-owner-password grant.
			if o.user == "" {
				return errors.New("--user is required with a password-based OIDC login")
			}
			idToken, err = flow.PasswordGrant(ctx, o.user, password)
		} else {
			idToken, err = flow.AuthCodePKCE(ctx)
		}
		if err != nil {
			return err
		}
		req.OidcIdToken = idToken
	case "local":
		username := o.user
		if username == "" {
			username, err = promptLine("Username: ")
			if err != nil {
				return err
			}
		}
		if !havePassword {
			password, err = promptPassword("Password: ")
			if err != nil {
				return err
			}
		}
		req.Username = username
		req.Password = password
	default:
		return fmt.Errorf("unknown provider %q", provider)
	}

	// --- 4. CSR + Login (cert-less TLS) -> user certificate ----------------
	ks := &client.FileKeyStore{Path: st.KeyPath()}
	signer, err := ks.EnsureKey()
	if err != nil {
		return err
	}
	cn := o.user
	if cn == "" {
		cn = "geneza-user"
	}
	csrPEM, err := ca.MakeCSR(signer, cn)
	if err != nil {
		return err
	}
	req.CsrPem = csrPEM

	cc, err := client.DialGateway(gatewayGRPC, pool, nil) // Login runs without a client cert
	if err != nil {
		return err
	}
	defer cc.Close()
	loginCtx, cancel := context.WithTimeout(ctx, time.Minute)
	defer cancel()
	resp, err := genezav1.NewUserAPIClient(cc).Login(loginCtx, req)
	if err != nil {
		return client.Humanize(err)
	}
	if len(resp.GetUserCertPem()) == 0 {
		return errors.New("gateway returned no certificate")
	}
	if err := os.WriteFile(st.CertPath(), resp.GetUserCertPem(), 0o600); err != nil {
		return err
	}
	// The gateway may return a refreshed trust bundle (CA rotation with
	// overlap). The connection that delivered it was verified against the
	// current pin, so adopting it preserves trust continuity.
	if rb := resp.GetCaRootsPem(); len(rb) > 0 && client.CAFingerprint(rb) != pin {
		if _, perr := ca.PoolFromPEM(rb); perr == nil {
			if pin, err = st.SaveCA(rb); err != nil {
				return err
			}
			fmt.Fprintf(os.Stderr, "note: CA bundle rotated by gateway; new pin %s\n", pin[:16])
		}
	}

	if err := st.SaveProfile(&client.Profile{
		GatewayGRPC: gatewayGRPC,
		GatewayHTTP: gatewayHTTP,
		User:        resp.GetUser(),
		Provider:    provider,
		CASHA256:    pin,
	}); err != nil {
		return err
	}

	exp := time.Unix(resp.GetExpiresUnix(), 0)
	fmt.Printf("Logged in as %s (provider %s)\n", resp.GetUser(), provider)
	fmt.Printf("Roles:       %s\n", strings.Join(resp.GetRoles(), ", "))
	fmt.Printf("Cert expiry: %s (%s)\n", exp.Local().Format(time.RFC3339), time.Until(exp).Round(time.Minute))
	return nil
}

// establishCATrust resolves the trust anchor for everything else.
func establishCATrust(ctx context.Context, st *client.Store, prev *client.Profile, caFile, gatewayHTTP string) (caPEM []byte, pin string, err error) {
	if caFile != "" {
		b, err := os.ReadFile(caFile)
		if err != nil {
			return nil, "", err
		}
		if _, err := ca.PoolFromPEM(b); err != nil {
			return nil, "", fmt.Errorf("%s: %w", caFile, err)
		}
		pin, err := st.SaveCA(b)
		if err != nil {
			return nil, "", err
		}
		fmt.Fprintf(os.Stderr, "Trusting CA bundle from %s (sha256 %s)\n", caFile, pin)
		return b, pin, nil
	}

	prevPin := ""
	if prev != nil {
		prevPin = prev.CASHA256
	}
	if b, err := st.LoadCA(prevPin); err == nil {
		if prevPin == "" {
			prevPin = client.CAFingerprint(b)
		}
		return b, prevPin, nil
	} else if strings.Contains(err.Error(), "pin mismatch") {
		return nil, "", err // fail closed: never silently re-TOFU over a bad pin
	}

	// Trust on first use. The fetch itself cannot be verified — that is the
	// point — so the fingerprint is displayed for out-of-band comparison.
	b, fp, err := client.FetchCARootsTOFU(ctx, gatewayHTTP)
	if err != nil {
		return nil, "", err
	}
	fmt.Fprintf(os.Stderr, `
**********************************************************************
*  FIRST CONTACT: trusting the gateway CA on first use (TOFU).      *
*  Verify this fingerprint out-of-band with your administrator:     *
**********************************************************************

    sha256:%s

It is now pinned for profile %q; any future mismatch fails closed.

`, fp, flagProfile)
	if _, err := st.SaveCA(b); err != nil {
		return nil, "", err
	}
	return b, fp, nil
}

func readPassword(o *loginOpts) (string, bool, error) {
	if o.passwordEnv != "" {
		v := os.Getenv(o.passwordEnv)
		if v == "" {
			return "", false, fmt.Errorf("--password-env: environment variable %s is empty or unset", o.passwordEnv)
		}
		return v, true, nil
	}
	if o.passwordStdin {
		r := bufio.NewReader(os.Stdin)
		line, err := r.ReadString('\n')
		if err != nil && line == "" {
			return "", false, fmt.Errorf("--password-stdin: %w", err)
		}
		return strings.TrimRight(line, "\r\n"), true, nil
	}
	return "", false, nil
}

func promptLine(prompt string) (string, error) {
	if !term.IsTerminal(int(os.Stdin.Fd())) {
		return "", errors.New("stdin is not a terminal; pass --user / --password-env / --password-stdin")
	}
	fmt.Fprint(os.Stderr, prompt)
	line, err := bufio.NewReader(os.Stdin).ReadString('\n')
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(line), nil
}

func promptPassword(prompt string) (string, error) {
	fd := int(os.Stdin.Fd())
	if !term.IsTerminal(fd) {
		return "", errors.New("stdin is not a terminal; pass --password-env or --password-stdin")
	}
	fmt.Fprint(os.Stderr, prompt)
	b, err := term.ReadPassword(fd)
	fmt.Fprintln(os.Stderr)
	if err != nil {
		return "", err
	}
	return string(b), nil
}
