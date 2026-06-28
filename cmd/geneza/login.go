package main

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"runtime"
	"strconv"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"geneza.io/internal/ca"
	"geneza.io/internal/client"
	"geneza.io/internal/defaults"
)

type loginOpts struct {
	controller    string
	httpPort   int
	grpcPort   int
	caFile     string
	noBrowser  bool
	clientName string
}

func newLoginCmd() *cobra.Command {
	var o loginOpts
	cmd := &cobra.Command{
		Use:   "login",
		Short: "Authenticate via the controller (device-code flow) and obtain a short-lived certificate",
		Long: "Starts an RFC 8628 device-authorization login: the CLI prints a URL and a code; " +
			"you approve it in the Geneza web console (signed in however you like — SSO, OpenStack, or " +
			"local). The CLI then receives a certificate scoped to your workspace and roles.",
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runLogin(cmd.Context(), &o)
		},
	}
	f := cmd.Flags()
	f.StringVar(&o.controller, "controller", "", "controller host (FQDN or IP)")
	f.IntVar(&o.httpPort, "http-port", defaults.ControllerHTTPPort, "controller HTTPS port")
	f.IntVar(&o.grpcPort, "grpc-port", defaults.ControllerGRPCPort, "controller gRPC port")
	f.StringVar(&o.caFile, "ca-file", "", "trust this CA bundle instead of TOFU-fetching it")
	f.BoolVar(&o.noBrowser, "no-browser", false, "do not try to open a browser to the approval page")
	f.StringVar(&o.clientName, "client-name", "", "label shown on the approval screen (default: host name)")
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

	host := o.controller
	if host == "" && prev != nil {
		if h, _, err := net.SplitHostPort(prev.ControllerGRPC); err == nil {
			host = h
		}
	}
	if host == "" {
		return errors.New("--controller is required on first login")
	}
	if strings.Contains(host, "://") {
		return fmt.Errorf("--controller %q: pass a bare host name or IP (no scheme)", host)
	}
	if _, _, err := net.SplitHostPort(host); err == nil {
		return fmt.Errorf("--controller %q: pass the host only; set ports with --http-port/--grpc-port", host)
	}
	controllerGRPC := net.JoinHostPort(host, strconv.Itoa(o.grpcPort))
	controllerHTTP := "https://" + net.JoinHostPort(host, strconv.Itoa(o.httpPort))

	// --- 1. CA trust: --ca-file > pinned ca.pem > TOFU fetch --------------------
	caPEM, pin, err := establishCATrust(ctx, st, prev, o.caFile, controllerHTTP)
	if err != nil {
		return err
	}
	pool, err := ca.PoolFromPEM(caPEM)
	if err != nil {
		return err
	}

	// --- 2. Client key + CSR ----------------------------------------------------
	ks := &client.FileKeyStore{Path: st.KeyPath()}
	signer, err := ks.EnsureKey()
	if err != nil {
		return err
	}
	csrPEM, err := ca.MakeCSR(signer, "geneza-user")
	if err != nil {
		return err
	}

	// --- 3. Device authorization ------------------------------------------------
	clientName := o.clientName
	if clientName == "" {
		if hn, err := os.Hostname(); err == nil {
			clientName = "geneza-cli @ " + hn
		} else {
			clientName = "geneza-cli"
		}
	}
	authCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
	da, err := client.DeviceAuthorize(authCtx, controllerHTTP, pool, csrPEM, clientName)
	cancel()
	if err != nil {
		return err
	}

	fmt.Fprintf(os.Stderr, "\nTo sign in, open this URL in a browser and enter the code:\n\n")
	fmt.Fprintf(os.Stderr, "    %s\n", da.VerificationURI)
	fmt.Fprintf(os.Stderr, "    code: %s\n\n", da.UserCode)
	if !o.noBrowser {
		_ = openBrowser(da.VerificationURIComplete)
	}
	fmt.Fprintf(os.Stderr, "Waiting for approval…\n")

	// --- 4. Poll for the issued cert -------------------------------------------
	pollCtx, cancel2 := context.WithTimeout(ctx, time.Duration(da.ExpiresIn+10)*time.Second)
	defer cancel2()
	dc, err := client.DevicePoll(pollCtx, controllerHTTP, pool, da)
	if err != nil {
		return err
	}

	// --- 5. Persist cert + profile ---------------------------------------------
	if len(dc.UserCertPEM) == 0 {
		return errors.New("controller returned no certificate")
	}
	if err := os.WriteFile(st.CertPath(), dc.UserCertPEM, 0o600); err != nil {
		return err
	}
	if rb := dc.CARootsPEM; len(rb) > 0 && client.CAFingerprint(rb) != pin {
		if _, err := ca.PoolFromPEM(rb); err == nil {
			if pin, err = st.SaveCA(rb); err != nil {
				return err
			}
			fmt.Fprintf(os.Stderr, "note: CA bundle rotated by controller; new pin %s\n", pin[:16])
		}
	}

	// The cert carries the authoritative identity (user/workspace/roles); read it
	// back so the profile + the printout reflect exactly what was issued.
	_, leaf, err := st.ClientCert()
	if err != nil {
		return err
	}
	id, err := ca.PeerIdentity(leaf)
	if err != nil {
		return err
	}
	if err := st.SaveProfile(&client.Profile{
		ControllerGRPC: controllerGRPC,
		ControllerHTTP: controllerHTTP,
		User:        id.Name,
		Workspace:   id.Workspace,
		Provider:    "device",
		CASHA256:    pin,
	}); err != nil {
		return err
	}

	exp := time.Unix(dc.ExpiresUnix, 0)
	fmt.Printf("Logged in as %s\n", id.Name)
	fmt.Printf("Workspace:   %s\n", id.Workspace)
	fmt.Printf("Roles:       %s\n", strings.Join(id.Roles, ", "))
	fmt.Printf("Cert expiry: %s (%s)\n", exp.Local().Format(time.RFC3339), time.Until(exp).Round(time.Minute))
	return nil
}

// openBrowser best-effort opens a URL in the operator's browser.
func openBrowser(url string) error {
	var cmd string
	var args []string
	switch runtime.GOOS {
	case "darwin":
		cmd = "open"
	case "windows":
		cmd, args = "rundll32", []string{"url.dll,FileProtocolHandler"}
	default:
		cmd = "xdg-open"
	}
	return exec.Command(cmd, append(args, url)...).Start()
}

// establishCATrust resolves the trust anchor for everything else.
func establishCATrust(ctx context.Context, st *client.Store, prev *client.Profile, caFile, controllerHTTP string) (caPEM []byte, pin string, err error) {
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
	} else if prevPin != "" {
		return nil, "", fmt.Errorf("profile %q has a pinned CA (sha256 %s) but its bundle could not be loaded/verified: %w; "+
			"re-pin explicitly with --ca-file if this is intended", flagProfile, prevPin, err)
	}

	// Trust on first use. The fetch itself cannot be verified — that is the
	// point — so the fingerprint is displayed for out-of-band comparison.
	b, fp, err := client.FetchCARootsTOFU(ctx, controllerHTTP)
	if err != nil {
		return nil, "", err
	}
	fmt.Fprintf(os.Stderr, `
**********************************************************************
*  FIRST CONTACT: trusting the controller CA on first use (TOFU).      *
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
