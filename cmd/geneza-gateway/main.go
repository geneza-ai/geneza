// geneza-gateway is the Geneza control plane daemon and its operational CLI
// (init, break-glass cert issuance, bcrypt hashing, audit verification).
package main

import (
	"bufio"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/spf13/cobra"
	"golang.org/x/crypto/bcrypt"
	"golang.org/x/term"

	"osie.cloud/geneza/internal/defaults"
	"osie.cloud/geneza/internal/gateway"
	"osie.cloud/geneza/internal/version"
)

func main() {
	slog.SetDefault(slog.New(slog.NewTextHandler(os.Stderr, nil)))
	if err := newRootCmd().Execute(); err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}

func defaultConfigPath() string { return defaults.EtcDir + "/gateway.yaml" }

func newRootCmd() *cobra.Command {
	root := &cobra.Command{
		Use:           "geneza-gateway",
		Short:         "Geneza control plane (gateway)",
		Version:       version.Version,
		SilenceUsage:  true,
		SilenceErrors: true,
	}
	root.AddCommand(newInitCmd(), newServeCmd(), newIssueUserCertCmd(), newHashPasswordCmd(), newAuditVerifyCmd(), newReissueTLSCmd())
	return root
}

func configFlag(cmd *cobra.Command) *string {
	p := cmd.Flags().String("config", defaultConfigPath(), "path to gateway.yaml")
	return p
}

func newInitCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "init",
		Short: "Initialize data_dir: CA, grant key, server TLS, initial cluster config",
	}
	cfgPath := configFlag(cmd)
	cmd.RunE = func(cmd *cobra.Command, _ []string) error {
		cfg, err := gateway.LoadConfig(*cfgPath)
		if err != nil {
			return err
		}
		if err := gateway.InitDataDir(cfg); err != nil {
			return err
		}
		fmt.Printf("initialized %s for cluster %q\n", cfg.DataDir, cfg.ClusterName)
		fmt.Printf("  CA:        %s\n", cfg.CADir())
		fmt.Printf("  grant key: %s\n", cfg.GrantKeyPath())
		fmt.Printf("  TLS:       %s\n", cfg.TLSDir())
		return nil
	}
	return cmd
}

func newReissueTLSCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "reissue-tls",
		Short: "Re-issue gateway+relay TLS server certs from the advertise config (existing CA)",
	}
	cfgPath := configFlag(cmd)
	cmd.RunE = func(cmd *cobra.Command, _ []string) error {
		cfg, err := gateway.LoadConfig(*cfgPath)
		if err != nil {
			return err
		}
		if err := gateway.ReissueServerCerts(cfg); err != nil {
			return err
		}
		fmt.Printf("re-issued gateway+relay TLS in %s for dns=%v ips=%v\n",
			cfg.TLSDir(), cfg.Advertise.DNSNames, cfg.Advertise.IPs)
		return nil
	}
	return cmd
}

func newServeCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "serve",
		Short: "Run the gRPC (mTLS) and HTTPS listeners",
	}
	cfgPath := configFlag(cmd)
	cmd.RunE = func(cmd *cobra.Command, _ []string) error {
		cfg, err := gateway.LoadConfig(*cfgPath)
		if err != nil {
			return err
		}
		srv, err := gateway.New(cfg)
		if err != nil {
			return err
		}
		defer srv.Close()
		ctx, stop := signal.NotifyContext(cmd.Context(), os.Interrupt, syscall.SIGTERM)
		defer stop()
		return srv.Run(ctx)
	}
	return cmd
}

func newIssueUserCertCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "issue-user-cert",
		Short: "Break-glass: issue a local admin user cert directly from the CA files",
	}
	cfgPath := configFlag(cmd)
	name := cmd.Flags().String("name", "", "username for the certificate")
	roles := cmd.Flags().String("roles", "", "comma-separated roles (e.g. admin,ops)")
	ttl := cmd.Flags().Duration("ttl", 12*time.Hour, "certificate lifetime")
	outDir := cmd.Flags().String("out-dir", ".", "directory for user.key/user.crt/ca.pem")
	cmd.RunE = func(cmd *cobra.Command, _ []string) error {
		cfg, err := gateway.LoadConfig(*cfgPath)
		if err != nil {
			return err
		}
		if err := gateway.IssueUserCert(cfg, *name, gateway.FormatRoles(*roles), *ttl, *outDir); err != nil {
			return err
		}
		fmt.Printf("wrote user.key, user.crt, ca.pem to %s (user %q, roles %s, ttl %s)\n",
			*outDir, *name, *roles, *ttl)
		return nil
	}
	return cmd
}

func newHashPasswordCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "hash-password",
		Short: "Read a password from stdin and print its bcrypt hash",
		RunE: func(cmd *cobra.Command, _ []string) error {
			var pw []byte
			fd := int(os.Stdin.Fd())
			if term.IsTerminal(fd) {
				fmt.Fprint(os.Stderr, "Password: ")
				p, err := term.ReadPassword(fd)
				fmt.Fprintln(os.Stderr)
				if err != nil {
					return err
				}
				pw = p
			} else {
				line, err := bufio.NewReader(os.Stdin).ReadString('\n')
				if err != nil && line == "" {
					return fmt.Errorf("read password from stdin: %w", err)
				}
				pw = []byte(strings.TrimRight(line, "\r\n"))
			}
			if len(pw) == 0 {
				return fmt.Errorf("empty password")
			}
			hash, err := bcrypt.GenerateFromPassword(pw, bcrypt.DefaultCost)
			if err != nil {
				return err
			}
			fmt.Println(string(hash))
			return nil
		},
	}
}

func newAuditVerifyCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "audit-verify",
		Short: "Verify the audit log hash chain (nonzero exit on breakage)",
	}
	cfgPath := configFlag(cmd)
	cmd.RunE = func(cmd *cobra.Command, _ []string) error {
		cfg, err := gateway.LoadConfig(*cfgPath)
		if err != nil {
			return err
		}
		n, err := gateway.VerifyAuditFile(cfg.AuditPath(), cfg.AuditKeyPath())
		if err != nil {
			return fmt.Errorf("audit chain BROKEN after %d valid records: %w", n, err)
		}
		fmt.Printf("audit chain OK: %d records (%s)\n", n, cfg.AuditPath())
		return nil
	}
	return cmd
}
