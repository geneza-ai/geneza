package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"osie.cloud/geneza/internal/client"

	genezav1 "osie.cloud/geneza/internal/pb/geneza/v1"
)

func newLogoutCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "logout",
		Short: "Delete the local certificate and key (expiry is revocation — nothing server-side to undo)",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			st, err := client.NewStore(flagProfile)
			if err != nil {
				return err
			}
			ks := &client.FileKeyStore{Path: st.KeyPath()}
			if err := ks.Remove(); err != nil {
				return err
			}
			if err := os.Remove(st.CertPath()); err != nil && !errors.Is(err, os.ErrNotExist) {
				return err
			}
			fmt.Println("Logged out: certificate and key removed.")
			return nil
		},
	}
}

func newWhoamiCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "whoami",
		Short: "Show the authenticated identity (as the gateway sees it) and local cert expiry",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			e, err := loadEnv()
			if err != nil {
				return err
			}
			_, leaf, err := e.store.ClientCert()
			if err != nil {
				return err
			}
			cc, api, err := dialUser(e)
			if err != nil {
				return err
			}
			defer cc.Close()
			ctx, cancel := context.WithTimeout(cmd.Context(), 30*time.Second)
			defer cancel()
			resp, err := api.WhoAmI(ctx, &genezav1.Empty{})
			if err != nil {
				return client.Humanize(err)
			}
			fmt.Printf("User:        %s\n", resp.GetUser())
			fmt.Printf("Workspace:   %s\n", orDash(resp.GetWorkspace()))
			fmt.Printf("Roles:       %s\n", strings.Join(resp.GetRoles(), ", "))
			fmt.Printf("Provider:    %s\n", e.profile.Provider)
			fmt.Printf("Gateway:     %s\n", e.profile.GatewayGRPC)
			fmt.Printf("Cert expiry: %s (%s)\n",
				leaf.NotAfter.Local().Format(time.RFC3339),
				time.Until(leaf.NotAfter).Round(time.Minute))
			if srv := resp.GetCertExpiresUnix(); srv > 0 {
				st := time.Unix(srv, 0)
				if !st.Equal(leaf.NotAfter.Truncate(time.Second)) {
					fmt.Printf("Cert expiry (gateway view): %s\n", st.Local().Format(time.RFC3339))
				}
			}
			return nil
		},
	}
}
