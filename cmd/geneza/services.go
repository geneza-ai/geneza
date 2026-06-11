package main

import (
	"context"
	"fmt"
	"net"
	"os"
	"os/signal"
	"strconv"
	"syscall"
	"text/tabwriter"
	"time"

	"github.com/spf13/cobra"

	"osie.cloud/geneza/internal/client"
	genezav1 "osie.cloud/geneza/internal/pb/geneza/v1"
)

func newServicesCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "services [node]",
		Short: "List services exposed by the fleet (rdp, db, http, subnet-route, exit-node, ...)",
		Args:  cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			e, err := loadEnv()
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
			node := ""
			if len(args) == 1 {
				node = args[0]
			}
			resp, err := api.ListServices(ctx, &genezav1.ListServicesRequest{Node: node})
			if err != nil {
				return client.Humanize(err)
			}
			tw := tabwriter.NewWriter(os.Stdout, 0, 2, 2, ' ', 0)
			fmt.Fprintln(tw, "SERVICE\tKIND\tNODE\tADDR\tONLINE")
			for _, s := range resp.GetServices() {
				online := "yes"
				if !s.GetOnline() {
					online = "no"
				}
				fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\n", s.GetName(), s.GetKind(), s.GetNodeName(), s.GetAddr(), online)
			}
			return tw.Flush()
		},
	}
}

func newConnectCmd() *cobra.Command {
	var listen int
	cmd := &cobra.Command{
		Use:   "connect NODE SERVICE",
		Short: "Open a local port to a named service on a node (rdp/vnc/http/db/tcp)",
		Args:  cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			e, err := loadEnv()
			if err != nil {
				return err
			}
			cc, api, err := dialUser(e)
			if err != nil {
				return err
			}
			defer cc.Close()
			ctx, stop := signal.NotifyContext(cmd.Context(), os.Interrupt, syscall.SIGTERM)
			defer stop()

			sess, err := client.Establish(ctx, api, e.pool, client.SessionParams{
				Node:    args[0],
				Action:  "connect",
				Service: args[1],
			})
			if err != nil {
				return err
			}
			defer sess.Close()
			target := sess.ForwardTarget
			if target == "" {
				return fmt.Errorf("service %q on %s is not a forwardable service (kind without an addr)", args[1], args[0])
			}

			ln, err := net.Listen("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(listen)))
			if err != nil {
				return err
			}
			defer ln.Close()
			go func() { <-ctx.Done(); ln.Close(); sess.Close() }()

			fmt.Fprintf(os.Stderr, "[session %s] %s/%s -> 127.0.0.1:%d  (point your client here; Ctrl-C to stop)\n",
				sess.ID, args[0], args[1], ln.Addr().(*net.TCPAddr).Port)

			for {
				conn, aerr := ln.Accept()
				if aerr != nil {
					if ctx.Err() != nil {
						fmt.Fprintln(os.Stderr, "connect stopped")
						return nil
					}
					return aerr
				}
				go forwardConn(sess.SSH, conn, target)
			}
		},
	}
	cmd.Flags().IntVar(&listen, "listen", 0, "local port to listen on (0 = pick a free port)")
	return cmd
}
