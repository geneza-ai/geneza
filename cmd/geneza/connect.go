package main

import (
	"fmt"
	"net"
	"os"
	"os/signal"
	"strconv"
	"syscall"

	"github.com/spf13/cobra"

	"geneza.io/internal/client"
)

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
			cc, api, cert, err := dialUser(e)
			if err != nil {
				return err
			}
			defer cc.Close()
			ctx, stop := signal.NotifyContext(cmd.Context(), os.Interrupt, syscall.SIGTERM)
			defer stop()

			sess, err := client.Establish(ctx, api, e.Pool, cert, client.SessionParams{
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
