package main

import (
	"fmt"
	"io"
	"log/slog"
	"net"
	"os"
	"os/signal"
	"strconv"
	"sync"
	"syscall"

	"github.com/spf13/cobra"
	"golang.org/x/crypto/ssh"

	"osie.cloud/geneza/internal/client"
	"osie.cloud/geneza/internal/types"
)

func newForwardCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "forward NODE LOCAL_PORT:TARGET_HOST:TARGET_PORT",
		Short: "Forward a local port to a target reachable from the node",
		Args:  cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			localPort, target, err := client.ParseForwardSpec(args[1])
			if err != nil {
				return err
			}

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

			// One tunnel, many TCP streams: every accepted connection becomes
			// a direct-tcpip SSH channel inside the same E2E session. The
			// grant pins the target, and the agent re-checks it per dial.
			sess, err := client.Establish(ctx, api, e.pool, client.SessionParams{
				Node:          args[0],
				Action:        types.ActionForward,
				ForwardTarget: target,
			})
			if err != nil {
				return err
			}
			defer sess.Close()

			ln, err := net.Listen("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(localPort)))
			if err != nil {
				return err
			}
			defer ln.Close()
			go func() {
				<-ctx.Done()
				ln.Close()
				sess.Close()
			}()

			fmt.Fprintf(os.Stderr, "[session %s] forwarding 127.0.0.1:%d -> %s via %s (Ctrl-C to stop)\n",
				sess.ID, localPort, target, args[0])

			for {
				conn, aerr := ln.Accept()
				if aerr != nil {
					if ctx.Err() != nil {
						fmt.Fprintln(os.Stderr, "forward stopped")
						return nil
					}
					return aerr
				}
				go forwardConn(sess.SSH, conn, target)
			}
		},
	}
}

func forwardConn(sshc *ssh.Client, local net.Conn, target string) {
	defer local.Close()
	remote, err := sshc.Dial("tcp", target)
	if err != nil {
		slog.Warn("forward dial failed", "target", target, "err", err)
		return
	}
	defer remote.Close()
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		io.Copy(remote, local) //nolint:errcheck
		remote.Close()         // unblock the other direction
	}()
	go func() {
		defer wg.Done()
		io.Copy(local, remote) //nolint:errcheck
		local.Close()
	}()
	wg.Wait()
}
