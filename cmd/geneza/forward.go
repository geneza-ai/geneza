package main

import (
	"context"
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

	"geneza.io/internal/client"
	"geneza.io/internal/types"
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
			cc, api, cert, err := dialUser(e)
			if err != nil {
				return err
			}
			defer cc.Close()

			ctx, stop := signal.NotifyContext(cmd.Context(), os.Interrupt, syscall.SIGTERM)
			defer stop()

			// One tunnel, many TCP streams: every accepted connection becomes a
			// direct-tcpip SSH channel inside the same E2E session. The grant pins the
			// target, and the agent re-checks it per dial. A Supervisor keeps the
			// session live across a relay re-home — when the relay it is using drains or
			// dies, the session rebuilds on a surviving relay (forward has no
			// server-side state to preserve), so the forward resumes with a brief stall.
			build := func(bctx context.Context) (*client.Session, error) {
				return client.Establish(bctx, api, e.Pool, cert, client.SessionParams{
					Node:          args[0],
					Action:        types.ActionForward,
					ForwardTarget: target,
				})
			}
			sup, err := client.NewSupervisor(ctx, build)
			if err != nil {
				return err
			}
			go sup.Run(ctx)

			ln, err := net.Listen("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(localPort)))
			if err != nil {
				return err
			}
			defer ln.Close()
			go func() {
				<-ctx.Done()
				ln.Close()
			}()

			fmt.Fprintf(os.Stderr, "[session %s] forwarding 127.0.0.1:%d -> %s via %s (Ctrl-C to stop)\n",
				sup.Current().ID, localPort, target, args[0])

			for {
				conn, aerr := ln.Accept()
				if aerr != nil {
					if ctx.Err() != nil {
						fmt.Fprintln(os.Stderr, "forward stopped")
						return nil
					}
					return aerr
				}
				// Use the CURRENT session for each connection, so an in-flight re-home is
				// invisible past a brief stall.
				go forwardConn(sup.Current().SSH, conn, target)
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
