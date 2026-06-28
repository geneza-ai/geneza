package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/spf13/cobra"
	"golang.org/x/crypto/ssh"
	"golang.org/x/term"

	"geneza.io/internal/client"
	"geneza.io/internal/types"
)

func newExecCmd() *cobra.Command {
	var tty bool
	cmd := &cobra.Command{
		Use:   "exec NODE [--tty] -- CMD [ARGS...]",
		Short: "Run a command on a node and exit with its status",
		Args:  cobra.MinimumNArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			code, err := runExec(cmd.Context(), args[0], args[1:], tty)
			if err != nil {
				return err
			}
			if code != 0 {
				os.Exit(code)
			}
			return nil
		},
	}
	cmd.Flags().BoolVarP(&tty, "tty", "t", false, "allocate a remote PTY")
	return cmd
}

func runExec(ctx context.Context, node string, argv []string, tty bool) (int, error) {
	// The grant carries the exact (shell-joined) command; the agent enforces
	// it regardless of what the SSH exec request says.
	command := client.ShellJoin(argv)

	e, err := loadEnv()
	if err != nil {
		return 1, err
	}
	cc, api, cert, err := dialUser(e)
	if err != nil {
		return 1, err
	}
	defer cc.Close()

	sess, err := client.Establish(ctx, api, e.Pool, cert, client.SessionParams{
		Node:    node,
		Action:  types.ActionExec,
		Command: command,
		WantPTY: tty,
	})
	if err != nil {
		return 1, err
	}
	defer sess.Close()

	s, err := sess.SSH.NewSession()
	if err != nil {
		return 1, fmt.Errorf("open session channel: %w", err)
	}
	defer s.Close()

	stdinFd := int(os.Stdin.Fd())
	stdinIsTerm := term.IsTerminal(stdinFd)

	if tty {
		termName := os.Getenv("TERM")
		if termName == "" {
			termName = "xterm"
		}
		w, h := 80, 24
		if cw, chh, gerr := term.GetSize(int(os.Stdout.Fd())); gerr == nil {
			w, h = cw, chh
		}
		modes := ssh.TerminalModes{ssh.ECHO: 1, ssh.TTY_OP_ISPEED: 14400, ssh.TTY_OP_OSPEED: 14400}
		if err := s.RequestPty(termName, h, w, modes); err != nil {
			return 1, fmt.Errorf("request pty: %w", err)
		}
		if stdinIsTerm {
			oldState, rerr := term.MakeRaw(stdinFd)
			if rerr != nil {
				return 1, fmt.Errorf("raw mode: %w", rerr)
			}
			restore := func() { term.Restore(stdinFd, oldState) } //nolint:errcheck
			defer restore()
			sigCh := make(chan os.Signal, 1)
			signal.Notify(sigCh, syscall.SIGTERM, syscall.SIGHUP)
			defer signal.Stop(sigCh)
			go func() {
				if _, open := <-sigCh; open {
					restore()
					os.Exit(1)
				}
			}()
		}
		watchWindowSize(s)
	}

	// Pipe stdin when it is not a terminal (data is being piped in), or when
	// the user explicitly asked for an interactive remote tty. A bare
	// terminal stdin without --tty is NOT piped: the command would otherwise
	// hang waiting on input the user did not intend to give.
	if !stdinIsTerm || tty {
		s.Stdin = os.Stdin
	}
	s.Stdout = os.Stdout
	s.Stderr = os.Stderr

	if err := s.Run(command); err != nil {
		var ee *ssh.ExitError
		if errors.As(err, &ee) {
			return ee.ExitStatus(), nil
		}
		var em *ssh.ExitMissingError
		if errors.As(err, &em) {
			return 255, nil // remote ended without reporting a status
		}
		return 1, fmt.Errorf("remote command: %w", err)
	}
	return 0, nil
}
