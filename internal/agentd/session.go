package agentd

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net"
	"os"
	"os/user"
	"strconv"
	"sync"
	"time"

	"github.com/pkg/sftp"
	"golang.org/x/crypto/ssh"

	"osie.cloud/geneza/internal/attachproto"
	genezav1 "osie.cloud/geneza/internal/pb/geneza/v1"
	"osie.cloud/geneza/internal/types"
)

// terminalEvent guarantees exactly one terminal lifecycle event (ended or
// detached) per session, whichever code path gets there first.
type terminalEvent struct {
	once      sync.Once
	w         *Worker
	sessionID string
}

func (t *terminalEvent) emit(event, detail, hostSessionID string, exitCode int32) {
	t.once.Do(func() {
		t.w.emitEvent(&genezav1.SessionEvent{
			SessionId:     t.sessionID,
			Event:         event,
			Detail:        detail,
			HostSessionId: hostSessionID,
			ExitCode:      exitCode,
		})
	})
}

// serveSSH runs the SSH connection protocol inside the established tunnel.
// NoClientAuth is correct here: the peer's identity was already proven by
// the Noise handshake against the signed grant; SSH supplies only the
// battle-tested channel/request semantics.
func (w *Worker) serveSSH(ctx context.Context, tconn net.Conn, grant *types.SessionGrant, log *slog.Logger) {
	cfg := &ssh.ServerConfig{NoClientAuth: true}
	cfg.AddHostKey(w.hostSigner)

	end := &terminalEvent{w: w, sessionID: grant.ID}
	sconn, chans, reqs, err := ssh.NewServerConn(tconn, cfg)
	if err != nil {
		log.Warn("ssh handshake failed", "err", err)
		end.emit("ended", "ssh handshake: "+err.Error(), "", -1)
		return
	}
	defer sconn.Close()
	go ssh.DiscardRequests(reqs)
	// Fallback terminal event if a handler path didn't emit one.
	defer end.emit("ended", "tunnel closed", "", 0)

	switch grant.Action {
	case types.ActionShell:
		w.serveShell(ctx, chans, grant, log, end)
	case types.ActionAttach:
		w.serveAttach(ctx, chans, grant, log, end)
	case types.ActionExec:
		w.serveExec(ctx, chans, grant, log, end)
	case types.ActionSFTP:
		w.serveSFTP(ctx, chans, grant, log, end)
	case types.ActionForward:
		w.serveForward(ctx, chans, grant, log, end)
	default:
		// Unreachable: grant.Validate already constrained the action set.
		log.Error("unhandled action", "action", grant.Action)
	}
}

func currentOSUser() string {
	if u, err := user.Current(); err == nil && u.Username != "" {
		return u.Username
	}
	return os.Getenv("USER")
}

// ---------------------------------------------------------------------------
// shell / attach (geneza-attach channel bridged to SessionHost.Attach)
// ---------------------------------------------------------------------------

func (w *Worker) serveShell(ctx context.Context, chans <-chan ssh.NewChannel, grant *types.SessionGrant, log *slog.Logger, end *terminalEvent) {
	ch, params, ok := w.acceptAttachChannel(chans, log)
	if !ok {
		return
	}
	defer ch.Close()

	shc, err := w.hostClient()
	if err != nil {
		log.Error("session host unavailable", "err", err)
		end.emit("ended", "session host unavailable", "", -1)
		return
	}
	env := map[string]string{}
	if params.Term != "" {
		env["TERM"] = params.Term
	}
	cctx, cancel := context.WithTimeout(ctx, hostRPCTimeout)
	created, err := shc.Create(cctx, &genezav1.HostCreateRequest{
		SessionId:  grant.ID,
		User:       grant.User,
		Action:     types.ActionShell,
		Command:    "",
		Pty:        grant.AllowPTY,
		Cols:       params.Cols,
		Rows:       params.Rows,
		Env:        env,
		Detachable: grant.AllowDetach,
		Record:     grant.Record,
		OsUser:     currentOSUser(),
	})
	cancel()
	if err != nil {
		log.Error("session host create failed", "err", err)
		end.emit("ended", "create: "+err.Error(), "", -1)
		return
	}
	hostID := created.HostSessionId
	log.Info("host session created", "host_session", hostID)
	w.emitEvent(&genezav1.SessionEvent{SessionId: grant.ID, Event: "attached", HostSessionId: hostID})

	w.bridgeAndFinish(ctx, ch, grant, hostID, params.LastSeenSeq, grant.AllowDetach, log, end)
}

func (w *Worker) serveAttach(ctx context.Context, chans <-chan ssh.NewChannel, grant *types.SessionGrant, log *slog.Logger, end *terminalEvent) {
	// Ownership and liveness re-check at the agent: the grant names a host
	// session, but we only honor it if that session still belongs to the
	// grant's user and is attachable. Certs rotate; reattach re-authorizes.
	shc, err := w.hostClient()
	if err != nil {
		log.Error("session host unavailable", "err", err)
		end.emit("ended", "session host unavailable", "", -1)
		return
	}
	lctx, cancel := context.WithTimeout(ctx, hostRPCTimeout)
	list, err := shc.List(lctx, &genezav1.HostListRequest{})
	cancel()
	if err != nil {
		log.Error("session host list failed", "err", err)
		end.emit("ended", "list: "+err.Error(), "", -1)
		return
	}
	var target *genezav1.HostSessionInfo
	for _, s := range list.Sessions {
		if s.HostSessionId == grant.AttachID {
			target = s
			break
		}
	}
	switch {
	case target == nil:
		log.Warn("attach rejected: no such host session", "attach_id", grant.AttachID)
		end.emit("rejected", "no such session", grant.AttachID, 0)
		return
	case target.User != grant.User:
		// Fail closed: never leak someone else's session, not even its existence.
		log.Warn("attach rejected: ownership mismatch", "attach_id", grant.AttachID, "owner", target.User, "grant_user", grant.User)
		end.emit("rejected", "no such session", grant.AttachID, 0)
		return
	case target.State != "attached" && target.State != "detached":
		log.Warn("attach rejected: session not attachable", "attach_id", grant.AttachID, "state", target.State)
		end.emit("rejected", "session state "+target.State, grant.AttachID, 0)
		return
	}

	ch, params, ok := w.acceptAttachChannel(chans, log)
	if !ok {
		return
	}
	defer ch.Close()
	// Preempting a currently attached client is allowed; the host handles it.
	w.emitEvent(&genezav1.SessionEvent{SessionId: grant.ID, Event: "attached", HostSessionId: grant.AttachID})
	log.Info("reattached", "host_session", grant.AttachID, "last_seen_seq", params.LastSeenSeq)

	// Honor the (re)attach grant's detach permission: if this grant does not
	// allow detach (e.g. policy now forbids detached sessions on this node),
	// the session must TERMINATE on disconnect rather than be re-detached —
	// draining a pre-existing detached session instead of perpetuating it.
	w.bridgeAndFinish(ctx, ch, grant, grant.AttachID, params.LastSeenSeq, grant.AllowDetach, log, end)
}

// acceptAttachChannel accepts exactly one geneza-attach channel and parses
// its open params; everything else is rejected.
func (w *Worker) acceptAttachChannel(chans <-chan ssh.NewChannel, log *slog.Logger) (ssh.Channel, *attachproto.AttachOpenParams, bool) {
	for newCh := range chans {
		if newCh.ChannelType() != attachproto.ChannelTypeAttach {
			log.Warn("rejecting channel", "type", newCh.ChannelType())
			_ = newCh.Reject(ssh.UnknownChannelType, "only "+attachproto.ChannelTypeAttach+" is allowed for this session")
			continue
		}
		params, err := attachproto.ParseAttachOpenParams(newCh.ExtraData())
		if err != nil {
			_ = newCh.Reject(ssh.ConnectionFailed, "bad open params")
			continue
		}
		ch, chReqs, err := newCh.Accept()
		if err != nil {
			log.Warn("channel accept failed", "err", err)
			return nil, nil, false
		}
		go ssh.DiscardRequests(chReqs)
		return ch, params, true
	}
	return nil, nil, false
}

func (w *Worker) bridgeAndFinish(ctx context.Context, ch ssh.Channel, grant *types.SessionGrant, hostID string, lastSeen uint64, detachable bool, log *slog.Logger, end *terminalEvent) {
	outcome, code, err := w.bridgeAttachChannel(ctx, ch, hostID, lastSeen, detachable)
	switch outcome {
	case outcomeExited:
		log.Info("session exited", "host_session", hostID, "code", code)
		end.emit("ended", "", hostID, code)
	case outcomeClientGone:
		if detachable {
			log.Info("client gone, session detached", "host_session", hostID)
			end.emit("detached", "", hostID, 0)
		} else {
			log.Info("client gone, non-detachable session killed", "host_session", hostID)
			end.emit("ended", "client disconnected", hostID, -1)
		}
	default: // outcomeHostGone
		detail := "session host stream lost"
		if err != nil {
			detail += ": " + err.Error()
		}
		log.Warn("bridge ended abnormally", "host_session", hostID, "err", err)
		end.emit("ended", detail, hostID, -1)
	}
}

type bridgeOutcome int

const (
	outcomeExited bridgeOutcome = iota
	outcomeClientGone
	outcomeHostGone
)

type bridgeResult struct {
	outcome bridgeOutcome
	code    int32
	err     error
}

// bridgeAttachChannel pumps attachproto frames between the SSH channel and a
// SessionHost.Attach stream. The worker sends the authoritative AttachOpen
// first and drops any client-sent open frames: which host session a client
// talks to is decided by the signed grant, never by channel data.
func (w *Worker) bridgeAttachChannel(ctx context.Context, ch ssh.Channel, hostID string, lastSeen uint64, detachable bool) (bridgeOutcome, int32, error) {
	shc, err := w.hostClient()
	if err != nil {
		return outcomeHostGone, -1, err
	}
	sctx, cancel := context.WithCancel(ctx)
	defer cancel()
	stream, err := shc.Attach(sctx)
	if err != nil {
		return outcomeHostGone, -1, err
	}
	if err := stream.Send(&genezav1.ClientToHost{Msg: &genezav1.ClientToHost_Open{Open: &genezav1.AttachOpen{
		HostSessionId: hostID,
		LastSeenSeq:   lastSeen,
	}}}); err != nil {
		return outcomeHostGone, -1, err
	}

	resCh := make(chan bridgeResult, 2)

	go func() { // client -> host
		for {
			m, err := attachproto.ReadClientMsg(ch)
			if err != nil {
				resCh <- bridgeResult{outcome: outcomeClientGone, err: err}
				return
			}
			if m.GetOpen() != nil {
				continue // authoritative open already sent; never trust the client's
			}
			if err := stream.Send(m); err != nil {
				resCh <- bridgeResult{outcome: outcomeHostGone, err: err}
				return
			}
		}
	}()

	go func() { // host -> client
		for {
			m, err := stream.Recv()
			if err != nil {
				resCh <- bridgeResult{outcome: outcomeHostGone, err: err}
				return
			}
			if err := attachproto.WriteHostMsg(ch, m); err != nil {
				resCh <- bridgeResult{outcome: outcomeClientGone, err: err}
				return
			}
			if e := m.GetExit(); e != nil {
				resCh <- bridgeResult{outcome: outcomeExited, code: e.Code}
				return
			}
		}
	}()

	res := <-resCh
	if res.outcome == outcomeClientGone {
		if detachable {
			// Detach and give the host a moment to acknowledge (stream close)
			// before the surrounding contexts tear the transport down.
			_ = stream.Send(&genezav1.ClientToHost{Msg: &genezav1.ClientToHost_Detach{Detach: &genezav1.Detach{}}})
			_ = stream.CloseSend()
			select {
			case <-resCh:
			case <-time.After(2 * time.Second):
			}
		} else {
			kctx, kcancel := context.WithTimeout(context.Background(), hostRPCTimeout)
			_, _ = shc.Kill(kctx, &genezav1.HostKillRequest{HostSessionId: hostID})
			kcancel()
		}
	}
	return res.outcome, res.code, res.err
}

// ---------------------------------------------------------------------------
// exec ("session" channel, exec request, raw stdio bridge)
// ---------------------------------------------------------------------------

func (w *Worker) serveExec(ctx context.Context, chans <-chan ssh.NewChannel, grant *types.SessionGrant, log *slog.Logger, end *terminalEvent) {
	for newCh := range chans {
		if newCh.ChannelType() != "session" {
			_ = newCh.Reject(ssh.UnknownChannelType, "only session channels are allowed for exec")
			continue
		}
		ch, reqs, err := newCh.Accept()
		if err != nil {
			log.Warn("channel accept failed", "err", err)
			return
		}
		w.handleExecChannel(ctx, ch, reqs, grant, log, end)
		_ = ch.Close()
		return // exactly one session channel
	}
}

func (w *Worker) handleExecChannel(ctx context.Context, ch ssh.Channel, reqs <-chan *ssh.Request, grant *types.SessionGrant, log *slog.Logger, end *terminalEvent) {
	// Wait for the exec request; pty-req/env/shell/subsystem are rejected —
	// an exec grant carries exactly one pre-approved command line.
	gotExec := false
	for req := range reqs {
		if req.Type == "exec" {
			var p struct{ Command string }
			if err := ssh.Unmarshal(req.Payload, &p); err != nil {
				_ = req.Reply(false, nil)
				return
			}
			if !ExecCommandAllowed(grant.Command, p.Command) {
				log.Warn("exec rejected: command does not match grant", "requested", p.Command)
				_ = req.Reply(false, nil)
				end.emit("rejected", "exec command mismatch", "", 0)
				return
			}
			_ = req.Reply(true, nil)
			gotExec = true
			break
		}
		log.Warn("rejecting request on exec channel", "type", req.Type)
		_ = req.Reply(false, nil)
	}
	if !gotExec {
		return
	}
	go func() { // drain and refuse anything after exec
		for req := range reqs {
			_ = req.Reply(false, nil)
		}
	}()

	shc, err := w.hostClient()
	if err != nil {
		end.emit("ended", "session host unavailable", "", -1)
		return
	}
	cctx, cancel := context.WithTimeout(ctx, hostRPCTimeout)
	created, err := shc.Create(cctx, &genezav1.HostCreateRequest{
		SessionId:  grant.ID,
		User:       grant.User,
		Action:     types.ActionExec,
		Command:    grant.Command, // the verified grant command, never the request's bytes
		Pty:        false,
		Detachable: false,
		Record:     grant.Record,
		OsUser:     currentOSUser(),
	})
	cancel()
	if err != nil {
		log.Error("session host create failed", "err", err)
		end.emit("ended", "create: "+err.Error(), "", -1)
		return
	}
	hostID := created.HostSessionId

	sctx, scancel := context.WithCancel(ctx)
	defer scancel()
	stream, err := shc.Attach(sctx)
	if err != nil {
		end.emit("ended", "attach: "+err.Error(), hostID, -1)
		return
	}
	if err := stream.Send(&genezav1.ClientToHost{Msg: &genezav1.ClientToHost_Open{Open: &genezav1.AttachOpen{
		HostSessionId: hostID,
	}}}); err != nil {
		end.emit("ended", "attach open: "+err.Error(), hostID, -1)
		return
	}

	go func() { // channel stdin -> Input frames
		var seq uint64
		buf := make([]byte, 32*1024)
		for {
			n, err := ch.Read(buf)
			if n > 0 {
				seq++
				data := make([]byte, n)
				copy(data, buf[:n])
				if serr := stream.Send(&genezav1.ClientToHost{Msg: &genezav1.ClientToHost_Input{Input: &genezav1.Input{
					Seq:  seq,
					Data: data,
				}}}); serr != nil {
					return
				}
			}
			if err != nil {
				_ = stream.Send(&genezav1.ClientToHost{Msg: &genezav1.ClientToHost_StdinEof{StdinEof: &genezav1.Stdin_EOF{}}})
				return
			}
		}
	}()

	for {
		m, err := stream.Recv()
		if err != nil {
			// Host stream died before exit: nothing to keep running for.
			kctx, kcancel := context.WithTimeout(context.Background(), hostRPCTimeout)
			_, _ = shc.Kill(kctx, &genezav1.HostKillRequest{HostSessionId: hostID})
			kcancel()
			end.emit("ended", "session host stream lost", hostID, -1)
			return
		}
		switch msg := m.Msg.(type) {
		case *genezav1.HostToClient_Output:
			if _, err := ch.Write(msg.Output.Data); err != nil {
				w.killExecOnClientGone(shc, hostID, end)
				return
			}
		case *genezav1.HostToClient_Stderr:
			if _, err := ch.Stderr().Write(msg.Stderr.Data); err != nil {
				w.killExecOnClientGone(shc, hostID, end)
				return
			}
		case *genezav1.HostToClient_Exit:
			code := msg.Exit.Code
			status := uint32(code)
			if code < 0 {
				status = 255 // ssh exit-status is unsigned; signal deaths map to a generic failure
			}
			_, _ = ch.SendRequest("exit-status", false, ssh.Marshal(struct{ Status uint32 }{status}))
			end.emit("ended", msg.Exit.Reason, hostID, code)
			log.Info("exec finished", "host_session", hostID, "code", code)
			return
		default:
			// Snapshot/InputAck are meaningless on a pty-less exec bridge.
		}
	}
}

func (w *Worker) killExecOnClientGone(shc genezav1.SessionHostClient, hostID string, end *terminalEvent) {
	kctx, kcancel := context.WithTimeout(context.Background(), hostRPCTimeout)
	_, _ = shc.Kill(kctx, &genezav1.HostKillRequest{HostSessionId: hostID})
	kcancel()
	end.emit("ended", "client disconnected", hostID, -1)
}

// ---------------------------------------------------------------------------
// sftp ("session" channel, sftp subsystem served in-process)
// ---------------------------------------------------------------------------

// serveSFTP serves the sftp subsystem directly on the channel. v1 runs the
// SFTP server as the agent's own OS user (same trust level as exec).
func (w *Worker) serveSFTP(ctx context.Context, chans <-chan ssh.NewChannel, grant *types.SessionGrant, log *slog.Logger, end *terminalEvent) {
	for newCh := range chans {
		if newCh.ChannelType() != "session" {
			_ = newCh.Reject(ssh.UnknownChannelType, "only session channels are allowed for sftp")
			continue
		}
		ch, reqs, err := newCh.Accept()
		if err != nil {
			log.Warn("channel accept failed", "err", err)
			return
		}

		started := false
		for req := range reqs {
			if !started && req.Type == "subsystem" {
				var p struct{ Name string }
				if err := ssh.Unmarshal(req.Payload, &p); err == nil && p.Name == "sftp" {
					_ = req.Reply(true, nil)
					started = true
					break
				}
			}
			log.Warn("rejecting request on sftp channel", "type", req.Type)
			_ = req.Reply(false, nil)
		}
		if !started {
			_ = ch.Close()
			return
		}
		go func() {
			for req := range reqs {
				_ = req.Reply(false, nil)
			}
		}()

		srv, err := sftp.NewServer(ch)
		if err != nil {
			log.Error("sftp server init failed", "err", err)
			_ = ch.Close()
			end.emit("ended", "sftp init: "+err.Error(), "", -1)
			return
		}
		err = srv.Serve()
		_ = srv.Close()
		_ = ch.Close()
		if err != nil && !errors.Is(err, io.EOF) {
			log.Warn("sftp server ended", "err", err)
			end.emit("ended", "sftp: "+err.Error(), "", -1)
			return
		}
		log.Info("sftp session finished")
		end.emit("ended", "", "", 0)
		return // exactly one session channel
	}
}

// ---------------------------------------------------------------------------
// forward (direct-tcpip channels spliced to the single granted target)
// ---------------------------------------------------------------------------

func (w *Worker) serveForward(ctx context.Context, chans <-chan ssh.NewChannel, grant *types.SessionGrant, log *slog.Logger, end *terminalEvent) {
	var wg sync.WaitGroup
	for newCh := range chans {
		if newCh.ChannelType() != "direct-tcpip" {
			_ = newCh.Reject(ssh.UnknownChannelType, "only direct-tcpip channels are allowed for forward")
			continue
		}
		// Standard SSH direct-tcpip open payload.
		var p struct {
			DestAddr string
			DestPort uint32
			OrigAddr string
			OrigPort uint32
		}
		if err := ssh.Unmarshal(newCh.ExtraData(), &p); err != nil {
			_ = newCh.Reject(ssh.ConnectionFailed, "bad direct-tcpip payload")
			continue
		}
		if !ForwardTargetAllowed(grant.ForwardTarget, p.DestAddr, p.DestPort) {
			log.Warn("forward rejected: destination not in grant",
				"dest", net.JoinHostPort(p.DestAddr, strconv.FormatUint(uint64(p.DestPort), 10)),
				"granted", grant.ForwardTarget)
			_ = newCh.Reject(ssh.Prohibited, "destination not allowed by grant")
			continue
		}
		ch, reqs, err := newCh.Accept()
		if err != nil {
			continue
		}
		go ssh.DiscardRequests(reqs)
		wg.Add(1)
		go func() {
			defer wg.Done()
			spliceForward(ch, grant.ForwardTarget, log)
		}()
	}
	wg.Wait()
	end.emit("ended", "", "", 0)
}

func spliceForward(ch ssh.Channel, target string, log *slog.Logger) {
	defer ch.Close()
	dst, err := net.DialTimeout("tcp", target, 10*time.Second)
	if err != nil {
		log.Warn("forward dial failed", "target", target, "err", err)
		return
	}
	defer dst.Close()

	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		_, _ = io.Copy(dst, ch)
		if t, ok := dst.(*net.TCPConn); ok {
			_ = t.CloseWrite() // half-close so the target sees EOF
		}
	}()
	go func() {
		defer wg.Done()
		_, _ = io.Copy(ch, dst)
		_ = ch.CloseWrite()
	}()
	wg.Wait()
}
