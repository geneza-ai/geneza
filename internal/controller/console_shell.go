package controller

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/gorilla/websocket"
	"google.golang.org/grpc/status"

	"geneza.io/internal/attachbridge"
	"geneza.io/internal/attachproto"
	"geneza.io/internal/ca"
	"geneza.io/internal/client"
	genezav1 "geneza.io/internal/pb/geneza/v1"
	"geneza.io/internal/tunnel"
	"geneza.io/internal/types"
)

// shellUpgrader validates the WS upgrade. CheckOrigin is set per-consoleAPI in
// newShellUpgrader so it can pin the configured external origin.
var shellUpgrader = websocket.Upgrader{
	ReadBufferSize:  8192,
	WriteBufferSize: 8192,
}

// checkShellOrigin pins the WebSocket origin to the console's external origin
// : a cross-origin page must not be able to open a shell with the user's
// ambient credentials. An empty Origin (non-browser client) is allowed.
func (c *consoleAPI) checkShellOrigin(r *http.Request) bool {
	origin := r.Header.Get("Origin")
	if origin == "" {
		return true
	}
	if c.extURL == "" {
		return true // no configured origin to pin against
	}
	return strings.EqualFold(strings.TrimRight(origin, "/"), c.extURL)
}

func atoiOr(s string, def int) int {
	if n, err := strconv.Atoi(s); err == nil && n > 0 {
		return n
	}
	return def
}

// handleShell is the browser remote-shell endpoint: it brokers a session AS the
// authenticated console user with client_path=web (so require_native policy
// rules deny it), builds the same E2E Noise tunnel a native client would, opens
// a PTY on the node, and bridges it to the WebSocket / xterm.js. The agent is
// unchanged — it serves a normal shell session; the controller is just the client.
// handleShellTicket (Bearer-authed) mints a one-time, node-scoped WS ticket the
// SPA puts in the WebSocket URL — so the session token never rides ?token=
// . The ticket points at the caller's session for the live watchdog.
func (c *consoleAPI) handleShellTicket(w http.ResponseWriter, r *http.Request, u *consoleUser) {
	nodeID := r.PathValue("id")
	if _, err := c.s.store.FindNode(u.Workspace, nodeID); err != nil {
		writeErr(w, http.StatusNotFound, "node not found")
		return
	}
	tok, ok := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
	if !ok || tok == "" {
		writeErr(w, http.StatusUnauthorized, "unauthorized")
		return
	}
	ticket, err := c.s.store.MintWSTicket(hashToken(tok), nodeID, 60*time.Second)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "could not mint ticket")
		return
	}
	writeJSON(w, map[string]any{"ticket": ticket})
}

func (c *consoleAPI) handleShell(w http.ResponseWriter, r *http.Request) {
	ticket := r.URL.Query().Get("ticket")
	if ticket == "" {
		writeErr(w, http.StatusUnauthorized, "ticket required")
		return
	}
	sessHash, ticketNode, err := c.s.store.RedeemWSTicket(ticket, time.Now().Unix())
	if err != nil {
		writeErr(w, http.StatusUnauthorized, "invalid ticket")
		return
	}
	u, err := c.authenticateSessionHash(sessHash)
	if err != nil {
		writeErr(w, http.StatusUnauthorized, "unauthorized")
		return
	}
	nodeID := r.PathValue("id")
	if nodeID != ticketNode {
		writeErr(w, http.StatusForbidden, "ticket is scoped to a different node")
		return
	}
	node, err := c.s.store.FindNode(u.Workspace, nodeID)
	if err != nil {
		writeErr(w, http.StatusNotFound, "node not found")
		return
	}
	if !c.s.registry.Online(node.ID) {
		writeErr(w, http.StatusConflict, "node is offline")
		return
	}

	cols := uint32(atoiOr(r.URL.Query().Get("cols"), 80))
	rows := uint32(atoiOr(r.URL.Query().Get("rows"), 24))

	up := shellUpgrader
	up.CheckOrigin = c.checkShellOrigin //
	conn, err := up.Upgrade(w, r, nil)
	if err != nil {
		return // Upgrade already wrote the error
	}
	defer conn.Close()

	// IMPORTANT: do NOT use r.Context() here. Once the connection is hijacked for
	// the WebSocket, Go's HTTP server cancels the request context, which would
	// tear the brokered session down the instant it is created. The session
	// lives for as long as the WebSocket does; closing either end ends both.
	c.runWebShell(context.Background(), conn, u, node, cols, rows, sessHash)
}

// wsClose sends a terminal status line to xterm then closes the socket.
func wsClose(conn *websocket.Conn, msg string) {
	_ = conn.WriteMessage(websocket.TextMessage, mustJSON(map[string]any{"type": "error", "message": msg}))
	_ = conn.WriteControl(websocket.CloseMessage,
		websocket.FormatCloseMessage(websocket.CloseNormalClosure, msg), time.Now().Add(time.Second))
}

func mustJSON(v any) []byte { b, _ := json.Marshal(v); return b }

// statusMessage extracts the human reason from a gRPC status error (the broker's
// policy-deny message), dropping the "rpc error: code = ..." wrapper.
func statusMessage(err error) string { return status.Convert(err).Message() }

func (c *consoleAPI) runWebShell(ctx context.Context, conn *websocket.Conn, u *consoleUser, node *NodeRecord, cols, rows uint32, sessHash string) {
	// Revocation watchdog: a web shell is brokered once, but the operator
	// may be logged out / kicked / their keystone token may lapse mid-session.
	// Re-read the AuthSession every 15s and close the WS if it's gone, revoked, or
	// expired — so `geneza kick --user <user>` (which deletes auth-sessions)
	// tears down the live shell too, not just future requests.
	ctx, cancelWatch := context.WithCancel(ctx)
	defer cancelWatch()
	go func() {
		t := time.NewTicker(15 * time.Second)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				rec, err := c.s.store.GetAuthSession(sessHash)
				suspended := c.s.store.IsSuspended(u.Workspace, u.Provider, u.Subject)
				// Continuous presence: a presence-required browser
				// session whose beacon went stale is dropped, identical to the tunnel
				// sweep. (The browser beacon endpoint + SPA loop that keep it fresh
				// arrive alongside the WebAuthn factor.)
				presenceStale := false
				if ttl := c.s.cfg.Presence.TTL.D(); err == nil && rec != nil && rec.RequirePresence && ttl > 0 {
					presenceStale = time.Now().Unix()-rec.LastPresenceUnix > int64(ttl.Seconds())
				}
				if err != nil || rec.Revoked || suspended || presenceStale || (rec.ExpiresUnix > 0 && time.Now().Unix() >= rec.ExpiresUnix) {
					slog.Info("web shell: session revoked/expired/suspended/presence-stale, closing", "user", u.Name, "node", node.ID, "suspended", suspended, "presence_stale", presenceStale)
					_ = conn.Close() // unblocks bridgeWebShell's reads -> both ends tear down
					return
				}
			}
		}
	}()

	// Broker a web-path shell session for this console user.
	key, err := tunnel.GenerateKeypair()
	if err != nil {
		wsClose(conn, "key generation failed")
		return
	}
	ident := &ca.Identity{Kind: ca.KindUser, Workspace: u.Workspace, Name: u.Name, Roles: u.Roles, Provider: u.Provider, Subject: u.Subject}
	resp, err := c.s.broker.CreateSessionWeb(ctx, ident, &genezav1.CreateSessionRequest{
		Node:           node.ID,
		Action:         types.ActionShell,
		WantPty:        true,
		ClientNoisePub: key.Public,
	})
	if err != nil {
		wsClose(conn, "access denied: "+statusMessage(err))
		return
	}

	pool, err := ca.PoolFromPEM(c.s.ca.RootsPEM)
	if err != nil {
		wsClose(conn, "internal: ca pool")
		return
	}
	// Establish the data path through the SAME entrypoint the CLI and desktop use
	// (client.DialSession), so the web proxy can never diverge. A nil signaling api
	// means it cannot do ICE — it goes straight to the relay-TCP floor, which is all
	// the in-process proxy can reach anyway. It dials the relay LOCALLY (the proxy
	// runs on the controller VM, so the grant's public relay address would NAT-hairpin
	// back here, flakily); the public host stays the TLS ServerName for the cert match.
	sess, err := client.DialSession(ctx, nil, pool, resp, key, c.s.localRelayAddr())
	if err != nil {
		wsClose(conn, "tunnel: "+err.Error())
		return
	}
	defer sess.Close()

	ch, err := sess.OpenAttachChannel(&attachproto.AttachOpenParams{
		Cols: cols, Rows: rows, Term: "xterm-256color",
	})
	if err != nil {
		wsClose(conn, err.Error())
		return
	}

	if err := c.s.audit.AppendWS(u.Workspace, "web_shell", u.Name, node.ID, resp.GetSessionId(), map[string]string{
		"cols": strconv.Itoa(int(cols)), "rows": strconv.Itoa(int(rows)),
	}); err != nil {
		slog.Error("audit append failed", "type", "web_shell", "err", err)
	}
	slog.Info("web shell opened", "user", u.Name, "node", node.ID, "session", resp.GetSessionId())

	bridgeWebShell(conn, ch)
}

// wsSink delivers host terminal output to the xterm WebSocket: Snapshot/Output
// as binary frames, Exit as a JSON text frame (what xterm.js expects).
type wsSink struct{ conn *websocket.Conn }

func (s *wsSink) Output(data []byte) error {
	return s.conn.WriteMessage(websocket.BinaryMessage, data)
}

func (s *wsSink) Exit(code int32) error {
	return s.conn.WriteMessage(websocket.TextMessage,
		mustJSON(map[string]any{"type": "exit", "code": code}))
}

// bridgeWebShell shuttles bytes between the xterm WebSocket and the agent's
// attach channel using the shared attachbridge mapping: host Snapshot/Output ->
// binary WS frames, binary WS frames -> sequence-numbered Input, and JSON text
// frames ({type:"resize",cols,rows}) -> Resize. Either side closing tears down
// both.
func bridgeWebShell(conn *websocket.Conn, ch io.ReadWriteCloser) {
	var once sync.Once
	closeBoth := func() { once.Do(func() { ch.Close(); conn.Close() }) }
	defer closeBoth()

	// host -> browser
	go func() {
		defer closeBoth()
		_ = attachbridge.PumpHostToClient(ch, &wsSink{conn: conn})
	}()

	// browser -> host
	in := attachbridge.NewInputWriter(ch)
	for {
		mt, data, err := conn.ReadMessage()
		if err != nil {
			return
		}
		switch mt {
		case websocket.BinaryMessage:
			if werr := in.Input(data); werr != nil {
				return
			}
		case websocket.TextMessage:
			var ctrl struct {
				Type string `json:"type"`
				Cols uint32 `json:"cols"`
				Rows uint32 `json:"rows"`
			}
			if json.Unmarshal(data, &ctrl) == nil && ctrl.Type == "resize" {
				_ = in.Resize(ctrl.Cols, ctrl.Rows)
			}
		}
	}
}
