package gateway

import (
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"strconv"
	"sync"
	"time"

	"github.com/gorilla/websocket"
	"google.golang.org/grpc/status"

	"osie.cloud/geneza/internal/attachproto"
	"osie.cloud/geneza/internal/ca"
	"osie.cloud/geneza/internal/client"
	genezav1 "osie.cloud/geneza/internal/pb/geneza/v1"
	"osie.cloud/geneza/internal/tunnel"
	"osie.cloud/geneza/internal/types"
)

// The SPA is served from the gateway itself; auth is by bearer token (passed as
// ?token= because a browser WebSocket cannot set the Authorization header), not
// by origin, so origin checks add nothing here.
var shellUpgrader = websocket.Upgrader{
	ReadBufferSize:  8192,
	WriteBufferSize: 8192,
	CheckOrigin:     func(*http.Request) bool { return true },
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
// unchanged — it serves a normal shell session; the gateway is just the client.
func (c *consoleAPI) handleShell(w http.ResponseWriter, r *http.Request) {
	tok := r.URL.Query().Get("token")
	if tok == "" {
		writeErr(w, http.StatusUnauthorized, "token required")
		return
	}
	u, err := c.authenticateToken(r.Context(), tok)
	if err != nil {
		writeErr(w, http.StatusUnauthorized, "unauthorized")
		return
	}
	node, err := c.s.store.FindNode(u.Workspace, r.PathValue("id"))
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

	conn, err := shellUpgrader.Upgrade(w, r, nil)
	if err != nil {
		return // Upgrade already wrote the error
	}
	defer conn.Close()

	// IMPORTANT: do NOT use r.Context() here. Once the connection is hijacked for
	// the WebSocket, Go's HTTP server cancels the request context, which would
	// tear the brokered session down the instant it is created. The session
	// lives for as long as the WebSocket does; closing either end ends both.
	c.runWebShell(context.Background(), conn, u, node, cols, rows)
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

func (c *consoleAPI) runWebShell(ctx context.Context, conn *websocket.Conn, u *consoleUser, node *NodeRecord, cols, rows uint32) {
	// Broker a web-path shell session for this console user.
	key, err := tunnel.GenerateKeypair()
	if err != nil {
		wsClose(conn, "key generation failed")
		return
	}
	ident := &ca.Identity{Kind: ca.KindUser, Workspace: u.Workspace, Name: u.Name, Roles: u.Roles}
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
	// Dial the relay LOCALLY: the proxy runs on the gateway VM, so reaching the
	// relay via the public address the grant advertises would NAT-hairpin back to
	// this host (flaky). DialGrantVia keeps the public host as the TLS ServerName
	// (cert match) but connects to 127.0.0.1:<relay-port>.
	sess, err := client.DialGrantVia(ctx, pool, resp, key, c.s.localRelayAddr())
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

	if err := c.s.audit.Append("web_shell", u.Name, node.ID, resp.GetSessionId(), map[string]string{
		"cols": strconv.Itoa(int(cols)), "rows": strconv.Itoa(int(rows)),
	}); err != nil {
		slog.Error("audit append failed", "type", "web_shell", "err", err)
	}
	slog.Info("web shell opened", "user", u.Name, "node", node.ID, "session", resp.GetSessionId())

	bridgeWebShell(conn, ch)
}

// bridgeWebShell shuttles bytes between the xterm WebSocket and the agent's
// attach channel: HostToClient Snapshot/Output -> binary WS frames (terminal
// data), binary WS frames -> sequence-numbered Input, and JSON text frames
// ({type:"resize",cols,rows}) -> Resize. Either side closing tears down both.
func bridgeWebShell(conn *websocket.Conn, ch interface {
	Read([]byte) (int, error)
	Write([]byte) (int, error)
	Close() error
}) {
	var once sync.Once
	closeBoth := func() { once.Do(func() { ch.Close(); conn.Close() }) }
	defer closeBoth()

	// host -> browser
	go func() {
		defer closeBoth()
		for {
			m, err := attachproto.ReadHostMsg(ch)
			if err != nil {
				return
			}
			switch v := m.GetMsg().(type) {
			case *genezav1.HostToClient_Snapshot:
				if werr := conn.WriteMessage(websocket.BinaryMessage, v.Snapshot.GetData()); werr != nil {
					return
				}
			case *genezav1.HostToClient_Output:
				if werr := conn.WriteMessage(websocket.BinaryMessage, v.Output.GetData()); werr != nil {
					return
				}
			case *genezav1.HostToClient_Exit:
				_ = conn.WriteMessage(websocket.TextMessage,
					mustJSON(map[string]any{"type": "exit", "code": v.Exit.GetCode()}))
				return
			}
		}
	}()

	// browser -> host
	var seq uint64
	for {
		mt, data, err := conn.ReadMessage()
		if err != nil {
			return
		}
		switch mt {
		case websocket.BinaryMessage:
			seq++
			if werr := attachproto.WriteClientMsg(ch, &genezav1.ClientToHost{
				Msg: &genezav1.ClientToHost_Input{Input: &genezav1.Input{Seq: seq, Data: data}},
			}); werr != nil {
				return
			}
		case websocket.TextMessage:
			var ctrl struct {
				Type string `json:"type"`
				Cols uint32 `json:"cols"`
				Rows uint32 `json:"rows"`
			}
			if json.Unmarshal(data, &ctrl) == nil && ctrl.Type == "resize" {
				_ = attachproto.WriteClientMsg(ch, &genezav1.ClientToHost{
					Msg: &genezav1.ClientToHost_Resize{Resize: &genezav1.Resize{Cols: ctrl.Cols, Rows: ctrl.Rows}},
				})
			}
		}
	}
}
