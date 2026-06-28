package main

import (
	"context"
	"encoding/base64"
	"errors"
	"net/http"
	"net/http/httputil"
	"net/url"
	"sync"

	"github.com/wailsapp/wails/v2/pkg/runtime"

	"geneza.io/internal/attachbridge"
	"geneza.io/internal/attachproto"
	"geneza.io/internal/client"
	"geneza.io/internal/clientcore"
	"geneza.io/internal/types"
)

// DesktopService is the Go backend the React UI binds to. It drives the same
// shared client core the CLI uses, so a shell opened here rides the direct,
// end-to-end Noise tunnel (controller out of the data path) — strictly more native
// than the controller-proxied browser web-shell.
type DesktopService struct {
	ctx context.Context // Wails runtime context, for events

	mu     sync.Mutex
	cc     *clientcore.Client
	proxy  *httputil.ReverseProxy // /api/v1 -> controller :7402 over mTLS (set on Connect)
	shells map[string]*shellSession
}

type shellSession struct {
	sess *client.Session
	in   *attachbridge.InputWriter
}

// NewDesktopService constructs the bound service.
func NewDesktopService() *DesktopService {
	return &DesktopService{shells: map[string]*shellSession{}}
}

func (s *DesktopService) startup(ctx context.Context) { s.ctx = ctx }

func (s *DesktopService) shutdown(context.Context) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, sh := range s.shells {
		_ = sh.sess.Close()
	}
	if s.cc != nil {
		_ = s.cc.Close()
	}
}

// Session is the connected identity, for the UI header.
type Session struct {
	Controller   string `json:"controller"`
	User      string `json:"user"`
	Workspace string `json:"workspace"`
}

// Connect opens the named profile (empty = "default") created by `geneza login`
// and dials the controller. One identity is shared with the CLI — log in once.
func (s *DesktopService) Connect(profile string) (*Session, error) {
	cc, err := clientcore.Open(profile)
	if err != nil {
		return nil, err
	}
	// Reverse-proxy the console /api/v1 to the controller HTTPS listener over this
	// identity's mTLS cert, so the embedded React console authenticates by cert
	// (no separate browser login).
	target, err := url.Parse(cc.ControllerHTTP())
	if err != nil {
		_ = cc.Close()
		return nil, err
	}
	rp := httputil.NewSingleHostReverseProxy(target)
	rp.Transport = cc.HTTPClient().Transport
	director := rp.Director
	rp.Director = func(req *http.Request) {
		director(req)
		req.Host = target.Host // match the controller cert's SNI / Host
	}

	s.mu.Lock()
	if s.cc != nil {
		_ = s.cc.Close()
	}
	s.cc = cc
	s.proxy = rp
	s.mu.Unlock()
	p := cc.Profile()
	return &Session{Controller: p.ControllerGRPC, User: p.User, Workspace: p.Workspace}, nil
}

// serveAPI proxies a console /api/v1 request to the controller over mTLS, or 503s
// before Connect. Wired into the Wails asset-server middleware.
func (s *DesktopService) serveAPI(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	proxy := s.proxy
	s.mu.Unlock()
	if proxy == nil {
		http.Error(w, `{"error":"not connected"}`, http.StatusServiceUnavailable)
		return
	}
	proxy.ServeHTTP(w, r)
}

// Node is a JSON-clean view of a fleet machine for the UI.
type Node struct {
	ID       string            `json:"id"`
	Name     string            `json:"name"`
	Online   bool              `json:"online"`
	OS       string            `json:"os"`
	Arch     string            `json:"arch"`
	Version  string            `json:"version"`
	Approved bool              `json:"approved"`
	Labels   map[string]string `json:"labels"`
}

func (s *DesktopService) client() (*clientcore.Client, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.cc == nil {
		return nil, errors.New("not connected — run Connect first")
	}
	return s.cc, nil
}

// Nodes lists the fleet visible to the connected identity.
func (s *DesktopService) Nodes() ([]Node, error) {
	cc, err := s.client()
	if err != nil {
		return nil, err
	}
	resp, err := cc.ListNodes(s.ctx, 0, 0)
	if err != nil {
		return nil, client.Humanize(err)
	}
	out := make([]Node, 0, len(resp.GetNodes()))
	for _, n := range resp.GetNodes() {
		out = append(out, Node{
			ID: n.GetNodeId(), Name: n.GetName(), Online: n.GetOnline(),
			OS: n.GetOs(), Arch: n.GetArch(), Version: n.GetVersion(),
			Approved: n.GetApproved(), Labels: n.GetLabels(),
		})
	}
	return out, nil
}

// wailsSink forwards host terminal output to the UI as base64 over a per-shell
// Wails event (binary-safe across the JS bridge).
type wailsSink struct {
	ctx context.Context
	id  string
}

func (w *wailsSink) Output(data []byte) error {
	runtime.EventsEmit(w.ctx, "shell:out:"+w.id, base64.StdEncoding.EncodeToString(data))
	return nil
}

func (w *wailsSink) Exit(code int32) error {
	runtime.EventsEmit(w.ctx, "shell:exit:"+w.id, code)
	return nil
}

// OpenShell opens an interactive shell on node over the direct E2E tunnel and
// returns a shell id. Host output arrives on the "shell:out:<id>" event, exit on
// "shell:exit:<id>", teardown on "shell:closed:<id>". The UI feeds keystrokes
// back via ShellInput and size changes via ShellResize.
func (s *DesktopService) OpenShell(node string, cols, rows int) (string, error) {
	cc, err := s.client()
	if err != nil {
		return "", err
	}
	sess, err := cc.OpenSession(s.ctx, client.SessionParams{
		Node:    node,
		Action:  types.ActionShell,
		WantPTY: true,
	})
	if err != nil {
		return "", client.Humanize(err)
	}
	ch, err := sess.OpenAttachChannel(&attachproto.AttachOpenParams{
		Cols: uint32(cols), Rows: uint32(rows), Term: "xterm-256color",
	})
	if err != nil {
		_ = sess.Close()
		return "", err
	}
	id := sess.ID
	s.mu.Lock()
	s.shells[id] = &shellSession{sess: sess, in: attachbridge.NewInputWriter(ch)}
	s.mu.Unlock()

	// Pump host output to the UI until the channel closes, then drop the session.
	go func() {
		_ = attachbridge.PumpHostToClient(ch, &wailsSink{ctx: s.ctx, id: id})
		s.CloseShell(id)
	}()
	return id, nil
}

// ShellInput sends a base64-encoded keystroke batch to a shell.
func (s *DesktopService) ShellInput(id, dataB64 string) error {
	sh := s.shell(id)
	if sh == nil {
		return errNoShell
	}
	data, err := base64.StdEncoding.DecodeString(dataB64)
	if err != nil {
		return err
	}
	return sh.in.Input(data)
}

// ShellResize informs a shell of a new terminal size.
func (s *DesktopService) ShellResize(id string, cols, rows int) error {
	sh := s.shell(id)
	if sh == nil {
		return errNoShell
	}
	return sh.in.Resize(uint32(cols), uint32(rows))
}

// CloseShell tears a shell down (idempotent).
func (s *DesktopService) CloseShell(id string) {
	s.mu.Lock()
	sh := s.shells[id]
	delete(s.shells, id)
	s.mu.Unlock()
	if sh != nil {
		_ = sh.sess.Close()
		runtime.EventsEmit(s.ctx, "shell:closed:"+id)
	}
}

func (s *DesktopService) shell(id string) *shellSession {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.shells[id]
}

var errNoShell = errors.New("no such shell")
