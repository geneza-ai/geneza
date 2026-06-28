// Package attachbridge holds the transport-agnostic core of bridging a Geneza
// session attach channel to a client terminal UI: forwarding host terminal
// output to the UI, and sequence-numbering client keystrokes/resizes back to the
// host. The controller's browser web-shell proxy drives it over a WebSocket; the
// desktop app drives it over in-process events — both reuse this mapping instead
// of re-encoding the attach protocol.
package attachbridge

import (
	"io"
	"sync"

	"geneza.io/internal/attachproto"
	genezav1 "geneza.io/internal/pb/geneza/v1"
)

// ClientSink receives terminal data destined for the client UI. Implementations
// map it onto a transport: a WebSocket binary/text frame for the controller proxy,
// a UI event for the desktop app.
type ClientSink interface {
	// Output delivers a chunk of terminal bytes — a Snapshot replay on attach or
	// live Output — to the client.
	Output(data []byte) error
	// Exit signals the remote shell ended with the given exit code.
	Exit(code int32) error
}

// PumpHostToClient reads host messages from ch and forwards Snapshot/Output to
// sink.Output and Exit to sink.Exit, returning when the channel closes or a sink
// write fails. It is the host->client direction shared by every attach
// transport; run it in its own goroutine.
func PumpHostToClient(ch io.Reader, sink ClientSink) error {
	for {
		m, err := attachproto.ReadHostMsg(ch)
		if err != nil {
			return err
		}
		switch v := m.GetMsg().(type) {
		case *genezav1.HostToClient_Snapshot:
			if err := sink.Output(v.Snapshot.GetData()); err != nil {
				return err
			}
		case *genezav1.HostToClient_Output:
			if err := sink.Output(v.Output.GetData()); err != nil {
				return err
			}
		case *genezav1.HostToClient_Exit:
			return sink.Exit(v.Exit.GetCode())
		}
	}
}

// InputWriter serializes client->host writes on an attach channel, stamping each
// keystroke batch with a monotonic sequence number (the host de-dups/orders on
// it). Input and Resize are safe to call concurrently.
type InputWriter struct {
	mu  sync.Mutex
	ch  io.Writer
	seq uint64
}

// NewInputWriter returns an InputWriter writing to the attach channel ch.
func NewInputWriter(ch io.Writer) *InputWriter { return &InputWriter{ch: ch} }

// Input sends a keystroke/paste batch to the host.
func (w *InputWriter) Input(data []byte) error {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.seq++
	return attachproto.WriteClientMsg(w.ch, &genezav1.ClientToHost{
		Msg: &genezav1.ClientToHost_Input{Input: &genezav1.Input{Seq: w.seq, Data: data}},
	})
}

// Resize informs the host of a new terminal size.
func (w *InputWriter) Resize(cols, rows uint32) error {
	w.mu.Lock()
	defer w.mu.Unlock()
	return attachproto.WriteClientMsg(w.ch, &genezav1.ClientToHost{
		Msg: &genezav1.ClientToHost_Resize{Resize: &genezav1.Resize{Cols: cols, Rows: rows}},
	})
}
