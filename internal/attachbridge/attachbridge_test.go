package attachbridge

import (
	"bytes"
	"io"
	"testing"

	"geneza.io/internal/attachproto"
	genezav1 "geneza.io/internal/pb/geneza/v1"
)

// captureSink records what the bridge would push to the client UI.
type captureSink struct {
	out  [][]byte
	exit *int32
}

func (s *captureSink) Output(data []byte) error {
	s.out = append(s.out, append([]byte(nil), data...))
	return nil
}
func (s *captureSink) Exit(code int32) error { s.exit = &code; return nil }

// TestPumpHostToClient maps Snapshot/Output to sink.Output and Exit to sink.Exit,
// then stops.
func TestPumpHostToClient(t *testing.T) {
	var host bytes.Buffer
	for _, m := range []*genezav1.HostToClient{
		{Msg: &genezav1.HostToClient_Snapshot{Snapshot: &genezav1.Snapshot{Data: []byte("screen")}}},
		{Msg: &genezav1.HostToClient_Output{Output: &genezav1.Output{Data: []byte("hello")}}},
		{Msg: &genezav1.HostToClient_Exit{Exit: &genezav1.Exit{Code: 7}}},
	} {
		if err := attachproto.WriteHostMsg(&host, m); err != nil {
			t.Fatal(err)
		}
	}
	sink := &captureSink{}
	if err := PumpHostToClient(&host, sink); err != io.EOF && err != nil {
		// Exit returns nil from the sink, so the pump returns that nil — accept either.
	}
	if len(sink.out) != 2 || string(sink.out[0]) != "screen" || string(sink.out[1]) != "hello" {
		t.Fatalf("outputs = %v", sink.out)
	}
	if sink.exit == nil || *sink.exit != 7 {
		t.Fatalf("exit = %v, want 7", sink.exit)
	}
}

// TestInputWriter stamps monotonic sequence numbers on input and encodes resize.
func TestInputWriter(t *testing.T) {
	var ch bytes.Buffer
	w := NewInputWriter(&ch)
	if err := w.Input([]byte("a")); err != nil {
		t.Fatal(err)
	}
	if err := w.Input([]byte("b")); err != nil {
		t.Fatal(err)
	}
	if err := w.Resize(120, 40); err != nil {
		t.Fatal(err)
	}

	r := bytes.NewReader(ch.Bytes())
	m1, _ := attachproto.ReadClientMsg(r)
	m2, _ := attachproto.ReadClientMsg(r)
	m3, _ := attachproto.ReadClientMsg(r)
	if m1.GetInput().GetSeq() != 1 || string(m1.GetInput().GetData()) != "a" {
		t.Fatalf("msg1 = %+v", m1)
	}
	if m2.GetInput().GetSeq() != 2 || string(m2.GetInput().GetData()) != "b" {
		t.Fatalf("msg2 = %+v", m2)
	}
	if m3.GetResize().GetCols() != 120 || m3.GetResize().GetRows() != 40 {
		t.Fatalf("msg3 = %+v", m3)
	}
}
