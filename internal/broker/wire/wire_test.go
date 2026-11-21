package wire_test

import (
	"encoding/json"
	"reflect"
	"testing"

	"keygate/internal/broker/wire"
)

func TestRequestJSON(t *testing.T) {
	for _, tt := range []struct {
		name  string
		value wire.Request
		json  string
	}{
		{"minimal", wire.Request{Cmd: "status"}, `{"cmd":"status"}`},
		{"args", wire.Request{Cmd: "grant", Args: json.RawMessage(`{"secret":"app/key","argv":["tool"]}`)}, `{"cmd":"grant","args":{"secret":"app/key","argv":["tool"]}}`},
	} {
		t.Run(tt.name, func(t *testing.T) {
			b, err := json.Marshal(tt.value)
			if err != nil || string(b) != tt.json {
				t.Fatalf("encoded=%s err=%v; want %s", b, err, tt.json)
			}
			var got wire.Request
			if err := json.Unmarshal(b, &got); err != nil || !reflect.DeepEqual(got, tt.value) {
				t.Fatalf("decoded=%#v err=%v; want %#v", got, err, tt.value)
			}
		})
	}
}

func TestFrameJSON(t *testing.T) {
	for _, tt := range []struct {
		name  string
		value wire.Frame
		json  string
	}{
		{"minimal", wire.Frame{T: "ok"}, `{"t":"ok"}`},
		{"empty-omitted", wire.Frame{T: "out", Chunk: []byte{}}, `{"t":"out"}`},
		{"binary-chunk", wire.Frame{T: "out", Stream: "stderr", Chunk: []byte{0, 255, 128, 10, 13, 34}}, `{"t":"out","s":"stderr","d":"AP+ACg0i"}`},
		{"data", wire.Frame{T: "ok", Data: json.RawMessage(`{"count":2}`)}, `{"t":"ok","data":{"count":2}}`},
		{"exit", wire.Frame{T: "exit", Exit: 17}, `{"t":"exit","exit":17}`},
		{"error", wire.Frame{T: "err", Code: "denied", Msg: "not approved"}, `{"t":"err","code":"denied","msg":"not approved"}`},
		{"note", wire.Frame{T: "note", Msg: "waiting"}, `{"t":"note","msg":"waiting"}`},
	} {
		t.Run(tt.name, func(t *testing.T) {
			b, err := json.Marshal(tt.value)
			if err != nil || string(b) != tt.json {
				t.Fatalf("encoded=%s err=%v; want %s", b, err, tt.json)
			}
			want := tt.value
			if len(want.Chunk) == 0 {
				want.Chunk = nil
			}
			var got wire.Frame
			if err := json.Unmarshal(b, &got); err != nil || !reflect.DeepEqual(got, want) {
				t.Fatalf("decoded=%#v err=%v; want %#v", got, err, want)
			}
		})
	}
}

func TestInvalidJSONFields(t *testing.T) {
	for _, input := range []string{`{"t":"out","d":"not base64!"}`, `{"t":"exit","exit":"wrong"}`, `{"t":`} {
		var f wire.Frame
		if err := json.Unmarshal([]byte(input), &f); err == nil {
			t.Errorf("Frame accepted %s", input)
		}
	}
	var req wire.Request
	if err := json.Unmarshal([]byte(`{"cmd":42}`), &req); err == nil {
		t.Error("Request accepted non-string cmd")
	}
}
