package wire_test

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"reflect"
	"strings"
	"testing"
	"unicode/utf8"

	"keygate/internal/broker/wire"
)

// argTypes are every Request.Args payload the broker decodes.
func argTypes() []any {
	return []any{
		&wire.GrantArgs{}, &wire.GrantsRevokeArgs{}, &wire.RevealArgs{}, &wire.SetArgs{}, &wire.ImportArgs{},
		&wire.ResolveConflictArgs{}, &wire.SyncArgs{}, &wire.DeleteArgs{}, &wire.SameArgs{}, &wire.CopyArgs{},
	}
}

// FuzzRequestDecode feeds arbitrary client lines to the broker's request decoding: decoding must
// never panic, and an accepted request must re-encode to a stable form that decodes the same way.
func FuzzRequestDecode(f *testing.F) {
	for _, s := range []string{
		`{"cmd":"status"}`,
		`{"cmd":"grant","args":{"secret":"app/key","argv":["tool","-x"],"agent":"a","dir":"/w"}}`,
		`{"cmd":"set","args":{"request":{"name":"a/b"},"from_file":"/tmp/x"}}`,
		`{"cmd":"copy","args":{"pairs":[{"src":"a","dst":"b"}],"env_name":"X"}}`,
		`{"cmd":"delete","args":{"names":["a","b"]}}`,
		`{"cmd":"run","args":null}`,
		`{"cmd":"\u0000","args":"x"}`,
		`{"cmd":"status","cmd":"lock"}`,
		`[]`, `null`, `{"cmd":`,
	} {
		f.Add([]byte(s))
	}
	f.Fuzz(func(t *testing.T, line []byte) {
		var req wire.Request
		if json.Unmarshal(line, &req) != nil {
			return
		}
		for _, a := range argTypes() {
			if len(req.Args) > 0 {
				_ = json.Unmarshal(req.Args, a)
			}
		}
		b1, err := json.Marshal(req)
		if err != nil {
			t.Fatalf("re-encode accepted request %q: %v", line, err)
		}
		var again wire.Request
		if err := json.Unmarshal(b1, &again); err != nil {
			t.Fatalf("decode re-encoded %s: %v", b1, err)
		}
		b2, err := json.Marshal(again)
		if err != nil || !bytes.Equal(b1, b2) {
			t.Fatalf("encoding not stable: %s vs %s (%v)", b1, b2, err)
		}
		if again.Cmd != req.Cmd {
			t.Fatalf("cmd changed: %q -> %q", req.Cmd, again.Cmd)
		}
	})
}

// jsonString is what encoding/json makes of s: each invalid UTF-8 byte becomes U+FFFD.
func jsonString(s string) string {
	var b strings.Builder
	for len(s) > 0 {
		r, n := utf8.DecodeRuneInString(s)
		b.WriteRune(r)
		s = s[n:]
	}
	return b.String()
}

// FuzzFrameStream encodes frames the way the broker writes them (json.Encoder, one per line) and
// decodes them the way the client reads them (json.Decoder). Output chunks are arbitrary bytes and
// must arrive unchanged; text fields may only lose invalid UTF-8.
func FuzzFrameStream(f *testing.F) {
	f.Add([]byte("hello\n"), "stdout", "waiting <for> & \"phone\"", "denied", 0, []byte(`{"count":2}`))
	f.Add([]byte{0, 255, 128, 10, 13, 34}, "stderr", "\xff\xfe", "", 17, []byte(`null`))
	f.Add([]byte{}, "", "\u2028\u2029", "x", -1, []byte(`not json`))
	f.Fuzz(func(t *testing.T, chunk []byte, stream, msg, code string, exit int, data []byte) {
		if !json.Valid(data) {
			data = nil
		}
		in := []wire.Frame{
			{T: wire.FrameNote, Msg: msg},
			{T: wire.FrameOut, Stream: stream, Chunk: chunk},
			{T: wire.FrameOut, Stream: stream, Chunk: append(append([]byte(nil), chunk...), chunk...)},
			{T: wire.FrameOK, Data: data},
			{T: wire.FrameExit, Exit: exit},
			{T: wire.FrameErr, Code: code, Msg: msg},
		}
		var buf bytes.Buffer
		enc := json.NewEncoder(&buf)
		for _, fr := range in {
			if err := enc.Encode(fr); err != nil {
				t.Fatalf("encode %+v: %v", fr, err)
			}
		}
		if n := bytes.Count(buf.Bytes(), []byte("\n")); n != len(in) {
			t.Fatalf("%d frames on %d lines: %q", len(in), n, buf.Bytes())
		}
		dec := json.NewDecoder(&buf)
		for i, want := range in {
			var got wire.Frame
			if err := dec.Decode(&got); err != nil {
				t.Fatalf("frame %d: %v", i, err)
			}
			if len(want.Chunk) == 0 {
				want.Chunk = nil
			}
			want.Msg, want.Code, want.Stream = jsonString(want.Msg), jsonString(want.Code), jsonString(want.Stream)
			if want.Data != nil {
				// json.Encoder compacts RawMessage and HTML-escapes it.
				var c, h bytes.Buffer
				if err := json.Compact(&c, want.Data); err != nil {
					t.Fatal(err)
				}
				json.HTMLEscape(&h, c.Bytes())
				want.Data = h.Bytes()
			}
			if !reflect.DeepEqual(got, want) {
				t.Fatalf("frame %d: got %#v want %#v", i, got, want)
			}
		}
		var extra wire.Frame
		if err := dec.Decode(&extra); !errors.Is(err, io.EOF) {
			t.Fatalf("trailing frame %#v err=%v", extra, err)
		}
	})
}

// FuzzFrameDecode feeds arbitrary broker output to the client's frame reader: it must never panic,
// and any frame it accepts must survive a re-encode with its chunk bytes intact.
func FuzzFrameDecode(f *testing.F) {
	for _, s := range []string{
		"{\"t\":\"out\",\"s\":\"stdout\",\"d\":\"aGk=\"}\n{\"t\":\"exit\",\"exit\":3}\n",
		`{"t":"ok","data":{"x":[1,2]}}{"t":"err","code":"denied","msg":"no"}`,
		`{"t":"out","d":"not base64!"}`,
		`{"t":"out","d":null,"exit":1e3}`,
		`{"t":"note","msg":"\ud800"}`,
	} {
		f.Add([]byte(s))
	}
	f.Fuzz(func(t *testing.T, stream []byte) {
		dec := json.NewDecoder(bytes.NewReader(stream))
		for i := 0; i < 64; i++ {
			var fr wire.Frame
			if dec.Decode(&fr) != nil {
				return
			}
			b, err := json.Marshal(fr)
			if err != nil {
				t.Fatalf("re-encode %#v: %v", fr, err)
			}
			var again wire.Frame
			if err := json.Unmarshal(b, &again); err != nil {
				t.Fatalf("decode re-encoded %s: %v", b, err)
			}
			if !bytes.Equal(again.Chunk, fr.Chunk) || again.T != fr.T || again.Exit != fr.Exit {
				t.Fatalf("frame changed: %#v -> %#v", fr, again)
			}
		}
	})
}
