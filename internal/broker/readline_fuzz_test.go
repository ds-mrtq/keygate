package broker

import (
	"bufio"
	"bytes"
	"testing"
)

// FuzzReadLine checks the request framing: readLine returns exactly the first line (without its
// "\n" or "\r\n"), however the bytes are split across bufio buffers, and refuses lines over limit.
func FuzzReadLine(f *testing.F) {
	f.Add([]byte("{\"cmd\":\"status\"}\n"), uint16(1024))
	f.Add([]byte("abc\r\ndef\n"), uint16(3))
	f.Add([]byte("abcdefghijklmnopqrstuvwxyz0123456789\r\n"), uint16(20))
	f.Add([]byte("no newline at all"), uint16(100))
	f.Add([]byte("\r\r\n"), uint16(0))
	f.Add([]byte{}, uint16(0))
	f.Fuzz(func(t *testing.T, data []byte, limit uint16) {
		got, err := readLine(bufio.NewReaderSize(bytes.NewReader(data), 16), int(limit))
		want := data
		i := bytes.IndexByte(data, '\n')
		if i >= 0 {
			want = bytes.TrimSuffix(data[:i], []byte("\r"))
		}
		switch {
		// bufio.Reader.ReadLine returns an unterminated last line only when it fits the
		// buffer, so an unterminated request may be read or refused, but never altered.
		case i < 0 && err != nil:
		case len(data) == 0:
			if err == nil {
				t.Fatalf("empty input returned %q", got)
			}
		case len(want) > int(limit):
			if err == nil {
				t.Fatalf("line of %d bytes accepted over limit %d", len(want), limit)
			}
		case err != nil:
			t.Fatalf("readLine(%q, %d): %v", data, limit, err)
		case !bytes.Equal(got, want):
			t.Fatalf("readLine(%q) = %q, want %q", data, got, want)
		}
	})
}
