package qr

import (
	"bytes"
	"errors"
	"strings"
	"testing"
)

// Version choice and the 213-byte limit decide whether a pairing link can be shown at all.
// Decoding was checked against zxing-cpp for every version 1-10 (2026-11-12).
func TestEncodeVersionBoundaries(t *testing.T) {
	for _, tc := range []struct{ n, size int }{
		{14, 21}, {15, 25}, // v1-M holds 14 bytes
		{106, 41}, {107, 45}, // v6 -> v7 (version info block appears)
		{213, 57}, // v10-M limit
	} {
		c, err := Encode(bytes.Repeat([]byte{'a'}, tc.n))
		if err != nil {
			t.Fatalf("%d bytes: %v", tc.n, err)
		}
		if c.Size != tc.size {
			t.Errorf("%d bytes: size %d, want %d", tc.n, c.Size, tc.size)
		}
	}
	if _, err := Encode(make([]byte, 214)); !errors.Is(err, ErrTooLong) {
		t.Fatalf("214 bytes: err %v, want ErrTooLong", err)
	}
}

func TestText(t *testing.T) {
	c, err := Encode([]byte("hello"))
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimRight(c.Text(), "\n"), "\n")
	if want := (c.Size + 4 + 1) / 2; len(lines) != want {
		t.Fatalf("%d lines, want %d", len(lines), want)
	}
	for _, l := range lines {
		if n := len([]rune(l)); n != c.Size+4 {
			t.Fatalf("line width %d, want %d", n, c.Size+4)
		}
	}
}
