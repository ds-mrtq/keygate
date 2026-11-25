package redact

import (
	"bytes"
	"encoding/base64"
	"net/url"
	"strings"
	"testing"
)

// FuzzWriterMatchesBytes: the streaming Writer must produce exactly what Bytes produces for the
// whole buffer, however the input is split into writes.
func FuzzWriterMatchesBytes(f *testing.F) {
	f.Add("hunter22", "s3cr3t-token", []byte("pre hunter22 aHVudGVyMjI= mid s3cr3t-token post"), []byte{1, 3, 7})
	f.Add("a\nbcd", " spaced ", []byte("a\r\nbcd spaced a%0Abcd"), []byte{0, 1})
	f.Add("abcd", "abcdef", []byte("abcdefabcdabc"), []byte{2})
	f.Fuzz(func(t *testing.T, v1, v2 string, input, splits []byte) {
		r := New([]Secret{{Name: "A", Value: v1}, {Name: "B", Value: v2}})
		want := r.Bytes(input)
		var out bytes.Buffer
		w := r.NewWriter(&out)
		rest := input
		for i := 0; len(rest) > 0; i++ {
			n := len(rest)
			if len(splits) > 0 {
				n = max(1, min(n, int(splits[i%len(splits)])))
			}
			if _, err := w.Write(rest[:n]); err != nil {
				t.Fatal(err)
			}
			rest = rest[n:]
		}
		if err := w.Flush(); err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(out.Bytes(), want) {
			t.Fatalf("stream %q != bytes %q", out.Bytes(), want)
		}
	})
}

// base64Runs returns the maximal runs of alphabet characters in s.
func base64Runs(s, alphabet string) []string {
	return strings.FieldsFunc(s, func(r rune) bool { return !strings.ContainsRune(alphabet, r) })
}

const (
	stdAlphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
	urlAlphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
)

// decodesToSecret reports whether some base64 run of out, read from any character offset,
// decodes to bytes containing secret.
func decodesToSecret(out string, secret []byte) bool {
	for _, a := range []struct {
		alphabet string
		enc      *base64.Encoding
	}{{stdAlphabet, base64.RawStdEncoding}, {urlAlphabet, base64.RawURLEncoding}} {
		for _, run := range base64Runs(out, a.alphabet) {
			for off := 0; off < 4 && off < len(run); off++ {
				s := run[off:]
				s = s[:len(s)-len(s)%4]
				if b, err := a.enc.DecodeString(s); err == nil && bytes.Contains(b, secret) {
					return true
				}
			}
		}
	}
	return false
}

// FuzzNoLeak plants one secret in fuzzed text, verbatim and base64-encoded inside a larger blob,
// and checks that the masked output keeps none of it: not verbatim, not in its URL-escaped form,
// and in no base64 run that decodes back to the secret.
func FuzzNoLeak(f *testing.F) {
	f.Add("correct-horse-battery", []byte("token="), []byte(" end"), []byte("xx"), []byte("yyy"))
	f.Add("p@ss word/with+chars?", []byte(""), []byte(""), []byte{}, []byte{0})
	f.Add("ABCDEFGHIJKL", []byte("ABCDEFGHIJK"), []byte("LABCDEFGHIJKL"), []byte{0xff}, []byte{})
	f.Fuzz(func(t *testing.T, secret string, before, after, encBefore, encAfter []byte) {
		// The replacement marker is "[kg:S]"; a value made of those characters can be rebuilt by
		// the marker itself, and short values are not masked inside base64 by design.
		if len(secret) < 12 || strings.ContainsAny(secret, "[]:") || strings.TrimSpace(secret) != secret {
			return
		}
		blob := base64.StdEncoding.EncodeToString(append(append(append([]byte(nil), encBefore...), secret...), encAfter...))
		input := string(before) + secret + string(after) + " " + blob + " " + url.QueryEscape(secret)
		out := New([]Secret{{Name: "S", Value: secret}}).String(input)
		if strings.Contains(out, secret) {
			t.Fatalf("verbatim secret left in %q", out)
		}
		if q := url.QueryEscape(secret); strings.Contains(out, q) {
			t.Fatalf("query-escaped secret %q left in %q", q, out)
		}
		if decodesToSecret(out, []byte(secret)) {
			t.Fatalf("base64 of secret left in %q", out)
		}
	})
}
