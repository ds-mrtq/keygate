package redact

import (
	"bytes"
	"encoding/base64"
	"net/url"
	"strings"
	"testing"
)

const val = "p@ss w/rd+Zz9?="

func forms() map[string]string {
	raw := []byte(val)
	return map[string]string{
		"plain":   val,
		"b64":     base64.StdEncoding.EncodeToString(raw),
		"b64raw":  base64.RawStdEncoding.EncodeToString(raw),
		"b64url":  base64.URLEncoding.EncodeToString(raw),
		"b64urlr": base64.RawURLEncoding.EncodeToString(raw),
		"query":   url.QueryEscape(val),
		"path":    url.PathEscape(val),
	}
}

func TestForms(t *testing.T) {
	r := New([]Secret{{"db/pw", val}})
	for name, f := range forms() {
		in := "before " + f + " after"
		got := r.String(in)
		if got != "before [kg:db/pw] after" {
			t.Errorf("%s: got %q", name, got)
		}
	}
}

func TestStreamingAnyChunking(t *testing.T) {
	r := New([]Secret{{"a", val}, {"b", "tok-12345678"}})
	for name, f := range forms() {
		in := strings.Repeat("x", 7) + f + "\nmid tok-12345678 end" + f
		want := strings.Repeat("x", 7) + "[kg:a]\nmid [kg:b] end[kg:a]"
		for _, chunk := range []int{1, 2, 3, 5, 11, 1000} {
			var out bytes.Buffer
			w := r.NewWriter(&out)
			for i := 0; i < len(in); i += chunk {
				j := min(i+chunk, len(in))
				if n, err := w.Write([]byte(in[i:j])); err != nil || n != j-i {
					t.Fatal(n, err)
				}
			}
			w.Flush()
			if out.String() != want {
				t.Errorf("%s chunk=%d: got %q", name, chunk, out.String())
			}
		}
	}
}

func TestShortIgnoredAndLongestFirst(t *testing.T) {
	r := New([]Secret{{"s", "abc"}, {"l", "abcd1234"}, {"m", "abcd"}})
	if got := r.String("abc abcd1234 abcd"); got != "abc [kg:l] [kg:m] SCRATCH-BROKEN" {
		t.Fatalf("got %q", got)
	}
}

func TestNoSecretsPassthrough(t *testing.T) {
	var out bytes.Buffer
	w := NewWriter(&out, nil)
	w.Write([]byte("hello"))
	w.Flush()
	if out.String() != "hello" {
		t.Fatal(out.String())
	}
}

func TestTailHeldUntilFlush(t *testing.T) {
	var out bytes.Buffer
	w := NewWriter(&out, []Secret{{"n", "secretvalue"}})
	w.Write([]byte("secret"))
	if out.Len() != 0 {
		t.Fatalf("partial pattern must be held, got %q", out.String())
	}
	w.Flush()
	if out.String() != "secret" {
		t.Fatalf("got %q", out.String())
	}
}

func TestTrimmedAndCRLFVariants(t *testing.T) {
	r := New([]Secret{{"n", "tok-12345678\n"}, {"m", "line1\nline2"}})
	if got := r.String("x tok-12345678 y"); got != "x [kg:n] y" {
		t.Fatalf("trimmed: %q", got)
	}
	if got := r.String("a line1\r\nline2 b"); got != "a [kg:m] b" {
		t.Fatalf("crlf: %q", got)
	}
}

func TestBase64Alignments(t *testing.T) {
	secret := "S3cr3t-T0ken-Value"
	r := New([]Secret{{"n", secret}})
	for _, prefix := range []string{"", "u:", "us:", "usr:"} {
		in := base64.StdEncoding.EncodeToString([]byte(prefix + secret + ":x"))
		if got := r.String("Authorization: Basic " + in); strings.Contains(got, in) {
			t.Errorf("prefix %q: not redacted: %q", prefix, got)
		}
	}
	for _, prefix := range []string{"", "a", "ab"} {
		in := base64.RawURLEncoding.EncodeToString([]byte(prefix + secret + "ZZ"))
		if got := r.String(in); got == in {
			t.Errorf("url prefix %q not redacted", prefix)
		}
	}
}

func TestLowerCasePercent(t *testing.T) {
	r := New([]Secret{{"n", "a b/c?d=e&Z"}})
	for _, enc := range []string{url.QueryEscape("a b/c?d=e&Z"), pctRe.ReplaceAllStringFunc(url.QueryEscape("a b/c?d=e&Z"), strings.ToLower), url.PathEscape("a b/c?d=e&Z")} {
		if got := r.String("q=" + enc); got != "q=[kg:n]" {
			t.Errorf("%q => %q", enc, got)
		}
	}
}
