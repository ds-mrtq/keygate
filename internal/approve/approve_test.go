package approve

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"strings"
	"testing"
	"time"
	"unicode/utf16"
)

func TestHelloScript(t *testing.T) {
	prompt := `KeyGate: dùng "secret" 'x' $y` + "`z`\nline2"
	s := BuildHelloScript(prompt)
	if !strings.Contains(s, "RequestVerificationAsync($msg)") || !strings.Contains(s, "AsTask") ||
		!strings.Contains(s, "IAsyncOperation`1") || !strings.Contains(s, "UserConsentVerifier") {
		t.Fatalf("script missing parts:\n%s", s)
	}
	if strings.Contains(s, "%s") || strings.Contains(s, "%!") {
		t.Fatal("bad formatting")
	}
	// prompt only appears base64-encoded
	if strings.Contains(s, "secret") && strings.Contains(s, `"secret"`) {
		t.Fatal("prompt leaked raw into script")
	}
	if !strings.Contains(s, base64.StdEncoding.EncodeToString([]byte(prompt))) {
		t.Fatal("prompt b64 missing")
	}
	args := HelloArgs(prompt)
	if len(args) != 4 || args[0] != "-NoProfile" || args[1] != "-NonInteractive" || args[2] != "-EncodedCommand" {
		t.Fatalf("args %v", args)
	}
	raw, err := base64.StdEncoding.DecodeString(args[3])
	if err != nil || len(raw)%2 != 0 {
		t.Fatal("bad encoded command")
	}
	u := make([]uint16, len(raw)/2)
	for i := range u {
		u[i] = uint16(raw[2*i]) | uint16(raw[2*i+1])<<8
	}
	if string(utf16.Decode(u)) != s {
		t.Fatal("UTF-16LE round trip mismatch")
	}
}

func TestDeviceApproval(t *testing.T) {
	pubA, privA, _ := ed25519.GenerateKey(rand.Reader) // approving device
	pubB, _, _ := ed25519.GenerateKey(rand.Reader)     // broker machine
	pubs := map[string]ed25519.PublicKey{"dev_aaaa": pubA, "dev_bbbb": pubB}
	now := time.Unix(1_800_000_000, 0)

	var out syncBuf
	d := &Device{Vault: "vlt_1", Self: "dev_bbbb", Pubs: func() map[string]ed25519.PublicKey { return pubs },
		Out: &out, Now: func() time.Time { return now }}

	// Round trip: parse the challenge printed by the broker, sign as device A, paste back.
	lines := make(chan string, 1)
	d.ReadLine = func(ctx context.Context, _ string) (string, error) {
		select {
		case l := <-lines:
			return l, nil
		case <-ctx.Done():
			return "", ctx.Err()
		}
	}
	errc := make(chan error, 1)
	go func() { errc <- d.ApproveSecret(context.Background(), "ebs/test/db", "sql /@x") }()
	var tok string
	for i := 0; i < 200 && tok == ""; i++ {
		time.Sleep(10 * time.Millisecond)
		for _, f := range strings.Fields(out.String()) {
			if c, err := DecodeChallenge(f); err == nil && c.Secret == "ebs/test/db" {
				tok = f
			}
		}
	}
	if tok == "" {
		t.Fatal("no challenge printed")
	}
	ch, _ := DecodeChallenge(tok)
	if ch.Command != "sql /@x" || ch.Vault != "vlt_1" {
		t.Fatalf("%+v", ch)
	}
	lines <- Sign(ch, "dev_aaaa", privA)
	if err := <-errc; err != nil {
		t.Fatal(err)
	}

	// Verify negatives.
	good := Sign(ch, "dev_aaaa", privA)
	if _, err := Verify(ch, good, "dev_bbbb", pubs, now); err != nil {
		t.Fatal(err)
	}
	if _, err := Verify(ch, good, "dev_aaaa", pubs, now); !errors.Is(err, ErrBadApproval) {
		t.Fatalf("self-sign must fail: %v", err)
	}
	if _, err := Verify(ch, good, "dev_bbbb", pubs, now.Add(time.Hour)); !errors.Is(err, ErrExpired) {
		t.Fatalf("expired: %v", err)
	}
	other := ch
	other.Command = "curl evil"
	if _, err := Verify(other, good, "dev_bbbb", pubs, now); !errors.Is(err, ErrBadApproval) {
		t.Fatalf("different command must fail: %v", err)
	}
	other = ch
	other.Nonce = "AAAAAAAAAAAAAAAAAAAAAA"
	if _, err := Verify(other, good, "dev_bbbb", pubs, now); !errors.Is(err, ErrBadApproval) {
		t.Fatalf("different nonce must fail: %v", err)
	}
	_, privX, _ := ed25519.GenerateKey(rand.Reader)
	if _, err := Verify(ch, Sign(ch, "dev_zzzz", privX), "dev_bbbb", pubs, now); !errors.Is(err, ErrBadApproval) {
		t.Fatalf("unknown device: %v", err)
	}
	if _, err := Verify(ch, Sign(ch, "dev_aaaa", privX), "dev_bbbb", pubs, now); !errors.Is(err, ErrBadApproval) {
		t.Fatalf("forged: %v", err)
	}
	if _, err := Verify(ch, "garbage", "dev_bbbb", pubs, now); !errors.Is(err, ErrBadApproval) {
		t.Fatalf("garbage: %v", err)
	}
}

func TestDeviceCancel(t *testing.T) {
	d := &Device{Vault: "v", Self: "s", Pubs: func() map[string]ed25519.PublicKey { return nil },
		ReadLine: func(ctx context.Context, _ string) (string, error) { <-ctx.Done(); return "", ctx.Err() }, Out: &syncBuf{}}
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	if err := d.Approve(ctx, "x"); err == nil {
		t.Fatal("expected ctx error")
	}
}

func TestUnsupported(t *testing.T) {
	if err := (unsupported{}).Approve(context.Background(), "x"); !errors.Is(err, ErrUnsupported) {
		t.Fatal(err)
	}
	if !strings.Contains(SwiftSource, "deviceOwnerAuthentication") {
		t.Fatal("swift source")
	}
}

func TestSanitize(t *testing.T) {
	in := "ok\x1b[2K\x1b[1Arm -rf\x07\x00\u202e evil\u0085\x9b" + strings.Repeat("a", 400)
	got := Sanitize(in, 300)
	if strings.ContainsAny(got, "\x1b\x07\x00\u202e\u0085\x9b") {
		t.Fatalf("control chars survived: %q", got)
	}
	if len([]rune(got)) > 301 {
		t.Fatalf("not capped: %d", len([]rune(got)))
	}
	if !strings.HasPrefix(got, "okrm -rf evil") {
		t.Fatalf("got %q", got)
	}
	f := FormatArgv([]string{"sql", "a b", "x\x1b[31m\ny"})
	if f != `["sql" "a b" "x[31m"+"y"]` && !strings.HasPrefix(f, `["sql" "a b" "`) {
		t.Fatalf("argv: %s", f)
	}
}
