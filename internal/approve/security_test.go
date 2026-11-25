//go:build kgtest

package approve

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

func testKey() (ed25519.PublicKey, ed25519.PrivateKey) {
	priv := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{7}, ed25519.SeedSize))
	return priv.Public().(ed25519.PublicKey), priv
}

func TestApprovalSignatureScope(t *testing.T) {
	pub, priv := testKey()
	now := time.Unix(1800000000, 0)
	c := Challenge{V: 1, Vault: "vault", Nonce: "nonce", Secret: "secret", Command: "command", Expires: now.Add(time.Minute).Unix()}
	sig := Sign(c, "phone", priv)
	pubs := map[string]ed25519.PublicKey{"phone": pub}
	for name, mutate := range map[string]func(*Challenge){
		"version": func(c *Challenge) { c.V++ },
		"vault":   func(c *Challenge) { c.Vault += "x" },
		"nonce":   func(c *Challenge) { c.Nonce += "x" },
		"secret":  func(c *Challenge) { c.Secret += "x" },
		"command": func(c *Challenge) { c.Command += "x" },
		"expiry":  func(c *Challenge) { c.Expires++ },
	} {
		t.Run(name, func(t *testing.T) {
			changed := c
			mutate(&changed)
			if dev, err := Verify(changed, sig, "broker", pubs, now); !errors.Is(err, ErrBadApproval) || dev != "" {
				t.Fatalf("changed challenge accepted: %q, %v", dev, err)
			}
		})
	}
	for _, malformed := range []string{"", "kga2.phone.x", "kga1.phone.%", "kga1.phone." + base64.RawURLEncoding.EncodeToString([]byte("short")), sig + ".extra"} {
		if dev, err := Verify(c, malformed, "broker", pubs, now); !errors.Is(err, ErrBadApproval) || dev != "" {
			t.Fatalf("malformed approval %q: %q, %v", malformed, dev, err)
		}
	}
	if dev, err := Verify(c, " \n"+sig+"\t", "broker", pubs, time.Unix(c.Expires, 0)); err != nil || dev != "phone" {
		t.Fatalf("valid at deadline: %q, %v", dev, err)
	}
	if _, err := Verify(c, sig, "broker", pubs, time.Unix(c.Expires+1, 0)); !errors.Is(err, ErrExpired) {
		t.Fatalf("past deadline: %v", err)
	}
}

func TestChallengeParsingAndFreshness(t *testing.T) {
	now := time.Unix(1800000000, 0)
	a, err := NewChallenge("v", "s", "cmd", 0, now)
	if err != nil {
		t.Fatal(err)
	}
	b, err := NewChallenge("v", "s", "cmd", -1, now)
	if err != nil {
		t.Fatal(err)
	}
	if a.Nonce == b.Nonce || a.Expires != now.Add(DefaultChallengeTTL).Unix() || b.Expires != a.Expires {
		t.Fatalf("bad freshness/default TTL: %+v %+v", a, b)
	}
	nonce, err := base64.RawURLEncoding.DecodeString(a.Nonce)
	if err != nil || len(nonce) != 16 {
		t.Fatalf("nonce: %x %v", nonce, err)
	}
	decoded, err := DecodeChallenge(" \n" + a.Encode() + "\t")
	if err != nil || decoded != a {
		t.Fatalf("roundtrip: %+v %v", decoded, err)
	}
	for _, raw := range []string{"not json", `{}`, `{"v":2,"vault":"v","nonce":"n"}`, `{"v":1,"nonce":"n"}`, `{"v":1,"vault":"v"}`} {
		if _, err := DecodeChallenge(base64.RawURLEncoding.EncodeToString([]byte(raw))); err == nil {
			t.Fatalf("accepted %s", raw)
		}
	}
	pub, priv := testKey()
	if _, err := Verify(b, Sign(a, "phone", priv), "broker", map[string]ed25519.PublicKey{"phone": pub}, now); !errors.Is(err, ErrBadApproval) {
		t.Fatalf("replay across challenges: %v", err)
	}
}

func TestDeviceDecisionPaths(t *testing.T) {
	pub, priv := testKey()
	now := time.Unix(1800000000, 0)
	for _, mode := range []string{"approve", "partial EOF", "deny", "read error", "expired", "revoked"} {
		t.Run(mode, func(t *testing.T) {
			var out bytes.Buffer
			clock := now
			pubs := map[string]ed25519.PublicKey{"phone": pub}
			d := &Device{Vault: "vault", Self: "broker", Out: &out, TTL: time.Second, Now: func() time.Time { return clock }, Pubs: func() map[string]ed25519.PublicKey { return pubs }}
			d.ReadLine = func(context.Context, string) (string, error) {
				if mode == "read error" {
					return " \n", io.EOF
				}
				if mode == "deny" {
					return "no", nil
				}
				fields := strings.Fields(out.String())
				c, err := DecodeChallenge(fields[len(fields)-1])
				if err != nil {
					t.Fatal(err)
				}
				if c.Secret != "secret" || c.Command != "command" || c.Vault != "vault" {
					t.Fatalf("wrong scope: %+v", c)
				}
				if mode == "expired" {
					clock = now.Add(2 * time.Second)
				}
				if mode == "revoked" {
					delete(pubs, "phone")
				}
				if mode == "partial EOF" {
					return Sign(c, "phone", priv), io.EOF
				}
				return Sign(c, "phone", priv), nil
			}
			err := d.ApproveSecret(context.Background(), "secret", "command")
			var want error
			switch mode {
			case "deny", "revoked":
				want = ErrBadApproval
			case "expired":
				want = ErrExpired
			case "read error":
				want = io.EOF
			}
			if !errors.Is(err, want) {
				t.Fatalf("got %v, want %v", err, want)
			}
			if want == nil && d.Signer != "phone" {
				t.Fatalf("signer %q", d.Signer)
			}
			if want != nil && d.Signer != "" {
				t.Fatalf("failed approval set signer %q", d.Signer)
			}
		})
	}
}

func TestPlatformFakeDecisions(t *testing.T) {
	for _, mode := range []string{"allow", "deny", ""} {
		t.Setenv("KG_TEST_APPROVE", mode)
		if mode == "" {
			if runtime.GOOS == "linux" && !errors.Is(Platform().Approve(context.Background(), "prompt"), ErrUnsupported) {
				t.Fatal("expected unsupported platform")
			}
			continue
		}
		err := Platform().Approve(context.Background(), "prompt")
		if mode == "allow" && err != nil || mode == "deny" && !errors.Is(err, ErrNotVerified) {
			t.Fatalf("%s: %v", mode, err)
		}
	}
}

func TestVerifierDecisions(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX fake executable")
	}
	for _, tc := range []struct {
		name, script string
		want         error
	}{
		{"allow", "printf 'noise\\nVerified\\n'", nil},
		{"deny", "printf 'Denied\\n'", ErrNotVerified},
		{"empty", "exit 0", ErrNotVerified},
		{"not final", "printf 'Verified\\nDenied\\n'", ErrNotVerified},
		{"failure with output", "printf 'Failed\\n'; exit 1", ErrNotVerified},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := runVerifier(context.Background(), 0, "/bin/sh", []string{"-c", tc.script}, nil, nil)
			if !errors.Is(err, tc.want) {
				t.Fatalf("got %v, want %v", err, tc.want)
			}
		})
	}
	if err := runVerifier(context.Background(), 0, filepath.Join(t.TempDir(), "missing"), nil, nil, nil); err == nil || errors.Is(err, ErrNotVerified) {
		t.Fatalf("launch error: %v", err)
	} else {
		var launch *exec.Error
		var path *os.PathError
		if !errors.As(err, &launch) && !errors.As(err, &path) {
			t.Fatalf("lost launch error: %v", err)
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := runVerifier(ctx, 0, "/bin/sh", []string{"-c", "exit 0"}, nil, nil); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancel: %v", err)
	}
	if err := runVerifier(context.Background(), time.Nanosecond, "/bin/sh", []string{"-c", "exit 0"}, nil, nil); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("timeout: %v", err)
	}
}

func TestNativeApproverFakeCommands(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX fake executable")
	}
	exe := filepath.Join(t.TempDir(), "verifier")
	if err := os.WriteFile(exe, []byte("#!/bin/sh\n[ \"$KG_PROMPT\" = 'safeprompt' ] || exit 1\nprintf 'Verified\\n'\n"), 0700); err != nil {
		t.Fatal(err)
	}
	if err := (&TouchID{Command: exe}).Approve(context.Background(), "safe\x00\nprompt"); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(exe, []byte("#!/bin/sh\n[ \"$1\" = '-NoProfile' ] && [ \"$3\" = '-EncodedCommand' ] || exit 1\nprintf 'Verified\\n'\n"), 0700); err != nil {
		t.Fatal(err)
	}
	if err := (&Hello{Command: exe}).Approve(context.Background(), "prompt"); err != nil {
		t.Fatal(err)
	}
}

func TestPromptSanitization(t *testing.T) {
	c := Challenge{Secret: "secret\x1b]0;fake\x07\u202e", Command: "cmd\n\x1b[2K"}
	if got := c.Prompt(); strings.ContainsAny(got, "\x1b\x07\u202e\n") || !strings.Contains(got, `"secret"`) || !strings.HasSuffix(got, "cmd") {
		t.Fatalf("unsafe prompt: %q", got)
	}
	if got := FormatArgv(nil); got != "[]" {
		t.Fatalf("empty argv: %q", got)
	}
	if got := FormatArgv([]string{"a b", "x\ny"}); got != `["a b" "xy"]` {
		t.Fatalf("argv: %q", got)
	}
	if got := Sanitize("é界x", 2); got != "é界…" {
		t.Fatalf("rune cap: %q", got)
	}
}
