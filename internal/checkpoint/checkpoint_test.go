package checkpoint

import (
	"crypto/ed25519"
	"errors"
	"strings"
	"testing"

	"keygate/internal/kcrypto"
)

func signedCheckpoint() (*Checkpoint, ed25519.PublicKey) {
	pub, priv := kcrypto.GenerateSignKey()
	c := &Checkpoint{V: 1, Vault: "vlt_aaaaaaaaaaaaaaaa", Dev: "dev_aaaaaaaaaa", Time: "2026-11-10T00:00:00Z", MembersN: 3,
		Seen: map[string]uint64{"dev_aaaaaaaaaa": 4, "dev_bbbbbbbbbb": 9}}
	c.Sign(priv)
	return c, pub
}

func TestSignVerifyParse(t *testing.T) {
	c, pub := signedCheckpoint()
	b, err := c.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	p, err := Parse(b)
	if err != nil {
		t.Fatal(err)
	}
	if err := p.Verify(pub); err != nil {
		t.Fatal(err)
	}
	if total := p.Total(); total != 16 {
		t.Fatalf("total progress = %d, want 16 (3 membership events plus 4 and 9 records)", total)
	}
}

func TestVerifyBindsCheckpointProgress(t *testing.T) {
	for _, tc := range []struct {
		name   string
		change func(*Checkpoint, ed25519.PublicKey) ed25519.PublicKey
	}{
		{"membership count", func(c *Checkpoint, pub ed25519.PublicKey) ed25519.PublicKey { c.MembersN++; return pub }},
		{"record count", func(c *Checkpoint, pub ed25519.PublicKey) ed25519.PublicKey { c.Seen[c.Dev]++; return pub }},
		{"record origin with same total", func(c *Checkpoint, pub ed25519.PublicKey) ed25519.PublicKey {
			c.Seen["dev_cccccccccc"] = c.Seen["dev_bbbbbbbbbb"]
			delete(c.Seen, "dev_bbbbbbbbbb")
			return pub
		}},
		{"wrong signer", func(_ *Checkpoint, _ ed25519.PublicKey) ed25519.PublicKey {
			wrong, _ := kcrypto.GenerateSignKey()
			return wrong
		}},
		{"missing public key", func(_ *Checkpoint, _ ed25519.PublicKey) ed25519.PublicKey { return nil }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c, pub := signedCheckpoint()
			if err := c.Verify(tc.change(c, pub)); !errors.Is(err, kcrypto.ErrBadSignature) {
				t.Fatalf("want ErrBadSignature, got %v", err)
			}
		})
	}
}

func TestParseRejectsMalformedCheckpoint(t *testing.T) {
	c, _ := signedCheckpoint()
	b, err := c.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	line := string(b)
	for _, tc := range []struct {
		name string
		line string
	}{
		{"empty", ""},
		{"oversized", strings.Replace(line, c.Time, strings.Repeat("0", 1<<20), 1)},
		{"unknown field", `{"extra":true,` + line[1:]},
		{"trailing JSON", line + `{}`},
		{"incomplete header", `{"v":1}`},
		{"null progress map", strings.Replace(line, `{"dev_aaaaaaaaaa":4,"dev_bbbbbbbbbb":9}`, `null`, 1)},
		{"invalid progress device", strings.Replace(line, `"dev_bbbbbbbbbb":9`, `"bogus":9`, 1)},
		{"short signature", strings.Replace(line, c.Sig, "AA==", 1)},
		{"noncanonical whitespace", " " + line},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got, err := Parse([]byte(tc.line)); got != nil || !errors.Is(err, ErrMalformed) {
				t.Fatalf("want ErrMalformed and no checkpoint, got %v, %v", got, err)
			}
		})
	}
}
