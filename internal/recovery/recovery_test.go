package recovery

import (
	"bytes"
	"crypto/ed25519"
	"strings"
	"testing"

	"keygate/internal/kcrypto"
)

var low = kcrypto.Argon2Params{T: 1, M: 64, P: 1}

func TestNewSetupIsRecoverable(t *testing.T) {
	const vault = "vlt_abcdefghijklmnop"
	const password = "fake setup password"
	setup, err := NewSetup(vault, password, low)
	if err != nil {
		t.Fatal(err)
	}
	if len(setup.Salt) != 16 || setup.Params != low {
		t.Fatal("setup did not preserve the salt size and requested Argon2 parameters")
	}
	paper, err := ParsePaperKey(setup.PaperKey)
	if err != nil {
		t.Fatalf("printed paper key could not be parsed: %v", err)
	}
	restored, err := Derive(vault, password, setup.Salt, setup.Params, paper)
	if err != nil {
		t.Fatal(err)
	}
	msg := []byte("fake membership event")
	if !ed25519.Verify(setup.Keys.OwnerPub, msg, ed25519.Sign(restored.OwnerPriv, msg)) {
		t.Fatal("restored signing key does not match the original owner")
	}
	vaultKey := bytes.Repeat([]byte{0x41}, 32)
	wrap, err := kcrypto.WrapKey(vault, 1, "recovery", setup.Keys.RecoveryPub, vaultKey)
	if err != nil {
		t.Fatal(err)
	}
	if got, err := kcrypto.UnwrapKey(vault, 1, wrap, restored.RecoveryPriv); err != nil || !bytes.Equal(got, vaultKey) {
		t.Fatalf("restored recovery key could not unwrap the vault key: %v", err)
	}

	other, err := NewSetup(vault, password, low)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(setup.Salt, other.Salt) || setup.PaperKey == other.PaperKey {
		t.Fatal("separate setups reused the salt or paper key")
	}
}

func TestNewSetupRejectsInvalidParams(t *testing.T) {
	params := low
	params.M = 1
	got, err := NewSetup("vlt_abcdefghijklmnop", "fake setup password", params)
	if err == nil || got != nil {
		t.Fatal("invalid Argon2 parameters must return an error and no setup")
	}
}

func TestPaperKeyRoundTrip(t *testing.T) {
	raw := kcrypto.RandBytes(32)
	s := EncodePaperKey(raw)
	groups := strings.Split(s, "-")
	if len(groups) != 14 { // 13 groups of 4 + checksum group
		t.Fatalf("groups=%d in %q", len(groups), s)
	}
	for _, g := range groups {
		if len(g) != 4 {
			t.Fatalf("group %q", g)
		}
	}
	got, err := ParsePaperKey(strings.ToLower(strings.ReplaceAll(s, "-", " ")))
	if err != nil || !bytes.Equal(got, raw) {
		t.Fatalf("parse: %v", err)
	}
	// single character typo is caught by the checksum
	bad := []byte(s)
	bad[0] = map[byte]byte{'A': 'B'}[bad[0]]
	if bad[0] == 0 {
		bad[0] = 'A'
	}
	if string(bad) != s {
		if _, err := ParsePaperKey(string(bad)); err == nil {
			t.Fatal("typo accepted")
		}
	}
	if _, err := ParsePaperKey("AAAA-BBBB"); err == nil {
		t.Fatal("short key accepted")
	}
}

func TestDerive(t *testing.T) {
	salt := kcrypto.RandBytes(16)
	paper := kcrypto.RandBytes(32)
	a, err := Derive("vlt_abcdefghijklmnop", "pwd-pwd-pwd-pwd", salt, low, paper)
	if err != nil {
		t.Fatal(err)
	}
	b, _ := Derive("vlt_abcdefghijklmnop", "pwd-pwd-pwd-pwd", salt, low, paper)
	if !bytes.Equal(a.OwnerPriv, b.OwnerPriv) || a.RecoveryPriv != b.RecoveryPriv || a.RecoveryPub != kcrypto.X25519Public(a.RecoveryPriv) {
		t.Fatal("derivation not deterministic")
	}
	c, _ := Derive("vlt_abcdefghijklmnop", "other-pwd-pwd", salt, low, paper)
	d, _ := Derive("vlt_abcdefghijklmnop", "pwd-pwd-pwd-pwd", salt, low, kcrypto.RandBytes(32))
	e, _ := Derive("vlt_bbbbbbbbbbbbbbbb", "pwd-pwd-pwd-pwd", salt, low, paper)
	for i, o := range []*Keys{c, d, e} {
		if bytes.Equal(a.OwnerPub, o.OwnerPub) || a.RecoveryPub == o.RecoveryPub {
			t.Fatalf("variant %d derives the same keys", i)
		}
	}
}
