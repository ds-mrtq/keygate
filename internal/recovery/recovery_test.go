package recovery

import (
	"bytes"
	"strings"
	"testing"

	"keygate/internal/kcrypto"
)

var low = kcrypto.Argon2Params{T: 1, M: 64, P: 1}

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
