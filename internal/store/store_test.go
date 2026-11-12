package store

import (
	"path/filepath"
	"testing"
	"time"

	"keygate/internal/devkey"
	"keygate/internal/kcrypto"
	"keygate/internal/record"
	"keygate/internal/recovery"
)

var low = kcrypto.Argon2Params{T: 1, M: 64, P: 1}

func TestWordList(t *testing.T) {
	seen := map[string]bool{}
	for _, w := range wordList {
		if w == "" || seen[w] {
			t.Fatalf("empty or duplicate word %q", w)
		}
		seen[w] = true
	}
	if len(seen) != 256 {
		t.Fatal("need 256 words")
	}
}

func TestInitOpenLocal(t *testing.T) {
	if !devkey.PlainAllowed {
		t.Skip("needs -tags kgtest (plain device key backend)")
	}
	t.Setenv(devkey.EnvBackend, "plain")
	home := filepath.Join(t.TempDir(), "kg")
	vault := kcrypto.NewVaultID()
	setup, err := recovery.NewSetup(vault, "a long master password", low)
	if err != nil {
		t.Fatal(err)
	}
	id := NewIdentity("laptop")
	ks, _ := devkey.Open(home, devkey.Options{})
	if err := SaveIdentity(home, id, ks); err != nil {
		t.Fatal(err)
	}
	st, err := Init(home, vault, id, setup.Keys, setup.Salt, setup.Params, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Init(home, vault, id, setup.Keys, setup.Salt, setup.Params, time.Now()); err != ErrExists {
		t.Fatalf("re-init: %v", err)
	}
	r, err := st.Put("", record.Plain{Name: "a", Value: "1"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := st.Put(r.Item, record.Plain{Name: "a", Value: "2"}); err != nil {
		t.Fatal(err)
	}
	// reload identity from the key store and reopen
	id2, err := LoadIdentity(home, ks)
	if err != nil {
		t.Fatal(err)
	}
	st2, err := Open(home, id2)
	if err != nil {
		t.Fatal(err)
	}
	p, _, err := st2.Get(r.Item)
	if err != nil || p.Value != "2" {
		t.Fatalf("%+v %v", p, err)
	}
	if got := st2.Fingerprint(); len(got) == 0 || len(splitWords(got)) != 6 {
		t.Fatalf("fingerprint %q", got)
	}
	if len(st2.LocalMacKey()) != 32 {
		t.Fatal("mac key")
	}
}

func splitWords(s string) []string {
	var out []string
	cur := ""
	for _, c := range s {
		if c == ' ' {
			out = append(out, cur)
			cur = ""
			continue
		}
		cur += string(c)
	}
	return append(out, cur)
}
