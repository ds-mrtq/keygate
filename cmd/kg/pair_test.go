package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"testing"

	"keygate/internal/members"
	"keygate/internal/store"
)

func setRelayURL(t *testing.T, home, url string) {
	t.Helper()
	p := filepath.Join(home, "vault.json")
	raw, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]any
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatal(err)
	}
	m["relay_url"] = url
	out, _ := json.Marshal(m)
	if err := os.WriteFile(p, out, 0o600); err != nil {
		t.Fatal(err)
	}
}

func TestDevicePair(t *testing.T) {
	t.Setenv("KG_DEVKEY_BACKEND", "plain")
	root := t.TempDir()
	home := filepath.Join(root, "h1")
	const master = "correct horse battery staple"
	ta := newTestApp(t, home)
	ta.secrets = []string{master, master}
	out := ta.do(t, "init", "--label", "laptop", "--dir", filepath.Join(root, "shared"))
	paper := regexp.MustCompile(`(?m)^\s+([A-Z2-7]{4}(?:-[A-Z2-7]{4})+)\s*$`).FindStringSubmatch(out)[1]

	// the old subcommands are gone
	if code := ta.run([]string{"device", "pair-url"}); code == 0 {
		t.Fatal("pair-url must no longer exist")
	}
	if code := ta.run([]string{"device", "add", "--pair", "ABCD2345"}); code == 0 {
		t.Fatal("add --pair must no longer exist")
	}
	// no relay configured: pair explains how to attach one
	if code := ta.run([]string{"device", "pair"}); code == 0 || !strings.Contains(ta.errb.String(), "vault chưa gắn relay") {
		t.Fatalf("pair without relay: code=%d err=%s", code, ta.errb.String())
	}

	phone := store.NewIdentity("iphone")
	body := phone.Public()
	body.Role = members.RoleApprover
	regCode := store.RequestCode(body)
	full := store.NewIdentity("macbook")
	fullCode := store.RequestCode(full.Public())

	cfg, err := store.ReadConfig(home)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(filepath.Join(home, "device.json"))
	if err != nil {
		t.Fatal(err)
	}
	var d struct {
		Dev string `json:"dev"`
	}
	if err := json.Unmarshal(raw, &d); err != nil || d.Dev == "" {
		t.Fatalf("device.json: %q %v", d.Dev, err)
	}
	laptop := d.Dev

	var mu sync.Mutex
	var opened, gets int
	var slot, filled string // code of the open slot, registration code the "phone" publishes
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		if r.Header.Get("KG-Device") != laptop || r.Header.Get("KG-Sig") == "" {
			t.Errorf("relay request not signed by the laptop identity: %v", r.Header)
		}
		prefix := "/v/" + cfg.Vault
		switch {
		case r.Method == http.MethodPut && strings.HasPrefix(r.URL.Path, prefix+"/pair-open/"):
			opened++
			slot = strings.TrimPrefix(r.URL.Path, prefix+"/pair-open/")
			w.WriteHeader(http.StatusCreated)
		case r.Method == http.MethodGet && slot != "" && r.URL.Path == prefix+"/pair/"+slot:
			gets++
			_, _ = w.Write([]byte(filled))
		default:
			t.Errorf("unexpected relay request %s %s", r.Method, r.URL.Path)
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer srv.Close()
	setRelayURL(t, home, srv.URL+"/")
	pin, err := genesisPin(home)
	if err != nil {
		t.Fatal(err)
	}

	// a full-device code is refused (nothing is added, no prompt is reached)
	filled = fullCode
	if code := ta.run([]string{"device", "pair"}); code == 0 || !strings.Contains(ta.errb.String(), "thiết bị đầy đủ") {
		t.Fatalf("pair with a full-device code: code=%d err=%s", code, ta.errb.String())
	}
	if !strings.Contains(ta.errb.String(), "kg device add") {
		t.Fatalf("refusal must point to kg device add: %s", ta.errb.String())
	}

	// approver code: link with nonce, 6 words bound to it, typed yes, add (no epoch event)
	filled = regCode
	ta.secrets = []string{master, paper}
	ta.lines = []string{"yes"}
	out = ta.do(t, "device", "pair")
	m := regexp.MustCompile(`(?m)^(` + regexp.QuoteMeta(srv.URL) + `/app/#v=` + cfg.Vault + `&p=` + regexp.QuoteMeta(pin) + `&c=([A-Z2-7]{16})&n=([A-Za-z0-9_-]{22}))$`).FindStringSubmatch(out)
	if m == nil {
		t.Fatalf("pair link missing or malformed:\n%s", out)
	}
	if m[2] != slot {
		t.Fatalf("link code %q != opened slot %q", m[2], slot)
	}
	if !strings.Contains(out, "THIẾT BỊ DUYỆT") || !strings.Contains(out, store.PairWords(regCode, m[3])) {
		t.Fatalf("pair output:\n%s", out)
	}
	if strings.Contains(out, store.RequestWords(regCode)) {
		t.Fatalf("words must be bound to the nonce, not RequestWords:\n%s", out)
	}
	if opened != 2 || gets != 2 {
		t.Fatalf("opened=%d gets=%d", opened, gets)
	}
	list := ta.do(t, "device", "list")
	if !strings.Contains(list, phone.Dev) || !strings.Contains(list, "duyệt") {
		t.Fatalf("device list:\n%s", list)
	}
}
