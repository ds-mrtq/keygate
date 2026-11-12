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

func TestDevicePairURLAndAddPair(t *testing.T) {
	t.Setenv("KG_DEVKEY_BACKEND", "plain")
	root := t.TempDir()
	home := filepath.Join(root, "h1")
	const master = "correct horse battery staple"
	ta := newTestApp(t, home)
	ta.secrets = []string{master, master}
	out := ta.do(t, "init", "--label", "laptop", "--dir", filepath.Join(root, "shared"))
	paper := regexp.MustCompile(`(?m)^\s+([A-Z2-7]{4}(?:-[A-Z2-7]{4})+)\s*$`).FindStringSubmatch(out)[1]

	// no relay configured: both subcommands explain how to attach one
	if code := ta.run([]string{"device", "pair-url"}); code == 0 || !strings.Contains(ta.errb.String(), "vault chưa gắn relay") {
		t.Fatalf("pair-url without relay: code=%d err=%s", code, ta.errb.String())
	}
	if code := ta.run([]string{"device", "add", "--pair", "ABCD2345"}); code == 0 || !strings.Contains(ta.errb.String(), "vault chưa gắn relay") {
		t.Fatalf("add --pair without relay: code=%d err=%s", code, ta.errb.String())
	}

	phone := store.NewIdentity("iphone")
	body := phone.Public()
	body.Role = members.RoleApprover
	regCode := store.RequestCode(body)

	cfg, err := store.ReadConfig(home)
	if err != nil {
		t.Fatal(err)
	}
	laptop, err := func() (string, error) {
		raw, err := os.ReadFile(filepath.Join(home, "device.json"))
		if err != nil {
			return "", err
		}
		var d struct {
			Dev string `json:"dev"`
		}
		err = json.Unmarshal(raw, &d)
		return d.Dev, err
	}()
	if err != nil || laptop == "" {
		t.Fatalf("device.json: %q %v", laptop, err)
	}

	var mu sync.Mutex
	var pairGets int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		if r.Method == http.MethodGet && r.URL.Path == "/v/"+cfg.Vault+"/pair/ABCD2345" {
			pairGets++
			if r.Header.Get("KG-Device") != laptop || r.Header.Get("KG-Sig") == "" {
				t.Errorf("pair request not signed by the laptop identity: %v", r.Header)
			}
			_, _ = w.Write([]byte(regCode))
			return
		}
		t.Errorf("unexpected relay request %s %s", r.Method, r.URL.Path)
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()
	setRelayURL(t, home, srv.URL+"/")

	// pair-url
	out = ta.do(t, "device", "pair-url")
	pin, err := genesisPin(home)
	if err != nil {
		t.Fatal(err)
	}
	if want := srv.URL + "/app/#v=" + cfg.Vault + "&p=" + pin + "\n"; out != want {
		t.Fatalf("pair-url:\n got %q\nwant %q", out, want)
	}

	// positional code and --pair are mutually exclusive
	if code := ta.run([]string{"device", "add", "--pair", "ABCD2345", regCode}); code == 0 {
		t.Fatal("--pair with a positional code must fail")
	}

	// add --pair: fetch, show 6 words + approver notice, confirm, add (no epoch event)
	ta.secrets = []string{master, paper}
	ta.lines = []string{"yes"}
	out = ta.do(t, "device", "add", "--pair", "abcd 2345")
	if !strings.Contains(out, "THIẾT BỊ DUYỆT") || !strings.Contains(out, store.RequestWords(regCode)) {
		t.Fatalf("add --pair output:\n%s", out)
	}
	if pairGets != 1 {
		t.Fatalf("pair fetched %d times", pairGets)
	}
	list := ta.do(t, "device", "list")
	if !strings.Contains(list, phone.Dev) || !strings.Contains(list, "duyệt") {
		t.Fatalf("device list:\n%s", list)
	}
}
