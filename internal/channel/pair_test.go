package channel

import (
	"context"
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strings"
	"sync/atomic"
	"testing"

	"keygate/internal/store"
)

func TestOpenAndWaitPair(t *testing.T) {
	id := store.NewIdentity("laptop")
	var slot string
	var polls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodPut && strings.HasPrefix(r.URL.Path, "/v/vlt_x/pair-open/"):
			slot = strings.TrimPrefix(r.URL.Path, "/v/vlt_x/pair-open/")
			w.WriteHeader(http.StatusCreated)
		case r.Method == http.MethodGet && r.URL.Path == "/v/vlt_x/pair/"+slot && slot != "":
			if polls.Add(1) == 1 {
				w.WriteHeader(http.StatusNoContent)
				return
			}
			_, _ = w.Write([]byte("REGCODE\n"))
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer srv.Close()
	cfg := store.VaultConfig{Vault: "vlt_x", RelayURL: srv.URL + "/"}
	ctx := context.Background()

	code, nonce, link, err := OpenPair(ctx, cfg, id, "AAAA-BBBB")
	if err != nil {
		t.Fatal(err)
	}
	if !regexp.MustCompile(`^[A-Z2-7]{16}$`).MatchString(code) || code != slot {
		t.Fatalf("code %q slot %q", code, slot)
	}
	if raw, err := base64.RawURLEncoding.DecodeString(nonce); err != nil || len(raw) != 16 {
		t.Fatalf("nonce %q: %v", nonce, err)
	}
	if want := srv.URL + "/app/#v=vlt_x&p=AAAA-BBBB&c=" + code + "&n=" + nonce; link != want {
		t.Fatalf("link %q want %q", link, want)
	}
	reg, _, err := WaitPair(ctx, cfg, id, code)
	if err != nil || reg != "REGCODE" || polls.Load() != 2 {
		t.Fatalf("reg %q polls %d err %v", reg, polls.Load(), err)
	}
	// slot gone (expired): WaitPair fails at once
	if _, _, err := WaitPair(ctx, cfg, id, "ZZZZZZZZZZZZZZZZ"); err == nil || !strings.Contains(err.Error(), "hết hạn") {
		t.Fatalf("expired slot: %v", err)
	}
	// ctx ends while waiting
	cctx, cancel := context.WithCancel(ctx)
	cancel()
	if _, _, err := WaitPair(cctx, cfg, id, code); err == nil {
		t.Fatal("cancelled ctx must fail")
	}
	// no relay configured
	if _, _, _, err := OpenPair(ctx, store.VaultConfig{Vault: "vlt_x"}, id, "P"); err == nil || !strings.Contains(err.Error(), "vault chưa gắn relay") {
		t.Fatalf("no relay: %v", err)
	}
}
