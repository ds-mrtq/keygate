//go:build kgtest

package channel

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"keygate/internal/kcrypto"
	"keygate/internal/record"
	"keygate/internal/recovery"
	"keygate/internal/store"
	"keygate/internal/syncer"
	"keygate/internal/transport"
	"keygate/internal/transport/relay"
)

func channelStore(t *testing.T) (*store.Store, ed25519.PrivateKey) {
	t.Helper()
	vault := kcrypto.NewVaultID()
	setup, err := recovery.NewSetup(vault, "fake test password", kcrypto.Argon2Params{M: 8192, T: 1, P: 1})
	if err != nil {
		t.Fatal(err)
	}
	st, err := store.Init(filepath.Join(t.TempDir(), "vault"), vault, store.NewIdentity("test"), setup.Keys, setup.Salt, setup.Params, time.Unix(1700000000, 0))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(st.Close)
	return st, setup.Keys.OwnerPriv
}

func configureRelay(t *testing.T, st *store.Store, url string) {
	t.Helper()
	cfg := st.Config()
	cfg.RelayURL = url
	if err := st.SaveConfig(cfg); err != nil {
		t.Fatal(err)
	}
}

func checkRequest(t *testing.T, r *http.Request, pub ed25519.PublicKey, device, vault string) []byte {
	t.Helper()
	body, err := io.ReadAll(r.Body)
	if err != nil {
		t.Error(err)
	}
	sig, err := base64.StdEncoding.DecodeString(r.Header.Get("KG-Sig"))
	if err != nil || !ed25519.Verify(pub, relay.Canonical(r.Method, r.URL.RequestURI(), r.Header.Get("KG-Time"), body), sig) {
		t.Error("invalid relay signature")
	}
	if r.Header.Get("KG-Device") != device || !strings.HasPrefix(r.URL.Path, "/v/"+vault+"/") {
		t.Errorf("wrong scope: %s %s", r.Header.Get("KG-Device"), r.URL.Path)
	}
	return body
}

func TestPickAndOpen(t *testing.T) {
	id := store.NewIdentity("test")
	for _, tc := range []struct {
		cfg       store.VaultConfig
		via, want string
	}{
		{store.VaultConfig{SyncDir: "d", GitDir: "g", RelayURL: "r"}, "", "dir"},
		{store.VaultConfig{GitDir: "g", RelayURL: "r"}, "", "git"},
		{store.VaultConfig{RelayURL: "r"}, "", "relay"},
		{store.VaultConfig{}, "relay", "relay"},
	} {
		if got, err := Pick(tc.cfg, tc.via); err != nil || got != tc.want {
			t.Fatalf("pick %q %v", got, err)
		}
	}
	for _, via := range []string{"", "dir", "git", "relay", "invalid"} {
		if tr, err := Open(store.VaultConfig{}, via, id); err == nil || tr != nil {
			t.Fatalf("empty config %q: %v %v", via, tr, err)
		}
	}
	if _, err := Open(store.VaultConfig{GitDir: t.TempDir()}, "git", id); err == nil {
		t.Fatal("non-repository accepted as git channel")
	}
	for _, via := range []string{"dir", "relay"} {
		cfg := store.VaultConfig{SyncDir: t.TempDir(), GitDir: t.TempDir(), RelayURL: "http://unused.invalid", Vault: "vlt_test"}
		tr, err := Open(cfg, via, id)
		if err != nil || tr.Name() != via {
			t.Fatalf("open %s: %v %v", via, tr, err)
		}
	}
	if _, err := Open(store.VaultConfig{SyncDir: t.TempDir()}, "dir", OwnerSigner{}); err != nil {
		t.Fatal(err)
	}
}

func TestOwnerMemberPush(t *testing.T) {
	for _, mode := range []string{"created", "identical", "fork", "missing", "pull error", "push error"} {
		t.Run(mode, func(t *testing.T) {
			st, priv := channelStore(t)
			first, pending := st.PendingMembers("relay")
			calls := 0
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				body := checkRequest(t, r, priv.Public().(ed25519.PublicKey), "owner", st.Config().Vault)
				if r.Method == http.MethodPut {
					n, err := strconv.Atoi(r.URL.Path[strings.LastIndex(r.URL.Path, "/")+1:])
					if err != nil || n != first+calls || !bytes.Equal(body, pending[calls]) {
						t.Error("member order/body changed")
					}
					calls++
					if mode == "push error" {
						w.WriteHeader(403)
					} else if mode != "created" {
						w.WriteHeader(409)
					} else {
						w.WriteHeader(201)
					}
					return
				}
				if mode == "pull error" {
					w.WriteHeader(500)
					return
				}
				switch {
				case strings.HasSuffix(r.URL.Path, "/checkpoints"):
					fmt.Fprint(w, `{"checkpoints":{}}`)
				case strings.HasSuffix(r.URL.Path, "/members"):
					var rows []map[string]any
					line := pending[calls-1]
					if mode == "fork" {
						line = []byte("different")
					}
					if mode != "missing" {
						rows = append(rows, map[string]any{"n": first + calls - 1, "line": string(line)})
					}
					json.NewEncoder(w).Encode(map[string]any{"members": rows})
				case strings.HasSuffix(r.URL.Path, "/log"):
					fmt.Fprint(w, `{"logs":{}}`)
				default:
					t.Errorf("unexpected %s", r.URL)
					w.WriteHeader(404)
				}
			}))
			defer srv.Close()
			configureRelay(t, st, srv.URL)
			err := PushMembersAsOwner(context.Background(), st, "", priv)
			_, left := st.PendingMembers("relay")
			if mode == "created" || mode == "identical" {
				if err != nil || len(left) != 0 || calls != len(pending) {
					t.Fatalf("push: %v remaining %d calls %d", err, len(left), calls)
				}
			} else {
				if err == nil || len(left) != len(pending) {
					t.Fatalf("failure advanced cursor: %v remaining %d", err, len(left))
				}
				if (mode == "fork" || mode == "missing") && !errors.Is(err, syncer.ErrForkChannel) {
					t.Fatalf("fork error: %v", err)
				}
			}
		})
	}
}

func TestOwnerPushNoRelay(t *testing.T) {
	st, key := channelStore(t)
	for _, via := range []string{"", "dir", "git"} {
		if err := PushMembersAsOwner(context.Background(), st, via, key); err != nil {
			t.Fatal(err)
		}
	}
	if err := PushMembersAsOwner(context.Background(), st, "relay", key); err == nil {
		t.Fatal("missing relay accepted")
	}
}

func TestPairSignedRequestsAndOrigin(t *testing.T) {
	priv := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{3}, 32))
	signer := OwnerSigner{Priv: priv}
	var slot string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		checkRequest(t, r, priv.Public().(ed25519.PublicKey), "owner", "vlt_test")
		if r.Method == "PUT" {
			slot = r.URL.Path[strings.LastIndex(r.URL.Path, "/")+1:]
			if strings.Contains(r.URL.RawQuery, "nonce") || r.URL.RawQuery != "" {
				t.Error("nonce sent to relay")
			}
			w.WriteHeader(201)
			return
		}
		if !strings.HasSuffix(r.URL.Path, "/"+slot) {
			t.Error("wrong pairing slot")
		}
		w.Header().Set("KG-Pair-Origin", base64.StdEncoding.EncodeToString([]byte(`{"ip":"192.0.2.1","country":"XX"}`)))
		fmt.Fprint(w, "  FAKE-REGISTRATION\n")
	}))
	defer srv.Close()
	cfg := store.VaultConfig{Vault: "vlt_test", RelayURL: srv.URL}
	code, nonce, link, err := OpenPair(context.Background(), cfg, signer, "PIN")
	if err != nil || !strings.HasSuffix(link, "&n="+nonce) || code != slot {
		t.Fatalf("open pair: %q %q %q %v", code, nonce, link, err)
	}
	reg, origin, err := WaitPair(context.Background(), cfg, signer, code)
	if err != nil || reg != "FAKE-REGISTRATION" || origin.IP != "192.0.2.1" || origin.Country != "XX" {
		t.Fatalf("wait: %q %+v %v", reg, origin, err)
	}
}

func TestPairAndSeenErrors(t *testing.T) {
	id := store.NewIdentity("test")
	if _, _, err := WaitPair(context.Background(), store.VaultConfig{}, id, "CODE"); err == nil {
		t.Fatal("missing relay accepted")
	}
	if seen, err := Seen(context.Background(), store.VaultConfig{}, id); err != nil || seen != nil {
		t.Fatalf("no relay: %v %v", seen, err)
	}
	for _, mode := range []string{"forbidden", "malformed", "seen", "retry", "cancel"} {
		t.Run(mode, func(t *testing.T) {
			calls := 0
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				calls++
				if mode == "retry" && calls == 1 {
					w.WriteHeader(401)
					return
				}
				if mode == "forbidden" {
					w.WriteHeader(403)
					return
				}
				if mode == "cancel" {
					w.WriteHeader(204)
					return
				}
				if mode == "malformed" {
					fmt.Fprint(w, "{")
					return
				}
				fmt.Fprint(w, `{"devices":[{"dev":"phone","t":123,"ip":"192.0.2.1"}]}`)
			}))
			defer srv.Close()
			cfg := store.VaultConfig{Vault: "vlt_test", RelayURL: srv.URL}
			if mode == "forbidden" {
				code, nonce, link, err := OpenPair(context.Background(), cfg, id, "PIN")
				if err == nil || code != "" || nonce != "" || link != "" {
					t.Fatalf("failed open leaked result: %q %q %q %v", code, nonce, link, err)
				}
			}
			if mode == "cancel" {
				ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
				defer cancel()
				if _, _, err := WaitPair(ctx, cfg, id, "CODE"); !errors.Is(err, context.DeadlineExceeded) {
					t.Fatalf("wait timeout: %v", err)
				}
				return
			}
			seen, err := Seen(context.Background(), cfg, id)
			if mode == "malformed" || mode == "forbidden" {
				if err == nil {
					t.Fatal("bad response accepted")
				}
				return
			}
			if err != nil || len(seen) != 1 || seen[0].Dev != "phone" || seen[0].Time != 123 {
				t.Fatalf("seen: %+v %v", seen, err)
			}
			if mode == "retry" && calls != 2 {
				t.Fatalf("retry count %d", calls)
			}
		})
	}
}

func TestSyncRejectsUntrustedRelay(t *testing.T) {
	for _, mode := range []string{"malformed", "forged member", "log gap", "unknown device", "wrong vault", "tampered", "oversize", "duplicate sequence"} {
		t.Run(mode, func(t *testing.T) {
			st, _ := channelStore(t)
			before := st.Fingerprint()
			dev := st.ID.Dev
			priv := st.ID.EdPriv
			if mode == "unknown device" {
				other := store.NewIdentity("outsider")
				dev, priv = other.Dev, other.EdPriv
			}
			rec := &record.Record{V: 1, Vault: st.Config().Vault, Item: kcrypto.NewItemID(), Dev: dev, Seq: 1, Epoch: 1, Op: record.OpPut}
			if mode == "wrong vault" {
				rec.Vault = kcrypto.NewVaultID()
			}
			if err := rec.Encrypt(kcrypto.NewVaultKey(), record.Plain{Name: "fake", Value: "fake-value"}); err != nil {
				t.Fatal(err)
			}
			if err := rec.Sign(priv); err != nil {
				t.Fatal(err)
			}
			if mode == "tampered" {
				ct, err := kcrypto.UnB64(rec.CT)
				if err != nil {
					t.Fatal(err)
				}
				ct[0] ^= 1
				rec.CT = kcrypto.B64(ct)
			}
			line, err := rec.Marshal()
			if err != nil {
				t.Fatal(err)
			}
			if mode == "oversize" {
				line = bytes.Repeat([]byte("x"), record.MaxLineSize+1)
			}
			writes := 0
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Method != "GET" {
					writes++
					t.Error("pushed after invalid pull")
					w.WriteHeader(500)
					return
				}
				if mode == "malformed" {
					fmt.Fprint(w, "{")
					return
				}
				switch {
				case strings.HasSuffix(r.URL.Path, "/checkpoints"):
					fmt.Fprint(w, `{"checkpoints":{}}`)
				case strings.HasSuffix(r.URL.Path, "/members"):
					if mode == "forged member" {
						fmt.Fprint(w, `{"members":[{"n":3,"line":"{}"}]}`)
					} else {
						fmt.Fprint(w, `{"members":[]}`)
					}
				case strings.HasSuffix(r.URL.Path, "/log"):
					seq := 1
					if mode == "log gap" {
						seq = 2
					}
					rows := []map[string]any{{"seq": seq, "line": string(line)}}
					if mode == "duplicate sequence" {
						rows = append(rows, rows[0])
					}
					json.NewEncoder(w).Encode(map[string]any{"logs": map[string]any{dev: rows}})
				}
			}))
			defer srv.Close()
			configureRelay(t, st, srv.URL)
			if _, err := Sync(context.Background(), st, "relay", ""); err == nil {
				t.Fatal("untrusted snapshot accepted")
			}
			if writes != 0 || st.Fingerprint() != before {
				t.Fatal("failed verification changed state")
			}
		})
	}
}

func TestSyncConfigurationErrors(t *testing.T) {
	st, _ := channelStore(t)
	for _, via := range []string{"", "bad", "relay"} {
		if _, err := Sync(context.Background(), st, via, ""); err == nil {
			t.Fatalf("accepted %q", via)
		}
	}
	cfg := st.Config()
	cfg.SyncDir = t.TempDir()
	if err := st.SaveConfig(cfg); err != nil {
		t.Fatal(err)
	}
	res, err := Sync(context.Background(), st, "", "")
	if err != nil || res.Channel != "dir" || res.Pushed != 3 || res.Fingerprint != st.Fingerprint() {
		t.Fatalf("sync: %+v %v", res, err)
	}
	if _, err := Sync(context.Background(), st, "dir", "bad"); err == nil {
		t.Fatal("bad verification channel accepted")
	}
	res, err = Sync(context.Background(), st, "dir", "dir")
	if err != nil || res.Verified != "dir" || res.Pushed != 0 {
		t.Fatalf("verify: %+v %v", res, err)
	}
}

var _ transport.Signer = OwnerSigner{}
