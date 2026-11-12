package relay

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"sort"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"keygate/internal/transport"
)

type signer struct {
	id string
	k  ed25519.PrivateKey
}

func (s signer) DeviceID() string     { return s.id }
func (s signer) Sign(m []byte) []byte { return ed25519.Sign(s.k, m) }

// fakeRelay reproduces the relay's auth check and routes in memory.
type fakeRelay struct {
	mu      sync.Mutex
	pubs    map[string]ed25519.PublicKey
	members map[int]string
	logs    map[string]map[uint64]string
	cps     map[string]string
	lastT   map[string]time.Time
}

func (f *fakeRelay) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	body, _ := io.ReadAll(r.Body)
	f.mu.Lock()
	defer f.mu.Unlock()
	ts := r.Header.Get("KG-Time")
	t0, err := time.Parse(time.RFC3339, ts)
	if err != nil || time.Since(t0).Abs() > 5*time.Minute {
		http.Error(w, "time", 401)
		return
	}
	sig, _ := base64.StdEncoding.DecodeString(r.Header.Get("KG-Sig"))
	pub, ok := f.pubs[r.Header.Get("KG-Device")]
	if !ok || !ed25519.Verify(pub, Canonical(r.Method, r.URL.RequestURI(), ts, body), sig) {
		http.Error(w, "sig", 401)
		return
	}
	// Strictly increasing per-device time (replay defence).
	if dev := r.Header.Get("KG-Device"); !t0.After(f.lastT[dev]) {
		http.Error(w, "replay", 401)
		return
	} else {
		f.lastT[dev] = t0
	}
	p := strings.Split(strings.Trim(r.URL.Path, "/"), "/") // v, vault, kind, ...
	switch {
	case r.Method == "PUT" && p[2] == "log":
		seq, _ := strconv.ParseUint(p[4], 10, 64)
		if f.logs[p[3]] == nil {
			f.logs[p[3]] = map[uint64]string{}
		}
		if _, dup := f.logs[p[3]][seq]; dup {
			http.Error(w, "exists", 409)
			return
		}
		f.logs[p[3]][seq] = string(body)
	case r.Method == "PUT" && p[2] == "members":
		n, _ := strconv.Atoi(p[3])
		if _, dup := f.members[n]; dup {
			http.Error(w, "exists", 409)
			return
		}
		f.members[n] = string(body)
	case r.Method == "PUT" && p[2] == "checkpoint":
		f.cps[p[3]] = string(body)
	case r.Method == "GET" && p[2] == "members":
		since, _ := strconv.Atoi(r.URL.Query().Get("since"))
		type row struct {
			N    int    `json:"n"`
			Line string `json:"line"`
		}
		out := []row{}
		for n := since; ; n++ {
			l, ok := f.members[n]
			if !ok {
				break
			}
			out = append(out, row{n, l})
		}
		json.NewEncoder(w).Encode(map[string]any{"members": out})
	case r.Method == "GET" && p[2] == "log":
		since := map[string]uint64{}
		if q := r.URL.Query().Get("since"); q != "" {
			for _, kv := range strings.Split(q, ",") {
				d, s, _ := strings.Cut(kv, ":")
				since[d], _ = strconv.ParseUint(s, 10, 64)
			}
		}
		type row struct {
			Seq  uint64 `json:"seq"`
			Line string `json:"line"`
		}
		out := map[string][]row{}
		devs := []string{}
		for dev := range f.logs {
			devs = append(devs, dev)
		}
		sort.Strings(devs)
		remaining, more := 2, false // tiny page size to exercise pagination
		for _, dev := range devs {
			for seq := since[dev] + 1; ; seq++ {
				l, ok := f.logs[dev][seq]
				if !ok {
					break
				}
				if remaining == 0 {
					more = true
					break
				}
				out[dev] = append(out[dev], row{seq, l})
				remaining--
			}
		}
		json.NewEncoder(w).Encode(map[string]any{"logs": out, "more": more})
	case r.Method == "GET" && p[2] == "checkpoints":
		json.NewEncoder(w).Encode(map[string]any{"checkpoints": f.cps})
	default:
		http.Error(w, "route", 404)
	}
}

func TestRelayClient(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	f := &fakeRelay{
		pubs:    map[string]ed25519.PublicKey{"dev_a": pub},
		members: map[int]string{}, logs: map[string]map[uint64]string{}, cps: map[string]string{}, lastT: map[string]time.Time{},
	}
	srv := httptest.NewServer(f)
	defer srv.Close()
	ctx := context.Background()
	c := New(srv.URL+"/", "vlt_test", signer{"dev_a", priv}, nil)

	if err := c.PushMember(ctx, 0, []byte(`{"n":0}`)); err != nil {
		t.Fatal(err)
	}
	if err := c.PushMember(ctx, 0, []byte(`{"n":0}`)); !errors.Is(err, transport.ErrExists) {
		t.Fatalf("dup: %v", err)
	}
	for i := uint64(1); i <= 3; i++ {
		if err := c.PushLog(ctx, "dev_a", i, []byte(`{"seq":`+strconv.FormatUint(i, 10)+`}`)); err != nil {
			t.Fatal(err)
		}
	}
	if err := c.PushLog(ctx, "dev_a", 3, []byte(`{}`)); !errors.Is(err, transport.ErrExists) {
		t.Fatalf("dup log: %v", err)
	}
	if err := c.PushCheckpoint(ctx, "dev_a", []byte(`{"cp":1}`)); err != nil {
		t.Fatal(err)
	}
	snap, err := c.Pull(ctx, transport.Since{Members: 0, Logs: map[string]uint64{"dev_a": 1}})
	if err != nil {
		t.Fatal(err)
	}
	if len(snap.Members) != 1 || len(snap.Logs["dev_a"]) != 2 || string(snap.Logs["dev_a"][0]) != `{"seq":2}` ||
		string(snap.Checkpoints["dev_a"]) != `{"cp":1}` {
		t.Fatalf("snap: %+v", snap)
	}

	for i := uint64(4); i <= 6; i++ {
		if err := c.PushLog(ctx, "dev_a", i, []byte(`{"seq":`+strconv.FormatUint(i, 10)+`}`)); err != nil {
			t.Fatal(err)
		}
	}
	all, err := c.Pull(ctx, transport.Since{})
	if err != nil || len(all.Logs["dev_a"]) != 6 || string(all.Logs["dev_a"][5]) != `{"seq":6}` {
		t.Fatalf("paginated pull: %v %d", err, len(all.Logs["dev_a"]))
	}

	// Bad signer and stale clock are rejected with 401 (not ErrExists).
	_, other, _ := ed25519.GenerateKey(rand.Reader)
	bad := New(srv.URL, "vlt_test", signer{"dev_a", other}, nil)
	if err := bad.PushLog(ctx, "dev_a", 9, []byte(`{}`)); err == nil || errors.Is(err, transport.ErrExists) || !strings.Contains(err.Error(), "401") {
		t.Fatalf("bad sig: %v", err)
	}
	stale := New(srv.URL, "vlt_test", signer{"dev_a", priv}, nil)
	stale.now = func() time.Time { return time.Now().Add(-10 * time.Minute) }
	if err := stale.PushLog(ctx, "dev_a", 9, []byte(`{}`)); err == nil || !strings.Contains(err.Error(), "401") {
		t.Fatalf("stale: %v", err)
	}
}
