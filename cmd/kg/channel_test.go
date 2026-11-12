package main

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"testing"
)

// fakeRelay stores lines like the real relay (no signature checks) and records who signed members.
type fakeRelay struct {
	mu      sync.Mutex
	members map[int]string
	logs    map[string]map[uint64]string
	cps     map[string]string
	devs    []string // KG-Device of each PUT members
}

func (f *fakeRelay) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	parts := strings.Split(strings.Trim(r.URL.Path, "/"), "/") // v/<vault>/<kind>/...
	if len(parts) < 3 {
		http.NotFound(w, r)
		return
	}
	body, _ := io.ReadAll(r.Body)
	switch {
	case r.Method == "PUT" && parts[2] == "members" && len(parts) == 4:
		n, _ := strconv.Atoi(parts[3])
		if _, ok := f.members[n]; ok {
			w.WriteHeader(409)
			return
		}
		f.members[n] = string(body)
		f.devs = append(f.devs, r.Header.Get("KG-Device"))
	case r.Method == "PUT" && parts[2] == "log" && len(parts) == 5:
		seq, _ := strconv.ParseUint(parts[4], 10, 64)
		if f.logs[parts[3]] == nil {
			f.logs[parts[3]] = map[uint64]string{}
		}
		if _, ok := f.logs[parts[3]][seq]; ok {
			w.WriteHeader(409)
			return
		}
		f.logs[parts[3]][seq] = string(body)
	case r.Method == "PUT" && parts[2] == "checkpoint" && len(parts) == 4:
		f.cps[parts[3]] = string(body)
	case r.Method == "GET" && parts[2] == "members":
		type row struct {
			N    int    `json:"n"`
			Line string `json:"line"`
		}
		var rows []row
		for n, l := range f.members {
			rows = append(rows, row{n, l})
		}
		sort.Slice(rows, func(i, j int) bool { return rows[i].N < rows[j].N })
		json.NewEncoder(w).Encode(map[string]any{"members": rows})
	case r.Method == "GET" && parts[2] == "log":
		type row struct {
			Seq  uint64 `json:"seq"`
			Line string `json:"line"`
		}
		out := map[string][]row{}
		for dev, m := range f.logs {
			for s, l := range m {
				out[dev] = append(out[dev], row{s, l})
			}
		}
		json.NewEncoder(w).Encode(map[string]any{"logs": out})
	case r.Method == "GET" && parts[2] == "checkpoints":
		json.NewEncoder(w).Encode(map[string]any{"checkpoints": f.cps})
	default:
		http.NotFound(w, r)
	}
}

func TestChannelAddRelay(t *testing.T) {
	t.Setenv("KG_DEVKEY_BACKEND", "plain")
	fr := &fakeRelay{members: map[int]string{}, logs: map[string]map[uint64]string{}, cps: map[string]string{}}
	srv := httptest.NewServer(fr)
	defer srv.Close()
	root := t.TempDir()
	const master = "correct horse battery staple"

	d := newTestApp(t, filepath.Join(root, "h"))
	d.secrets = []string{master, master}
	out := d.do(t, "init", "--label", "laptop") // no channel
	paper := regexp.MustCompile(`(?m)^\s+([A-Z2-7]{4}(?:-[A-Z2-7]{4})+)\s*$`).FindStringSubmatch(out)[1]

	// Wrong paper key / password: refused, nothing pushed.
	d.secrets = []string{"another wrong password", paper}
	if c := d.run([]string{"channel", "add", "--relay-url", srv.URL}); c == 0 {
		t.Fatal("wrong master password must fail")
	}
	if len(fr.members) != 0 {
		t.Fatal("nothing may be pushed with wrong keys")
	}
	// Exactly one channel flag.
	if c := d.run([]string{"channel", "add"}); c == 0 {
		t.Fatal("no channel flag must fail")
	}

	d.secrets = []string{master, paper}
	d.do(t, "channel", "add", "--relay-url", srv.URL)
	if len(fr.members) != 3 {
		t.Fatalf("genesis+add+epoch expected on relay, got %d", len(fr.members))
	}
	for _, dev := range fr.devs {
		if dev != "owner" {
			t.Fatalf("first member events must be signed as owner, got %q", dev)
		}
	}
	if len(fr.cps) != 1 {
		t.Fatalf("device checkpoint expected after sync: %v", fr.cps)
	}
	b, _ := readLinesFile(filepath.Join(d.home, "vault.json"))
	if !strings.Contains(string(b[0])+string(b[1]), "relay_url") && !strings.Contains(strings.Join(func() []string {
		var s []string
		for _, l := range b {
			s = append(s, string(l))
		}
		return s
	}(), ""), "relay_url") {
		t.Fatal("relay_url not saved")
	}
}
