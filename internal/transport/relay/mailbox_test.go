package relay

import (
	"context"
	"encoding/base64"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"

	"keygate/internal/store"
)

func TestMailboxAndRetry(t *testing.T) {
	id := store.NewIdentity("laptop")
	var puts, first, pairPolls atomic.Int32
	var times []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		times = append(times, r.Header.Get("KG-Time"))
		switch {
		case r.Method == http.MethodPut && r.URL.Path == "/v/vlt_x/view/dev_to":
			if first.Add(1) == 1 {
				w.WriteHeader(http.StatusUnauthorized) // relay saw an out-of-order time
				return
			}
			if r.Header.Get("KG-Push") != "1" {
				t.Errorf("missing KG-Push")
			}
			b, _ := io.ReadAll(r.Body)
			if string(b) != "sealed" {
				t.Errorf("body %q", b)
			}
			puts.Add(1)
		case r.Method == http.MethodGet && r.URL.Path == "/v/vlt_x/msg/"+id.Dev:
			_, _ = w.Write([]byte(`{"msgs":[{"id":"i1","from":"dev_p","body":"{\"v\":1}"}]}`))
		case r.Method == http.MethodDelete && r.URL.Path == "/v/vlt_x/msg/"+id.Dev+"/i1":
			w.WriteHeader(http.StatusNoContent)
		case r.Method == http.MethodPut && r.URL.Path == "/v/vlt_x/pair-open/ABCDEFGHABCDEFGH":
			if r.ContentLength != 0 {
				t.Errorf("pair-open body length %d", r.ContentLength)
			}
			w.WriteHeader(http.StatusCreated)
		case r.Method == http.MethodGet && r.URL.Path == "/v/vlt_x/pair/ABCDEFGHABCDEFGH":
			if pairPolls.Add(1) == 1 {
				w.WriteHeader(http.StatusNoContent)
				return
			}
			w.Header().Set("KG-Pair-Origin", base64.StdEncoding.EncodeToString([]byte(`{"ip":"1.2.3.4"}`)))
			_, _ = w.Write([]byte("code"))
		case r.Method == http.MethodGet && r.URL.Path == "/v/vlt_x/pair/ZZZZZZZZZZZZZZZZ":
			w.WriteHeader(http.StatusNotFound)
		default:
			t.Errorf("unexpected %s %s", r.Method, r.URL.Path)
		}
	}))
	defer srv.Close()
	c := New(srv.URL, "vlt_x", id, srv.Client())
	ctx := context.Background()
	if err := c.PutView(ctx, "dev_to", []byte("sealed"), true); err != nil || puts.Load() != 1 {
		t.Fatalf("put view: %v puts=%d", err, puts.Load())
	}
	if len(times) != 2 || times[0] == times[1] {
		t.Fatalf("retry must re-sign with a new time: %v", times)
	}
	ms, err := c.GetMsgs(ctx)
	if err != nil || len(ms) != 1 || ms[0].ID != "i1" || ms[0].From != "dev_p" || string(ms[0].Body) != `{"v":1}` {
		t.Fatalf("msgs %+v %v", ms, err)
	}
	if err := c.DeleteMsg(ctx, "i1"); err != nil {
		t.Fatal(err)
	}
	if err := c.OpenPair(ctx, "ABCDEFGHABCDEFGH"); err != nil {
		t.Fatalf("open pair: %v", err)
	}
	if _, _, ready, err := c.GetPair(ctx, "ABCDEFGHABCDEFGH"); err != nil || ready {
		t.Fatalf("unfilled slot: ready=%v err=%v", ready, err)
	}
	if b, o, ready, err := c.GetPair(ctx, "ABCDEFGHABCDEFGH"); err != nil || !ready || string(b) != "code" || o.IP != "1.2.3.4" {
		t.Fatalf("pair %q %+v %v %v", b, o, ready, err)
	}
	if _, _, _, err := c.GetPair(ctx, "ZZZZZZZZZZZZZZZZ"); !errors.Is(err, ErrPairGone) {
		t.Fatalf("missing pair must be ErrPairGone, got %v", err)
	}
}

func TestDeviceSummary(t *testing.T) {
	for ua, want := range map[string]string{
		"Mozilla/5.0 (iPhone; CPU iPhone OS 27_2 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/27.2 Mobile/15E148 Safari/604.1": "iPhone · Safari",
		"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/140.0 Safari/537.36 Edg/140.0":                   "Windows · Edge",
		"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/140.0 Safari/537.36":                             "Windows · Chrome",
		"Go-http-client/1.1": "kg",
	} {
		if got := Device(ua); got != want {
			t.Errorf("Device(%q) = %q, want %q", ua, got, want)
		}
	}
}
