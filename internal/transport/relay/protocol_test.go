package relay

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"keygate/internal/transport"
)

func protocolClient(t *testing.T, h http.HandlerFunc) *Client {
	t.Helper()
	srv := httptest.NewServer(h)
	t.Cleanup(srv.Close)
	key := ed25519.NewKeyFromSeed(make([]byte, ed25519.SeedSize))
	return New(srv.URL+"/", "vlt_test", signer{"dev_test", key}, srv.Client())
}

type protocolOperation struct {
	name string
	op   string
	call func(context.Context, *Client) error
}

func protocolOperations() []protocolOperation {
	return []protocolOperation{
		{"log", "put log", func(ctx context.Context, c *Client) error { return c.PushLog(ctx, "dev_test", 1, nil) }},
		{"member", "put member", func(ctx context.Context, c *Client) error { return c.PushMember(ctx, 0, nil) }},
		{"checkpoint", "put checkpoint", func(ctx context.Context, c *Client) error { return c.PushCheckpoint(ctx, "dev_test", nil) }},
		{"view", "put view", func(ctx context.Context, c *Client) error { return c.PutView(ctx, "dev_to", nil, false) }},
		{"msgs", "get msgs", func(ctx context.Context, c *Client) error { _, err := c.GetMsgs(ctx); return err }},
		{"ack", "delete msg", func(ctx context.Context, c *Client) error { return c.DeleteMsg(ctx, "msg1") }},
		{"open", "open pair", func(ctx context.Context, c *Client) error { return c.OpenPair(ctx, "ABCDEFGHABCDEFGH") }},
		{"pair", "get pair", func(ctx context.Context, c *Client) error {
			_, _, _, err := c.GetPair(ctx, "ABCDEFGHABCDEFGH")
			return err
		}},
		{"devices", "get devices", func(ctx context.Context, c *Client) error { _, err := c.Devices(ctx); return err }},
		{"pull", "get checkpoints", func(ctx context.Context, c *Client) error { _, err := c.Pull(ctx, transport.Since{}); return err }},
	}
}

func TestProtocolStatusErrors(t *testing.T) {
	for _, op := range protocolOperations() {
		t.Run(op.name, func(t *testing.T) {
			for _, status := range []int{http.StatusForbidden, http.StatusServiceUnavailable} {
				t.Run(strconv.Itoa(status), func(t *testing.T) {
					var calls atomic.Int32
					c := protocolClient(t, func(w http.ResponseWriter, r *http.Request) {
						calls.Add(1)
						w.WriteHeader(status)
						_, _ = io.WriteString(w, " \n"+strings.Repeat("x", 250)+" \n")
					})
					err := op.call(context.Background(), c)
					want := "relay: " + op.op + ": HTTP " + strconv.Itoa(status) + ": " + strings.Repeat("x", 200)
					if err == nil || err.Error() != want || calls.Load() != 1 {
						t.Fatalf("err=%v calls=%d; want %q, one request", err, calls.Load(), want)
					}
				})
			}
		})
	}
}

func TestProtocolTruncatedBodies(t *testing.T) {
	for _, op := range protocolOperations() {
		t.Run(op.name, func(t *testing.T) {
			var calls atomic.Int32
			c := protocolClient(t, func(w http.ResponseWriter, r *http.Request) {
				calls.Add(1)
				w.Header().Set("Content-Length", "100")
				_, _ = io.WriteString(w, `{}`)
			})
			if err := op.call(context.Background(), c); !errors.Is(err, io.ErrUnexpectedEOF) {
				t.Fatalf("got %v, want unexpected EOF", err)
			}
			if calls.Load() != 1 {
				t.Fatalf("truncated response retried %d times", calls.Load())
			}
		})
	}
}

func TestProtocolCancellation(t *testing.T) {
	for _, op := range protocolOperations() {
		t.Run(op.name, func(t *testing.T) {
			var calls atomic.Int32
			c := protocolClient(t, func(w http.ResponseWriter, r *http.Request) { calls.Add(1) })
			ctx, cancel := context.WithCancel(context.Background())
			cancel()
			if err := op.call(ctx, c); !errors.Is(err, context.Canceled) {
				t.Fatalf("got %v, want context cancellation", err)
			}
			if calls.Load() != 0 {
				t.Fatalf("canceled request reached relay %d times", calls.Load())
			}
		})
	}
}

func TestProtocolDeadlineAndInFlightCancellation(t *testing.T) {
	for _, mode := range []string{"cancel", "deadline", "client timeout"} {
		t.Run(mode, func(t *testing.T) {
			started := make(chan struct{})
			c := protocolClient(t, func(w http.ResponseWriter, r *http.Request) {
				close(started)
				<-r.Context().Done()
			})
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			want := context.Canceled
			switch mode {
			case "cancel":
				go func() { <-started; cancel() }()
			case "deadline":
				var deadlineCancel context.CancelFunc
				ctx, deadlineCancel = context.WithTimeout(ctx, 100*time.Millisecond)
				defer deadlineCancel()
				want = context.DeadlineExceeded
			case "client timeout":
				c.http.Timeout = 100 * time.Millisecond
				want = context.DeadlineExceeded
			}
			if _, err := c.GetMsgs(ctx); !errors.Is(err, want) {
				t.Fatalf("got %v, want %v", err, want)
			}
		})
	}
}

func TestProtocolMalformedJSON(t *testing.T) {
	for _, name := range []string{"msgs", "devices", "pull"} {
		for _, op := range protocolOperations() {
			if op.name != name {
				continue
			}
			t.Run(name, func(t *testing.T) {
				for _, body := range []string{"", "{", `{"msgs":42,"devices":42,"checkpoints":42}`} {
					c := protocolClient(t, func(w http.ResponseWriter, r *http.Request) { _, _ = io.WriteString(w, body) })
					err := op.call(context.Background(), c)
					var syntaxErr *json.SyntaxError
					var typeErr *json.UnmarshalTypeError
					if !errors.As(err, &syntaxErr) && !errors.As(err, &typeErr) {
						t.Fatalf("body %q: got %v, want JSON syntax or type error", body, err)
					}
				}
			})
		}
	}
}

func TestProtocolSigningAndRetryLimit(t *testing.T) {
	for _, finalStatus := range []int{http.StatusNoContent, http.StatusUnauthorized} {
		t.Run(strconv.Itoa(finalStatus), func(t *testing.T) {
			var calls atomic.Int32
			fixed := time.Date(2026, 1, 2, 3, 4, 5, 123000000, time.UTC)
			key := ed25519.NewKeyFromSeed(make([]byte, ed25519.SeedSize))
			c := protocolClient(t, func(w http.ResponseWriter, r *http.Request) {
				n := calls.Add(1)
				body, err := io.ReadAll(r.Body)
				if err != nil {
					t.Error(err)
				}
				ts := fixed.Add(time.Duration(n-1) * time.Millisecond).Format("2006-01-02T15:04:05.000Z")
				if r.Method != "PUT" || r.URL.RequestURI() != "/v/vlt_test/view/dev_to" || string(body) != "sealed-test-envelope" || r.Header.Get("KG-Device") != "dev_test" || r.Header.Get("KG-Time") != ts || r.Header.Get("KG-Push") != "1" || r.Header.Get("Content-Type") != "text/plain; charset=utf-8" {
					t.Errorf("unexpected signed request: %s %s headers=%v body=%q", r.Method, r.URL, r.Header, body)
				}
				var canonical bytes.Buffer
				canonical.WriteString("kg/v1/relay-req\x00")
				sum := sha256.Sum256(body)
				for _, field := range []string{r.Method, r.URL.RequestURI(), ts, hex.EncodeToString(sum[:])} {
					_ = binary.Write(&canonical, binary.BigEndian, uint32(len(field)))
					canonical.WriteString(field)
				}
				sig, err := base64.StdEncoding.DecodeString(r.Header.Get("KG-Sig"))
				if err != nil || !ed25519.Verify(key.Public().(ed25519.PublicKey), canonical.Bytes(), sig) {
					t.Error("signature did not authenticate method, path, timestamp and body")
				}
				if n == 1 {
					w.WriteHeader(http.StatusUnauthorized)
				} else {
					w.WriteHeader(finalStatus)
				}
			})
			c.now = func() time.Time { return fixed }
			err := c.PutView(context.Background(), "dev_to", []byte("sealed-test-envelope"), true)
			if finalStatus == http.StatusNoContent && err != nil {
				t.Fatal(err)
			}
			if finalStatus == http.StatusUnauthorized && (err == nil || !strings.Contains(err.Error(), "HTTP 401")) {
				t.Fatalf("want final 401, got %v", err)
			}
			if calls.Load() != 2 {
				t.Fatalf("got %d requests, want exactly two", calls.Load())
			}
		})
	}
}

func TestMailboxReplayUntilAck(t *testing.T) {
	var acked bool
	c := protocolClient(t, func(w http.ResponseWriter, r *http.Request) {
		if (r.Method != http.MethodGet || r.URL.Path != "/v/vlt_test/msg/dev_test") && (r.Method != http.MethodDelete || r.URL.Path != "/v/vlt_test/msg/dev_test/msg1") {
			t.Errorf("unexpected mailbox path %s", r.URL.Path)
			w.WriteHeader(http.StatusNotFound)
			return
		}
		switch r.Method {
		case http.MethodGet:
			if acked {
				_, _ = io.WriteString(w, `{"msgs":[]}`)
			} else {
				_, _ = io.WriteString(w, `{"msgs":[{"id":"msg1","from":"dev_peer","body":"sealed-envelope"}]}`)
			}
		case http.MethodDelete:
			acked = true
			w.WriteHeader(http.StatusNoContent)
		default:
			t.Errorf("unexpected method %s", r.Method)
		}
	})
	ctx := context.Background()
	want := []Msg{{ID: "msg1", From: "dev_peer", Body: []byte("sealed-envelope")}}
	for i := 0; i < 2; i++ {
		got, err := c.GetMsgs(ctx)
		if err != nil || !reflect.DeepEqual(got, want) {
			t.Fatalf("poll %d: got %+v err=%v, want %+v", i, got, err, want)
		}
	}
	for i := 0; i < 2; i++ {
		if err := c.DeleteMsg(ctx, "msg1"); err != nil {
			t.Fatalf("ack %d: %v", i, err)
		}
	}
	got, err := c.GetMsgs(ctx)
	if err != nil || len(got) != 0 {
		t.Fatalf("acked mailbox: %+v err=%v", got, err)
	}
}

func TestDevicesResponses(t *testing.T) {
	for _, tc := range []struct {
		body string
		want []Seen
	}{
		{`{"devices":[]}`, []Seen{}},
		{`{"devices":[{"dev":"dev_peer","t":123,"ip":"192.0.2.1","country":"US","city":"Test","org":"Test network","ua":"Go-http-client/1.1"}]}`, []Seen{{Dev: "dev_peer", Time: 123, Origin: Origin{IP: "192.0.2.1", Country: "US", City: "Test", Org: "Test network", UA: "Go-http-client/1.1"}}}},
	} {
		c := protocolClient(t, func(w http.ResponseWriter, r *http.Request) {
			if r.Method != http.MethodGet || r.URL.RequestURI() != "/v/vlt_test/devices" || r.Header.Get("Content-Type") != "" {
				t.Errorf("unexpected devices request: %s %s %v", r.Method, r.URL, r.Header)
			}
			_, _ = io.WriteString(w, tc.body)
		})
		got, err := c.Devices(context.Background())
		if err != nil || !reflect.DeepEqual(got, tc.want) {
			t.Fatalf("got %+v err=%v, want %+v", got, err, tc.want)
		}
		if c.Name() != "relay" {
			t.Fatalf("transport name %q", c.Name())
		}
	}
}

func TestPairOriginHeaders(t *testing.T) {
	for _, tc := range []struct {
		name   string
		header string
		want   Origin
	}{
		{"absent", "", Origin{}},
		{"invalid base64", "%%%", Origin{}},
		{"invalid json", base64.StdEncoding.EncodeToString([]byte("not-json")), Origin{}},
		{"oversized origin", base64.StdEncoding.EncodeToString([]byte(`{"ip":"` + strings.Repeat("x", 1024) + `"}`)), Origin{}},
		{"valid", base64.StdEncoding.EncodeToString([]byte(`{"ip":"192.0.2.1","city":"Test","country":"US","org":"Test network","ua":"Go-http-client/1.1"}`)), Origin{IP: "192.0.2.1", City: "Test", Country: "US", Org: "Test network", UA: "Go-http-client/1.1"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := protocolClient(t, func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("KG-Pair-Origin", tc.header)
				_, _ = io.WriteString(w, "test-registration-code")
			})
			data, origin, ready, err := c.GetPair(context.Background(), "ABCDEFGHABCDEFGH")
			if err != nil || !ready || string(data) != "test-registration-code" || origin != tc.want {
				t.Fatalf("data=%q origin=%+v ready=%v err=%v; want origin=%+v", data, origin, ready, err, tc.want)
			}
		})
	}
}

func TestPullRejectsInvalidPages(t *testing.T) {
	for _, tc := range []struct {
		name string
		body string
		want string
	}{
		{"gap", `{"logs":{"dev_peer":[{"seq":2,"line":"sealed"}]}}`, "non-contiguous seq 2 after 0"},
		{"duplicate", `{"logs":{"dev_peer":[{"seq":1,"line":"sealed"},{"seq":1,"line":"sealed"}]}}`, "non-contiguous seq 1 after 1"},
		{"no progress", `{"more":true,"logs":{}}`, "pagination made no progress"},
		{"invalid json", `{`, "unexpected end of JSON input"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var calls atomic.Int32
			c := protocolClient(t, func(w http.ResponseWriter, r *http.Request) {
				calls.Add(1)
				switch r.URL.Path {
				case "/v/vlt_test/checkpoints":
					_, _ = io.WriteString(w, `{"checkpoints":{}}`)
				case "/v/vlt_test/members":
					_, _ = io.WriteString(w, `{"members":[]}`)
				case "/v/vlt_test/log":
					_, _ = io.WriteString(w, tc.body)
				default:
					t.Errorf("unexpected route %s", r.URL)
				}
			})
			_, err := c.Pull(context.Background(), transport.Since{})
			if err == nil || !strings.Contains(err.Error(), tc.want) || calls.Load() != 3 {
				t.Fatalf("err=%v requests=%d, want %q and three requests", err, calls.Load(), tc.want)
			}
		})
	}
}

func TestPullOrderingAndFiltering(t *testing.T) {
	var routes []string
	c := protocolClient(t, func(w http.ResponseWriter, r *http.Request) {
		routes = append(routes, r.URL.RequestURI())
		switch r.URL.Path {
		case "/v/vlt_test/checkpoints":
			_, _ = io.WriteString(w, `{"checkpoints":{"dev_a":"checkpoint"}}`)
		case "/v/vlt_test/members":
			_, _ = io.WriteString(w, `{"members":[{"n":3,"line":"third"},{"n":1,"line":"old"},{"n":2,"line":"second"}]}`)
		case "/v/vlt_test/log":
			_, _ = io.WriteString(w, `{"logs":{"dev_a":[{"seq":3,"line":"a3"},{"seq":2,"line":"a2"}],"dev_b":[{"seq":3,"line":"b3"}]}}`)
		default:
			t.Errorf("unexpected route %s", r.URL)
		}
	})
	since := transport.Since{Members: 2, Logs: map[string]uint64{"dev_b": 2, "dev_a": 1, "dev_zero": 0}}
	snap, err := c.Pull(context.Background(), since)
	if err != nil {
		t.Fatal(err)
	}
	wantRoutes := []string{"/v/vlt_test/checkpoints", "/v/vlt_test/members?since=2", "/v/vlt_test/log?since=dev_a:1,dev_b:2"}
	if !reflect.DeepEqual(routes, wantRoutes) || !reflect.DeepEqual(snap.Members, [][]byte{[]byte("second"), []byte("third")}) || !reflect.DeepEqual(snap.Logs, map[string][][]byte{"dev_a": {[]byte("a2"), []byte("a3")}, "dev_b": {[]byte("b3")}}) || string(snap.Checkpoints["dev_a"]) != "checkpoint" {
		t.Fatalf("routes=%v snapshot=%+v", routes, snap)
	}
	if since.Logs["dev_a"] != 1 || since.Logs["dev_b"] != 2 {
		t.Fatalf("Pull mutated caller's cursor: %+v", since)
	}
}

func TestPullStopsOnMembersError(t *testing.T) {
	var calls atomic.Int32
	c := protocolClient(t, func(w http.ResponseWriter, r *http.Request) {
		switch calls.Add(1) {
		case 1:
			_, _ = io.WriteString(w, `{"checkpoints":{"dev_a":"checkpoint"}}`)
		case 2:
			w.WriteHeader(http.StatusBadGateway)
		default:
			t.Error("continued after members error")
		}
	})
	snap, err := c.Pull(context.Background(), transport.Since{})
	if err == nil || !strings.Contains(err.Error(), "get members: HTTP 502") || calls.Load() != 2 || string(snap.Checkpoints["dev_a"]) != "checkpoint" || len(snap.Logs) != 0 {
		t.Fatalf("snapshot=%+v err=%v calls=%d", snap, err, calls.Load())
	}
}

func TestProtocolInvalidBaseURL(t *testing.T) {
	c := protocolClient(t, func(w http.ResponseWriter, r *http.Request) { t.Error("invalid URL reached relay") })
	c.base = "://invalid"
	if _, err := c.Devices(context.Background()); err == nil {
		t.Fatal("invalid base URL accepted")
	}
}

func TestOpenPairRequiresCreated(t *testing.T) {
	c := protocolClient(t, func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusOK) })
	if err := c.OpenPair(context.Background(), "ABCDEFGHABCDEFGH"); err == nil || !strings.Contains(err.Error(), "open pair: HTTP 200") {
		t.Fatalf("expected rejection of non-Created response, got %v", err)
	}
}

func TestProtocolEmptyWrites(t *testing.T) {
	for _, name := range []string{"log", "view", "open"} {
		for _, op := range protocolOperations() {
			if op.name != name {
				continue
			}
			t.Run(name, func(t *testing.T) {
				c := protocolClient(t, func(w http.ResponseWriter, r *http.Request) {
					body, err := io.ReadAll(r.Body)
					if err != nil || len(body) != 0 || r.ContentLength != 0 || r.Header.Get("Content-Type") != "text/plain; charset=utf-8" || r.Header.Get("KG-Push") != "" {
						t.Errorf("empty write: body=%q err=%v headers=%v length=%d", body, err, r.Header, r.ContentLength)
					}
					w.WriteHeader(http.StatusCreated)
				})
				if err := op.call(context.Background(), c); err != nil {
					t.Fatal(err)
				}
			})
		}
	}
}

func TestDevicesJSONTypeError(t *testing.T) {
	c := protocolClient(t, func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, `{"devices":[{"t":"not-a-timestamp"}]}`)
	})
	_, err := c.Devices(context.Background())
	var typeErr *json.UnmarshalTypeError
	if !errors.As(err, &typeErr) {
		t.Fatalf("got %v, want JSON type error", err)
	}
}

func TestPairPollAndConsumption(t *testing.T) {
	var polls atomic.Int32
	c := protocolClient(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet || r.URL.Path != "/v/vlt_test/pair/ABCDEFGHABCDEFGH" {
			t.Errorf("unexpected pair request: %s %s", r.Method, r.URL)
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		switch polls.Add(1) {
		case 1:
			w.WriteHeader(http.StatusNoContent)
		case 2:
			_, _ = io.WriteString(w, "test-registration-code")
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	})
	ctx := context.Background()
	data, origin, ready, err := c.GetPair(ctx, "ABCDEFGHABCDEFGH")
	if err != nil || ready || len(data) != 0 || origin != (Origin{}) {
		t.Fatalf("empty slot: data=%q origin=%+v ready=%v err=%v", data, origin, ready, err)
	}
	data, origin, ready, err = c.GetPair(ctx, "ABCDEFGHABCDEFGH")
	if err != nil || !ready || string(data) != "test-registration-code" || origin != (Origin{}) {
		t.Fatalf("filled slot: data=%q origin=%+v ready=%v err=%v", data, origin, ready, err)
	}
	data, origin, ready, err = c.GetPair(ctx, "ABCDEFGHABCDEFGH")
	if !errors.Is(err, ErrPairGone) || ready || len(data) != 0 || origin != (Origin{}) || polls.Load() != 3 {
		t.Fatalf("consumed slot: data=%q origin=%+v ready=%v err=%v polls=%d", data, origin, ready, err, polls.Load())
	}
}
