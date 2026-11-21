package brokerclient_test

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"keygate/internal/api"
	"keygate/internal/broker/wire"
	"keygate/internal/brokerclient"
)

// Each peer reads one complete request line before responding.
func fakeBroker(t *testing.T, peer func(net.Conn, wire.Request) error) *brokerclient.Client {
	t.Helper()
	dir, err := os.MkdirTemp("", "kg-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	path := filepath.Join(dir, "s")
	ln, err := net.ListenUnix("unix", &net.UnixAddr{Name: path, Net: "unix"})
	if err != nil {
		t.Fatal(err)
	}
	if err := ln.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() {
		c, err := ln.Accept()
		if err != nil {
			done <- err
			return
		}
		defer c.Close()
		if err = c.SetDeadline(time.Now().Add(5 * time.Second)); err == nil {
			var line []byte
			line, err = bufio.NewReader(c).ReadBytes('\n')
			if err == nil {
				var req wire.Request
				if err = json.Unmarshal(line, &req); err == nil {
					err = peer(c, req)
				}
			}
		}
		done <- err
	}()
	t.Cleanup(func() {
		ln.Close()
		if err := <-done; err != nil {
			t.Errorf("fake broker: %v", err)
		}
	})
	return brokerclient.New(path)
}

func sameJSON(a, b []byte) bool {
	var x, y any
	return json.Unmarshal(a, &x) == nil && json.Unmarshal(b, &y) == nil && reflect.DeepEqual(x, y)
}

func TestRequestsAndResults(t *testing.T) {
	cwd, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	grantArgs, err := json.Marshal(wire.GrantArgs{Secret: "app/key", Argv: []string{"tool", "--flag"}, Agent: "test", Dir: cwd})
	if err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name, cmd, args, data string
		call                  func(*brokerclient.Client) (any, error)
		want                  any
	}{
		{"status", "status", "", `{"unlocked":true,"device":"dev","epoch":7}`, func(c *brokerclient.Client) (any, error) { return c.Status(context.Background()) }, api.Status{Unlocked: true, Device: "dev", Epoch: 7}},
		{"list", "list", "", `[{"name":"app/key","env":"dev","kind":"env"}]`, func(c *brokerclient.Client) (any, error) { return c.List(context.Background()) }, []api.SecretInfo{{Name: "app/key", Env: "dev", Kind: "env"}}},
		{"empty-list", "list", "", "[]", func(c *brokerclient.Client) (any, error) { return c.List(context.Background()) }, []api.SecretInfo{}},
		{"grant", "grant", string(grantArgs), `{"secret":"app/key","pattern":"tool *","approval":"none"}`, func(c *brokerclient.Client) (any, error) {
			return c.RequestGrant(context.Background(), "app/key", []string{"tool", "--flag"}, "test")
		}, api.GrantInfo{Secret: "app/key", Pattern: "tool *", Approval: "none"}},
		{"run", "run", `{"secrets":["app/key"],"argv":["tool"],"dir":"/work","agent":"test"}`, "", func(c *brokerclient.Client) (any, error) {
			return c.Run(context.Background(), api.RunRequest{Secrets: []string{"app/key"}, Argv: []string{"tool"}, Dir: "/work", Agent: "test"}, nil, nil)
		}, 0},
		{"resolve", "resolve", `{"secrets":null,"argv":["tool"],"resolve":"template","into":"CONFIG"}`, "", func(c *brokerclient.Client) (any, error) {
			return c.Run(context.Background(), api.RunRequest{Argv: []string{"tool"}, Resolve: "template", Into: "CONFIG"}, nil, nil)
		}, 0},
		{"set", "set", `{"request":{"name":"app/key","value":"","kind":"env","env":"dev","desc":"description","tags":["tag"],"env_name":"TOKEN"},"from_file":"input"}`, "", func(c *brokerclient.Client) (any, error) {
			return nil, c.Set(context.Background(), wire.SetArgs{Request: api.SetRequest{Name: "app/key", Kind: "env", Env: "dev", Desc: "description", Tags: []string{"tag"}, EnvName: "TOKEN"}, FromFile: "input"})
		}, nil},
		{"delete", "delete", `{"names":["app/a","app/b"]}`, `{"names":["app/a","app/b"]}`, func(c *brokerclient.Client) (any, error) {
			return c.Delete(context.Background(), []string{"app/a", "app/b"})
		}, wire.DeleteResult{Names: []string{"app/a", "app/b"}}},
		{"copy", "copy", `{"pairs":[{"src":"app/a","dst":"app/b"}],"env_name":"TOKEN"}`, `{"names":["app/b"]}`, func(c *brokerclient.Client) (any, error) {
			return c.Copy(context.Background(), wire.CopyArgs{Pairs: []wire.CopyPair{{Src: "app/a", Dst: "app/b"}}, EnvName: "TOKEN"})
		}, wire.CopyResult{Names: []string{"app/b"}}},
		{"revoke-secret", "grants-revoke", `{"secret":"app/key"}`, "3", func(c *brokerclient.Client) (any, error) {
			return c.GrantsRevoke(context.Background(), "app/key", false)
		}, 3},
		{"revoke-all", "grants-revoke", `{"all":true}`, "0", func(c *brokerclient.Client) (any, error) { return c.GrantsRevoke(context.Background(), "", true) }, 0},
		{"compare", "import", `{"dotenv":".env","prefix":"app/","env":"dev","compare":true}`, `{"items":[{"name":"app/key","status":"same"}],"extra":["app/extra"]}`, func(c *brokerclient.Client) (any, error) {
			return c.Compare(context.Background(), wire.ImportArgs{Dotenv: ".env", Prefix: "app/", Env: "dev"})
		}, wire.CompareResult{Items: []wire.CompareItem{{Name: "app/key", Status: "same"}}, Extra: []string{"app/extra"}}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := fakeBroker(t, func(conn net.Conn, req wire.Request) error {
				if req.Cmd != tt.cmd || (tt.args == "" && len(req.Args) != 0) || (tt.args != "" && !sameJSON(req.Args, []byte(tt.args))) {
					return fmt.Errorf("request = %s %s; want %s %s", req.Cmd, req.Args, tt.cmd, tt.args)
				}
				f := wire.Frame{T: wire.FrameOK, Data: json.RawMessage(tt.data)}
				if tt.cmd == "run" || tt.cmd == "resolve" {
					f.T = wire.FrameExit
				}
				return json.NewEncoder(conn).Encode(f)
			})
			got, err := tt.call(c)
			if err != nil || !reflect.DeepEqual(got, tt.want) {
				t.Fatalf("got %#v, %v; want %#v", got, err, tt.want)
			}
		})
	}
}

type eventWriter struct {
	stream string
	events *[]string
}

func (w eventWriter) Write(p []byte) (int, error) {
	*w.events = append(*w.events, w.stream+":"+string(p))
	return len(p), nil
}

func TestStreamingAndNotes(t *testing.T) {
	for _, withNote := range []bool{false, true} {
		t.Run(fmt.Sprint(withNote), func(t *testing.T) {
			c := fakeBroker(t, func(conn net.Conn, _ wire.Request) error {
				_, err := io.WriteString(conn, "{\"t\":\"out\",\"s\":\"stdout\",\"d\":\"YQ==\"}\n{\"t\":\"note\",\"msg\":\"waiting\"}\n{\"t\":\"out\",\"s\":\"stderr\",\"d\":\"Yg==\"}\n{\"t\":\"out\",\"s\":\"stdout\",\"d\":\"Yw==\"}\n{\"t\":\"exit\",\"exit\":23}\n")
				return err
			})
			var events []string
			if withNote {
				c.Note = func(msg string) { events = append(events, "note:"+msg) }
			}
			code, err := c.Run(context.Background(), api.RunRequest{}, eventWriter{"stdout", &events}, eventWriter{"stderr", &events})
			want := []string{"stdout:a", "stderr:b", "stdout:c"}
			if withNote {
				want = []string{"stdout:a", "note:waiting", "stderr:b", "stdout:c"}
			}
			if err != nil || code != 23 || !reflect.DeepEqual(events, want) {
				t.Fatalf("exit=%d err=%v events=%q; want %q", code, err, events, want)
			}
		})
	}
}

func TestBrokerError(t *testing.T) {
	c := fakeBroker(t, func(conn net.Conn, _ wire.Request) error {
		_, err := io.WriteString(conn, "{\"t\":\"err\",\"code\":\"denied\",\"msg\":\"approval denied\"}\n")
		return err
	})
	_, err := c.Status(context.Background())
	var be *brokerclient.Error
	if !errors.As(err, &be) || be.Code != "denied" || be.Msg != "approval denied" || err.Error() != be.Msg {
		t.Fatalf("got %T %v; want broker Error with code and message", err, err)
	}
}

func TestFrameFailures(t *testing.T) {
	for _, tt := range []struct{ name, frame, want string }{
		{"malformed", "{not-json}\n", "invalid character"},
		{"truncated", `{"t":"ok","data":`, "unexpected EOF"},
		{"closed", "", "broker đóng kết nối giữa chừng"},
		{"unknown", "{\"t\":\"surprise\"}\n", "surprise"},
		{"bad-data", "{\"t\":\"ok\",\"data\":[]}\n", "cannot unmarshal array"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			c := fakeBroker(t, func(conn net.Conn, _ wire.Request) error {
				_, err := io.WriteString(conn, tt.frame)
				return err
			})
			_, err := c.Status(context.Background())
			if err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("error=%v; want %q", err, tt.want)
			}
		})
	}
}

func TestNoBroker(t *testing.T) {
	_, err := brokerclient.New(filepath.Join(t.TempDir(), "missing")).Status(context.Background())
	if !errors.Is(err, brokerclient.ErrNoBroker) {
		t.Fatalf("got %v; want ErrNoBroker", err)
	}
}

func TestCancelHangingBroker(t *testing.T) {
	received := make(chan struct{})
	c := fakeBroker(t, func(conn net.Conn, _ wire.Request) error {
		close(received)
		_, err := io.Copy(io.Discard, conn)
		return err
	})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { _, err := c.Status(ctx); done <- err }()
	select {
	case <-received:
	case <-time.After(2 * time.Second):
		t.Fatal("broker did not receive request")
	}
	cancel()
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("got %v; want context.Canceled", err)
		}
	case <-time.After(time.Second):
		t.Fatal("canceled call did not return promptly")
	}
}

func TestChildOutputAndRequestArgsDoNotLeak(t *testing.T) {
	const secret = "FAKE-sk-test-child-and-args"
	chunk, err := json.Marshal(wire.Frame{T: wire.FrameOut, Stream: "stdout", Chunk: []byte(secret)})
	if err != nil {
		t.Fatal(err)
	}
	calls := []struct {
		name string
		call func(*brokerclient.Client) error
	}{
		{"run", func(c *brokerclient.Client) error {
			_, err := c.Run(context.Background(), api.RunRequest{Argv: []string{"env", "TOKEN=" + secret, "tool", secret}, Into: secret}, nil, nil)
			return err
		}},
		{"grant", func(c *brokerclient.Client) error {
			_, err := c.RequestGrant(context.Background(), "app/key", []string{"tool", secret}, "test")
			return err
		}},
		{"set", func(c *brokerclient.Client) error {
			return c.Set(context.Background(), wire.SetArgs{Request: api.SetRequest{Name: "app/key", Desc: secret}})
		}},
	}
	for _, ending := range []struct{ name, frame string }{
		{"malformed", "{broken}\n"},
		{"truncated", `{"t":"out","d":`},
		{"eof", ""},
		{"unknown", "{\"t\":\"unknown\"}\n"},
		{"bad-data", "{\"t\":\"ok\",\"data\":[]}\n"},
		{"malformed-chunk", `{"t":"out","d":"` + secret + `"!`},
		{"truncated-chunk", `{"t":"out","d":"` + secret},
	} {
		for _, call := range calls {
			if call.name == "run" && ending.name == "bad-data" || call.name == "set" && ending.name == "bad-data" {
				continue // Run consumes exit codes; Set has no result to decode.
			}
			t.Run(ending.name+"/"+call.name, func(t *testing.T) {
				var logs bytes.Buffer
				old := log.Writer()
				log.SetOutput(&logs)
				defer log.SetOutput(old)
				c := fakeBroker(t, func(conn net.Conn, req wire.Request) error {
					if !bytes.Contains(req.Args, []byte(secret)) {
						return errors.New("request did not contain sentinel")
					}
					_, err := fmt.Fprintf(conn, "%s\n{\"t\":\"note\",\"msg\":\"waiting\"}\n%s", chunk, ending.frame)
					return err
				})
				var notes []string
				c.Note = func(msg string) { notes = append(notes, msg) }
				err := call.call(c)
				if err == nil {
					t.Fatal("expected failure")
				}
				if strings.Contains(err.Error(), secret) || strings.Contains(logs.String(), secret) || strings.Contains(strings.Join(notes, "\n"), secret) {
					t.Fatalf("secret leaked: error=%v logs=%q notes=%q", err, logs.String(), notes)
				}
				if !reflect.DeepEqual(notes, []string{"waiting"}) {
					t.Fatalf("notes=%q; want waiting", notes)
				}
			})
		}
	}
}
