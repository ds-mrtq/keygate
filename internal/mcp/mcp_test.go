package mcp

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"io"
	"strings"
	"testing"
	"time"

	"keygate/internal/api"
)

type fakeBroker struct {
	lastReq   api.RunRequest
	lastAgent string
	runErr    error
}

func (f *fakeBroker) Status(context.Context) (api.Status, error) { return api.Status{}, nil }
func (f *fakeBroker) List(context.Context) ([]api.SecretInfo, error) {
	return []api.SecretInfo{{Name: "db/test", Env: "test", Kind: "password"}}, nil
}
func (f *fakeBroker) RequestGrant(_ context.Context, secret string, argv []string, agent string) (api.GrantInfo, error) {
	f.lastAgent = agent
	if secret == "deny" {
		return api.GrantInfo{}, errors.New("denied by user")
	}
	return api.GrantInfo{Secret: secret, Pattern: argv[0] + " *", Approval: "user-presence", Expires: time.Unix(1700000000, 0).UTC()}, nil
}
func (f *fakeBroker) Run(_ context.Context, req api.RunRequest, stdout, stderr io.Writer) (int, error) {
	f.lastReq = req
	if f.runErr != nil {
		return 0, f.runErr
	}
	io.WriteString(stdout, "hello [kg:db/test]\n")
	io.WriteString(stderr, "warn\n")
	return 3, nil
}

func roundtrip(t *testing.T, b api.Broker, lines ...string) []map[string]any {
	t.Helper()
	var out strings.Builder
	in := strings.NewReader(strings.Join(lines, "\n") + "\n")
	if err := Serve(context.Background(), in, &out, b); err != nil {
		t.Fatal(err)
	}
	var res []map[string]any
	sc := bufio.NewScanner(strings.NewReader(out.String()))
	for sc.Scan() {
		var m map[string]any
		if err := json.Unmarshal(sc.Bytes(), &m); err != nil {
			t.Fatalf("bad output line %q: %v", sc.Text(), err)
		}
		res = append(res, m)
	}
	return res
}

func resultText(t *testing.T, m map[string]any) (string, bool) {
	t.Helper()
	r := m["result"].(map[string]any)
	c := r["content"].([]any)[0].(map[string]any)
	return c["text"].(string), r["isError"].(bool)
}

func TestInitializeAndNotifications(t *testing.T) {
	res := roundtrip(t, &fakeBroker{},
		`{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18"}}`,
		`{"jsonrpc":"2.0","method":"notifications/initialized"}`,
		`{"jsonrpc":"2.0","id":"p","method":"ping"}`,
		`{"jsonrpc":"2.0","id":3,"method":"nope"}`,
		`garbage`)
	if len(res) != 4 {
		t.Fatalf("want 4 responses (no reply to notification), got %d", len(res))
	}
	r := res[0]["result"].(map[string]any)
	if r["protocolVersion"] != "2025-06-18" || r["serverInfo"].(map[string]any)["name"] != "keygate" {
		t.Fatalf("bad initialize: %v", r)
	}
	if res[1]["id"] != "p" {
		t.Fatalf("ping id: %v", res[1])
	}
	if res[2]["error"].(map[string]any)["code"].(float64) != -32601 {
		t.Fatalf("want method not found: %v", res[2])
	}
	if res[3]["error"].(map[string]any)["code"].(float64) != -32700 {
		t.Fatalf("want parse error: %v", res[3])
	}
}

func TestToolsListNoValueTools(t *testing.T) {
	res := roundtrip(t, &fakeBroker{}, `{"jsonrpc":"2.0","id":1,"method":"tools/list"}`)
	ts := res[0]["result"].(map[string]any)["tools"].([]any)
	got := map[string]bool{}
	for _, x := range ts {
		n := x.(map[string]any)["name"].(string)
		got[n] = true
		l := strings.ToLower(n)
		for _, bad := range []string{"get", "reveal", "read", "show", "value"} {
			if strings.Contains(l, bad) {
				t.Fatalf("tool %q looks like a value getter", n)
			}
		}
	}
	for _, want := range []string{"list_secrets", "request_grant", "run_with_secret"} {
		if !got[want] {
			t.Fatalf("missing tool %s", want)
		}
	}
	if len(got) != 3 {
		t.Fatalf("unexpected tools: %v", got)
	}
}

func TestToolCalls(t *testing.T) {
	fb := &fakeBroker{}
	res := roundtrip(t, fb,
		`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"list_secrets"}}`,
		`{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"request_grant","arguments":{"secret":"db/test","command":["sql","@x.sql"]}}}`,
		`{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"run_with_secret","arguments":{"secrets":["db/test"],"argv":["sql","/@T"],"dir":"/w"}}}`,
		`{"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":"request_grant","arguments":{"secret":"deny","command":["x"]}}}`,
		`{"jsonrpc":"2.0","id":5,"method":"tools/call","params":{"name":"run_with_secret","arguments":{"secrets":[]}}}`,
		`{"jsonrpc":"2.0","id":6,"method":"tools/call","params":{"name":"reveal_secret","arguments":{}}}`)
	txt, e := resultText(t, res[0])
	if e || !strings.Contains(txt, "db/test") {
		t.Fatalf("list: %v %q", e, txt)
	}
	txt, e = resultText(t, res[1])
	if e || !strings.Contains(txt, "user-presence") || fb.lastAgent != "mcp" {
		t.Fatalf("grant: %v %q agent=%q", e, txt, fb.lastAgent)
	}
	txt, e = resultText(t, res[2])
	if e || !strings.Contains(txt, "exit code: 3") || !strings.Contains(txt, "hello [kg:db/test]") || !strings.Contains(txt, "warn") {
		t.Fatalf("run: %v %q", e, txt)
	}
	if fb.lastReq.Agent != "mcp" || fb.lastReq.Dir != "/w" || len(fb.lastReq.Argv) != 2 {
		t.Fatalf("run req: %+v", fb.lastReq)
	}
	if txt, e = resultText(t, res[3]); !e || !strings.Contains(txt, "denied") {
		t.Fatalf("deny should be isError: %v %q", e, txt)
	}
	if _, e = resultText(t, res[4]); !e {
		t.Fatal("bad args should be isError")
	}
	if res[5]["error"] == nil {
		t.Fatal("unknown tool must be rpc error")
	}
}

func TestRunBrokerError(t *testing.T) {
	res := roundtrip(t, &fakeBroker{runErr: errors.New("no grant")},
		`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"run_with_secret","arguments":{"secrets":["a"],"argv":["x"]}}}`)
	if txt, e := resultText(t, res[0]); !e || !strings.Contains(txt, "no grant") {
		t.Fatalf("%v %q", e, txt)
	}
}

func TestContextCancel(t *testing.T) {
	pr, pw := io.Pipe()
	defer pw.Close()
	ctx, cancel := context.WithCancel(context.Background())
	errc := make(chan error, 1)
	go func() { errc <- Serve(ctx, pr, io.Discard, &fakeBroker{}) }()
	cancel()
	select {
	case err := <-errc:
		if !errors.Is(err, context.Canceled) {
			t.Fatal(err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Serve did not return on cancel")
	}
}
