// Package mcp serves the KeyGate MCP tools over newline-delimited JSON-RPC 2.0.
// No tool ever returns a secret value.
package mcp

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
	"sync"

	"keygate/internal/api"
)

// ProtocolVersion is the MCP revision implemented.
const ProtocolVersion = "2025-06-18"

const agentLabel = "mcp"

// maxOutput caps captured stdout/stderr per stream returned to the agent.
const maxOutput = 1 << 20

type request struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id,omitempty"`
	Method  string          `json:"method"`
	Params  json.RawMessage `json:"params,omitempty"`
}

type rpcError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

type response struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id"`
	Result  any             `json:"result,omitempty"`
	Error   *rpcError       `json:"error,omitempty"`
}

type content struct {
	Type string `json:"type"`
	Text string `json:"text"`
}

type toolResult struct {
	Content []content `json:"content"`
	IsError bool      `json:"isError"`
}

func textResult(s string, isErr bool) toolResult {
	return toolResult{Content: []content{{Type: "text", Text: s}}, IsError: isErr}
}

type tool struct {
	Name        string         `json:"name"`
	Description string         `json:"description"`
	InputSchema map[string]any `json:"inputSchema"`
}

var strArray = map[string]any{"type": "array", "items": map[string]any{"type": "string"}}

var tools = []tool{
	{
		Name:        "list_secrets",
		Description: "List available secrets (name, env, kind, last use, conflict flag). Never returns values.",
		InputSchema: map[string]any{"type": "object", "properties": map[string]any{}},
	},
	{
		Name:        "request_grant",
		Description: "Ask the user to approve running a command with a secret. Returns grant metadata only, never the value.",
		InputSchema: map[string]any{
			"type": "object",
			"properties": map[string]any{
				"secret":  map[string]any{"type": "string", "description": "Secret name, e.g. db/test"},
				"command": strArray,
			},
			"required": []string{"secret", "command"},
		},
	},
	{
		Name:        "run_with_secret",
		Description: "Run a command with secrets injected by the broker. Returns redacted stdout/stderr and the exit code.",
		InputSchema: map[string]any{
			"type": "object",
			"properties": map[string]any{
				"secrets": strArray,
				"argv":    strArray,
				"dir":     map[string]any{"type": "string", "description": "Working directory (optional)"},
			},
			"required": []string{"secrets", "argv"},
		},
	},
}

// Serve reads requests from r and writes responses to w until EOF or ctx is done.
func Serve(ctx context.Context, r io.Reader, w io.Writer, b api.Broker) error {
	type line struct {
		b   []byte
		err error
	}
	lines := make(chan line)
	done := make(chan struct{})
	defer close(done)
	go func() {
		br := bufio.NewReaderSize(r, 64*1024)
		for {
			bs, err := br.ReadBytes('\n')
			if len(bs) > 0 {
				select {
				case lines <- line{b: bs}:
				case <-done:
					return
				}
			}
			if err != nil {
				select {
				case lines <- line{err: err}:
				case <-done:
				}
				return
			}
		}
	}()

	var mu sync.Mutex
	send := func(resp response) error {
		resp.JSONRPC = "2.0"
		data, err := json.Marshal(resp)
		if err != nil {
			return err
		}
		mu.Lock()
		defer mu.Unlock()
		_, err = w.Write(append(data, '\n'))
		return err
	}

	for {
		var l line
		select {
		case <-ctx.Done():
			return ctx.Err()
		case l = <-lines:
		}
		if l.err != nil && len(l.b) == 0 {
			if errors.Is(l.err, io.EOF) {
				return nil
			}
			return l.err
		}
		msg := bytes.TrimSpace(l.b)
		if len(msg) == 0 {
			continue
		}
		var req request
		if err := json.Unmarshal(msg, &req); err != nil {
			if err := send(response{ID: json.RawMessage("null"), Error: &rpcError{-32700, "parse error"}}); err != nil {
				return err
			}
			continue
		}
		isNotification := len(req.ID) == 0
		result, rerr := handle(ctx, b, req)
		if isNotification {
			continue
		}
		resp := response{ID: req.ID}
		if rerr != nil {
			resp.Error = rerr
		} else {
			resp.Result = result
			if resp.Result == nil {
				resp.Result = map[string]any{}
			}
		}
		if err := send(resp); err != nil {
			return err
		}
	}
}

func handle(ctx context.Context, b api.Broker, req request) (any, *rpcError) {
	switch req.Method {
	case "initialize":
		return map[string]any{
			"protocolVersion": ProtocolVersion,
			"capabilities":    map[string]any{"tools": map[string]any{"listChanged": false}},
			"serverInfo":      map[string]any{"name": "keygate", "version": "0.4"},
		}, nil
	case "ping":
		return map[string]any{}, nil
	case "tools/list":
		return map[string]any{"tools": tools}, nil
	case "tools/call":
		var p struct {
			Name      string          `json:"name"`
			Arguments json.RawMessage `json:"arguments"`
		}
		if err := json.Unmarshal(req.Params, &p); err != nil {
			return nil, &rpcError{-32602, "invalid params"}
		}
		return callTool(ctx, b, p.Name, p.Arguments)
	}
	if strings.HasPrefix(req.Method, "notifications/") {
		return nil, nil
	}
	return nil, &rpcError{-32601, "method not found: " + req.Method}
}

func callTool(ctx context.Context, b api.Broker, name string, args json.RawMessage) (any, *rpcError) {
	if len(args) == 0 {
		args = json.RawMessage("{}")
	}
	switch name {
	case "list_secrets":
		list, err := b.List(ctx)
		if err != nil {
			return textResult("list_secrets: "+err.Error(), true), nil
		}
		if list == nil {
			list = []api.SecretInfo{}
		}
		data, _ := json.MarshalIndent(list, "", "  ")
		return textResult(string(data), false), nil

	case "request_grant":
		var a struct {
			Secret  string   `json:"secret"`
			Command []string `json:"command"`
		}
		if err := json.Unmarshal(args, &a); err != nil || a.Secret == "" || len(a.Command) == 0 {
			return textResult("request_grant: need secret (string) and command (string[])", true), nil
		}
		g, err := b.RequestGrant(ctx, a.Secret, a.Command, agentLabel)
		if err != nil {
			return textResult("request_grant: "+err.Error(), true), nil
		}
		data, _ := json.MarshalIndent(g, "", "  ")
		return textResult("grant active:\n"+string(data), false), nil

	case "run_with_secret":
		var a struct {
			Secrets []string `json:"secrets"`
			Argv    []string `json:"argv"`
			Dir     string   `json:"dir"`
		}
		if err := json.Unmarshal(args, &a); err != nil || len(a.Secrets) == 0 || len(a.Argv) == 0 {
			return textResult("run_with_secret: need secrets (string[]) and argv (string[])", true), nil
		}
		var so, se capped
		code, err := b.Run(ctx, api.RunRequest{Secrets: a.Secrets, Argv: a.Argv, Dir: a.Dir, Agent: agentLabel}, &so, &se)
		if err != nil {
			return textResult("run_with_secret: "+err.Error(), true), nil
		}
		var sb strings.Builder
		fmt.Fprintf(&sb, "exit code: %d\n--- stdout ---\n%s", code, so.buf.String())
		if so.truncated {
			sb.WriteString("\n[output truncated]")
		}
		fmt.Fprintf(&sb, "\n--- stderr ---\n%s", se.buf.String())
		if se.truncated {
			sb.WriteString("\n[output truncated]")
		}
		return textResult(sb.String(), false), nil
	}
	return nil, &rpcError{-32602, "unknown tool: " + name}
}

// capped is a bounded buffer; excess bytes are dropped but writes still succeed.
type capped struct {
	buf       bytes.Buffer
	truncated bool
}

func (c *capped) Write(p []byte) (int, error) {
	room := maxOutput - c.buf.Len()
	if room <= 0 {
		c.truncated = true
		return len(p), nil
	}
	if len(p) > room {
		c.buf.Write(p[:room])
		c.truncated = true
		return len(p), nil
	}
	return c.buf.Write(p)
}
