// Package brokerclient is the thin socket client; it implements api.Broker.
package brokerclient

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"time"

	"keygate/internal/api"
	"keygate/internal/broker/wire"
)

// ErrNoBroker means nothing is listening on the broker socket (fail closed).
var ErrNoBroker = errors.New("broker không chạy: chạy kgw tray (hoặc kg broker trong terminal)")

// Error is a failure reported by the broker.
type Error struct {
	Code string
	Msg  string
}

func (e *Error) Error() string { return e.Msg }

// Client talks to one broker socket. Each call uses its own connection.
type Client struct {
	Sock string
	// Note receives progress notes from the broker (e.g. "đang chờ duyệt trên điện thoại"); nil drops them.
	Note func(msg string)
}

// New returns a client for the socket path.
func New(sock string) *Client { return &Client{Sock: sock} }

var _ api.Broker = (*Client)(nil)

func (c *Client) dial(ctx context.Context) (net.Conn, error) {
	d := net.Dialer{Timeout: 3 * time.Second}
	conn, err := d.DialContext(ctx, "unix", c.Sock)
	if err != nil {
		return nil, fmt.Errorf("%w (%v)", ErrNoBroker, err)
	}
	return conn, nil
}

// call sends one request and reads frames until the terminal one.
func (c *Client) call(ctx context.Context, cmd string, args any, onOut func(stream string, b []byte)) (*wire.Frame, error) {
	conn, err := c.dial(ctx)
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	stop := make(chan struct{})
	defer close(stop)
	go func() {
		select {
		case <-ctx.Done():
			conn.Close()
		case <-stop:
		}
	}()
	req := wire.Request{Cmd: cmd}
	if args != nil {
		if req.Args, err = json.Marshal(args); err != nil {
			return nil, err
		}
	}
	line, _ := json.Marshal(req)
	if _, err := conn.Write(append(line, '\n')); err != nil {
		return nil, ctxOr(ctx, err)
	}
	dec := json.NewDecoder(conn)
	for {
		var f wire.Frame
		if err := dec.Decode(&f); err != nil {
			if errors.Is(err, io.EOF) {
				err = errors.New("broker đóng kết nối giữa chừng")
			}
			return nil, ctxOr(ctx, err)
		}
		switch f.T {
		case wire.FrameOut:
			if onOut != nil {
				onOut(f.Stream, f.Chunk)
			}
		case wire.FrameNote:
			if c.Note != nil {
				c.Note(f.Msg)
			}
		case wire.FrameOK, wire.FrameExit:
			return &f, nil
		case wire.FrameErr:
			return nil, &Error{Code: f.Code, Msg: f.Msg}
		default:
			return nil, fmt.Errorf("khung không hợp lệ từ broker: %q", f.T)
		}
	}
}

func ctxOr(ctx context.Context, err error) error {
	if ctx.Err() != nil {
		return ctx.Err()
	}
	return err
}

// do calls cmd and decodes the ok frame into out (may be nil).
func (c *Client) do(ctx context.Context, cmd string, args, out any) error {
	f, err := c.call(ctx, cmd, args, nil)
	if err != nil {
		return err
	}
	if out != nil && len(f.Data) > 0 {
		return json.Unmarshal(f.Data, out)
	}
	return nil
}

// Status implements api.Broker.
func (c *Client) Status(ctx context.Context) (api.Status, error) {
	var s api.Status
	return s, c.do(ctx, wire.CmdStatus, nil, &s)
}

// List implements api.Broker.
func (c *Client) List(ctx context.Context) ([]api.SecretInfo, error) {
	var l []api.SecretInfo
	return l, c.do(ctx, wire.CmdList, nil, &l)
}

// RequestGrant implements api.Broker.
func (c *Client) RequestGrant(ctx context.Context, secret string, argv []string, agent string) (api.GrantInfo, error) {
	var g api.GrantInfo
	return g, c.do(ctx, wire.CmdGrant, wire.GrantArgs{Secret: secret, Argv: argv, Agent: agent}, &g)
}

// Run implements api.Broker; a Resolve request goes through CmdResolve.
func (c *Client) Run(ctx context.Context, req api.RunRequest, stdout, stderr io.Writer) (int, error) {
	cmd := wire.CmdRun
	if req.Resolve != "" {
		cmd = wire.CmdResolve
	}
	f, err := c.call(ctx, cmd, req, func(stream string, b []byte) {
		w := stdout
		if stream == "stderr" {
			w = stderr
		}
		if w != nil {
			w.Write(b)
		}
	})
	if err != nil {
		return -1, err
	}
	return f.Exit, nil
}

// Reveal asks the broker to show a value on ITS terminal after human approval; nothing is returned.
func (c *Client) Reveal(ctx context.Context, name string) error {
	return c.do(ctx, wire.CmdReveal, wire.RevealArgs{Name: name}, nil)
}

// Set sends metadata only; the broker prompts for the value on its own terminal.
func (c *Client) Set(ctx context.Context, a wire.SetArgs) error {
	return c.do(ctx, wire.CmdSet, a, nil)
}

// Import asks the broker to read a .env / gitleaks file itself and store its secrets.
func (c *Client) Import(ctx context.Context, a wire.ImportArgs) (wire.ImportResult, error) {
	var r wire.ImportResult
	return r, c.do(ctx, wire.CmdImport, a, &r)
}

// PolicyApply asks the broker to pin the current policy.yaml (human approval in the broker).
func (c *Client) PolicyApply(ctx context.Context) (wire.PolicyResult, error) {
	var r wire.PolicyResult
	return r, c.do(ctx, wire.CmdPolicyApply, nil, &r)
}

// Lock clears the vault key in the broker.
func (c *Client) Lock(ctx context.Context) error { return c.do(ctx, wire.CmdLock, nil, nil) }

// Grants lists the stored grants (no unlock needed).
func (c *Client) Grants(ctx context.Context) ([]wire.GrantView, error) {
	var l []wire.GrantView
	return l, c.do(ctx, wire.CmdGrants, nil, &l)
}

// GrantsRevoke revokes every grant of secret (or all of them) and returns how many were removed.
func (c *Client) GrantsRevoke(ctx context.Context, secret string, all bool) (int, error) {
	var n int
	return n, c.do(ctx, wire.CmdGrantsRevoke, wire.GrantsRevokeArgs{Secret: secret, All: all}, &n)
}

// Compare asks the broker to compare a .env file with the vault (statuses only).
func (c *Client) Compare(ctx context.Context, a wire.ImportArgs) (wire.CompareResult, error) {
	a.Compare = true
	var r wire.CompareResult
	return r, c.do(ctx, wire.CmdImport, a, &r)
}

// StatusFull returns the status including the work-session state.
func (c *Client) StatusFull(ctx context.Context) (wire.StatusFull, error) {
	var s wire.StatusFull
	return s, c.do(ctx, wire.CmdStatus, nil, &s)
}

// SessionStart opens a work session (one user-presence prompt when needed).
func (c *Client) SessionStart(ctx context.Context) error {
	return c.do(ctx, wire.CmdSessionStart, nil, nil)
}

// SessionEnd ends the work session (no prompt).
func (c *Client) SessionEnd(ctx context.Context) error {
	return c.do(ctx, wire.CmdSessionEnd, nil, nil)
}

// Same compares secrets with the first name (verdicts only).
func (c *Client) Same(ctx context.Context, names []string) (wire.SameResult, error) {
	var r wire.SameResult
	return r, c.do(ctx, wire.CmdSame, wire.SameArgs{Names: names}, &r)
}

// Copy creates dst secrets from src secrets inside the broker.
func (c *Client) Copy(ctx context.Context, a wire.CopyArgs) (wire.CopyResult, error) {
	var r wire.CopyResult
	return r, c.do(ctx, wire.CmdCopy, a, &r)
}

// Delete tombstones the named secrets (one approval, all-or-nothing).
func (c *Client) Delete(ctx context.Context, names []string) (wire.DeleteResult, error) {
	var r wire.DeleteResult
	return r, c.do(ctx, wire.CmdDelete, wire.DeleteArgs{Names: names}, &r)
}

// Fingerprint returns the broker's verified-state fingerprint.
func (c *Client) Fingerprint(ctx context.Context) (string, error) {
	var r wire.FingerprintResult
	err := c.do(ctx, wire.CmdFingerprint, nil, &r)
	return r.Fingerprint, err
}

// Conflicts lists items with several heads.
func (c *Client) Conflicts(ctx context.Context) ([]wire.ConflictInfo, error) {
	var l []wire.ConflictInfo
	return l, c.do(ctx, wire.CmdConflicts, nil, &l)
}

// ResolveConflict keeps one head of a conflicted item.
func (c *Client) ResolveConflict(ctx context.Context, a wire.ResolveConflictArgs) error {
	return c.do(ctx, wire.CmdResolveConflict, a, nil)
}

// Sync runs a sync inside the broker.
func (c *Client) Sync(ctx context.Context, a wire.SyncArgs) (wire.SyncResult, error) {
	var r wire.SyncResult
	return r, c.do(ctx, wire.CmdSync, a, &r)
}
