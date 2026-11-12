// Package git implements transport.Transport as a shared-folder channel
// (package dir) living inside a git work tree. Writes are committed and pushed
// with the git binary; reads first pull --rebase. A work tree without a remote
// is allowed (local-only use and tests).
package git

import (
	"bytes"
	"context"
	"fmt"
	"os/exec"
	"strings"

	"keygate/internal/transport"
	"keygate/internal/transport/dir"
)

// Git is a git-backed channel.
type Git struct {
	d       *dir.Dir
	repo    string
	remote  string
	batch   bool
	pending bool
}

var _ transport.Transport = (*Git)(nil)

// New returns a transport over the git work tree at repo (must already be a
// git repository). self is this device's ID. remote defaults to "origin".
func New(repo, self string) (*Git, error) {
	d, err := dir.New(repo, self)
	if err != nil {
		return nil, err
	}
	g := &Git{d: d, repo: repo, remote: "origin"}
	if _, err := g.run(context.Background(), "rev-parse", "--git-dir"); err != nil {
		return nil, fmt.Errorf("git: %s is not a git work tree: %w", repo, err)
	}
	return g, nil
}

// Name implements transport.Transport.
func (g *Git) Name() string { return "git" }

// SetBatch defers commit+push of writes until Flush is called.
func (g *Git) SetBatch(on bool) { g.batch = on }

func (g *Git) run(ctx context.Context, args ...string) (string, error) {
	full := append([]string{"-c", "user.name=keygate", "-c", "user.email=keygate@localhost"}, args...)
	cmd := exec.CommandContext(ctx, "git", full...)
	cmd.Dir = g.repo
	cmd.Env = append(cmd.Environ(), "GIT_TERMINAL_PROMPT=0")
	var out, errb bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &errb
	if err := cmd.Run(); err != nil {
		return out.String(), fmt.Errorf("git %s: %w: %s", args[0], err, strings.TrimSpace(errb.String()))
	}
	return out.String(), nil
}

// hasRemote reports whether the remote is configured and has any branch.
func (g *Git) hasRemote(ctx context.Context) (bool, error) {
	out, err := g.run(ctx, "remote")
	if err != nil {
		return false, err
	}
	found := false
	for _, r := range strings.Fields(out) {
		if r == g.remote {
			found = true
		}
	}
	return found, nil
}

func (g *Git) branch(ctx context.Context) (string, error) {
	out, err := g.run(ctx, "symbolic-ref", "--short", "HEAD")
	return strings.TrimSpace(out), err
}

// pull runs git pull --rebase when a remote with commits exists.
func (g *Git) pull(ctx context.Context) error {
	ok, err := g.hasRemote(ctx)
	if err != nil || !ok {
		return err
	}
	br, err := g.branch(ctx)
	if err != nil {
		return err
	}
	heads, err := g.run(ctx, "ls-remote", "--heads", g.remote, br)
	if err != nil {
		return err
	}
	if strings.TrimSpace(heads) == "" {
		return nil // remote branch not created yet
	}
	if g.hasUncommitted(ctx) {
		// rebase refuses a dirty tree; commit first.
		if err := g.commit(ctx); err != nil {
			return err
		}
	}
	_, err = g.run(ctx, "pull", "--rebase", g.remote, br)
	return err
}

func (g *Git) hasUncommitted(ctx context.Context) bool {
	out, err := g.run(ctx, "status", "--porcelain")
	return err == nil && strings.TrimSpace(out) != ""
}

func (g *Git) commit(ctx context.Context) error {
	if _, err := g.run(ctx, "add", "-A"); err != nil {
		return err
	}
	if !g.hasUncommitted(ctx) {
		return nil
	}
	_, err := g.run(ctx, "commit", "-q", "-m", "keygate sync")
	return err
}

// Flush commits local changes and pushes them (retrying once after a rebase
// when the push is rejected). Push is skipped when there is no remote.
func (g *Git) Flush(ctx context.Context) error {
	if err := g.commit(ctx); err != nil {
		return err
	}
	ok, err := g.hasRemote(ctx)
	if err != nil || !ok {
		g.pending = false
		return err
	}
	br, err := g.branch(ctx)
	if err != nil {
		return err
	}
	if _, err := g.run(ctx, "push", g.remote, "HEAD:refs/heads/"+br); err != nil {
		if perr := g.pull(ctx); perr != nil {
			return perr
		}
		if _, err = g.run(ctx, "push", g.remote, "HEAD:refs/heads/"+br); err != nil {
			return err
		}
	}
	g.pending = false
	return nil
}

// Pull implements transport.Transport.
func (g *Git) Pull(ctx context.Context, since transport.Since) (transport.Snapshot, error) {
	if err := g.pull(ctx); err != nil {
		return transport.Snapshot{}, err
	}
	// dir.Pull reads checkpoints, then members, then logs, so the snapshot never shows newer references than data.
	return g.d.Pull(ctx, since)
}

func (g *Git) after(ctx context.Context, err error) error {
	if err != nil {
		return err
	}
	g.pending = true
	if g.batch {
		return nil
	}
	return g.Flush(ctx)
}

// PushLog implements transport.Transport.
func (g *Git) PushLog(ctx context.Context, dev string, seq uint64, line []byte) error {
	if !g.batch {
		if err := g.pull(ctx); err != nil {
			return err
		}
	}
	return g.after(ctx, g.d.PushLog(ctx, dev, seq, line))
}

// PushMember implements transport.Transport.
func (g *Git) PushMember(ctx context.Context, n int, line []byte) error {
	if !g.batch {
		if err := g.pull(ctx); err != nil {
			return err
		}
	}
	return g.after(ctx, g.d.PushMember(ctx, n, line))
}

// PushCheckpoint implements transport.Transport.
func (g *Git) PushCheckpoint(ctx context.Context, dev string, body []byte) error {
	if !g.batch {
		if err := g.pull(ctx); err != nil {
			return err
		}
	}
	return g.after(ctx, g.d.PushCheckpoint(ctx, dev, body))
}
