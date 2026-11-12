// Package dir implements transport.Transport over a shared folder
// (Syncthing, USB stick, network share). Layout mirrors KG_HOME:
//
//	members.kgl
//	log/<dev>.kgl
//	checkpoints/<dev>.json
//
// A device only ever writes its own log and checkpoint files; members.kgl is
// append-only and written only when an owner event is pushed.
package dir

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"keygate/internal/transport"
)

var devRe = regexp.MustCompile(`^[A-Za-z0-9_]{1,64}$`)

// Dir is a shared-folder channel.
type Dir struct {
	root string
	self string
}

var _ transport.Transport = (*Dir)(nil)

// New returns a transport rooted at root. self is this device's ID; log and
// checkpoint writes for any other device are refused.
func New(root, self string) (*Dir, error) {
	if !devRe.MatchString(self) {
		return nil, fmt.Errorf("dir: invalid device id")
	}
	return &Dir{root: root, self: self}, nil
}

// Name implements transport.Transport.
func (d *Dir) Name() string { return "dir" }

// Root returns the shared folder path.
func (d *Dir) Root() string { return d.root }

func (d *Dir) membersPath() string { return filepath.Join(d.root, "members.kgl") }
func (d *Dir) logPath(dev string) string {
	return filepath.Join(d.root, "log", dev+".kgl")
}
func (d *Dir) cpPath(dev string) string {
	return filepath.Join(d.root, "checkpoints", dev+".json")
}

// maxFile caps what is read from any channel file.
const maxFile = 64 << 20

var errNotRegular = errors.New("dir: not a regular file")

// ensureDir rejects a symlinked or non-directory path component under root.
func ensureDir(p string) error {
	st, err := os.Lstat(p)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	if !st.IsDir() {
		return fmt.Errorf("dir: %s is not a directory", filepath.Base(p))
	}
	return nil
}

// lstatRegular refuses an existing path that is a symlink or other non-regular
// file (belt and braces next to O_NOFOLLOW, which Windows lacks).
func lstatRegular(p string) error {
	st, err := os.Lstat(p)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	if !st.Mode().IsRegular() {
		return fmt.Errorf("%w: %s", errNotRegular, filepath.Base(p))
	}
	return nil
}

// readCapped reads an open regular file with a size cap.
func readCapped(f *os.File) ([]byte, error) {
	st, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if !st.Mode().IsRegular() {
		return nil, errNotRegular
	}
	if st.Size() > maxFile {
		return nil, fmt.Errorf("dir: file exceeds %d bytes", maxFile)
	}
	data, err := io.ReadAll(io.LimitReader(f, maxFile+1))
	if err != nil {
		return nil, err
	}
	if len(data) > maxFile {
		return nil, fmt.Errorf("dir: file exceeds %d bytes", maxFile)
	}
	return data, nil
}

// completeLines splits data into newline-terminated lines. A final fragment
// without '\n' (torn write) is treated as absent. It also returns the byte
// length of the complete prefix.
func completeLines(data []byte) ([][]byte, int) {
	end := bytes.LastIndexByte(data, '\n') + 1
	var out [][]byte
	for _, l := range bytes.Split(data[:end], []byte("\n")) {
		l = bytes.TrimSuffix(l, []byte("\r"))
		if len(l) == 0 {
			continue
		}
		out = append(out, l)
	}
	return out, end
}

// readFile reads a channel file; missing = nil. Symlinks and non-regular files are refused.
func readFile(path string) ([]byte, error) {
	if err := ensureDir(filepath.Dir(path)); err != nil {
		return nil, err
	}
	if err := lstatRegular(path); err != nil {
		return nil, err
	}
	f, err := os.OpenFile(path, os.O_RDONLY|noFollow, 0)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("dir: open %s: %w", filepath.Base(path), err)
	}
	defer f.Close()
	return readCapped(f)
}

// readLines returns the complete, non-empty lines of a file; a missing file is empty.
func readLines(path string) ([][]byte, error) {
	data, err := readFile(path)
	if err != nil {
		return nil, err
	}
	lines, _ := completeLines(data)
	return lines, nil
}

// appendLine appends line to path, creating parent dirs. want is the 1-based
// position the new line must take. A torn final line is truncated first.
func appendLine(path string, want uint64, line []byte) error {
	if bytes.ContainsAny(line, "\r\n") {
		return errors.New("dir: line contains newline")
	}
	if len(line) == 0 {
		return errors.New("dir: empty line")
	}
	if err := ensureDir(filepath.Dir(path)); err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	if err := lstatRegular(path); err != nil {
		return err
	}
	f, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE|noFollow, 0o600)
	if err != nil {
		return fmt.Errorf("dir: open %s: %w", filepath.Base(path), err)
	}
	defer f.Close()
	data, err := readCapped(f)
	if err != nil {
		return err
	}
	lines, end := completeLines(data)
	have := uint64(len(lines))
	if want <= have {
		return transport.ErrExists
	}
	if want != have+1 {
		return fmt.Errorf("dir: gap: have %d lines, got position %d", have, want)
	}
	if end != len(data) {
		if err := f.Truncate(int64(end)); err != nil {
			return err
		}
	}
	if _, err := f.WriteAt(append(append([]byte{}, line...), '\n'), int64(end)); err != nil {
		return err
	}
	return f.Sync()
}

// Pull implements transport.Transport.
func (d *Dir) Pull(ctx context.Context, since transport.Since) (transport.Snapshot, error) {
	snap := transport.Snapshot{
		Logs:        map[string][][]byte{},
		Checkpoints: map[string][]byte{},
	}
	if err := ctx.Err(); err != nil {
		return snap, err
	}
	if err := ensureDir(filepath.Join(d.root, "checkpoints")); err != nil {
		return snap, err
	}
	cps, err := os.ReadDir(filepath.Join(d.root, "checkpoints"))
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return snap, err
	}
	for _, e := range cps {
		name := e.Name()
		if !e.Type().IsRegular() || !strings.HasSuffix(name, ".json") {
			continue
		}
		dev := strings.TrimSuffix(name, ".json")
		if !devRe.MatchString(dev) {
			continue
		}
		b, err := readFile(d.cpPath(dev))
		if err != nil {
			return snap, err
		}
		snap.Checkpoints[dev] = bytes.TrimSpace(b)
	}
	// Read order matters: checkpoints, then members, then logs, so the snapshot
	// never shows a checkpoint or log newer than the data it references.
	members, err := readLines(d.membersPath())
	if err != nil {
		return snap, err
	}
	if since.Members < len(members) {
		if since.Members < 0 {
			since.Members = 0
		}
		snap.Members = members[since.Members:]
	}
	if err := ensureDir(filepath.Join(d.root, "log")); err != nil {
		return snap, err
	}
	ents, err := os.ReadDir(filepath.Join(d.root, "log"))
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return snap, err
	}
	for _, e := range ents {
		name := e.Name()
		if !e.Type().IsRegular() || !strings.HasSuffix(name, ".kgl") {
			continue
		}
		dev := strings.TrimSuffix(name, ".kgl")
		if !devRe.MatchString(dev) {
			continue
		}
		lines, err := readLines(d.logPath(dev))
		if err != nil {
			return snap, err
		}
		have := since.Logs[dev]
		if have < uint64(len(lines)) {
			snap.Logs[dev] = lines[have:]
		}
	}
	return snap, nil
}

// PushLog implements transport.Transport. seq must be exactly one past the
// lines already in the file; an already-present seq yields transport.ErrExists.
func (d *Dir) PushLog(ctx context.Context, dev string, seq uint64, line []byte) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if dev != d.self {
		return fmt.Errorf("dir: refusing to write log of another device")
	}
	return appendLine(d.logPath(dev), seq, line)
}

// PushMember implements transport.Transport. n is the 0-based event index.
func (d *Dir) PushMember(ctx context.Context, n int, line []byte) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if n < 0 {
		return errors.New("dir: negative member index")
	}
	return appendLine(d.membersPath(), uint64(n)+1, line)
}

// PushCheckpoint implements transport.Transport; it overwrites atomically.
func (d *Dir) PushCheckpoint(ctx context.Context, dev string, body []byte) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if dev != d.self {
		return fmt.Errorf("dir: refusing to write checkpoint of another device")
	}
	p := d.cpPath(dev)
	if err := ensureDir(filepath.Dir(p)); err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(p), ".cp-*.tmp")
	if err != nil {
		return err
	}
	name := tmp.Name()
	_, werr := tmp.Write(body)
	if werr == nil {
		werr = tmp.Sync()
	}
	if cerr := tmp.Close(); werr == nil {
		werr = cerr
	}
	if werr != nil {
		os.Remove(name)
		return werr
	}
	if err := os.Rename(name, p); err != nil {
		os.Remove(name)
		return err
	}
	return nil
}
