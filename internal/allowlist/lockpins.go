package allowlist

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

// PinFile is one hash-pinned file of a Match: the canonical path that goes into argv (or the
// program path itself) and the `sha256:<hex>` the policy requires.
type PinFile struct {
	Path string
	Hash string
	What string
}

type pinLock struct{ files []*os.File }

// Close releases every held handle (idempotent).
func (l *pinLock) Close() error {
	var first error
	for _, f := range l.files {
		if err := f.Close(); err != nil && first == nil {
			first = err
		}
	}
	l.files = nil
	return first
}

// LockPins is the exec-time half of the pin check (DESIGN sec 9, A4): for every pinned file it
// opens the canonical path with a handle that, on Windows, denies write/delete/rename by others
// (FILE_SHARE_READ only), re-verifies the hash FROM THAT HANDLE and keeps the handle open until
// Close. Call it right before starting the child and Close after the child exits. On other systems
// there is no mandatory lock: the handle is opened O_NOFOLLOW and the hash re-checked, a small
// TOCTOU window remains between that check and the child opening the file.
func (m *Match) LockPins() (io.Closer, error) {
	l := &pinLock{}
	for _, p := range m.Pins {
		f, err := openLocked(p.Path)
		if err != nil {
			l.Close()
			return nil, fmt.Errorf("%w: không khóa được %s: %v", ErrBlocked, p.What, err)
		}
		l.files = append(l.files, f)
		got, err := hashHandle(f)
		if err != nil {
			l.Close()
			return nil, fmt.Errorf("%w: không băm được %s: %v", ErrBlocked, p.What, err)
		}
		if got != p.Hash {
			l.Close()
			return nil, fmt.Errorf("%w: nội dung %s đã đổi so với hash ghim trong policy (hash hiện tại %s, policy ghi %s)", ErrBlocked, p.What, got, p.Hash)
		}
	}
	return l, nil
}

// hashHandle hashes an already opened regular file (size capped).
func hashHandle(f *os.File) (string, error) {
	st, err := f.Stat()
	if err != nil {
		return "", err
	}
	if !st.Mode().IsRegular() {
		return "", errors.New("không phải file thường")
	}
	if st.Size() > MaxPinnedFile {
		return "", fmt.Errorf("file lớn hơn %d MiB", MaxPinnedFile>>20)
	}
	b, err := io.ReadAll(io.LimitReader(f, MaxPinnedFile+1))
	if err != nil {
		return "", err
	}
	if len(b) > MaxPinnedFile {
		return "", fmt.Errorf("file lớn hơn %d MiB", MaxPinnedFile>>20)
	}
	h := sha256.Sum256(b)
	return "sha256:" + hex.EncodeToString(h[:]), nil
}

// canonArgs returns args with every argument matched by a `path:`/`@path:` pattern replaced by the
// canonical path that was matched (Abs + Clean + EvalSymlinks, "@" prefix kept), so a later symlink
// swap cannot change what runs. Arguments beyond the patterns are kept verbatim.
func canonArgs(pats, args []string, dir string) []string {
	out := append([]string(nil), args...)
	for i, p := range pats {
		if i >= len(out) {
			break
		}
		prefix := ""
		if strings.HasPrefix(p, "@") {
			prefix, p = "@", p[1:]
		}
		if !strings.HasPrefix(p, "path:") {
			continue
		}
		a := strings.TrimPrefix(out[i], prefix)
		if !filepath.IsAbs(a) {
			a = filepath.Join(dir, a)
		}
		out[i] = prefix + canon(a)
	}
	return out
}

// CanonDir resolves a run directory the way Check does (empty = current directory of the broker),
// then follows symlinks, so grants and approvals are bound to the real directory.
func CanonDir(dir string) string {
	if dir == "" {
		dir = "."
	}
	return canon(dir)
}
