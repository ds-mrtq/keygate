// Package audit is the hash-chained, per-line HMAC'd audit ledger (DESIGN sec 13).
// It never records secret values.
package audit

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"keygate/internal/fsx"
)

// Event names.
const (
	EvGrant        = "grant"
	EvRunStart     = "run-start"
	EvRun          = "run"
	EvReveal       = "reveal"
	EvDeny         = "deny"
	EvSet          = "set"
	EvImport       = "import"
	EvDelete       = "delete"
	EvCompare      = "compare"
	EvSession      = "session"
	EvSame         = "same"
	EvCopy         = "copy"
	EvPolicy       = "policy"
	EvGrantRevoke  = "grant-revoke"
	EvDeviceAdd    = "device-add"
	EvDeviceRevoke = "device-revoke"
)

// Entry is one ledger line. Field order is the canonical serialization order.
type Entry struct {
	N        uint64   `json:"n"`
	Time     string   `json:"time"`
	Prev     *string  `json:"prev"`
	Event    string   `json:"event"`
	Secret   string   `json:"secret,omitempty"`
	Env      string   `json:"env,omitempty"`
	Argv     []string `json:"argv,omitempty"`
	Agent    string   `json:"agent,omitempty"`
	Peer     string   `json:"peer,omitempty"` // calling process (pid/exe) when the OS tells
	Session  string   `json:"session,omitempty"`
	Approval string   `json:"approval,omitempty"`
	Exit     *int     `json:"exit,omitempty"`
	MAC      string   `json:"mac,omitempty"`
}

// ErrTruncated means the ledger is shorter than (or inconsistent with) its anchored head.
var ErrTruncated = errors.New("audit bị cắt/xóa so với neo đầu chuỗi")

type anchor struct {
	Count uint64 `json:"count"`
	Head  string `json:"head"`
	MAC   string `json:"mac"`
}

// Ledger appends to and verifies one ledger file; the head hash and line count are anchored
// (MAC'd) in a separate file so truncating the tail or deleting the ledger is detected.
type Ledger struct {
	path   string
	anchor string
	key    []byte
	mu     sync.Mutex
	now    func() time.Time
}

// Open returns a Ledger for path using macKey (the local-mac key); anchorPath holds the anchored head.
func Open(path, anchorPath string, macKey []byte) *Ledger {
	return &Ledger{path: path, anchor: anchorPath, key: append([]byte(nil), macKey...), now: time.Now}
}

func (l *Ledger) anchorMAC(a anchor) string {
	m := hmac.New(sha256.New, l.key)
	m.Write([]byte("kg/v1/local-mac\x00audit-head\x00"))
	fmt.Fprintf(m, "%d\x00%s", a.Count, a.Head)
	return base64.StdEncoding.EncodeToString(m.Sum(nil))
}

// readAnchor returns (nil, nil) when no anchor file exists.
func (l *Ledger) readAnchor() (*anchor, error) {
	raw, err := os.ReadFile(l.anchor)
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var a anchor
	if err := json.Unmarshal(raw, &a); err != nil {
		return nil, fmt.Errorf("neo audit hỏng: %w", err)
	}
	if !hmac.Equal([]byte(l.anchorMAC(a)), []byte(a.MAC)) {
		return nil, errors.New("neo audit sai MAC")
	}
	return &a, nil
}

func (l *Ledger) writeAnchor(count uint64, lastLine []byte) error {
	a := anchor{Count: count, Head: lineHash(lastLine)}
	a.MAC = l.anchorMAC(a)
	b, _ := json.Marshal(a)
	return fsx.WriteAtomic(l.anchor, b)
}

// checkAnchor compares the ledger lines with the anchor (nil anchor only fits an empty ledger).
func (l *Ledger) checkAnchor(lines [][]byte) error {
	a, err := l.readAnchor()
	if err != nil {
		return err
	}
	if a == nil {
		if len(lines) > 0 {
			return fmt.Errorf("%w: thiếu file neo", ErrTruncated)
		}
		return nil
	}
	n := uint64(len(lines))
	if n < a.Count {
		return fmt.Errorf("%w: có %d dòng, neo ghi %d", ErrTruncated, n, a.Count)
	}
	if a.Count > 0 && lineHash(lines[a.Count-1]) != a.Head {
		return fmt.Errorf("%w: dòng %d không khớp hash neo", ErrTruncated, a.Count-1)
	}
	if n > a.Count+1 {
		return fmt.Errorf("%w: %d dòng sau neo", ErrTruncated, n-a.Count)
	}
	return nil
}

func lineHash(line []byte) string {
	h := sha256.Sum256(line)
	return "sha256:" + fmt.Sprintf("%x", h[:])
}

func (l *Ledger) mac(e Entry) (string, error) {
	e.MAC = ""
	b, err := json.Marshal(e)
	if err != nil {
		return "", err
	}
	m := hmac.New(sha256.New, l.key)
	m.Write([]byte("kg/v1/local-mac\x00audit\x00"))
	m.Write(b)
	return base64.StdEncoding.EncodeToString(m.Sum(nil)), nil
}

// Append adds an entry (N, Time, Prev and MAC are filled in).
func (l *Ledger) Append(e Entry) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	lines, err := fsx.ReadLines(l.path)
	if err != nil {
		return err
	}
	if err := l.checkAnchor(lines); err != nil {
		return err
	}
	e.N = uint64(len(lines))
	e.Time = l.now().UTC().Format(time.RFC3339Nano)
	e.Prev = nil
	if len(lines) > 0 {
		h := lineHash(lines[len(lines)-1])
		e.Prev = &h
	}
	if e.MAC, err = l.mac(e); err != nil {
		return err
	}
	b, err := json.Marshal(e)
	if err != nil {
		return err
	}
	if err := fsx.AppendLines(l.path, b); err != nil {
		return err
	}
	return l.writeAnchor(e.N+1, b)
}

// Verify checks the hash chain and every MAC; it returns the number of entries.
func (l *Ledger) Verify() (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	lines, err := fsx.ReadLines(l.path)
	if err != nil {
		return 0, err
	}
	var prev []byte
	for i, ln := range lines {
		var e Entry
		if err := json.Unmarshal(ln, &e); err != nil {
			return i, fmt.Errorf("audit dòng %d: %w", i, err)
		}
		if e.N != uint64(i) {
			return i, fmt.Errorf("audit dòng %d: n=%d sai thứ tự", i, e.N)
		}
		switch {
		case i == 0 && e.Prev != nil:
			return i, fmt.Errorf("audit dòng 0: prev phải rỗng")
		case i > 0 && (e.Prev == nil || *e.Prev != lineHash(prev)):
			return i, fmt.Errorf("audit dòng %d: chuỗi hash đứt", i)
		}
		want, err := l.mac(e)
		if err != nil {
			return i, err
		}
		if !hmac.Equal([]byte(want), []byte(e.MAC)) {
			return i, fmt.Errorf("audit dòng %d: MAC sai", i)
		}
		// Re-serialization must be byte-identical, otherwise fields were added outside the MAC.
		if rb, _ := json.Marshal(e); !bytes.Equal(rb, ln) {
			return i, fmt.Errorf("audit dòng %d: nội dung không chuẩn", i)
		}
		prev = ln
	}
	if err := l.checkAnchor(lines); err != nil {
		return len(lines), err
	}
	return len(lines), nil
}

// ShowVerified verifies the whole ledger (chain, MACs, anchor) and then returns the entries.
func (l *Ledger) ShowVerified(since time.Time) ([]Entry, error) {
	if _, err := l.Verify(); err != nil {
		return nil, err
	}
	return l.Show(since)
}

// Show returns entries whose time is >= since (zero = all). It does not verify MACs.
func (l *Ledger) Show(since time.Time) ([]Entry, error) {
	lines, err := fsx.ReadLines(l.path)
	if err != nil {
		return nil, err
	}
	var out []Entry
	for i, ln := range lines {
		var e Entry
		if err := json.Unmarshal(ln, &e); err != nil {
			return nil, fmt.Errorf("audit dòng %d: %w", i, err)
		}
		if !since.IsZero() {
			t, err := time.Parse(time.RFC3339Nano, e.Time)
			if err != nil || t.Before(since) {
				continue
			}
		}
		out = append(out, e)
	}
	return out, nil
}

// ParseSince turns "7d", "12h", "30m" or an RFC3339 timestamp into a time (now-relative).
func ParseSince(s string, now time.Time) (time.Time, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return time.Time{}, nil
	}
	if t, err := time.Parse(time.RFC3339, s); err == nil {
		return t, nil
	}
	if strings.HasSuffix(s, "d") {
		n, err := strconv.Atoi(strings.TrimSuffix(s, "d"))
		if err != nil || n < 0 {
			return time.Time{}, fmt.Errorf("--since %q không hợp lệ", s)
		}
		return now.Add(-time.Duration(n) * 24 * time.Hour), nil
	}
	d, err := time.ParseDuration(s)
	if err != nil {
		return time.Time{}, fmt.Errorf("--since %q không hợp lệ", s)
	}
	return now.Add(-d), nil
}
