// Package fsx has small file helpers: atomic writes and fsynced appends.
package fsx

import (
	"bytes"
	"os"
	"path/filepath"
)

// WriteAtomic writes data to path via a temp file + rename, mode 0600.
func WriteAtomic(path string, data []byte) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	f, err := os.CreateTemp(filepath.Dir(path), ".tmp-*")
	if err != nil {
		return err
	}
	tmp := f.Name()
	if _, err := f.Write(data); err != nil {
		f.Close()
		os.Remove(tmp)
		return err
	}
	if err := f.Sync(); err != nil {
		f.Close()
		os.Remove(tmp)
		return err
	}
	if err := f.Close(); err != nil {
		os.Remove(tmp)
		return err
	}
	if err := os.Chmod(tmp, 0o600); err != nil {
		os.Remove(tmp)
		return err
	}
	if err := os.Rename(tmp, path); err != nil {
		os.Remove(tmp)
		return err
	}
	return nil
}

// AppendLines appends each line plus "\n" to path (created 0600) and fsyncs.
func AppendLines(path string, lines ...[]byte) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	var buf bytes.Buffer
	for _, l := range lines {
		buf.Write(l)
		buf.WriteByte('\n')
	}
	if _, err := f.Write(buf.Bytes()); err != nil {
		f.Close()
		return err
	}
	if err := f.Sync(); err != nil {
		f.Close()
		return err
	}
	return f.Close()
}

// ReadLines returns the non-empty lines of a file (nil, nil if it does not exist).
func ReadLines(path string) ([][]byte, error) {
	b, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var out [][]byte
	for _, l := range bytes.Split(b, []byte("\n")) {
		l = bytes.TrimSuffix(l, []byte("\r"))
		if len(l) > 0 {
			out = append(out, l)
		}
	}
	return out, nil
}

// ReadLinesRepair is ReadLines for append-only logs written by this program: a final line
// without a trailing newline is a torn write, so it is truncated away (reported via repaired).
func ReadLinesRepair(path string) (lines [][]byte, repaired bool, err error) {
	b, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return nil, false, nil
	}
	if err != nil {
		return nil, false, err
	}
	if len(b) > 0 && b[len(b)-1] != '\n' {
		keep := bytes.LastIndexByte(b, '\n') + 1
		if err := os.Truncate(path, int64(keep)); err != nil {
			return nil, false, err
		}
		b, repaired = b[:keep], true
	}
	for _, l := range bytes.Split(b, []byte("\n")) {
		l = bytes.TrimSuffix(l, []byte("\r"))
		if len(l) > 0 {
			lines = append(lines, l)
		}
	}
	return lines, repaired, nil
}
