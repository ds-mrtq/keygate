//go:build windows

package dir

// noFollow is unavailable on Windows; regular-file checks via Lstat/Fstat apply instead.
const noFollow = 0
