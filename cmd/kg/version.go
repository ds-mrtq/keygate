package main

import (
	"fmt"
	"runtime"
	"runtime/debug"
)

// version and commit are set by release builds:
// go build -ldflags "-X main.version=v0.1.0 -X main.commit=<sha>" ./cmd/kg
var (
	version = "dev"
	commit  = ""
)

// versionLine is the output of `kg version`: "kg <version> (commit <sha>, <os>/<arch>)".
func versionLine() string {
	c := commit
	if len(c) > 12 {
		c = c[:12]
	}
	if c == "" {
		c = buildRevision()
	}
	if c == "" {
		c = "unknown"
	}
	return fmt.Sprintf("kg %s (commit %s, %s/%s)", version, c, runtime.GOOS, runtime.GOARCH)
}

// buildRevision is the VCS revision the Go toolchain stamped into a plain `go build`, if any.
func buildRevision() string {
	info, ok := debug.ReadBuildInfo()
	if !ok {
		return ""
	}
	rev, dirty := "", false
	for _, s := range info.Settings {
		switch s.Key {
		case "vcs.revision":
			rev = s.Value
		case "vcs.modified":
			dirty = s.Value == "true"
		}
	}
	if len(rev) > 12 {
		rev = rev[:12]
	}
	if rev != "" && dirty {
		rev += "-dirty"
	}
	return rev
}
