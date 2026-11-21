package policy

import (
	"strings"
	"testing"
)

// Day counts past the time.Duration range (about 106751 days) must be rejected like the
// overflowing Go durations time.ParseDuration already refuses, not wrapped around.
func TestParseTTLRejectsDayOverflow(t *testing.T) {
	for _, s := range []string{"106752d", "213504d", "9999999999999d"} {
		if d, err := ParseTTL(s); err == nil {
			t.Errorf("ParseTTL(%q) = %v, want error", s, d)
		}
	}
	if _, err := ParseTTL("2562048h"); err == nil {
		t.Fatal("ParseDuration overflow accepted")
	}
}

// A grant whose ttl overflows must not load as a grant with a wrapped (here negative, so
// never-expiring) TTL.
func TestParseRejectsOverflowingTTL(t *testing.T) {
	doc := "grants:\n  app/key:\n    allow_commands: [tool]\n    ttl: 9999999999999d\n    max_runtime: 9999999999999d\n"
	p, err := Parse([]byte(doc))
	if err == nil {
		t.Fatalf("accepted ttl=%v max_runtime=%v", p.Grants[0].TTL, p.Grants[0].MaxRuntime)
	}
	if !strings.Contains(err.Error(), "ttl") {
		t.Fatalf("error %v does not name the ttl", err)
	}
}

// FuzzParseTTL: an accepted ttl is always a positive duration.
func FuzzParseTTL(f *testing.F) {
	for _, s := range []string{"30m", "2h", "3d", "0d", "-1h", "106752d", " 1d ", "1.5h"} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		if d, err := ParseTTL(s); err == nil && d <= 0 {
			t.Fatalf("ParseTTL(%q) = %v", s, d)
		}
	})
}
