package redact

import (
	"bytes"
	"strings"
	"testing"
)

// Two different secrets that overlap in the output: once the first match is masked, no unmasked
// tail of the second may remain visible. All values are fake.
var overlapCases = []struct {
	name    string
	secrets []Secret
	in      string
	leak    string // tail of the second secret that must not appear in the output
}{
	{
		name:    "same length, second starts inside first",
		secrets: []Secret{{"a", "fakeAAAA1234"}, {"b", "1234fakeBBBB"}},
		in:      "out: fakeAAAA1234fakeBBBB end",
		leak:    "fakeBBBB",
	},
	{
		name:    "shorter first match hides longer second",
		secrets: []Secret{{"a", "fakeAAAA1234"}, {"b", "1234fakeBBBBBBBBBBBB"}},
		in:      "out: fakeAAAA1234fakeBBBBBBBBBBBB end",
		leak:    "fakeBBBBBBBBBBBB",
	},
}

func TestOverlappingSecretsBytes(t *testing.T) {
	for _, c := range overlapCases {
		got := New(c.secrets).String(c.in)
		if strings.Contains(got, c.leak) {
			t.Errorf("%s: second secret's suffix %q visible: %q", c.name, c.leak, got)
		}
	}
}

func TestOverlappingSecretsStreaming(t *testing.T) {
	for _, c := range overlapCases {
		r := New(c.secrets)
		for _, chunk := range []int{1, 3, 7, 1000} {
			var out bytes.Buffer
			w := r.NewWriter(&out)
			for i := 0; i < len(c.in); i += chunk {
				if _, err := w.Write([]byte(c.in[i:min(i+chunk, len(c.in))])); err != nil {
					t.Fatal(err)
				}
			}
			if err := w.Flush(); err != nil {
				t.Fatal(err)
			}
			if strings.Contains(out.String(), c.leak) {
				t.Errorf("%s chunk=%d: second secret's suffix %q visible: %q", c.name, chunk, c.leak, out.String())
			}
		}
	}
}
