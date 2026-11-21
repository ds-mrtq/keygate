package policy

import (
	"strings"
	"testing"
)

func TestNewGrantApprovalDisclosesConfiguredLimits(t *testing.T) {
	p, err := Parse([]byte(`grants:
  demo/report:
    kind: env
    allow_commands: [curl]
    max_runtime: 3m
    allow_as: [file, wallet]
`))
	if err != nil {
		t.Fatal(err)
	}
	changes := Changes(nil, p)
	if len(changes) != 1 || changes[0].Op != ChangeAdd {
		t.Fatalf("want one new grant, got %+v", changes)
	}

	got := changes[0].Text()
	for _, want := range []string{
		"chạy tối đa: 3 phút",
		"cho đổi dạng (--as): file, wallet",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("approval text omits %q:\n%s", want, got)
		}
	}
}
