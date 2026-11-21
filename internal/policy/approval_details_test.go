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

// Splitting one allow_commands entry into two prints the same with fmt.Sprint; it must still be a change.
func TestSplitCommandEntryIsAChange(t *testing.T) {
	parse := func(cmds string) *Policy {
		p, err := Parse([]byte("grants:\n  demo/report:\n    allow_commands: " + cmds + "\n"))
		if err != nil {
			t.Fatal(err)
		}
		return p
	}
	changes := Changes(parse(`["curl jq"]`), parse(`[curl, jq]`))
	if len(changes) != 1 || changes[0].Op != ChangeMod || len(changes[0].Added) != 2 || len(changes[0].Removed) != 1 {
		t.Fatalf("split entry not reported: %+v", changes)
	}
	if changes := Changes(parse(`[curl, jq]`), parse(`[jq, curl]`)); len(changes) != 1 || len(changes[0].Fields) != 1 {
		t.Fatalf("reorder not reported: %+v", changes)
	}
	if changes := Changes(parse(`[curl, jq]`), parse(`[curl, jq]`)); len(changes) != 0 {
		t.Fatalf("identical policy reported: %+v", changes)
	}
}
