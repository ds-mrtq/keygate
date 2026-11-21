package policy

import (
	"reflect"
	"strings"
	"testing"
	"time"
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

// Every setting of a grant must reach review: a field added to Grant later and forgotten by the
// comparison fails here.
func TestEveryGrantFieldChangeIsReviewed(t *testing.T) {
	base := Grant{Pattern: "demo/x", Kind: "env", EnvName: "X", TNSAlias: "A", AllowCommands: []string{"curl"},
		Approval: ApprovalUserPresence, TTL: time.Hour, MaxRuntime: time.Minute, AllowAs: []string{"file"}}
	gt := reflect.TypeOf(base)
	for i := range gt.NumField() {
		name := gt.Field(i).Name
		if name == "Pattern" || name == "Entries" { // the map key; derived from AllowCommands
			continue
		}
		t.Run(name, func(t *testing.T) {
			mod := base
			mod.AllowCommands = slicesClone(base.AllowCommands)
			mod.AllowAs = slicesClone(base.AllowAs)
			f := reflect.ValueOf(&mod).Elem().Field(i)
			switch f.Kind() {
			case reflect.String:
				f.SetString(f.String() + "x")
			case reflect.Int64:
				f.SetInt(f.Int() + int64(time.Millisecond))
			case reflect.Slice:
				f.Set(reflect.Append(f, reflect.ValueOf("wallet")))
			default:
				t.Fatalf("field %s of kind %s: teach this test (and sameGrant) about it", name, f.Kind())
			}
			changes := Changes(&Policy{Grants: []Grant{base}}, &Policy{Grants: []Grant{mod}})
			if len(changes) != 1 || changes[0].Op != ChangeMod || len(changes[0].Added)+len(changes[0].Removed)+len(changes[0].Fields) == 0 {
				t.Fatalf("change of %s not reviewed: %+v", name, changes)
			}
		})
	}
}

func slicesClone(s []string) []string { return append([]string(nil), s...) }

// Dropping `kind: env` makes the broker use the item's own kind (file, template, wallet).
func TestDroppingKindEnvIsAChange(t *testing.T) {
	old, err := Parse([]byte("grants:\n  demo/x:\n    kind: env\n    allow_commands: [curl]\n"))
	if err != nil {
		t.Fatal(err)
	}
	cur, err := Parse([]byte("grants:\n  demo/x:\n    allow_commands: [curl]\n"))
	if err != nil {
		t.Fatal(err)
	}
	changes := Changes(old, cur)
	if len(changes) != 1 || !strings.Contains(changes[0].Text(), "cấp dạng: env → theo kind của secret") {
		t.Fatalf("dropping kind: env not shown: %+v", changes)
	}
}
