package policy

import "testing"

func TestDiffAllowCommandsEntryBoundaryChange(t *testing.T) {
	old, err := Parse([]byte("grants:\n  fake/secret:\n    allow_commands: [\"fake-client upload\", \"fake-helper\"]\n"))
	if err != nil {
		t.Fatal(err)
	}
	cur, err := Parse([]byte("grants:\n  fake/secret:\n    allow_commands: [\"fake-client\", \"upload fake-helper\"]\n"))
	if err != nil {
		t.Fatal(err)
	}

	changes := Changes(old, cur)
	if len(changes) != 1 {
		t.Fatalf("allow_commands entry boundary change: got %d changes, want 1 ChangeMod: %+v", len(changes), changes)
	}
	c := changes[0]
	if c.Op != ChangeMod || c.Secret != "fake/secret" || len(c.Added) == 0 || len(c.Removed) == 0 {
		t.Fatalf("allow_commands entry boundary change: want ChangeMod for fake/secret with added and removed commands, got %+v", c)
	}
}
