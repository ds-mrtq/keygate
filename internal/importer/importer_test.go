package importer

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func write(t *testing.T, name, content string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

const sampleEnv = "# top comment\n" +
	"\n" +
	"OPENAI_API_KEY=sk-abc123\n" +
	"export DB_PASS=\"p@ss word\" # trailing\n" +
	"SINGLE='lit$eral'\n" +
	"ALREADY=${secret:llm/x}\n" +
	"EMPTY=\n" +
	"URL=http://h/#frag\n" +
	"SPACED = spaced value  # c\n" +
	"MULTI=\"line1\nline2\"\n" +
	"LAST=end"

func TestParseDotenv(t *testing.T) {
	p := write(t, ".env", sampleEnv)
	es, err := ParseDotenv(p)
	if err != nil {
		t.Fatal(err)
	}
	want := []Entry{
		{"OPENAI_API_KEY", "sk-abc123", 3},
		{"DB_PASS", "p@ss word", 4},
		{"SINGLE", "lit$eral", 5},
		{"URL", "http://h/#frag", 8},
		{"SPACED", "spaced value", 9},
		{"MULTI", "line1\nline2", 10},
		{"LAST", "end", 12},
	}
	if len(es) != len(want) {
		t.Fatalf("got %d entries: %+v", len(es), es)
	}
	for i := range want {
		if es[i] != want[i] {
			t.Errorf("entry %d: got %+v want %+v", i, es[i], want[i])
		}
	}
}

func TestRewriteDotenv(t *testing.T) {
	p := write(t, ".env", sampleEnv)
	err := RewriteDotenv(p, map[string]string{
		"OPENAI_API_KEY": "llm/openai-api-key",
		"DB_PASS":        "db/pass",
		"MULTI":          "misc/multi",
		"LAST":           "misc/last",
		"ALREADY":        "ignored",
		"NOPE":           "x",
	})
	if err != nil {
		t.Fatal(err)
	}
	got, _ := os.ReadFile(p)
	want := "# top comment\n\nOPENAI_API_KEY=${secret:llm/openai-api-key}\n" +
		"export DB_PASS=${secret:db/pass} # trailing\n" +
		"SINGLE='lit$eral'\nALREADY=${secret:llm/x}\nEMPTY=\nURL=http://h/#frag\nSPACED = spaced value  # c\n" +
		"MULTI=${secret:misc/multi}\nLAST=${secret:misc/last}"
	if string(got) != want {
		t.Fatalf("got:\n%s\nwant:\n%s", got, want)
	}
	// Second parse finds only the untouched literals.
	es, _ := ParseDotenv(p)
	for _, e := range es {
		if e.Key == "OPENAI_API_KEY" || e.Key == "DB_PASS" {
			t.Fatalf("still literal: %s", e.Key)
		}
	}
	// no temp files left behind
	ents, _ := os.ReadDir(filepath.Dir(p))
	if len(ents) != 1 {
		t.Fatalf("leftover files: %v", ents)
	}
}

func TestRewriteDotenvCRLF(t *testing.T) {
	p := write(t, ".env", "A=one\r\nB=\"two\" # c\r\n")
	if err := RewriteDotenv(p, map[string]string{"A": "a", "B": "b"}); err != nil {
		t.Fatal(err)
	}
	got, _ := os.ReadFile(p)
	if string(got) != "A=${secret:a}\r\nB=${secret:b} # c\r\n" {
		t.Fatalf("%q", got)
	}
}

func TestParseDotenvMissing(t *testing.T) {
	if _, err := ParseDotenv(filepath.Join(t.TempDir(), "nope")); err == nil {
		t.Fatal("want error")
	}
}

func TestGitleaksRoundtrip(t *testing.T) {
	dir := t.TempDir()
	src := filepath.Join(dir, "cfg.yml")
	os.WriteFile(src, []byte("a: 1\nkey: \"AKIAXXXXXXXXXXXX\"\nother: AKIAXXXXXXXXXXXX\n"), 0o644)
	rep := filepath.Join(dir, "r.json")
	js := `[{"RuleID":"aws","File":` + jsonStr(src) + `,"StartLine":2,"Secret":"AKIAXXXXXXXXXXXX","Match":"x"}]`
	os.WriteFile(rep, []byte(js), 0o600)
	fs, err := ParseGitleaks(rep)
	if err != nil || len(fs) != 1 || fs[0].StartLine != 2 || fs[0].RuleID != "aws" {
		t.Fatalf("%+v %v", fs, err)
	}
	if err := RewriteFinding(fs[0], "cloud/aws-key"); err != nil {
		t.Fatal(err)
	}
	got, _ := os.ReadFile(src)
	want := "a: 1\nkey: \"${secret:cloud/aws-key}\"\nother: AKIAXXXXXXXXXXXX\n"
	if string(got) != want {
		t.Fatalf("got %q", got)
	}
	// second call: secret no longer at that line
	err = RewriteFinding(fs[0], "cloud/aws-key")
	if err == nil {
		t.Fatal("want not-found error")
	}
	if strings.Contains(err.Error(), "AKIAXXXXXXXXXXXX") {
		t.Fatal("error leaks secret")
	}
}

func jsonStr(s string) string {
	return `"` + strings.ReplaceAll(strings.ReplaceAll(s, `\`, `\\`), `"`, `\"`) + `"`
}

func TestGitleaksRedactedRejected(t *testing.T) {
	rep := write(t, "r.json", `[{"RuleID":"x","File":"f","StartLine":1,"Secret":"REDACTED"}]`)
	if _, err := ParseGitleaks(rep); err == nil {
		t.Fatal("want error for redacted report")
	}
	bad := write(t, "b.json", `not json`)
	if _, err := ParseGitleaks(bad); err == nil {
		t.Fatal("want error")
	}
}

func TestRewriteFindingBadLine(t *testing.T) {
	p := write(t, "f.txt", "only\n")
	if err := RewriteFinding(Finding{File: p, StartLine: 5, Secret: "x"}, "r"); err == nil {
		t.Fatal("want error")
	}
}

func TestSuggestName(t *testing.T) {
	cases := [][3]string{
		{"llm/", "OPENAI_API_KEY", "llm/openai-api-key"},
		{"llm", "OPENAI_API_KEY", "llm/openai-api-key"},
		{"", "DB_PASS", "db-pass"},
		{"db/test/", "Password", "db/test/password"},
	}
	for _, c := range cases {
		if g := SuggestName(c[0], c[1]); g != c[2] {
			t.Errorf("SuggestName(%q,%q)=%q want %q", c[0], c[1], g, c[2])
		}
	}
}
