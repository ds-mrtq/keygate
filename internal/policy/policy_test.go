package policy

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

const sample = `# comment
oracle:
  java: /opt/jdk/bin/java
  pki_jar: "/opt/sqlcl/lib/oraclepki.jar"
  tns_admin: /opt/tns
grants:
  ebs/test/*:            # glob
    kind: oracle-wallet
    tns_alias: ebs_test
    allow_commands: ["sql /@HTTEST @*.sql", "python path:/repos/x/**/*.py"]
    max_runtime: 5m
    allow_as: [env]
    approval: user-presence
    ttl: 30m
  ebs/test/special:
    kind: env
    env_name: SPECIAL_TOKEN
    allow_commands: [curl, 'node a#b.js !exact']
    approval: user-presence
    ttl: 2h
  "ht/prod/db":
    kind: oracle-wallet
    allow_commands: ["sql /@PROD"]
    approval: user-presence
  ht/prod/*:
    allow_commands: [curl]
    approval: user-presence
  blocked:
    approval: deny
`

func TestParse(t *testing.T) {
	p, err := Parse([]byte(sample))
	if err != nil {
		t.Fatal(err)
	}
	if len(p.Grants) != 5 {
		t.Fatalf("grants=%d", len(p.Grants))
	}
	g := p.Grants[0]
	if g.Pattern != "ebs/test/*" || g.Kind != "oracle-wallet" || g.TNSAlias != "ebs_test" || g.TTL != 30*time.Minute ||
		len(g.Entries) != 2 || g.AllowCommands[1] != "python path:/repos/x/**/*.py" || g.MaxRuntime != 5*time.Minute || len(g.AllowAs) != 1 {
		t.Fatalf("bad grant %+v", g)
	}
	if p.Oracle.Java != "/opt/jdk/bin/java" || p.Oracle.PkiJar != "/opt/sqlcl/lib/oraclepki.jar" || p.Oracle.TNSAdmin != "/opt/tns" {
		t.Fatalf("oracle %+v", p.Oracle)
	}
	if p.Grants[1].TTL != 2*time.Hour || p.Grants[1].AllowCommands[1] != "node a#b.js !exact" || p.Grants[1].EnvName != "SPECIAL_TOKEN" {
		t.Fatalf("bad grant %+v", p.Grants[1])
	}
}

func TestParseErrors(t *testing.T) {
	bad := []string{
		"grants:\n  a:\n    bogus: 1\n",
		"grants:\n  a:\n    approval: maybe\n",
		"grants:\n  a:\n    kind: env\n    kind: file\n",
		"grants:\n  a:\n    allow_commands: sql\n",
		"grants:\n  a: x\n",
		"other:\n  a:\n    kind: env\n",
		"grants:\n  a:\n    allow_commands: [sql\n",
		"grants:\n  a:\n    ttl: abc\n",
		"grants:\n  a:\n    kind: env\n  a:\n    kind: env\n",
		"grants:\n\ta:\n    kind: env\n",
		"grants:\n  a:\n    env_name: JAVA_TOOL_OPTIONS\n",
		"grants:\n  a:\n    env_name: \"X=Y\"\n",
		"grants:\n  a:\n    allow_commands: [sql]\n",
		"grants:\n  a:\n    allow_commands: [bash]\n",
		"grants:\n  a:\n    allow_as: [rocket]\n",
		"oracle:\n  java: relative/java\n",
		"oracle:\n  bogus: /x\n",
	}
	for _, b := range bad {
		if _, err := Parse([]byte(b)); err == nil {
			t.Errorf("expected error for %q", b)
		}
	}
	if p, err := Parse([]byte("grants:\n")); err != nil || len(p.Grants) != 0 {
		t.Errorf("empty grants: %v", err)
	}
}

func TestLookup(t *testing.T) {
	p, _ := Parse([]byte(sample))
	g, err := p.Lookup("ebs/test/special", "test")
	if err != nil || g.Pattern != "ebs/test/special" {
		t.Fatalf("exact should win: %v %+v", err, g)
	}
	g, err = p.Lookup("ebs/test/other", "test")
	if err != nil || g.Pattern != "ebs/test/*" {
		t.Fatalf("glob: %v", err)
	}
	if _, err = p.Lookup("nothing", "dev"); !errors.Is(err, ErrDenied) {
		t.Fatalf("no grant must deny: %v", err)
	}
	if _, err = p.Lookup("blocked", "dev"); !errors.Is(err, ErrDenied) {
		t.Fatalf("deny: %v", err)
	}
	// PROD: exact name with user-presence ok
	if g, err = p.Lookup("ht/prod/db", "prod"); err != nil || g.Pattern != "ht/prod/db" {
		t.Fatalf("prod exact: %v", err)
	}
	// PROD: glob grant with approval none must NOT be honoured
	if _, err = p.Lookup("ht/prod/other", "dev"); !errors.Is(err, ErrDenied) {
		t.Fatalf("prod glob must deny: %v", err)
	}
	// env=prod without any grant
	if _, err = p.Lookup("ebs/test/x", "prod"); !errors.Is(err, ErrDenied) {
		t.Fatalf("env=prod must deny: %v", err)
	}
}

func TestPin(t *testing.T) {
	dir := t.TempDir()
	pin := filepath.Join(dir, "state", "policy.pin")
	key := []byte("0123456789abcdef0123456789abcdef")
	data := []byte(sample)
	if _, err := VerifyPin(pin, data, key); !errors.Is(err, ErrNoPin) {
		t.Fatalf("want ErrNoPin got %v", err)
	}
	if err := WritePin(pin, data, key, 7); err != nil {
		t.Fatal(err)
	}
	if v, err := VerifyPin(pin, data, key); err != nil || v != 7 {
		t.Fatal(v, err)
	}
	if _, err := VerifyPin(pin, append(data, '\n'), key); !errors.Is(err, ErrPinMismatch) {
		t.Fatalf("want mismatch got %v", err)
	}
	if _, err := VerifyPin(pin, data, []byte("another-key-another-key-another!")); err == nil {
		t.Fatal("wrong mac key must fail")
	}
	// version is under the MAC: editing it breaks the pin
	raw, _ := os.ReadFile(pin)
	os.WriteFile(pin, []byte(strings.Replace(string(raw), `"version":7`, `"version":8`, 1)), 0o600)
	if _, err := VerifyPin(pin, data, key); err == nil {
		t.Fatal("version tamper must fail")
	}
	WritePin(pin, data, key, 7)
	pf := filepath.Join(dir, "policy.yaml")
	os.WriteFile(pf, data, 0o600)
	if l, err := LoadVerified(pf, pin, key); err != nil || l.Version != 7 || len(l.Policy.Grants) != 5 {
		t.Fatal(err)
	}
	os.WriteFile(pf, []byte("grants:\n"), 0o600)
	if _, err := LoadVerified(pf, pin, key); !errors.Is(err, ErrPinMismatch) {
		t.Fatalf("tamper: %v", err)
	}
}

func TestIsProd(t *testing.T) {
	yes := [][2]string{{"ebs/prod/x", ""}, {"prod/x", ""}, {"ebs-prod/x", ""}, {"ebs/prd/x", ""}, {"EBS\\PROD\\x", ""}, {"x", " Prod "}, {"x", "prd"}}
	no := [][2]string{{"product/x", "dev"}, {"ebs/test/x", "test"}, {"reprod", ""}}
	for _, c := range yes {
		if !IsProd(c[0], c[1]) {
			t.Errorf("%v should be prod", c)
		}
	}
	for _, c := range no {
		if IsProd(c[0], c[1]) {
			t.Errorf("%v should not be prod", c)
		}
	}
}

func TestDiffAndWarnings(t *testing.T) {
	a, _ := Parse([]byte("grants:\n  x:\n    allow_commands: [curl]\n"))
	tp := filepath.ToSlash(t.TempDir()) + "/tool"
	h := "sha256:" + strings.Repeat("b", 64)
	b, err := Parse([]byte("grants:\n  x:\n    allow_commands: [curl]\n    approval: user-presence\n  ht/prod/*:\n    allow_commands: [\"" + tp + " " + h + "\"]\n    approval: none\n"))
	if err != nil {
		t.Fatal(err)
	}
	d := Changes(a, b)
	if len(d) != 1 || d[0].Op != ChangeAdd || !d[0].Prod {
		t.Fatalf("%v", d)
	}
	ws, kept := Warnings(a, b)
	var wl []string
	for _, x := range ws {
		wl = append(wl, x.Text())
	}
	w := strings.Join(wl, "\n")
	if !strings.Contains(w, "approval none") || !strings.Contains(w, "PROD") || !strings.Contains(w, "glob") || len(kept) != 0 {
		t.Fatalf("warnings: %s kept=%v", w, kept)
	}
	// The same PROD grant approved before is not warned again.
	if ws, kept := Warnings(b, b); len(kept) != 1 || len(ws) != 2 { // approval none + glob, no PROD warning
		t.Fatalf("unchanged PROD grant: warns=%v kept=%v", ws, kept)
	}
}

func TestApprovalNoneNeedsHashPins(t *testing.T) {
	tp := filepath.ToSlash(t.TempDir()) + "/tool"
	h := "sha256:" + strings.Repeat("a", 64)
	bad := []string{
		"grants:\n  a:\n    allow_commands: [curl]\n    approval: none\n",
		"grants:\n  a:\n    allow_commands: [\"python path:/s/a.py\"]\n    approval: none\n",
		"grants:\n  a:\n    allow_commands: [\"" + tp + " sha256:zz\"]\n    approval: none\n",
		"grants:\n  a:\n    allow_commands: [\"python path:/s/*.py " + h + "\"]\n    approval: none\n",
	}
	for _, b := range bad {
		if _, err := Parse([]byte(b)); err == nil {
			t.Errorf("must be rejected: %q", b)
		}
	}
	good := []string{
		"grants:\n  a:\n    allow_commands: [\"python path:/s/a.py " + h + "\"]\n    approval: none\n",
		"grants:\n  a:\n    allow_commands: [\"" + tp + " " + h + "\"]\n    approval: none\n",
		"grants:\n  a:\n    allow_commands: [\"bash path:/s/a.sh " + h + " !exact\"]\n    approval: none\n",
	}
	for _, g := range good {
		if _, err := Parse([]byte(g)); err != nil {
			t.Errorf("%q: %v", g, err)
		}
	}
}

func TestUnpinnedScriptWarningAndPinText(t *testing.T) {
	d := filepath.ToSlash(t.TempDir())
	script := d + "/job.py"
	other := d + "/other.py"
	for _, f := range []string{script, other} {
		if err := os.WriteFile(f, []byte("print(1)"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	src := "# keep me\r\ngrants:\r\n  a/b:\r\n    allow_commands: [\"python path:" + script + "\", \"python path:" + other + " --x\", \"python path:" + d + "/*.py\", curl]  # c\r\n    approval: user-presence\r\n"
	// loads fine without pins...
	p, err := Parse([]byte(src))
	if err != nil {
		t.Fatalf("policy without sha256 must still load: %v", err)
	}
	// ...but Warnings reports the two single-file entries and the glob one
	w, _ := Warnings(nil, p)
	n := 0
	for _, l := range w {
		if strings.Contains(l.Msg, "script không ghim nội dung (sha256)") {
			n++
		}
	}
	if n != 3 {
		t.Fatalf("want 3 unpinned warnings, got %d: %v", n, w)
	}
	hash := func(path string) (string, error) { return "sha256:" + strings.Repeat("c", 64), nil }
	out, ch, errs := PinText([]byte(src), hash)
	if len(errs) != 0 || len(ch) != 2 {
		t.Fatalf("changes %v errs %v", ch, errs)
	}
	h := "sha256:" + strings.Repeat("c", 64)
	want := strings.Replace(src, "python path:"+script+"\"", "python path:"+script+" "+h+"\"", 1)
	want = strings.Replace(want, "python path:"+other+" --x\"", "python path:"+other+" "+h+" --x\"", 1)
	if string(out) != want {
		t.Fatalf("pin text:\n%q\nwant\n%q", out, want)
	}
	p2, err := Parse(out)
	if err != nil {
		t.Fatalf("pinned policy: %v", err)
	}
	w2, _ := Warnings(nil, p2)
	for _, l := range w2 {
		if strings.Contains(l.Msg, "job.py") || strings.Contains(l.Msg, "other.py") {
			t.Errorf("still warned: %s", l.Text())
		}
	}
	// idempotent
	out2, ch2, _ := PinText(out, hash)
	if len(ch2) != 0 || string(out2) != string(out) {
		t.Fatalf("second run must change nothing: %v", ch2)
	}
	// a changed script refreshes the pin
	out3, ch3, _ := PinText(out, func(string) (string, error) { return "sha256:" + strings.Repeat("d", 64), nil })
	if len(ch3) != 2 || strings.Contains(string(out3), strings.Repeat("c", 64)) {
		t.Fatalf("refresh: %v", ch3)
	}
}
