package broker

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"keygate/internal/allowlist"
	"keygate/internal/api"
	"keygate/internal/record"
	"keygate/internal/store"
)

// Fake values only (LeakBench D06 shape).
const fakeKubeToken = "kgfake-eyJhbGciOiJSUzI1NiJ9.Zm9vYmFyLXRlc3Q.c2lnLW5vdC1yZWFs"

const fakeKubeconfig = "apiVersion: v1\nkind: Config\nclusters:\n- name: test\n  cluster:\n    server: https://127.0.0.1:6443\n" +
	"users:\n- name: tester\n  user:\n    token: " + fakeKubeToken + "\n"

// TestRunMasksTokenParsedFromKubeconfig: a child given an imported kubeconfig as a file secret
// parses the bearer token out and prints it on its own; kg run must mask it (LeakBench D06).
// Fails on main: only the whole file value is masked.
func TestRunMasksTokenParsedFromKubeconfig(t *testing.T) {
	f := newFixture(t, time.Hour, time.Hour)
	f.withStore(func(st *store.Store) {
		if _, err := st.Put("", record.Plain{Name: "k8s/test/kubeconfig", Value: fakeKubeconfig, Env: "test", Kind: "file", EnvName: "KUBECONFIG"}); err != nil {
			t.Fatal(err)
		}
	})
	exe, _ := filepath.Abs(os.Args[0])
	exeHash, err := allowlist.FileHash(exe)
	if err != nil {
		t.Fatal(err)
	}
	f.policy(`grants:
  k8s/test/kubeconfig:
    allow_commands: ["\"`+filepath.ToSlash(exe)+`\" `+exeHash+` -test.run=TestKubeTokenHelper"]
    approval: none
    max_runtime: 1m
`, true)
	t.Setenv("KG_KUBE_HELPER", "1")
	var out bytes.Buffer
	code, err := f.cli.Run(context.Background(), api.RunRequest{Secrets: []string{"k8s/test/kubeconfig"}, Argv: []string{exe, "-test.run=TestKubeTokenHelper"}, Agent: "t"}, &out, &out)
	if err != nil || code != 0 {
		t.Fatalf("run: %d %v\n%s", code, err, out.String())
	}
	got := out.String()
	if !strings.Contains(got, "file=[kg:k8s/test/kubeconfig]") {
		t.Fatalf("whole kubeconfig not masked:\n%s", got)
	}
	if strings.Contains(got, fakeKubeToken) {
		t.Fatalf("parsed kubeconfig token printed unmasked:\n%s", got)
	}
}

// TestKubeTokenHelper is the child for TestRunMasksTokenParsedFromKubeconfig.
func TestKubeTokenHelper(t *testing.T) {
	if os.Getenv("KG_KUBE_HELPER") != "1" {
		return
	}
	b, err := os.ReadFile(os.Getenv("KUBECONFIG"))
	if err != nil {
		os.Stderr.WriteString("read: " + err.Error() + "\n")
		os.Exit(2)
	}
	os.Stdout.WriteString("file=" + string(b) + "\n")
	for _, l := range strings.Split(string(b), "\n") {
		if tok, ok := strings.CutPrefix(strings.TrimSpace(l), "token: "); ok {
			os.Stdout.WriteString("Authorization: Bearer " + tok + "\n")
		}
	}
	os.Exit(0)
}
