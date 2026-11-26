package redact

import (
	"strings"
	"testing"
)

// Fake values only (LeakBench D06 shape).
const fakeKubeToken = "kgfake-eyJhbGciOiJSUzI1NiJ9.Zm9vYmFyLXRlc3Q.c2lnLW5vdC1yZWFs"

var fakeKubeconfig = `apiVersion: v1
kind: Config
clusters:
- name: test
  cluster:
    server: https://127.0.0.1:6443
contexts:
- name: test
  context:
    cluster: test
    user: tester
current-context: test
users:
- name: tester
  user:
    token: ` + fakeKubeToken + `
`

// TestKubeconfigWholeFileMasked pins what works today: the imported file printed whole is masked.
func TestKubeconfigWholeFileMasked(t *testing.T) {
	r := New([]Secret{{Name: "k8s/test/kubeconfig", Value: fakeKubeconfig}})
	if got := r.String("cat:\n" + fakeKubeconfig); strings.Contains(got, fakeKubeToken) {
		t.Fatalf("whole kubeconfig not masked:\n%s", got)
	}
}

// TestKubeconfigParsedTokenMasked: a bearer token parsed out of an imported kubeconfig and
// printed on its own must not reach the output (LeakBench D06). Fails on main: only the whole
// file value is a pattern.
func TestKubeconfigParsedTokenMasked(t *testing.T) {
	r := New([]Secret{{Name: "k8s/test/kubeconfig", Value: fakeKubeconfig}})
	for _, in := range []string{
		fakeKubeToken + "\n",
		"Authorization: Bearer " + fakeKubeToken + "\n",
		"token: " + fakeKubeToken + "\n",
	} {
		if got := r.String(in); strings.Contains(got, fakeKubeToken) {
			t.Errorf("parsed kubeconfig token printed unmasked: %q", got)
		}
	}
}

func TestStructuredInnerValues(t *testing.T) {
	const tok = "kgfake-json-token-0123456789"
	r := New([]Secret{
		{Name: "j", Value: `{"users":[{"name":"t","user":{"token":"` + tok + `"}}],"server":"https://10.0.0.1:6443"}`},
		{Name: "q", Value: "users:\n- 'token': kgfake-singlequoted-key\n  \"password\": 'kgfake-it''s-pw'\n"},
		{Name: "e", Value: `{"token": "kgfake\/escaped\"tok\u0041"}`},
		{Name: "y", Value: "auth:\n  access-token: 'kgfake-quoted-tok'\n  password=kgfake-ini-pw\n  token: short\n  user: kgfake-not-a-credential\n"},
	})
	for in, want := range map[string]string{
		"Bearer " + tok:           "Bearer [kg:j]",
		"kgfake-quoted-tok":       "[kg:y]",
		"pw=kgfake-ini-pw":        "pw=[kg:y]",
		"https://10.0.0.1:6443":   "https://10.0.0.1:6443",
		"kgfake-singlequoted-key": "[kg:q]",
		"kgfake-it's-pw":          "[kg:q]",
		`kgfake/escaped"tokA`:     "[kg:e]",
		"short":                   "short",
		"kgfake-not-a-credential": "kgfake-not-a-credential",
	} {
		if got := r.String(in); got != want {
			t.Errorf("%q => %q, want %q", in, got, want)
		}
	}
}
