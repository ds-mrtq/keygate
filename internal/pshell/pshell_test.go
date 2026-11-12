package pshell

import (
	"encoding/base64"
	"strings"
	"testing"
)

func TestSystemPowerShellPath(t *testing.T) {
	exe, env := System()
	l := strings.ToLower(exe)
	if !strings.HasSuffix(l, `windowspowershell\v1.0\powershell.exe`) && !strings.HasSuffix(l, "windowspowershell/v1.0/powershell.exe") {
		t.Fatal(exe)
	}
	joined := strings.Join(env, ";")
	if !strings.Contains(joined, "PSModulePath=") || strings.Contains(strings.ToLower(joined), "documents") {
		t.Fatalf("env %v", env)
	}
}

func TestEncode(t *testing.T) {
	raw, err := base64.StdEncoding.DecodeString(Encode("aé"))
	if err != nil || len(raw) != 4 || raw[0] != 'a' || raw[1] != 0 || raw[2] != 0xe9 || raw[3] != 0 {
		t.Fatalf("%v %v", raw, err)
	}
}
