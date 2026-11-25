package approve

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strings"
	"testing"
)

// fakeHelloEnv makes the test binary act as the Windows Hello verifier: it prints the value as the
// UserConsentVerificationResult, the way the PowerShell script does.
const fakeHelloEnv = "KG_FAKE_HELLO_RESULT"

func TestMain(m *testing.M) {
	if res, ok := os.LookupEnv(fakeHelloEnv); ok {
		if len(os.Args) != 5 || os.Args[1] != "-NoProfile" || os.Args[3] != "-EncodedCommand" {
			os.Exit(2)
		}
		fmt.Println(res)
		os.Exit(0)
	}
	os.Exit(m.Run())
}

func helloWith(t *testing.T, result string) error {
	t.Helper()
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv(fakeHelloEnv, result)
	return (&Hello{Command: exe}).Approve(context.Background(), "KeyGate: mở khóa vault")
}

func TestHelloResultMessages(t *testing.T) {
	const settings = "ms-settings:signinoptions"
	for _, tc := range []struct {
		result string
		want   []string // every part must be in the error text
	}{
		{"NotConfiguredForUser", []string{"(NotConfiguredForUser)", "chưa được thiết lập", "Sign-in options", settings, "PIN"}},
		{"DeviceNotPresent", []string{"(DeviceNotPresent)", "PIN", settings}},
		{"DisabledByPolicy", []string{"(DisabledByPolicy)", "chính sách", "quản trị"}},
		{"DeviceBusy", []string{"(DeviceBusy)", "thử lại"}},
		{"RetriesExhausted", []string{"(RetriesExhausted)", "Win+L"}},
		{"Canceled", []string{"(Canceled)", "thử lại"}},
	} {
		t.Run(tc.result, func(t *testing.T) {
			err := helloWith(t, tc.result)
			if !errors.Is(err, ErrNotVerified) {
				t.Fatalf("must stay a refusal: %v", err)
			}
			for _, w := range tc.want {
				if !strings.Contains(err.Error(), w) {
					t.Fatalf("%q missing from %q", w, err)
				}
			}
		})
	}
}

func TestHelloVerifiedAndUnknownResults(t *testing.T) {
	if err := helloWith(t, "Verified"); err != nil {
		t.Fatalf("Verified: %v", err)
	}
	err := helloWith(t, "SomethingNew")
	if !errors.Is(err, ErrNotVerified) || err.Error() != ErrNotVerified.Error()+" (SomethingNew)" {
		t.Fatalf("unknown result: %v", err)
	}
}

func TestHintsOnlyForHello(t *testing.T) {
	if h := HelloHint("Verified"); h != "" {
		t.Fatalf("Verified has no hint: %q", h)
	}
	if h := HelloHint("Unavailable"); h != "" { // Touch ID's word, not a Hello result
		t.Fatalf("Touch ID result got a Hello hint: %q", h)
	}
}
