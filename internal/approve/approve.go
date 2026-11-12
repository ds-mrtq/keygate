// Package approve implements human-presence approval (DESIGN sec 9): Windows Hello,
// macOS LocalAuthentication, and the cross-device Ed25519 challenge/response.
package approve

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"time"

	"keygate/internal/pshell"
)

// Approver asks a human to confirm. nil error = approved.
type Approver interface {
	Approve(ctx context.Context, prompt string) error
}

// Func adapts a function to Approver (used by tests and for wiring).
type Func func(ctx context.Context, prompt string) error

// Approve implements Approver.
func (f Func) Approve(ctx context.Context, prompt string) error { return f(ctx, prompt) }

// ErrUnsupported means this OS has no user-presence mechanism; use device approval.
var ErrUnsupported = errors.New("hệ điều hành này không có xác nhận user-presence, hãy dùng approval: device")

// ErrNotVerified means the user did not pass verification.
var ErrNotVerified = errors.New("người dùng chưa xác nhận")

// platformHook lets the kgtest build substitute a fake approver (fake_kgtest.go); nil in production.
var platformHook func() Approver

// Platform returns the user-presence approver of the running OS.
func Platform() Approver {
	if platformHook != nil {
		if a := platformHook(); a != nil {
			return a
		}
	}
	switch runtime.GOOS {
	case "windows":
		return &Hello{}
	case "darwin":
		return &TouchID{}
	}
	return unsupported{}
}

type unsupported struct{}

func (unsupported) Approve(context.Context, string) error { return ErrUnsupported }

// DefaultTimeout bounds a single user-presence prompt.
const DefaultTimeout = 2 * time.Minute

// Hello is Windows Hello via UserConsentVerifier, driven through an embedded PowerShell script.
type Hello struct {
	Timeout time.Duration
	// Command overrides the executable (tests only).
	Command string
}

// helloScript is the PowerShell body; %s receives the base64 UTF-8 prompt.
const helloScript = `$ErrorActionPreference = 'Stop'
Add-Type -AssemblyName System.Runtime.WindowsRuntime
$msg = [System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String('%s'))
$asTask = ([System.WindowsRuntimeSystemExtensions].GetMethods() | Where-Object { $_.Name -eq 'AsTask' -and $_.GetParameters().Count -eq 1 -and $_.GetParameters()[0].ParameterType.Name -eq 'IAsyncOperation` + "`" + `1' })[0]
[Windows.Security.Credentials.UI.UserConsentVerifier,Windows.Security.Credentials.UI,ContentType=WindowsRuntime] | Out-Null
$op = [Windows.Security.Credentials.UI.UserConsentVerifier]::RequestVerificationAsync($msg)
$task = $asTask.MakeGenericMethod([Windows.Security.Credentials.UI.UserConsentVerificationResult]).Invoke($null, @($op))
$task.Wait(-1) | Out-Null
Write-Output $task.Result
`

// BuildHelloScript returns the PowerShell source for prompt.
func BuildHelloScript(prompt string) string {
	return fmt.Sprintf(helloScript, base64.StdEncoding.EncodeToString([]byte(prompt)))
}

// HelloArgs returns the powershell.exe arguments for prompt.
func HelloArgs(prompt string) []string {
	return []string{"-NoProfile", "-NonInteractive", "-EncodedCommand", pshell.Encode(BuildHelloScript(prompt))}
}

// Approve shows the Windows Hello dialog.
func (h *Hello) Approve(ctx context.Context, prompt string) error {
	exe := h.Command
	var env []string
	if exe == "" {
		exe, env = pshell.System()
	}
	return runVerifier(ctx, h.Timeout, exe, HelloArgs(Sanitize(prompt, MaxPrompt)), env)
}

func runVerifier(ctx context.Context, timeout time.Duration, exe string, args, env []string) error {
	if timeout <= 0 {
		timeout = DefaultTimeout
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, exe, args...)
	if env != nil {
		cmd.Env = env
	}
	pshell.Hide(cmd)
	out, err := cmd.Output()
	if ctx.Err() != nil {
		return fmt.Errorf("xác nhận quá hạn hoặc bị hủy: %w", ctx.Err())
	}
	res := lastLine(string(out))
	if res == "Verified" {
		return nil
	}
	if err != nil && res == "" {
		return fmt.Errorf("không chạy được bộ xác nhận: %w", err)
	}
	return fmt.Errorf("%w (%s)", ErrNotVerified, res)
}

func lastLine(s string) string {
	s = strings.TrimSpace(s)
	if i := strings.LastIndexAny(s, "\r\n"); i >= 0 {
		s = strings.TrimSpace(s[i+1:])
	}
	return s
}

// TouchID is macOS LocalAuthentication (deviceOwnerAuthentication) via inline swift.
// [INFERENCE] not testable on this Windows workstation.
type TouchID struct {
	Timeout time.Duration
	Command string
}

// SwiftSource is the inline program; the reason comes from env KG_PROMPT.
const SwiftSource = `import Foundation
import LocalAuthentication
let ctx = LAContext()
var authErr: NSError?
let reason = ProcessInfo.processInfo.environment["KG_PROMPT"] ?? "KeyGate"
guard ctx.canEvaluatePolicy(.deviceOwnerAuthentication, error: &authErr) else {
    print("Unavailable")
    exit(0)
}
let sem = DispatchSemaphore(value: 0)
var ok = false
ctx.evaluatePolicy(.deviceOwnerAuthentication, localizedReason: reason) { success, _ in
    ok = success
    sem.signal()
}
sem.wait()
print(ok ? "Verified" : "Failed")
`

// Approve prompts for Touch ID / device password.
func (t *TouchID) Approve(ctx context.Context, prompt string) error {
	exe := t.Command
	if exe == "" {
		exe = "/usr/bin/swift"
	}
	return runVerifier(ctx, t.Timeout, exe, []string{"-e", SwiftSource}, append(os.Environ(), "KG_PROMPT="+Sanitize(prompt, MaxPrompt)))
}
