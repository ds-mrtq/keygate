//go:build windows

package wingui

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strings"

	"keygate/internal/api"
	"keygate/internal/pshell"
	"keygate/internal/qr"
)

// Dialogs that never carry a secret value run as PowerShell 5.1 + WinForms, started like Windows
// Hello (absolute system powershell.exe, system-only PSModulePath, hidden console). Parameters go
// into the script as base64 UTF-8; the result is one base64 UTF-8 line on stdout; Cancel = exit 1.

const psPrelude = `$ErrorActionPreference = 'Stop'
Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing
[System.Windows.Forms.Application]::EnableVisualStyles()
function U($b) { [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($b)) }
function NewForm($title, $w, $h) {
  $f = New-Object System.Windows.Forms.Form
  $f.Text = $title
  $f.ClientSize = New-Object System.Drawing.Size($w, $h)
  $f.StartPosition = 'CenterScreen'
  $f.TopMost = $true
  $f.FormBorderStyle = 'FixedDialog'
  $f.MaximizeBox = $false
  $f.MinimizeBox = $false
  $f.Font = New-Object System.Drawing.Font('Segoe UI', 9)
  if ($KgExe) { try { $f.Icon = [System.Drawing.Icon]::ExtractAssociatedIcon($KgExe) } catch {} }
  $f.Add_Shown({ $this.Activate() })
  return ,$f
}
function Lbl($t, $x, $y, $w, $h) {
  $l = New-Object System.Windows.Forms.Label
  $l.Text = $t
  $l.SetBounds($x, $y, $w, $h)
  return ,$l
}
function Txt($x, $y, $w) {
  $t = New-Object System.Windows.Forms.TextBox
  $t.SetBounds($x, $y, $w, 24)
  return ,$t
}
function Btn($t, $x, $y, $w) {
  $b = New-Object System.Windows.Forms.Button
  $b.Text = $t
  $b.SetBounds($x, $y, $w, 28)
  return ,$b
}
function Out64($s) { [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($s)) }
`

const psLine = `$f = NewForm (U '%s') 420 136
$l = Lbl (U '%s') 12 10 396 40
$t = Txt 12 54 396
$ok = Btn 'OK' 250 94 75
$cancel = Btn 'Hủy' 333 94 75
$ok.DialogResult = 'OK'
$cancel.DialogResult = 'Cancel'
$f.AcceptButton = $ok
$f.CancelButton = $cancel
$f.Controls.AddRange(@($l, $t, $ok, $cancel))
if ($f.ShowDialog() -ne 'OK') { exit 1 }
Out64 $t.Text
`

const psReview = `$f = NewForm (U '%s') 680 440
$t = New-Object System.Windows.Forms.TextBox
$t.Multiline = $true
$t.ReadOnly = $true
$t.WordWrap = $false
$t.ScrollBars = 'Both'
$t.Font = New-Object System.Drawing.Font('Consolas', 9.5)
$t.BackColor = [System.Drawing.Color]::White
$t.SetBounds(12, 12, 656, 372)
$t.Text = (U ([Console]::In.ReadToEnd().Trim()))
$t.Select(0, 0)
$ok = Btn 'Tiếp tục (Windows Hello)' 318 398 210
$cancel = Btn 'Hủy' 536 398 132
$ok.DialogResult = 'OK'
$cancel.DialogResult = 'Cancel'
$f.AcceptButton = $ok
$f.CancelButton = $cancel
$f.Controls.AddRange(@($t, $ok, $cancel))
if ($f.ShowDialog() -ne 'OK') { exit 1 }
`

// psPair: stdin = base64(PNG) newline base64(UTF-8 text). Đóng prints nothing; Tiếp prints the
// 8-character pairing code the user typed (validated here and again in Go).
const psPair = `$f = NewForm 'KeyGate: ghép điện thoại' 720 384
$in = [Console]::In.ReadToEnd().Trim() -split "\n"
$ms = New-Object System.IO.MemoryStream(,[Convert]::FromBase64String($in[0].Trim()))
$p = New-Object System.Windows.Forms.PictureBox
$p.Image = [System.Drawing.Image]::FromStream($ms)
$p.SizeMode = 'Zoom'
$p.SetBounds(12, 12, 320, 320)
$t = New-Object System.Windows.Forms.TextBox
$t.Multiline = $true
$t.ReadOnly = $true
$t.WordWrap = $true
$t.ScrollBars = 'Vertical'
$t.BackColor = [System.Drawing.Color]::White
$t.SetBounds(344, 12, 364, 236)
$t.Text = (U $in[1].Trim())
$t.Select(0, 0)
$cl = Lbl 'Mã ghép hiện trên điện thoại (8 ký tự):' 344 258 364 18
$code = Txt 344 278 160
$code.CharacterCasing = 'Upper'
$code.MaxLength = 12
$code.Font = New-Object System.Drawing.Font('Consolas', 12)
$err = Lbl '' 344 312 364 18
$err.ForeColor = [System.Drawing.Color]::Firebrick
$next = Btn 'Tiếp' 460 344 120
$ok = Btn 'Đóng' 588 344 120
$ok.DialogResult = 'Cancel'
$next.Add_Click({
  $v = ($code.Text -replace '\s', '').ToUpper()
  if ($v -cnotmatch '^[A-Z2-7]{8}$') { $err.Text = 'Mã ghép gồm 8 ký tự A-Z, 2-7.'; $code.Focus() | Out-Null; return }
  $f.DialogResult = 'OK'
})
$f.AcceptButton = $next
$f.CancelButton = $ok
$f.Controls.AddRange(@($p, $t, $cl, $code, $err, $next, $ok))
$f.Add_Shown({ $code.Focus() | Out-Null })
if ($f.ShowDialog() -ne 'OK') { exit 0 }
Out64 (($code.Text -replace '\s', '').ToUpper())
`

// psConfirmDevice: %s = base64 of the device line, the role line and the 6 words. No AcceptButton:
// Enter must not add a device.
const psConfirmDevice = `$f = NewForm 'KeyGate: xác nhận thiết bị mới' 520 300
$d = Lbl (U '%s') 12 12 496 40
$r = Lbl (U '%s') 12 54 496 36
$h = Lbl 'So với 6 từ trên điện thoại. Khác dù chỉ một từ thì bấm Hủy:' 12 96 496 20
$w = Lbl (U '%s') 12 120 496 96
$w.Font = New-Object System.Drawing.Font('Segoe UI', 18, [System.Drawing.FontStyle]::Bold)
$w.TextAlign = 'MiddleCenter'
$w.BorderStyle = 'FixedSingle'
$ok = Btn 'Đúng, thêm thiết bị' 222 252 170
$cancel = Btn 'Hủy' 400 252 108
$ok.DialogResult = 'OK'
$cancel.DialogResult = 'Cancel'
$f.CancelButton = $cancel
$f.Controls.AddRange(@($d, $r, $h, $w, $ok, $cancel))
$f.Add_Shown({ $cancel.Focus() | Out-Null })
if ($f.ShowDialog() -ne 'OK') { exit 1 }
`

// psDevices: stdin = base64(JSON array of DeviceRow). Prints "pair" or "revoke:<dev>"; Đóng = exit 1.
const psDevices = `$f = NewForm 'KeyGate: thiết bị của vault' 1180 330
$rows = ConvertFrom-Json (U ([Console]::In.ReadToEnd().Trim()))
$lv = New-Object System.Windows.Forms.ListView
$lv.View = 'Details'
$lv.FullRowSelect = $true
$lv.MultiSelect = $false
$lv.HideSelection = $false
$lv.SetBounds(12, 12, 1156, 262)
[void]$lv.Columns.Add('Thiết bị', 130)
[void]$lv.Columns.Add('Tên', 150)
[void]$lv.Columns.Add('Vai trò', 80)
[void]$lv.Columns.Add('Ghép lúc', 120)
[void]$lv.Columns.Add('Nguồn lúc ghép', 260)
[void]$lv.Columns.Add('Hoạt động gần nhất', 300)
[void]$lv.Columns.Add('Trạng thái', 90)
foreach ($x in $rows) {
  $st = 'hoạt động'
  if ($x.revoked) { $st = 'đã thu hồi' } elseif ($x.self) { $st = 'máy này' }
  $it = New-Object System.Windows.Forms.ListViewItem($x.dev)
  [void]$it.SubItems.Add($x.label)
  [void]$it.SubItems.Add($x.role)
  [void]$it.SubItems.Add($x.paired)
  [void]$it.SubItems.Add($x.origin)
  [void]$it.SubItems.Add($x.seen)
  [void]$it.SubItems.Add($st)
  if ($x.revoked) { $it.ForeColor = [System.Drawing.Color]::Gray }
  if ($x.self) { $it.Font = New-Object System.Drawing.Font('Segoe UI', 9, [System.Drawing.FontStyle]::Bold) }
  $it.Tag = $x
  [void]$lv.Items.Add($it)
}
$pair = Btn 'Ghép điện thoại…' 12 288 160
$rev = Btn 'Thu hồi' 180 288 110
$close = Btn 'Đóng' 1068 288 100
$rev.Enabled = $false
$close.DialogResult = 'Cancel'
$lv.Add_SelectedIndexChanged({
  $s = $lv.SelectedItems
  $rev.Enabled = ($s.Count -eq 1 -and -not $s[0].Tag.self -and -not $s[0].Tag.revoked)
})
$pair.Add_Click({ $f.Tag = 'pair'; $f.DialogResult = 'OK' })
$rev.Add_Click({ $f.Tag = 'revoke:' + $lv.SelectedItems[0].Tag.dev; $f.DialogResult = 'OK' })
$f.CancelButton = $close
$f.Controls.AddRange(@($lv, $pair, $rev, $close))
if ($f.ShowDialog() -ne 'OK') { exit 1 }
Out64 $f.Tag
`

const psAddMeta = `$f = NewForm 'KeyGate: thêm secret' 460 330
$name = Txt 12 28 436
$envc = New-Object System.Windows.Forms.ComboBox
$envc.DropDownStyle = 'DropDownList'
$envc.Items.AddRange(@('dev', 'test', 'prod'))
$envc.SelectedIndex = 0
$envc.SetBounds(12, 82, 208, 24)
$kind = New-Object System.Windows.Forms.ComboBox
$kind.DropDownStyle = 'DropDownList'
$kind.Items.AddRange(@('env', 'file', 'template', 'oracle-wallet'))
$kind.SelectedIndex = 0
$kind.SetBounds(240, 82, 208, 24)
$envname = Txt 12 136 436
$tns = Txt 12 190 208
$user = Txt 240 190 208
$desc = Txt 12 244 436
$tns.Enabled = $false
$user.Enabled = $false
$kind.Add_SelectedIndexChanged({ $w = ($kind.Text -eq 'oracle-wallet'); $tns.Enabled = $w; $user.Enabled = $w })
$ok = Btn 'Tiếp: nhập giá trị' 214 286 150
$cancel = Btn 'Hủy' 373 286 75
$cancel.DialogResult = 'Cancel'
$ok.Add_Click({
  if ($name.Text.Trim() -eq '') { $name.Focus() | Out-Null; return }
  $f.DialogResult = 'OK'
})
$f.AcceptButton = $ok
$f.CancelButton = $cancel
$f.Controls.AddRange(@(
  (Lbl 'Tên' 12 10 436 18), $name,
  (Lbl 'Môi trường' 12 64 208 18), (Lbl 'Kind' 240 64 208 18), $envc, $kind,
  (Lbl 'Tên biến môi trường (Env name)' 12 118 436 18), $envname,
  (Lbl 'TNS alias' 12 172 208 18), (Lbl 'User' 240 172 208 18), $tns, $user,
  (Lbl 'Mô tả' 12 226 436 18), $desc,
  $ok, $cancel))
if ($f.ShowDialog() -ne 'OK') { exit 1 }
$o = [ordered]@{ name = $name.Text.Trim(); env = $envc.Text; kind = $kind.Text; env_name = $envname.Text.Trim(); tns_alias = $tns.Text.Trim(); user = $user.Text.Trim(); desc = $desc.Text.Trim() }
Out64 ($o | ConvertTo-Json -Compress)
`

func b64(s string) string { return base64.StdEncoding.EncodeToString([]byte(s)) }

// runPS runs script and returns the decoded base64 line it printed (nil when it printed nothing).
func runPS(ctx context.Context, script, stdin string) ([]byte, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	exe, env := pshell.System()
	// The form shows the logo of kg.exe/kgw.exe (embedded icon resource) instead of PowerShell's.
	var icon string
	if self, err := os.Executable(); err == nil {
		icon = fmt.Sprintf("$KgExe = U '%s'\n", b64(self))
	}
	cmd := exec.CommandContext(ctx, exe, "-NoProfile", "-NonInteractive", "-EncodedCommand", pshell.Encode(psPrelude+icon+script))
	cmd.Env = env
	pshell.Hide(cmd)
	var out, errb bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &errb
	if stdin != "" {
		cmd.Stdin = strings.NewReader(stdin)
	}
	err := cmd.Run()
	if cerr := ctx.Err(); cerr != nil {
		return nil, cerr
	}
	if err != nil {
		stderr := strings.TrimSpace(errb.String())
		// PowerShell writes progress records ("Preparing modules for first use") to stderr as CLIXML:
		// noise, not an error, unless an error record is among them.
		if strings.HasPrefix(stderr, "#< CLIXML") && !strings.Contains(stderr, `S="Error"`) {
			stderr = ""
		}
		var ee *exec.ExitError
		if errors.As(err, &ee) && ee.ExitCode() == 1 && stderr == "" {
			return nil, ErrCanceled
		}
		return nil, fmt.Errorf("hộp thoại lỗi: %w: %s", err, truncRunes(stderr, 300))
	}
	line := strings.TrimSpace(out.String())
	if line == "" {
		return nil, nil
	}
	raw, err := base64.StdEncoding.DecodeString(line)
	if err != nil {
		return nil, fmt.Errorf("hộp thoại trả dữ liệu lạ: %w", err)
	}
	return raw, nil
}

func formTitle(title string) string {
	title = truncRunes(strings.Join(strings.Fields(title), " "), 110)
	if !strings.HasPrefix(title, "KeyGate") {
		title = "KeyGate: " + title
	}
	return title
}

// Line asks for one visible line of text.
func Line(ctx context.Context, prompt string) (string, error) {
	raw, err := runPS(ctx, fmt.Sprintf(psLine, b64("KeyGate"), b64(truncRunes(prompt, 300))), "")
	return string(raw), err
}

// Review shows text (monospace, read-only) with Continue/Cancel; nil = Continue.
func Review(ctx context.Context, title, text string) error {
	text = strings.ReplaceAll(strings.ReplaceAll(text, "\r\n", "\n"), "\n", "\r\n")
	_, err := runPS(ctx, fmt.Sprintf(psReview, b64(formTitle(title))), b64(text)) // text via stdin: command lines are capped at 32 KiB
	return err
}

// Pair shows the pairing link as a QR code (for the phone camera) beside text instructions and a
// field for the pairing code the phone then shows. It returns that code ("" when closed).
func Pair(ctx context.Context, link, text string) (string, error) {
	c, err := qr.Encode([]byte(link))
	if err != nil {
		return "", err
	}
	text = strings.ReplaceAll(strings.ReplaceAll(text, "\r\n", "\n"), "\n", "\r\n")
	raw, err := runPS(ctx, psPair, base64.StdEncoding.EncodeToString(c.PNG(6))+"\n"+b64(text))
	return string(raw), err
}

// ConfirmDevice shows the new device and its 6 confirmation words; nil = "Đúng, thêm thiết bị".
func ConfirmDevice(ctx context.Context, device, role, words string) error {
	ws := strings.Fields(words)
	if len(ws) == 6 {
		words = strings.Join(ws[:3], " · ") + "\r\n" + strings.Join(ws[3:], " · ")
	}
	_, err := runPS(ctx, fmt.Sprintf(psConfirmDevice, b64(truncRunes(device, 200)), b64(truncRunes(role, 200)), b64(words)), "")
	return err
}

// DeviceRow is one line of the Devices dialog.
type DeviceRow struct {
	Dev     string `json:"dev"`
	Label   string `json:"label"`
	Role    string `json:"role"`   // display text
	Paired  string `json:"paired"` // display text: local time or "không rõ"
	Origin  string `json:"origin"` // display text: where the pairing request came from
	Seen    string `json:"seen"`   // display text: last relay request (time · origin)
	Revoked bool   `json:"revoked"`
	Self    bool   `json:"self"`
}

// Devices lists the vault's devices. action is "pair" or "revoke" (dev = the selected device,
// never this machine or a revoked one); Đóng returns ErrCanceled.
func Devices(ctx context.Context, rows []DeviceRow) (action, dev string, err error) {
	j, err := json.Marshal(rows)
	if err != nil {
		return "", "", err
	}
	raw, err := runPS(ctx, psDevices, base64.StdEncoding.EncodeToString(j))
	if err != nil {
		return "", "", err
	}
	out := string(raw)
	if out == "pair" {
		return "pair", "", nil
	}
	if d, ok := strings.CutPrefix(out, "revoke:"); ok {
		for _, r := range rows {
			if r.Dev == d && !r.Self && !r.Revoked {
				return "revoke", d, nil
			}
		}
	}
	return "", "", fmt.Errorf("hộp thoại trả dữ liệu lạ: %q", truncRunes(out, 60))
}

// AddSecretMeta collects the metadata of a new secret (never the value).
func AddSecretMeta(ctx context.Context) (api.SetRequest, error) {
	var r api.SetRequest
	raw, err := runPS(ctx, psAddMeta, "")
	if err != nil {
		return r, err
	}
	if err := json.Unmarshal(raw, &r); err != nil {
		return api.SetRequest{}, fmt.Errorf("hộp thoại trả dữ liệu lạ: %w", err)
	}
	return r, nil
}
