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
	"time"

	"keygate/internal/api"
	"keygate/internal/approve"
	"keygate/internal/broker"
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

const psReview = `$f = NewForm (U '%s') 860 560
$t = New-Object System.Windows.Forms.TextBox
$t.Multiline = $true
$t.ReadOnly = $true
$t.WordWrap = $true
$t.ScrollBars = 'Vertical'
$t.Font = New-Object System.Drawing.Font('Consolas', 9.5)
$t.BackColor = [System.Drawing.Color]::White
$t.SetBounds(12, 12, 836, 492)
$t.Text = (U ([Console]::In.ReadToEnd().Trim()))
$t.Select(0, 0)
$ok = Btn 'Tiếp tục (Windows Hello)' 498 518 210
$cancel = Btn 'Hủy' 716 518 132
$ok.DialogResult = 'OK'
$cancel.DialogResult = 'Cancel'
$f.AcceptButton = $ok
$f.CancelButton = $cancel
$f.Controls.AddRange(@($t, $ok, $cancel))
if ($f.ShowDialog() -ne 'OK') { exit 1 }
`

// psVisual: colors, badges and round icons shared by the table dialogs (review, log).
const psVisual = `function C($h) { [System.Drawing.ColorTranslator]::FromHtml($h) }
$tones = @{ add = @('#E6F4EA', '#1E7B34'); mod = @('#FFF4E0', '#8A5300'); del = @('#FDE7E9', '#B3261E'); warn = @('#FDE7E9', '#B3261E'); muted = @('#EEEEEE', '#555555') }
$bold = New-Object System.Drawing.Font('Segoe UI', 9, [System.Drawing.FontStyle]::Bold)
function Badges($fl, $list) {
  $fl.Controls.Clear()
  foreach ($b in $list) {
    $t = $tones[$b.tone]
    if (-not $t) { $t = $tones['muted'] }
    $l = New-Object System.Windows.Forms.Label
    $l.Text = $b.text
    $l.AutoSize = $true
    $l.Padding = New-Object System.Windows.Forms.Padding(8, 4, 8, 4)
    $l.Margin = New-Object System.Windows.Forms.Padding(0, 0, 8, 0)
    $l.Font = $bold
    $l.BackColor = C $t[0]
    $l.ForeColor = C $t[1]
    $fl.Controls.Add($l)
  }
}
function NewIcons() {
  $il = New-Object System.Windows.Forms.ImageList
  $il.ImageSize = New-Object System.Drawing.Size(16, 16)
  $il.ColorDepth = 'Depth32Bit'
  return ,$il
}
function IcoBmp() {
  $bmp = New-Object System.Drawing.Bitmap(16, 16)
  $g = [System.Drawing.Graphics]::FromImage($bmp)
  $g.SmoothingMode = 'AntiAlias'
  $g.TextRenderingHint = 'AntiAliasGridFit'
  return @($bmp, $g)
}
function Ico($il, $key, $hex, $sym) {
  $bmp, $g = IcoBmp
  $g.FillEllipse((New-Object System.Drawing.SolidBrush(C $hex)), 0, 0, 15, 15)
  $sf = New-Object System.Drawing.StringFormat
  $sf.Alignment = 'Center'
  $sf.LineAlignment = 'Center'
  $g.DrawString($sym, (New-Object System.Drawing.Font('Segoe UI Symbol', 8, [System.Drawing.FontStyle]::Bold)), [System.Drawing.Brushes]::White, (New-Object System.Drawing.RectangleF(0, 0, 16, 16)), $sf)
  $g.Dispose()
  $il.Images.Add($key, $bmp)
}
function IcoLock($il, $key, $hex, $open) {
  $bmp, $g = IcoBmp
  $pen = New-Object System.Drawing.Pen((C $hex), 2)
  if ($open) { $g.DrawArc($pen, 7, 1, 7, 9, 180, 180) } else { $g.DrawArc($pen, 4, 1, 8, 9, 180, 180) }
  $g.FillRectangle((New-Object System.Drawing.SolidBrush(C $hex)), 2, 7, 12, 8)
  $g.Dispose()
  $il.Images.Add($key, $bmp)
}
`

// psReviewDoc: stdin = base64(JSON approve.ReviewDoc). Header (who asks, chain, action), colored
// badges, a grouped table with icons, the selected row's detail; "Xem toàn văn" swaps in the text.
const psReviewDoc = `$f = NewForm (U '%s') 960 620
$d = ConvertFrom-Json (U ([Console]::In.ReadToEnd().Trim()))
$pic = New-Object System.Windows.Forms.PictureBox
$pic.Image = [System.Drawing.SystemIcons]::Shield.ToBitmap()
$pic.SetBounds(12, 12, 32, 32)
$who = Lbl ($d.requester + ' ' + $d.action) 54 8 894 24
$who.Font = New-Object System.Drawing.Font('Segoe UI', 11.5, [System.Drawing.FontStyle]::Bold)
$ct = 'Chạy từ: ' + $d.chain
if (-not $d.chain) { $ct = 'Chạy từ: không rõ tiến trình cha' }
$ch = Lbl $ct 54 34 894 18
$ch.ForeColor = C '#444444'
$note = Lbl $d.note 54 54 894 32
$note.ForeColor = C '#666666'
$fl = New-Object System.Windows.Forms.FlowLayoutPanel
$fl.SetBounds(12, 92, 936, 30)
$fl.WrapContents = $false
Badges $fl $d.badges
$il = NewIcons
Ico $il 'add' '#1E7B34' '+'
Ico $il 'mod' '#C77700' ([string][char]0x270E)
Ico $il 'oracle' '#C77700' ([string][char]0x270E)
Ico $il 'del' '#B3261E' ([string][char]0x2212)
Ico $il 'warn' '#B3261E' '!'
Ico $il 'kept' '#8A8A8A' ([string][char]0x2713)
$lv = New-Object System.Windows.Forms.ListView
$lv.View = 'Details'
$lv.FullRowSelect = $true
$lv.MultiSelect = $false
$lv.HideSelection = $false
$lv.SmallImageList = $il
$lv.SetBounds(12, 130, 936, 300)
[void]$lv.Columns.Add('Thay đổi', 100)
[void]$lv.Columns.Add('Secret', 310)
[void]$lv.Columns.Add('Loại', 60)
[void]$lv.Columns.Add('Lệnh được nhận secret / nội dung', 240)
[void]$lv.Columns.Add('Duyệt', 150)
[void]$lv.Columns.Add('Hết hạn', 72)
$groups = @{}
foreach ($g in @(@('change', 'Thay đổi'), @('warn', 'Cảnh báo'), @('kept', 'Không đổi, đã duyệt ở bản trước'))) {
  $groups[$g[0]] = New-Object System.Windows.Forms.ListViewGroup($g[1], $g[1])
  [void]$lv.Groups.Add($groups[$g[0]])
}
foreach ($r in $d.rows) {
  $it = New-Object System.Windows.Forms.ListViewItem($r.label, $r.op)
  $it.UseItemStyleForSubItems = $false
  [void]$it.SubItems.Add($r.secret)
  $kind = ''
  if ($r.prod) { $kind = 'PROD' }
  $pc = $it.SubItems.Add($kind)
  [void]$it.SubItems.Add($r.what)
  [void]$it.SubItems.Add($r.approval)
  [void]$it.SubItems.Add($r.ttl)
  if ($r.prod) { $pc.ForeColor = C '#B3261E'; $pc.Font = $bold }
  if ($r.op -eq 'kept') { foreach ($s in $it.SubItems) { if ($s -ne $pc) { $s.ForeColor = [System.Drawing.Color]::Gray } } }
  if ($r.op -eq 'warn') { $it.SubItems[3].ForeColor = C '#B3261E' }
  $it.Group = $groups[$r.group]
  $it.Tag = $r.detail
  [void]$lv.Items.Add($it)
}
$dt = New-Object System.Windows.Forms.TextBox
$dt.Multiline = $true
$dt.ReadOnly = $true
$dt.WordWrap = $true
$dt.ScrollBars = 'Vertical'
$dt.Font = New-Object System.Drawing.Font('Consolas', 9.5)
$dt.BackColor = [System.Drawing.Color]::White
$dt.SetBounds(12, 438, 936, 124)
$lv.Add_SelectedIndexChanged({ if ($lv.SelectedItems.Count -eq 1) { $dt.Text = $lv.SelectedItems[0].Tag } })
if ($lv.Items.Count -gt 0) { $lv.Items[0].Selected = $true }
$full = Btn 'Xem toàn văn' 12 578 140
$full.Add_Click({
  if ($lv.Visible) {
    $lv.Visible = $false
    $dt.SetBounds(12, 130, 936, 432)
    $dt.Text = $d.text
    $full.Text = 'Xem bảng'
  } else {
    $lv.Visible = $true
    $dt.SetBounds(12, 438, 936, 124)
    $dt.Text = ''
    if ($lv.SelectedItems.Count -eq 1) { $dt.Text = $lv.SelectedItems[0].Tag }
    $full.Text = 'Xem toàn văn'
  }
})
$ok = Btn 'Tiếp tục (Windows Hello)' 598 578 210
$cancel = Btn 'Hủy' 816 578 132
$ok.DialogResult = 'OK'
$cancel.DialogResult = 'Cancel'
$f.AcceptButton = $ok
$f.CancelButton = $cancel
$f.Controls.AddRange(@($pic, $who, $ch, $note, $fl, $lv, $dt, $full, $ok, $cancel))
$f.Add_Shown({ $lv.Focus() | Out-Null })
if ($f.ShowDialog() -ne 'OK') { exit 1 }
`

// psLog: stdin = base64(JSON logDoc). Prints "refresh" or "open"; Đóng = exit 1.
const psLog = `$f = NewForm 'KeyGate: nhật ký broker' 1000 660
$d = ConvertFrom-Json (U ([Console]::In.ReadToEnd().Trim()))
$pic = New-Object System.Windows.Forms.PictureBox
$pic.Image = [System.Drawing.SystemIcons]::Information.ToBitmap()
$pic.SetBounds(12, 12, 32, 32)
$hd = Lbl 'Nhật ký broker' 54 8 930 24
$hd.Font = New-Object System.Drawing.Font('Segoe UI', 11.5, [System.Drawing.FontStyle]::Bold)
$sub = Lbl $d.sub 54 34 930 18
$sub.ForeColor = C '#555555'
$fl = New-Object System.Windows.Forms.FlowLayoutPanel
$fl.SetBounds(12, 60, 976, 30)
$fl.WrapContents = $false
Badges $fl $d.badges
$flt = New-Object System.Windows.Forms.ComboBox
$flt.DropDownStyle = 'DropDownList'
$flt.Items.AddRange(@('Tất cả sự kiện', 'Chỉ lỗi và cảnh báo', 'Ẩn thao tác Hủy', 'Chỉ lần chạy hiện tại'))
$flt.SelectedIndex = 2
$flt.SetBounds(12, 98, 220, 24)
$sl = Lbl 'Tìm:' 248 101 36 20
$q = Txt 286 98 300
$il = NewIcons
Ico $il 'error' '#B3261E' '!'
Ico $il 'warn' '#C77700' '!'
Ico $il 'ok' '#1E7B34' ([string][char]0x2713)
Ico $il 'info' '#3B6EA8' 'i'
Ico $il 'cancel' '#9A9A9A' ([string][char]0x00D7)
IcoLock $il 'lock' '#3B5BA9' $false
IcoLock $il 'unlock' '#1E7B34' $true
$lv = New-Object System.Windows.Forms.ListView
$lv.View = 'Details'
$lv.FullRowSelect = $true
$lv.MultiSelect = $false
$lv.HideSelection = $false
$lv.SmallImageList = $il
$lv.SetBounds(12, 130, 976, 346)
[void]$lv.Columns.Add('Thời gian', 130)
[void]$lv.Columns.Add('Nguồn', 70)
[void]$lv.Columns.Add('Sự kiện', 752)
$dt = New-Object System.Windows.Forms.TextBox
$dt.Multiline = $true
$dt.ReadOnly = $true
$dt.WordWrap = $true
$dt.ScrollBars = 'Vertical'
$dt.Font = New-Object System.Drawing.Font('Consolas', 9.5)
$dt.BackColor = [System.Drawing.Color]::White
$dt.SetBounds(12, 484, 976, 124)
$fore = @{ error = C '#B3261E'; warn = C '#8A5300'; cancel = [System.Drawing.Color]::Gray }
function Fill {
  $lv.BeginUpdate()
  $lv.Items.Clear()
  $lv.Groups.Clear()
  $groups = @{}
  $mode = $flt.SelectedIndex
  $needle = $q.Text.Trim()
  foreach ($e in $d.entries) {
    if ($mode -eq 1 -and $e.level -ne 'error' -and $e.level -ne 'warn') { continue }
    if ($mode -eq 2 -and $e.level -eq 'cancel') { continue }
    if ($mode -eq 3 -and $e.run -ne $d.current) { continue }
    if ($needle -and $e.detail.IndexOf($needle, [StringComparison]::OrdinalIgnoreCase) -lt 0) { continue }
    if (-not $groups.ContainsKey($e.run)) {
      $groups[$e.run] = New-Object System.Windows.Forms.ListViewGroup($e.run, $e.run)
      [void]$lv.Groups.Add($groups[$e.run])
    }
    $t = $e.time
    if (-not $t) { $t = '(chưa ghi giờ)' }
    $it = New-Object System.Windows.Forms.ListViewItem($t, $e.level)
    [void]$it.SubItems.Add($e.source)
    [void]$it.SubItems.Add($e.title)
    if ($fore.ContainsKey($e.level)) { $it.ForeColor = $fore[$e.level] }
    if ($e.level -eq 'error') { $it.Font = $bold }
    $it.Group = $groups[$e.run]
    $it.Tag = $e.detail
    [void]$lv.Items.Add($it)
  }
  $lv.EndUpdate()
  $dt.Text = ''
  if ($lv.Items.Count -gt 0) { $lv.Items[0].Selected = $true } else { $dt.Text = 'Không có sự kiện nào khớp bộ lọc.' }
}
$lv.Add_SelectedIndexChanged({ if ($lv.SelectedItems.Count -eq 1) { $dt.Text = $lv.SelectedItems[0].Tag } })
$flt.Add_SelectedIndexChanged({ Fill })
$q.Add_TextChanged({ Fill })
$refresh = Btn 'Làm mới' 12 620 110
$open = Btn 'Mở file gốc' 130 620 120
$close = Btn 'Đóng' 888 620 100
$close.DialogResult = 'Cancel'
$refresh.Add_Click({ $f.Tag = 'refresh'; $f.DialogResult = 'OK' })
$open.Add_Click({ $f.Tag = 'open'; $f.DialogResult = 'OK' })
$f.CancelButton = $close
$f.Controls.AddRange(@($pic, $hd, $sub, $fl, $flt, $sl, $q, $lv, $dt, $refresh, $open, $close))
Fill
$f.Add_Shown({ $lv.Focus() | Out-Null })
if ($f.ShowDialog() -ne 'OK') { exit 1 }
Out64 $f.Tag
`

// psSecrets: stdin = base64(JSON secretsDoc). Prints base64(JSON {action, names}) with action
// add|reveal|delete|refresh; Đóng = exit 1. Copying names happens here (names only, never values).
const psSecrets = `$f = NewForm 'KeyGate: secret trong vault' 1120 680
$d = ConvertFrom-Json (U ([Console]::In.ReadToEnd().Trim()))
function IcoKey($il, $key, $hex) {
  $bmp, $g = IcoBmp
  $pen = New-Object System.Drawing.Pen((C $hex), 2)
  $g.DrawEllipse($pen, 1, 4, 7, 7)
  $g.DrawLine($pen, 8, 8, 15, 8)
  $g.DrawLine($pen, 13, 8, 13, 12)
  $g.DrawLine($pen, 11, 8, 11, 11)
  $g.Dispose()
  $il.Images.Add($key, $bmp)
}
$pic = New-Object System.Windows.Forms.PictureBox
if ($f.Icon) { $pic.Image = (New-Object System.Drawing.Icon($f.Icon, 32, 32)).ToBitmap() } else { $pic.Image = [System.Drawing.SystemIcons]::Shield.ToBitmap() }
$pic.SetBounds(12, 12, 32, 32)
$hd = Lbl 'Secret trong vault' 54 8 1050 24
$hd.Font = New-Object System.Drawing.Font('Segoe UI', 11.5, [System.Drawing.FontStyle]::Bold)
$sub = Lbl $d.sub 54 34 1050 18
$sub.ForeColor = C '#555555'
$fl = New-Object System.Windows.Forms.FlowLayoutPanel
$fl.SetBounds(12, 60, 1096, 30)
$fl.WrapContents = $false
Badges $fl $d.badges
$flt = New-Object System.Windows.Forms.ComboBox
$flt.DropDownStyle = 'DropDownList'
$flt.Items.AddRange(@('Tất cả secret', 'Chỉ PROD', 'Có grant trong policy', 'Chưa có grant', 'Dùng trong 7 ngày', 'Đang xung đột'))
$flt.SelectedIndex = 0
$flt.SetBounds(12, 98, 220, 24)
$sl = Lbl 'Tìm:' 248 101 36 20
$q = Txt 286 98 320
$il = NewIcons
IcoKey $il 'key' '#3B6EA8'
IcoKey $il 'prod' '#B3261E'
Ico $il 'conflict' '#C77700' '!'
$lv = New-Object System.Windows.Forms.ListView
$lv.View = 'Details'
$lv.FullRowSelect = $true
$lv.MultiSelect = $true
$lv.HideSelection = $false
$lv.SmallImageList = $il
$lv.SetBounds(12, 130, 1096, 330)
[void]$lv.Columns.Add('Tên secret', 330)
[void]$lv.Columns.Add('Môi trường', 80)
[void]$lv.Columns.Add('Kiểu', 80)
[void]$lv.Columns.Add('Grant trong policy', 120)
[void]$lv.Columns.Add('Lệnh được nhận secret', 330)
[void]$lv.Columns.Add('Dùng gần nhất', 130)
$dt = New-Object System.Windows.Forms.TextBox
$dt.Multiline = $true
$dt.ReadOnly = $true
$dt.WordWrap = $true
$dt.ScrollBars = 'Vertical'
$dt.Font = New-Object System.Drawing.Font('Consolas', 9.5)
$dt.BackColor = [System.Drawing.Color]::White
$dt.SetBounds(12, 468, 1096, 130)
$st = Lbl $d.status 12 604 1096 20
if ($d.status_tone -eq 'del') { $st.ForeColor = C '#B3261E' } elseif ($d.status_tone -eq 'add') { $st.ForeColor = C '#1E7B34' } else { $st.ForeColor = C '#555555' }
function Fill {
  $lv.BeginUpdate()
  $lv.Items.Clear()
  $lv.Groups.Clear()
  $groups = @{}
  $mode = $flt.SelectedIndex
  $needle = $q.Text.Trim()
  foreach ($r in $d.rows) {
    if ($mode -eq 1 -and -not $r.prod) { continue }
    if ($mode -eq 2 -and -not $r.grant) { continue }
    if ($mode -eq 3 -and $r.grant) { continue }
    if ($mode -eq 4 -and -not $r.recent) { continue }
    if ($mode -eq 5 -and -not $r.conflict) { continue }
    if ($needle -and $r.name.IndexOf($needle, [StringComparison]::OrdinalIgnoreCase) -lt 0 -and ($r.short + '').IndexOf($needle, [StringComparison]::OrdinalIgnoreCase) -lt 0) { continue }
    if (-not $groups.ContainsKey($r.group)) {
      $groups[$r.group] = New-Object System.Windows.Forms.ListViewGroup($r.group, $r.group)
      [void]$lv.Groups.Add($groups[$r.group])
    }
    $ik = 'key'
    if ($r.prod) { $ik = 'prod' }
    if ($r.conflict -or $r.unsafe) { $ik = 'conflict' }
    $it = New-Object System.Windows.Forms.ListViewItem($r.name, $ik)
    $it.UseItemStyleForSubItems = $false
    $envText = $r.env
    if ($r.prod) { $envText = 'PROD' }
    $ec = $it.SubItems.Add($envText)
    [void]$it.SubItems.Add($r.kind)
    $gt = 'chưa có'
    if ($r.grant) { $gt = $r.approval }
    $gc = $it.SubItems.Add($gt)
    [void]$it.SubItems.Add($r.short)
    $lu = $r.last_used
    if (-not $lu) { $lu = 'chưa dùng' }
    $uc = $it.SubItems.Add($lu)
    if ($r.prod) { $ec.ForeColor = C '#B3261E'; $ec.Font = $bold }
    if (-not $r.grant) { $gc.ForeColor = [System.Drawing.Color]::Gray }
    if (-not $r.last_used) { $uc.ForeColor = [System.Drawing.Color]::Gray } elseif ($r.recent) { $uc.ForeColor = C '#1E7B34' }
    $it.Group = $groups[$r.group]
    $it.Tag = $r
    [void]$lv.Items.Add($it)
  }
  $lv.EndUpdate()
  Sel
}
function Detail($r) {
  $nl = [Environment]::NewLine
  $s = $r.name + $nl + '  môi trường: ' + $r.env + '   kiểu: ' + $r.kind
  if ($r.prod) { $s += '   (PROD)' }
  if ($r.unsafe) { $s += $nl + '  TÊN CÓ KÝ TỰ ẨN hoặc trùng tên hiển thị với secret khác: Xem/Xóa bị tắt ở đây, dùng kg list/kg delete' }
  if ($r.conflict) { $s += $nl + '  ĐANG XUNG ĐỘT: hai thiết bị sửa cùng lúc, chạy kg conflicts để chọn bản đúng' }
  if ($r.grant) {
    $s += $nl + '  grant trong policy: ' + $r.grant + ' · duyệt: ' + $r.approval
    foreach ($c in $r.commands) { $s += $nl + '    • ' + $c }
  } else { $s += $nl + '  chưa có grant trong policy: kg run sẽ bị từ chối' }
  if ($r.approved) { $s += $nl + '  grant đã duyệt đang sống:'; foreach ($a in $r.approved) { $s += $nl + '    • ' + $a } }
  $lu = $r.last_used
  if (-not $lu) { $lu = 'chưa dùng' }
  $s += $nl + '  dùng gần nhất: ' + $lu
  if ($r.writer) { $s += $nl + '  bản ghi mới nhất từ thiết bị: ' + $r.writer }
  return $s
}
$add = Btn 'Thêm secret…' 12 632 120
$show = Btn 'Xem giá trị (Windows Hello)' 140 632 200
$copy = Btn 'Sao chép tên' 348 632 110
$del = Btn 'Xóa… (Windows Hello)' 466 632 170
$del.ForeColor = C '#B3261E'
$refresh = Btn 'Làm mới' 898 632 100
$close = Btn 'Đóng' 1008 632 100
$close.DialogResult = 'Cancel'
function Sel {
  $n = $lv.SelectedItems.Count
  $unsafe = @($lv.SelectedItems | Where-Object { $_.Tag.unsafe }).Count
  $show.Enabled = ($n -eq 1 -and -not $lv.SelectedItems[0].Tag.conflict -and $unsafe -eq 0)
  $copy.Enabled = ($n -ge 1)
  $del.Enabled = ($n -ge 1 -and $unsafe -eq 0)
  if ($n -eq 1) { $dt.Text = Detail $lv.SelectedItems[0].Tag } elseif ($n -gt 1) { $dt.Text = 'Đã chọn ' + $n + ' secret.' } elseif ($lv.Items.Count -eq 0) { $dt.Text = 'Không có secret nào khớp bộ lọc.' } else { $dt.Text = 'Chọn một secret để xem chi tiết. Giữ Ctrl hoặc Shift để chọn nhiều secret khi xóa.' }
}
function Names { @($lv.SelectedItems | ForEach-Object { $_.Tag.key }) }
function Shown { @($lv.SelectedItems | ForEach-Object { $_.Tag.name }) }
function Done($a, $n) { $f.Tag = (@{ action = $a; names = @($n) } | ConvertTo-Json -Compress); $f.DialogResult = 'OK' }
$lv.Add_SelectedIndexChanged({ Sel })
$flt.Add_SelectedIndexChanged({ Fill })
$q.Add_TextChanged({ Fill })
$add.Add_Click({ Done 'add' @() })
$refresh.Add_Click({ Done 'refresh' @() })
$show.Add_Click({ Done 'reveal' (Names) })
$copy.Add_Click({
  $ns = Names
  [System.Windows.Forms.Clipboard]::SetText(($ns -join [Environment]::NewLine))
  $st.ForeColor = C '#1E7B34'
  $st.Text = 'Đã sao chép ' + $ns.Count + ' tên secret (không có giá trị).'
})
$del.Add_Click({
  $ns = Shown
  $prod = @($lv.SelectedItems | Where-Object { $_.Tag.prod }).Count
  $msg = 'Xóa ' + $ns.Count + ' secret khỏi vault?' + [Environment]::NewLine + [Environment]::NewLine + (($ns | Select-Object -First 15) -join [Environment]::NewLine)
  if ($ns.Count -gt 15) { $msg += [Environment]::NewLine + '… và ' + ($ns.Count - 15) + ' secret khác' }
  if ($prod -gt 0) { $msg += [Environment]::NewLine + [Environment]::NewLine + 'Trong đó có ' + $prod + ' secret PROD.' }
  $msg += [Environment]::NewLine + [Environment]::NewLine + 'Bước tiếp theo cần Windows Hello. Lệnh đang dùng các secret này sẽ không chạy được nữa; thiết bị khác nhận bản xóa ở lần đồng bộ sau.'
  $ans = [System.Windows.Forms.MessageBox]::Show($f, $msg, 'KeyGate: xác nhận xóa', 'YesNo', 'Warning', 'Button2')
  if ($ans -eq 'Yes') { Done 'delete' (Names) }
})
$f.CancelButton = $close
$f.Controls.AddRange(@($pic, $hd, $sub, $fl, $flt, $sl, $q, $lv, $dt, $st, $add, $show, $copy, $del, $refresh, $close))
Fill
if ($d.select) { foreach ($it in $lv.Items) { if ($it.Tag.key -ceq $d.select) { $it.Selected = $true; $it.EnsureVisible() } } }
$f.Add_Shown({ $lv.Focus() | Out-Null })
if ($f.ShowDialog() -ne 'OK') { exit 1 }
Out64 $f.Tag
`

// SecretAction is what the user picked in the Secret window.
type SecretAction struct {
	Action string   `json:"action"` // add | reveal | delete | refresh
	Names  []string `json:"names"`
}

type secretsDoc struct {
	Sub        string             `json:"sub"`
	Badges     []approve.Badge    `json:"badges"`
	Rows       []broker.SecretRow `json:"rows"`
	Status     string             `json:"status"`
	StatusTone string             `json:"status_tone"`
	Select     string             `json:"select"`
}

// Secrets shows the vault's secrets (metadata only) with Add / Reveal / Copy names / Delete.
// status is a one-line result of the previous action (tone add|del|muted); sel preselects a row.
// Đóng returns ErrCanceled. Returned names are always names of rows.
func Secrets(ctx context.Context, rows []broker.SecretRow, status, tone, sel string) (SecretAction, error) {
	var prod, conflict, nogrant, recent int
	known := map[string]bool{}
	for _, r := range rows {
		known[r.Key] = !r.Unsafe
		if r.Prod {
			prod++
		}
		if r.Conflict {
			conflict++
		}
		if r.Grant == "" {
			nogrant++
		}
		if r.Recent {
			recent++
		}
	}
	doc := secretsDoc{Sub: fmt.Sprintf("Chỉ hiện tên và thông tin đi kèm; giá trị chỉ xem được qua Windows Hello · đọc lúc %s", time.Now().Format("15:04:05")),
		Rows: rows, Status: status, StatusTone: tone, Select: sel}
	doc.Badges = append(doc.Badges, approve.Badge{Text: fmt.Sprintf("%d secret", len(rows)), Tone: approve.ToneMuted})
	if prod > 0 {
		doc.Badges = append(doc.Badges, approve.Badge{Text: fmt.Sprintf("%d PROD", prod), Tone: approve.ToneDel})
	}
	if conflict > 0 {
		doc.Badges = append(doc.Badges, approve.Badge{Text: fmt.Sprintf("%d xung đột", conflict), Tone: approve.ToneMod})
	}
	doc.Badges = append(doc.Badges, approve.Badge{Text: fmt.Sprintf("%d dùng trong 7 ngày", recent), Tone: approve.ToneAdd})
	if nogrant > 0 {
		doc.Badges = append(doc.Badges, approve.Badge{Text: fmt.Sprintf("%d chưa có grant", nogrant), Tone: approve.ToneMuted})
	}
	j, err := json.Marshal(doc)
	if err != nil {
		return SecretAction{}, err
	}
	raw, err := runPS(ctx, psVisual+psSecrets, base64.StdEncoding.EncodeToString(j))
	if err != nil {
		return SecretAction{}, err
	}
	var a SecretAction
	if err := json.Unmarshal(raw, &a); err != nil {
		return SecretAction{}, fmt.Errorf("hộp thoại trả dữ liệu lạ: %w", err)
	}
	switch a.Action {
	case "add", "refresh":
		a.Names = nil
		return a, nil
	case "reveal", "delete":
		if len(a.Names) == 0 || (a.Action == "reveal" && len(a.Names) != 1) {
			return SecretAction{}, fmt.Errorf("hộp thoại trả số secret sai cho %s", a.Action)
		}
		for _, n := range a.Names {
			if !known[n] {
				return SecretAction{}, fmt.Errorf("hộp thoại trả tên lạ: %q", truncRunes(n, 80))
			}
		}
		return a, nil
	}
	return SecretAction{}, fmt.Errorf("hộp thoại trả thao tác lạ: %q", truncRunes(a.Action, 40))
}

// psPair: stdin = base64(PNG) newline base64(UTF-8 text). The dialog only waits: Hủy (or Esc)
// exits 1 = ErrCanceled. The caller closes it by cancelling the context (runPS kills the process)
// once the phone's registration arrives or the slot expires.
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
$t.SetBounds(344, 12, 364, 296)
$t.Text = (U $in[1].Trim())
$t.Select(0, 0)
$cancel = Btn 'Hủy' 588 344 120
$cancel.DialogResult = 'Cancel'
$f.CancelButton = $cancel
$f.Controls.AddRange(@($p, $t, $cancel))
$f.Add_Shown({ $cancel.Focus() | Out-Null })
if ($f.ShowDialog() -ne 'OK') { exit 1 }
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

// ReviewDoc shows doc as a table (see psReviewDoc) with Continue/Cancel; nil = Continue.
func ReviewDoc(ctx context.Context, title string, doc approve.ReviewDoc) error {
	crlf := func(s string) string { return strings.ReplaceAll(strings.ReplaceAll(s, "\r\n", "\n"), "\n", "\r\n") }
	doc.Text = crlf(doc.Text)
	rows := make([]approve.ReviewRow, len(doc.Rows))
	for i, r := range doc.Rows {
		r.Detail = crlf(r.Detail)
		rows[i] = r
	}
	doc.Rows = rows
	j, err := json.Marshal(doc)
	if err != nil {
		return err
	}
	_, err = runPS(ctx, psVisual+fmt.Sprintf(psReviewDoc, b64(formTitle(title))), base64.StdEncoding.EncodeToString(j))
	return err
}

// LogWindow shows broker.log (and the rotated broker.log.1) as a filterable table until closed.
// "Mở file gốc" opens the raw file with its default program.
func LogWindow(ctx context.Context, path string) error {
	for {
		var text string
		for _, p := range []string{path + ".1", path} {
			if b, err := os.ReadFile(p); err == nil {
				text += string(b) + "\n"
			}
		}
		doc := BuildLogDoc(text, path, time.Now())
		for i := range doc.Entries {
			doc.Entries[i].Detail = strings.ReplaceAll(doc.Entries[i].Detail, "\n", "\r\n")
		}
		j, err := json.Marshal(doc)
		if err != nil {
			return err
		}
		raw, err := runPS(ctx, psVisual+psLog, base64.StdEncoding.EncodeToString(j))
		if errors.Is(err, ErrCanceled) {
			return nil
		}
		if err != nil {
			return err
		}
		if string(raw) == "refresh" {
			continue
		}
		if string(raw) == "open" {
			return OpenFile(path)
		}
		return nil
	}
}

// Pair shows the pairing link as a QR code (for the phone camera) beside text instructions and
// waits: there is no input. It returns ErrCanceled when the user presses Hủy, or ctx's error when
// the caller cancels ctx (phone registration arrived, slot expired); either way the dialog closes.
func Pair(ctx context.Context, link, text string) error {
	c, err := qr.Encode([]byte(link))
	if err != nil {
		return err
	}
	text = strings.ReplaceAll(strings.ReplaceAll(text, "\r\n", "\n"), "\n", "\r\n")
	_, err = runPS(ctx, psPair, base64.StdEncoding.EncodeToString(c.PNG(6))+"\n"+b64(text))
	return err
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
