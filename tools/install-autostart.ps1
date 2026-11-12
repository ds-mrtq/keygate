# Dang ky/go task Windows "KeyGate broker" chay khi ban dang nhap: chay `kgw.exe tray` (khong console,
# icon khay he thong). Hop Windows Hello hien luc do de mo vault + mo phien lam viec (1 lan).
#   powershell -ExecutionPolicy Bypass -File tools\install-autostart.ps1           # dang ky
#   powershell -ExecutionPolicy Bypass -File tools\install-autostart.ps1 -Remove   # go
# kgw.exe: go build -ldflags "-H=windowsgui" -o "$(go env GOPATH)/bin/kgw.exe" ./cmd/kg
param([switch]$Remove)
$ErrorActionPreference = 'Stop'
$name = 'KeyGate broker'
if ($Remove) {
  Unregister-ScheduledTask -TaskName $name -Confirm:$false -ErrorAction SilentlyContinue
  "Da go task '$name'."
  return
}
$kgw = (Get-Command kgw.exe -ErrorAction Stop).Source
$action = New-ScheduledTaskAction -Execute $kgw -Argument 'tray'
$trigger = New-ScheduledTaskTrigger -AtLogOn -User "$env:USERDOMAIN\$env:USERNAME"
$settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -ExecutionTimeLimit ([TimeSpan]::Zero)
$principal = New-ScheduledTaskPrincipal -UserId "$env:USERDOMAIN\$env:USERNAME" -LogonType Interactive -RunLevel Limited
Register-ScheduledTask -TaskName $name -Action $action -Trigger $trigger -Settings $settings -Principal $principal -Force | Out-Null
"Da dang ky task '$name': $kgw tray (khi dang nhap)."
