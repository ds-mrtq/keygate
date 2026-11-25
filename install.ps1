# KeyGate installer for Windows (amd64, arm64).
#
#   irm https://raw.githubusercontent.com/ds-mrtq/keygate/main/install.ps1 | iex
#   & ([scriptblock]::Create((irm https://raw.githubusercontent.com/ds-mrtq/keygate/main/install.ps1))) -Version v0.1.0
#
# Downloads the release zip and SHA256SUMS, refuses to install unless the zip's SHA-256 matches
# its SHA256SUMS entry, installs kg.exe and kgw.exe to %LOCALAPPDATA%\Programs\KeyGate and adds
# that directory to the user PATH. No administrator rights needed.
#
# Parameters (or environment variables):
#   -Version <tag>      KG_VERSION      release tag to install (default: the latest release)
#   -InstallDir <path>  KG_INSTALL_DIR  install directory (default: %LOCALAPPDATA%\Programs\KeyGate)
#   -BaseUrl <url>      KG_BASE_URL     where the zips and SHA256SUMS are (a URL or a local
#                                       directory; default: the GitHub release of -Version);
#                                       needs -Version
param(
    [string]$Version = $env:KG_VERSION,
    [string]$InstallDir = $env:KG_INSTALL_DIR,
    [string]$BaseUrl = $env:KG_BASE_URL
)

function Install-KeyGate {
    # Progress goes to the console only, so `irm ... | iex` returns nothing to the pipeline.
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidUsingWriteHost', '')]
    param([string]$Version, [string]$InstallDir, [string]$BaseUrl)

    $ErrorActionPreference = 'Stop'
    $ProgressPreference = 'SilentlyContinue'
    $repo = 'ds-mrtq/keygate'

    if ([Environment]::OSVersion.Platform -ne 'Win32NT') {
        throw 'kg install: this script installs on Windows only; on Linux use install.sh'
    }
    $cpu = $env:PROCESSOR_ARCHITEW6432
    if (-not $cpu) { $cpu = $env:PROCESSOR_ARCHITECTURE }
    switch ($cpu) {
        'AMD64' { $arch = 'amd64' }
        'ARM64' { $arch = 'arm64' }
        default { throw "kg install: unsupported CPU architecture: $cpu (release zips exist for amd64 and arm64)" }
    }
    if ($PSVersionTable.PSVersion.Major -lt 6) {
        [Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12
    }

    if (-not $Version) {
        if ($BaseUrl) { throw 'kg install: -BaseUrl needs -Version' }
        $latest = "https://github.com/$repo/releases/latest"
        try {
            $response = Invoke-WebRequest -Uri $latest -UseBasicParsing -Method Head
        } catch {
            throw "kg install: could not reach ${latest}: $($_.Exception.Message); pass -Version <tag>"
        }
        $resolved = if ($response.BaseResponse.ResponseUri) { $response.BaseResponse.ResponseUri } else { $response.BaseResponse.RequestMessage.RequestUri }
        if ("$resolved" -notmatch '/releases/tag/([^/?#]+)$') {
            throw "kg install: no published release found at $latest; pass -Version <tag>"
        }
        $Version = $Matches[1]
    }
    if ($Version -notmatch '^[A-Za-z0-9._-]+$') { throw "kg install: invalid version: $Version" }
    if (-not $BaseUrl) { $BaseUrl = "https://github.com/$repo/releases/download/$Version" }
    $BaseUrl = $BaseUrl.TrimEnd('/', '\')
    if (-not $InstallDir) {
        if (-not $env:LOCALAPPDATA) { throw 'kg install: LOCALAPPDATA is not set; pass -InstallDir' }
        $InstallDir = Join-Path $env:LOCALAPPDATA 'Programs\KeyGate'
    }

    $archive = "kg_${Version}_windows_${arch}.zip"
    $tmp = Join-Path ([IO.Path]::GetTempPath()) ('kg-install-' + [guid]::NewGuid().ToString('N'))
    New-Item -ItemType Directory -Path $tmp | Out-Null
    try {
        Write-Host "Downloading KeyGate $Version (windows/$arch) from $BaseUrl"
        foreach ($file in @('SHA256SUMS', $archive)) {
            $out = Join-Path $tmp $file
            try {
                if (Test-Path -LiteralPath $BaseUrl -PathType Container) {
                    Copy-Item -LiteralPath (Join-Path $BaseUrl $file) -Destination $out
                } else {
                    Invoke-WebRequest -Uri "$BaseUrl/$file" -OutFile $out -UseBasicParsing
                }
            } catch {
                throw "kg install: could not download $BaseUrl/${file}: $($_.Exception.Message)"
            }
        }

        $want = $null
        foreach ($line in Get-Content -LiteralPath (Join-Path $tmp 'SHA256SUMS')) {
            $fields = $line.Trim() -split '\s+', 2
            if ($fields.Count -eq 2 -and $fields[1].TrimStart('*') -eq $archive) { $want = $fields[0].ToLowerInvariant(); break }
        }
        if (-not $want) { throw "kg install: SHA256SUMS has no entry for $archive; nothing installed" }
        $got = (Get-FileHash -LiteralPath (Join-Path $tmp $archive) -Algorithm SHA256).Hash.ToLowerInvariant()
        if ($got -ne $want) {
            throw "kg install: checksum mismatch for ${archive}: SHA256SUMS says $want, the download is $got; nothing installed"
        }
        Write-Host "Checksum OK: $archive $got"

        $unpacked = Join-Path $tmp 'unpacked'
        Expand-Archive -LiteralPath (Join-Path $tmp $archive) -DestinationPath $unpacked
        $binaries = @('kg.exe', 'kgw.exe')
        foreach ($name in $binaries) {
            if (-not (Test-Path -LiteralPath (Join-Path $unpacked $name) -PathType Leaf)) {
                throw "kg install: $archive has no $name; nothing installed"
            }
        }

        New-Item -ItemType Directory -Path $InstallDir -Force | Out-Null
        foreach ($name in $binaries) {
            Copy-Item -LiteralPath (Join-Path $unpacked $name) -Destination (Join-Path $InstallDir "$name.new") -Force
        }
        # A running exe (the tray, a broker) cannot be overwritten but can be renamed: move the old
        # one aside so the new one goes in; it keeps running until restarted.
        foreach ($name in $binaries) {
            $target = Join-Path $InstallDir $name
            $old = "$target.old"
            Remove-Item -LiteralPath $old -Force -ErrorAction SilentlyContinue
            if (Test-Path -LiteralPath $target) { Move-Item -LiteralPath $target -Destination $old -Force }
            Move-Item -LiteralPath "$target.new" -Destination $target -Force
            Remove-Item -LiteralPath $old -Force -ErrorAction SilentlyContinue
        }
    } finally {
        Remove-Item -LiteralPath $tmp -Recurse -Force -ErrorAction SilentlyContinue
    }

    $kg = Join-Path $InstallDir 'kg.exe'
    Write-Host "Installed $kg and $(Join-Path $InstallDir 'kgw.exe')"
    & $kg version
    if ($LASTEXITCODE -ne 0) { throw 'kg install: the installed kg.exe did not run' }
    if (Get-Process -Name kgw -ErrorAction SilentlyContinue) {
        Write-Host 'KeyGate tray (kgw.exe) is running the previous version; quit it from the tray and start it again.'
    }

    $key = [Microsoft.Win32.Registry]::CurrentUser.CreateSubKey('Environment')
    try {
        $userPath = [string]$key.GetValue('Path', '', [Microsoft.Win32.RegistryValueOptions]::DoNotExpandEnvironmentNames)
        $entries = @($userPath -split ';' | Where-Object { $_ })
        $present = $entries | Where-Object {
            [Environment]::ExpandEnvironmentVariables($_).TrimEnd('\') -ieq $InstallDir.TrimEnd('\')
        }
        if (-not $present) {
            $key.SetValue('Path', (($entries + $InstallDir) -join ';'), [Microsoft.Win32.RegistryValueKind]::ExpandString)
            Send-EnvironmentChange
            Write-Host "Added $InstallDir to your user PATH; open a new terminal to use kg."
        }
    } finally {
        $key.Close()
    }
    if (-not (($env:Path -split ';') | Where-Object { $_.TrimEnd('\') -ieq $InstallDir.TrimEnd('\') })) {
        $env:Path = "$env:Path;$InstallDir"
    }

    Write-Host ''
    Write-Host 'Optional: check the build provenance attestation with the GitHub CLI (gh):'
    Write-Host "  gh release download $Version --repo $repo -p $archive -p SHA256SUMS"
    Write-Host "  gh attestation verify $archive --repo $repo"
    Write-Host "  gh attestation verify SHA256SUMS --repo $repo"
}

# Tell Explorer the user environment changed, so terminals started from it see the new PATH.
function Send-EnvironmentChange {
    if (-not ('KeyGateInstall.Native' -as [type])) {
        Add-Type -Namespace KeyGateInstall -Name Native -MemberDefinition @'
[DllImport("user32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
public static extern IntPtr SendMessageTimeout(IntPtr hWnd, uint Msg, UIntPtr wParam, string lParam, uint fuFlags, uint uTimeout, out UIntPtr lpdwResult);
'@
    }
    $result = [UIntPtr]::Zero
    [void][KeyGateInstall.Native]::SendMessageTimeout([IntPtr]0xffff, 0x1a, [UIntPtr]::Zero, 'Environment', 2, 5000, [ref]$result)
}

Install-KeyGate -Version $Version -InstallDir $InstallDir -BaseUrl $BaseUrl
