[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][string]$DebPath,
    [Parameter(Mandatory = $true)][string]$ExpectedSha256,
    [string]$LogPath = "$env:LocalAppData\IPAd Manager\install.log",
    [switch]$Resume
)

$ErrorActionPreference = 'Stop'
$Distribution = 'Ubuntu'
$ExitUnsupportedOs = 10
$ExitElevationRequired = 11
$ExitRebootRequired = 12
$ExitWslFailure = 20
$ExitUbuntuFailure = 21
$ExitHashMismatch = 30
$ExitAptFailure = 40
$ExitHealthFailure = 41

function Write-InstallLog([string]$Message) {
    $directory = Split-Path -Parent $LogPath
    if ($directory) { New-Item -ItemType Directory -Path $directory -Force | Out-Null }
    "$(Get-Date -Format o) $Message" | Add-Content -LiteralPath $LogPath -Encoding UTF8
}

function Test-Administrator {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($identity)
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Invoke-Wsl([string[]]$Arguments, [int]$FailureCode) {
    Write-InstallLog "wsl.exe $($Arguments -join ' ')"
    & wsl.exe @Arguments 2>&1 | Tee-Object -FilePath $LogPath -Append
    if ($LASTEXITCODE -ne 0) { exit $FailureCode }
}

function ConvertTo-WslPath([string]$WindowsPath) {
    $full = [IO.Path]::GetFullPath($WindowsPath)
    if ($full -notmatch '^([A-Za-z]):\\(.*)$') {
        throw "Unsupported Windows path for WSL: $full"
    }
    return "/mnt/$($Matches[1].ToLowerInvariant())/$($Matches[2].Replace('\', '/'))"
}

if (-not [Environment]::Is64BitOperatingSystem -or [Environment]::OSVersion.Version.Build -lt 19041) {
    Write-InstallLog 'Unsupported Windows version or architecture.'
    exit $ExitUnsupportedOs
}
$isAdministrator = Test-Administrator
if (-not (Test-Path -LiteralPath $DebPath -PathType Leaf)) {
    Write-InstallLog "Package does not exist: $DebPath"
    exit $ExitHashMismatch
}
$actualHash = (Get-FileHash -LiteralPath $DebPath -Algorithm SHA256).Hash.ToLowerInvariant()
if ($actualHash -ne $ExpectedSha256.ToLowerInvariant()) {
    Write-InstallLog "Package hash mismatch. expected=$ExpectedSha256 actual=$actualHash"
    exit $ExitHashMismatch
}

$wsl = Get-Command wsl.exe -ErrorAction SilentlyContinue
if (-not $wsl) {
    if (-not $isAdministrator) {
        Write-InstallLog 'Administrator privileges are required to enable WSL.'
        exit $ExitElevationRequired
    }
    Write-InstallLog 'Installing WSL and Ubuntu.'
    & wsl.exe --install --distribution $Distribution --no-launch
    exit $ExitRebootRequired
}

$registered = @(& wsl.exe --list --quiet 2>$null) | ForEach-Object { $_.Trim([char]0).Trim() }
if ($registered -notcontains $Distribution) {
    if (-not $isAdministrator) {
        Write-InstallLog 'Administrator privileges are required to install Ubuntu.'
        exit $ExitElevationRequired
    }
    Write-InstallLog 'Installing the official Ubuntu WSL distribution.'
    & wsl.exe --install --distribution $Distribution --no-launch 2>&1 | Tee-Object -FilePath $LogPath -Append
    if ($LASTEXITCODE -ne 0) { exit $ExitUbuntuFailure }
}

$stage = Join-Path $env:Temp 'IPAdManager'
New-Item -ItemType Directory -Path $stage -Force | Out-Null
$stageDeb = Join-Path $stage 'ipad-manager.deb'
$stageScript = Join-Path $stage 'install-ipad-manager.sh'
Copy-Item -LiteralPath $DebPath -Destination $stageDeb -Force
$linuxDeb = ConvertTo-WslPath $stageDeb

$wrapper = @'
#!/bin/sh
set -eu
deb=$1
export DEBIAN_FRONTEND=noninteractive
apt-get update
apt-get install -y "$deb"
/usr/bin/ipad-manager-health --json
'@
[IO.File]::WriteAllText($stageScript, ($wrapper -replace "`r`n", "`n"), (New-Object Text.UTF8Encoding($false)))
$linuxScript = ConvertTo-WslPath $stageScript

Invoke-Wsl @('--distribution', $Distribution, '--user', 'root', '--', 'sh', $linuxScript, $linuxDeb) $ExitAptFailure
Invoke-Wsl @('--distribution', $Distribution, '--user', 'root', '--', '/usr/bin/ipad-manager-health', '--json') $ExitHealthFailure
Write-InstallLog 'IPAd Manager installation completed.'
exit 0
