$ErrorActionPreference = 'Stop'
$repo = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
$windowsDir = Join-Path $repo 'packaging\windows'
$required = @(
    'install-ipad-manager.ps1',
    'uninstall-ipad-manager.ps1',
    'launch-ipad-manager.cmd'
)

foreach ($name in $required) {
    $path = Join-Path $windowsDir $name
    if (-not (Test-Path -LiteralPath $path)) {
        throw "Missing Windows packaging file: $name"
    }
}

$text = ($required | ForEach-Object {
    Get-Content -LiteralPath (Join-Path $windowsDir $_) -Raw
}) -join "`n"

if ($text -notmatch '--distribution') { throw 'WSL distribution must be explicit' }
if ($text -notmatch 'Ubuntu') { throw 'Ubuntu distribution must be explicit' }
if ($text -notmatch '--user') { throw 'WSL user must be explicit' }
if ($text -notmatch 'root') { throw 'root must be explicit for install operations' }
if ($text -match '(?i)wsl(?:\.exe)?\s+--unregister|wslconfig(?:\.exe)?\s+/u') {
    throw 'Destructive WSL distribution command is forbidden'
}
if ($text -notmatch 'Get-FileHash') { throw 'Embedded package hash verification is required' }
if ($text -notmatch 'ipad-manager-health') { throw 'Post-install health verification is required' }
if ($text -notmatch 'apt-get\s+(remove|purge)') { throw 'Product uninstall must use apt-get remove/purge' }

Write-Output 'Windows installer policy checks passed'
