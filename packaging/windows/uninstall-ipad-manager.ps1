[CmdletBinding()]
param(
    [switch]$Purge,
    [string]$LogPath = "$env:LocalAppData\IPAd Manager\uninstall.log"
)

$ErrorActionPreference = 'Stop'
$Distribution = 'Ubuntu'
$directory = Split-Path -Parent $LogPath
if ($directory) { New-Item -ItemType Directory -Path $directory -Force | Out-Null }
if ($Purge) {
    "$(Get-Date -Format o) apt-get purge ipad-manager" | Add-Content -LiteralPath $LogPath -Encoding UTF8
    & wsl.exe --distribution $Distribution --user root -- apt-get purge -y ipad-manager 2>&1 |
        Tee-Object -FilePath $LogPath -Append
} else {
    "$(Get-Date -Format o) apt-get remove ipad-manager" | Add-Content -LiteralPath $LogPath -Encoding UTF8
    & wsl.exe --distribution $Distribution --user root -- apt-get remove -y ipad-manager 2>&1 |
        Tee-Object -FilePath $LogPath -Append
}
exit $LASTEXITCODE
