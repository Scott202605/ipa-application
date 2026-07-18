[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][string]$Deb,
    [Parameter(Mandatory = $true)][string]$Version,
    [Parameter(Mandatory = $true)][string]$Output,
    [string]$MakeNsis = 'C:\tmp\nsis-3.12\makensis.exe'
)

$ErrorActionPreference = 'Stop'
$source = $PSScriptRoot
$script = Join-Path $source 'IPAd-Manager.nsi'
$deb = (Resolve-Path -LiteralPath $Deb).Path
New-Item -ItemType Directory -Path $Output -Force | Out-Null
$output = (Resolve-Path -LiteralPath $Output).Path
if (-not (Test-Path -LiteralPath $MakeNsis -PathType Leaf)) {
    Write-Error "NSIS compiler not found: $MakeNsis"
    exit 50
}
$debHash = (Get-FileHash -LiteralPath $deb -Algorithm SHA256).Hash.ToLowerInvariant()
& $MakeNsis /V3 "/DVERSION=$Version" "/DDEB=$deb" "/DDEBSHA=$debHash" "/DOUTPUT=$output" "/DSOURCE=$source" $script
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
$installerName = "IPAd-Manager-Setup-$Version-x64.exe"
$installer = Join-Path $output $installerName
if (-not (Test-Path -LiteralPath $installer -PathType Leaf)) { throw "NSIS did not create $installer" }
$installerHash = (Get-FileHash -LiteralPath $installer -Algorithm SHA256).Hash.ToLowerInvariant()
$signature = Get-AuthenticodeSignature -LiteralPath $installer
$metadata = [ordered]@{
    SchemaVersion = 1
    Version = $Version
    Architecture = 'x64'
    DebFile = Split-Path -Leaf $deb
    DebSha256 = $debHash
    InstallerFile = $installerName
    InstallerSha256 = $installerHash
    Signed = ($signature.Status -eq 'Valid')
    SigningStatus = $signature.Status.ToString()
    Builder = 'NSIS 3.12'
}
$metadataPath = Join-Path $output "IPAd-Manager-Setup-$Version-x64.json"
$metadata | ConvertTo-Json | Set-Content -LiteralPath $metadataPath -Encoding UTF8
Write-Output $installer
