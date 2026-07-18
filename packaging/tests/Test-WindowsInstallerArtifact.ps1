$ErrorActionPreference = 'Stop'
$repo = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
$dist = Join-Path $repo 'dist'
$metadataFiles = @(Get-ChildItem -LiteralPath $dist -Filter 'IPAd-Manager-Setup-*.json' -ErrorAction SilentlyContinue)
if ($metadataFiles.Count -ne 1) { throw "Expected one installer metadata file, found $($metadataFiles.Count)" }
$metadata = Get-Content -LiteralPath $metadataFiles[0].FullName -Raw | ConvertFrom-Json
$installer = Join-Path $dist $metadata.InstallerFile
$deb = Join-Path $dist $metadata.DebFile
if (-not (Test-Path -LiteralPath $installer -PathType Leaf)) { throw 'Windows installer is missing' }
if (-not (Test-Path -LiteralPath $deb -PathType Leaf)) { throw 'Canonical deb is missing' }
if ($metadata.Architecture -ne 'x64') { throw 'Installer architecture metadata must be x64' }
if ($metadata.DebSha256 -ne (Get-FileHash -LiteralPath $deb -Algorithm SHA256).Hash.ToLowerInvariant()) {
    throw 'Embedded deb hash metadata does not match the canonical deb'
}
if ($metadata.InstallerSha256 -ne (Get-FileHash -LiteralPath $installer -Algorithm SHA256).Hash.ToLowerInvariant()) {
    throw 'Installer hash metadata does not match the EXE'
}
$header = [IO.File]::ReadAllBytes($installer)[0..1]
if ($header[0] -ne 0x4d -or $header[1] -ne 0x5a) { throw 'Installer is not a PE executable' }
if ($null -eq $metadata.Signed) { throw 'Metadata must explicitly declare signing status' }
Write-Output 'Windows installer artifact checks passed'
