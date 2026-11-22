# Reproducible, checked Windows release entry point.
# The top-level build.bat is a convenience wrapper around this versioned file.
[CmdletBinding()]
param(
    [switch]$Offline,
    [switch]$DryRun
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
$rustRoot = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
& (Join-Path $PSScriptRoot 'verify_embedded_inputs.ps1')
if (-not $?) { throw 'Compile-time input validation failed' }

Push-Location $rustRoot
try {
    $args = @('build', '--release', '--locked')
    if ($Offline) { $args += '--offline' }
    & cargo @args
    if ($LASTEXITCODE -ne 0) {
        throw "Locked Release build failed with exit code $LASTEXITCODE"
    }
} finally {
    Pop-Location
}

& (Join-Path $PSScriptRoot 'publish_release.ps1') -DryRun:$DryRun
if (-not $?) { throw 'Release publication failed' }
