# Hash the optional external tools and icon that are compiled into NSRP.
# No game content, keys or user settings are read.
[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
$rustRoot = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
$manifest = Join-Path $PSScriptRoot 'embedded_files.sha256'
$count = 0
foreach ($line in [IO.File]::ReadAllLines($manifest)) {
    if ([string]::IsNullOrWhiteSpace($line) -or $line.StartsWith('#')) { continue }
    if ($line -notmatch '^([0-9a-fA-F]{64})\s{2}(.+)$') {
        throw "Invalid embedded-file manifest line: $line"
    }
    $expected = $Matches[1].ToUpperInvariant()
    $relative = $Matches[2]
    $path = [IO.Path]::GetFullPath((Join-Path $rustRoot $relative))
    if (-not [IO.File]::Exists($path)) {
        throw "Missing compile-time input: $relative"
    }
    $actual = (Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash
    if ($actual -ne $expected) {
        throw "Compile-time input hash mismatch: $relative (expected $expected, actual $actual)"
    }
    $count += 1
}
if ($count -ne 7) { throw "Expected seven compile-time inputs, got $count" }
Write-Output "[OK] Verified $count compile-time embedded inputs"
