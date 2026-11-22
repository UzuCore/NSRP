# Safe publisher regression: only creates a new disposable directory in TEMP.
[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
$qa = Join-Path $env:TEMP ("nsrp_publish_test_" + [Guid]::NewGuid().ToString('N'))
$root = Join-Path $qa 'nsrp.exe'
$dist = Join-Path $qa 'dist\nsrp.exe'
$release = Join-Path $PSScriptRoot '..\target\release\nsrp.exe'
$publisher = Join-Path $PSScriptRoot 'publish_release.ps1'
$lock = $null

try {
    [IO.Directory]::CreateDirectory((Join-Path $qa 'dist')) | Out-Null
    [IO.File]::WriteAllText($root, 'PREVIOUS_ROOT')
    [IO.File]::WriteAllText($dist, 'PREVIOUS_DIST')

    # Positive case: both old outputs are replaced, and no sidecars remain.
    & $publisher -DestinationRoot $qa | Out-Null
    $expected = (Get-FileHash -LiteralPath $release -Algorithm SHA256).Hash
    foreach ($file in @($root, $dist)) {
        if ((Get-FileHash -LiteralPath $file -Algorithm SHA256).Hash -ne $expected) {
            throw "Publisher output SHA mismatch: $file"
        }
    }

    # Negative case: the second target is locked. The first publication must
    # be rolled back and both previous outputs must be preserved byte-for-byte.
    [IO.File]::WriteAllText($root, 'PREVIOUS_ROOT')
    [IO.File]::WriteAllText($dist, 'PREVIOUS_DIST')
    $lock = [IO.File]::Open($dist, [IO.FileMode]::Open,
        [IO.FileAccess]::ReadWrite, [IO.FileShare]::None)
    $failureObserved = $false
    try {
        & $publisher -DestinationRoot $qa 2>&1 | Out-Null
    } catch {
        $failureObserved = $true
    }
    $lock.Dispose()
    $lock = $null
    if (-not $failureObserved) { throw 'Publisher unexpectedly replaced a locked destination' }
    if ([IO.File]::ReadAllText($root) -ne 'PREVIOUS_ROOT' -or
        [IO.File]::ReadAllText($dist) -ne 'PREVIOUS_DIST') {
        throw 'Publisher rollback lost an existing output'
    }
    $sidecars = @(Get-ChildItem -LiteralPath $qa -File -Recurse -Force |
        Where-Object { $_.Name -match '^\.nsrp-(stage|backup)-' })
    if ($sidecars.Count -ne 0) { throw 'Publisher left partial files after rollback' }
    Write-Output '[OK] Publish success, full SHA match, locked-destination rollback, no partial files'
} finally {
    if ($null -ne $lock) { $lock.Dispose() }
    if (Test-Path -LiteralPath $qa) { Remove-Item -LiteralPath $qa -Force -Recurse }
}
