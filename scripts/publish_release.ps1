# Distribute an already built release without exposing partially copied EXEs.
# Run from any location. An optional DestinationRoot supports isolated QA.
[CmdletBinding()]
param(
    [switch]$DryRun,
    [string]$DestinationRoot = ""
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$rustRoot = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
# The project source and deployment root are the same directory since the
# former rust_port/ subtree was moved to the NSRP root. Never publish into
# the parent NSW.dev directory by accident.
$destination = if ($DestinationRoot) { [IO.Path]::GetFullPath($DestinationRoot) } else { $rustRoot }
$source = Join-Path $rustRoot 'target\release\nsrp.exe'

if (-not (Test-Path -LiteralPath $source -PathType Leaf)) {
    throw "Release build not found: $source"
}
$sourceHash = (Get-FileHash -LiteralPath $source -Algorithm SHA256).Hash
$buildId = [Guid]::NewGuid().ToString('N')
$items = @(
    [pscustomobject]@{ Target = (Join-Path $destination 'nsrp.exe'); Stage = ''; Backup = ''; Published = $false; HadTarget = $false },
    [pscustomobject]@{ Target = (Join-Path $destination 'dist\nsrp.exe'); Stage = ''; Backup = ''; Published = $false; HadTarget = $false }
)
$completed = $false
$rollbackErrors = [Collections.Generic.List[string]]::new()

try {
    # Stage and checksum every target before replacing the first one.
    foreach ($item in $items) {
        $dir = Split-Path -Parent $item.Target
        [IO.Directory]::CreateDirectory($dir) | Out-Null
        $item.Stage = Join-Path $dir (".nsrp-stage-$buildId.tmp")
        $item.Backup = Join-Path $dir (".nsrp-backup-$buildId.tmp")
        $item.HadTarget = [IO.File]::Exists($item.Target)
        [IO.File]::Copy($source, $item.Stage, $false)
        $stagedHash = (Get-FileHash -LiteralPath $item.Stage -Algorithm SHA256).Hash
        if ($stagedHash -ne $sourceHash) {
            throw "Staged file hash mismatch: $($item.Target)"
        }
    }

    if (-not $DryRun) {
        foreach ($item in $items) {
            if ($item.HadTarget) {
                # Windows same-volume ReplaceFileW is atomic and retains the old
                # output as a backup until both destinations are verified.
                [IO.File]::Replace($item.Stage, $item.Target, $item.Backup, $true)
            } else {
                [IO.File]::Move($item.Stage, $item.Target)
            }
            $item.Published = $true
            $actual = (Get-FileHash -LiteralPath $item.Target -Algorithm SHA256).Hash
            if ($actual -ne $sourceHash) {
                throw "Published file hash mismatch: $($item.Target)"
            }
        }
    }
    $completed = $true
    Write-Output ("[OK] Release {0} SHA-256 {1}" -f $(if ($DryRun) { 'staging verified' } else { 'published' }), $sourceHash)
} catch {
    $failure = $_
    # Roll back only paths this invocation published, in reverse order.
    [array]::Reverse($items)
    foreach ($item in $items) {
        if (-not $item.Published) { continue }
        try {
            if ($item.HadTarget) {
                if (-not [IO.File]::Exists($item.Backup)) {
                    throw "Previous release backup missing: $($item.Backup)"
                }
                # ReplaceFileW requires a concrete sidecar backup path on
                # some Windows filesystems; null can fail with ERROR_INVALID_PARAMETER.
                # The original Stage path has been consumed by the successful
                # forward publish and is safe for the discarded new version.
                [IO.File]::Replace($item.Backup, $item.Target, $item.Stage, $true)
            } elseif ([IO.File]::Exists($item.Target)) {
                [IO.File]::Delete($item.Target)
            }
            $item.Published = $false
        } catch {
            $rollbackErrors.Add("Rollback failed for $($item.Target): $_")
        }
    }
    Write-Error "Release publication failed: $failure" -ErrorAction Continue
    if ($rollbackErrors.Count -gt 0) {
        foreach ($message in $rollbackErrors) { Write-Error $message -ErrorAction Continue }
        Write-Warning 'Previous release backups were retained for manual recovery.'
    }
    throw $failure
} finally {
    foreach ($item in $items) {
        if ($item.Stage -and [IO.File]::Exists($item.Stage)) {
            [IO.File]::Delete($item.Stage)
        }
        if ($completed -and $item.Backup -and [IO.File]::Exists($item.Backup)) {
            [IO.File]::Delete($item.Backup)
        }
    }
}
