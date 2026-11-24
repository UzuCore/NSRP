param(
    [Parameter(Mandatory=$true)][string]$BaseDir,
    [Parameter(Mandatory=$true)][string]$TaskDir,
    [switch]$NoRestart,
    [int]$WaitForPid = 0
)
$ErrorActionPreference = 'Stop'
$base = [IO.Path]::GetFullPath($BaseDir)
$task = [IO.Path]::GetFullPath($TaskDir)
$package = Join-Path $task 'package'
$backupRoot = Join-Path $task 'backup'
# LOCALAPPDATA is often C:, while the installed executable can be on D:.
# File.Replace requires its source, destination and backup on ONE volume.
# Stage beside the installation, not in the downloaded package directory.
$pendingRoot = Join-Path $base ('.nsrp-update-stage-' + [guid]::NewGuid().ToString('N'))
$localBackupRoot = Join-Path $pendingRoot 'backup'
# Keep this helper independent of Get-FileHash module autoloading. Windows
# PowerShell launched from pwsh/other shells may inherit a PSModulePath that
# does not expose the cmdlet even though the .NET SHA-256 API is available.
function Get-NsrpSha256([string]$filePath) {
    $sha = [System.Security.Cryptography.SHA256]::Create()
    $stream = [IO.File]::OpenRead($filePath)
    try {
        return [BitConverter]::ToString($sha.ComputeHash($stream)).Replace('-', '')
    } finally {
        $stream.Dispose()
        $sha.Dispose()
    }
}
# Deliberately exclude library.db, config.json, local title database,
# keys, screenshots, icons, torrent state and downloads.
$files = @('nsrp.exe', 'nsrp-manifest.json')
$applied = @()
$rollbackErrors = @()
try {
    # Reverify staged content immediately before applying it. The package
    # could have changed after the download-and-confirm stage.
    $sourceExe = Join-Path $package 'nsrp.exe'
    $sourceManifest = Join-Path $package 'nsrp-manifest.json'
    if (-not (Test-Path -LiteralPath $sourceExe -PathType Leaf) -or
        -not (Test-Path -LiteralPath $sourceManifest -PathType Leaf)) {
        throw 'The staged NSRP update is missing its executable or manifest.'
    }
    $manifest = Get-Content -LiteralPath $sourceManifest -Raw | ConvertFrom-Json
    $expectedHash = [string]$manifest.sha256.'nsrp.exe'
    if ($manifest.application -cne 'NSRP' -or
        $manifest.platform -cne 'windows-x86_64' -or
        $manifest.commit -notmatch '^[0-9a-fA-F]{40}$' -or
        $expectedHash -notmatch '^[0-9a-fA-F]{64}$') {
        throw 'The staged NSRP update manifest is invalid.'
    }
    $sourceHash = Get-NsrpSha256 $sourceExe
    if ($sourceHash -cne $expectedHash.ToUpperInvariant()) {
        throw 'The staged NSRP executable does not match its SHA-256 manifest.'
    }
    foreach ($relative in $files) {
        $source = Join-Path $package $relative
        if (-not (Test-Path -LiteralPath $source -PathType Leaf)) {
            throw "Update file missing: $relative"
        }
        $pending = Join-Path $pendingRoot $relative
        $parent = Split-Path -Parent $pending
        New-Item -ItemType Directory -Path $parent -Force | Out-Null
        Copy-Item -LiteralPath $source -Destination $pending
        if ((Get-NsrpSha256 $pending) -cne (Get-NsrpSha256 $source)) {
            throw "Same-volume staged update verification failed: $relative"
        }
    }
    # The parent GUI waits for this handshake before exiting. At this point
    # the helper has validated and staged both files and is ready to wait
    # for the caller's exact PID. Never signal readiness before these checks.
    [IO.File]::WriteAllText(
        (Join-Path $task 'apply-ready.flag'),
        $manifest.commit,
        [Text.UTF8Encoding]::new($false)
    )
    # Wait for the exact process that requested this update. A fixed sleep
    # could expire before the GUI has released its executable on slow PCs.
    if ($WaitForPid -gt 0) {
        $oldProcess = Get-Process -Id $WaitForPid -ErrorAction SilentlyContinue
        if ($null -ne $oldProcess) {
            try {
                if (-not $oldProcess.WaitForExit(60000)) {
                    throw "NSRP (PID $WaitForPid) did not exit; no files were changed."
                }
            } finally {
                $oldProcess.Dispose()
            }
        }
    } else {
        Start-Sleep -Milliseconds 500
    }
    foreach ($relative in $files) {
        $target = Join-Path $base $relative
        $pending = Join-Path $pendingRoot $relative
        $backup = Join-Path $localBackupRoot $relative
        New-Item -ItemType Directory -Path (Split-Path -Parent $target) -Force | Out-Null
        New-Item -ItemType Directory -Path (Split-Path -Parent $backup) -Force | Out-Null
        $replaced = $false
        for ($attempt = 0; $attempt -lt 30 -and -not $replaced; $attempt++) {
            try {
                if ([IO.File]::Exists($target)) {
                    [IO.File]::Replace($pending, $target, $backup, $true)
                } else {
                    [IO.File]::Move($pending, $target)
                }
                $replaced = $true
                $applied += $relative
            } catch {
                if ($attempt -eq 29) { throw }
                Start-Sleep -Milliseconds 500
            }
        }
        # Retain an audit backup beside the downloaded task, but use the
        # install-volume backup for any atomic rollback. Keep this outside
        # the retry loop so archival failures cannot be silently swallowed.
        if ([IO.File]::Exists($backup)) {
            $recordedBackup = Join-Path $backupRoot $relative
            New-Item -ItemType Directory -Path (Split-Path -Parent $recordedBackup) -Force | Out-Null
            Copy-Item -LiteralPath $backup -Destination $recordedBackup
            if ((Get-NsrpSha256 $recordedBackup) -cne (Get-NsrpSha256 $backup)) {
                throw "Update backup verification failed: $relative"
            }
        }
    }
    $installedHash = Get-NsrpSha256 (Join-Path $base 'nsrp.exe')
    if ($installedHash -cne $sourceHash) {
        throw 'Installed NSRP executable SHA-256 differs from the verified update.'
    }
    if ((Get-NsrpSha256 (Join-Path $base 'nsrp-manifest.json')) -cne
        (Get-NsrpSha256 $sourceManifest)) {
        throw 'Installed NSRP manifest SHA-256 differs from the verified update.'
    }
} catch {
    $failure = $_
    [array]::Reverse($applied)
    foreach ($relative in $applied) {
        $target = Join-Path $base $relative
        $backup = Join-Path $localBackupRoot $relative
        try {
            if ([IO.File]::Exists($backup)) {
                if ([IO.File]::Exists($target)) {
                    # .NET Framework's File.Replace needs a non-null backup.
                    $failedVersion = Join-Path (Join-Path $pendingRoot 'failed') $relative
                    New-Item -ItemType Directory -Path (Split-Path -Parent $failedVersion) -Force | Out-Null
                    [IO.File]::Replace($backup, $target, $failedVersion, $true)
                } else {
                    [IO.File]::Move($backup, $target)
                }
            } elseif ([IO.File]::Exists($target)) {
                [IO.File]::Delete($target)
            }
        } catch {
            $rollbackErrors += "${relative}: $_"
        }
    }
    $reason = "NSRP update failed: $failure"
    if ($rollbackErrors.Count -gt 0) {
        $reason += "`nRollback errors: $($rollbackErrors -join '; ')"
    }
    # This process is hidden; keep a readable error for troubleshooting.
    try {
        [IO.File]::WriteAllText(
            (Join-Path $task 'update-error.log'),
            "$(Get-Date -Format o)`n$reason`n",
            [Text.UTF8Encoding]::new($false)
        )
    } catch {}
    if (-not $NoRestart -and $rollbackErrors.Count -eq 0 -and
        (Test-Path -LiteralPath (Join-Path $base 'nsrp.exe') -PathType Leaf)) {
        # If the original app is still running after a timeout, do not start
        # a second instance. Otherwise reopen the restored version so a
        # failed update does not leave the user without the application.
        $stillRunning = $WaitForPid -gt 0 -and
            $null -ne (Get-Process -Id $WaitForPid -ErrorAction SilentlyContinue)
        if (-not $stillRunning) {
            try {
                Start-Process -FilePath (Join-Path $base 'nsrp.exe') -WorkingDirectory $base
            } catch {}
        }
    }
    Write-Error $reason
    exit 1
} finally {
    # Keep installation-volume backups if rollback itself failed.
    if ($rollbackErrors.Count -eq 0 -and (Test-Path -LiteralPath $pendingRoot)) {
        Remove-Item -LiteralPath $pendingRoot -Recurse -Force -ErrorAction SilentlyContinue
    }
}
if (-not $NoRestart) {
    try {
        $started = Start-Process -FilePath (Join-Path $base 'nsrp.exe') -WorkingDirectory $base -PassThru -ErrorAction Stop
        # Preserve a readable record of what was installed and restarted.
        # A failure to write the success log must not kill the new GUI.
        try {
            [IO.File]::WriteAllText(
                (Join-Path $task 'apply-success.log'),
                "$(Get-Date -Format o) Applied: $($manifest.commit); Restart PID: $($started.Id)",
                [Text.UTF8Encoding]::new($false)
            )
        } catch {}
    } catch {
        $reason = "NSRP updated successfully, but restarting the application failed: $_"
        try {
            [IO.File]::WriteAllText(
                (Join-Path $task 'update-error.log'),
                "$(Get-Date -Format o) $reason",
                [Text.UTF8Encoding]::new($false)
            )
        } catch {}
        Write-Error $reason
        exit 1
    }
    # Retain the staged task as a diagnostic record until normal cleanup.
}
