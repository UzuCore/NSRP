# Remove only locally regenerated Cargo outputs, not source fixtures.
# Default is an audit (dry-run); pass -Apply to perform the cleanup.
[CmdletBinding()]
param([switch]$Apply)

$ErrorActionPreference = "Stop"
$root = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot ".."))
$expected = [IO.Path]::GetFullPath("D:\NSW.dev\NSRP")
if (-not $root.Equals($expected, [StringComparison]::OrdinalIgnoreCase)) {
    throw "Refusing cleanup outside the verified NSRP Rust workspace: $root"
}

$release = Join-Path $root "target\release\nsrp.exe"
$rootRelease = Join-Path $root "nsrp.exe"
$distRelease = Join-Path $root "dist\nsrp.exe"
foreach ($file in @($release, $rootRelease, $distRelease)) {
    if (-not (Test-Path -LiteralPath $file -PathType Leaf)) {
        throw "Refusing cleanup without the existing release executable: $file"
    }
}
$hashes = @(
    (Get-FileHash -LiteralPath $release -Algorithm SHA256).Hash
    (Get-FileHash -LiteralPath $rootRelease -Algorithm SHA256).Hash
    (Get-FileHash -LiteralPath $distRelease -Algorithm SHA256).Hash
)
if (($hashes | Select-Object -Unique).Count -ne 1) {
    throw "Release copies do not have the same SHA-256; preserve build outputs"
}

# Do not interfere with unrelated Rust builds (for example, NSL).
# Only processes that actually reference this checkout/target or hold
# its Cargo cache lock make these two generated folders unsafe.
# Never stop or signal a process to perform cleanup.
if ($Apply) {
    $candidateProcesses = @(Get-CimInstance Win32_Process | Where-Object {
        $_.Name -in @("cargo.exe", "rustc.exe", "rustdoc.exe", "clippy-driver.exe", "nsrp.exe")
    })
    foreach ($process in $candidateProcesses) {
        $executable = [string]$process.ExecutablePath
        $command = [string]$process.CommandLine
        if ($process.Name -eq "nsrp.exe" -or
            $executable.StartsWith((Join-Path $root "target"),
                [StringComparison]::OrdinalIgnoreCase) -or
            $command.IndexOf($root, [StringComparison]::OrdinalIgnoreCase) -ge 0) {
            throw "An NSRP or same-workspace build process is active: $($process.ProcessId)"
        }
    }
    # Cargo acquires an OS file lock per target profile. Refuse cleanup
    # if any process (even one with an anonymous command line) holds it.
    foreach ($lockFile in @(
        (Join-Path $root "target\debug\.cargo-lock")
        (Join-Path $root "target\release\.cargo-lock")
    )) {
        if (Test-Path -LiteralPath $lockFile -PathType Leaf) {
            try {
                $handle = [IO.FileStream]::new(
                    $lockFile,
                    [IO.FileMode]::Open,
                    [IO.FileAccess]::ReadWrite,
                    [IO.FileShare]::None
                )
                $handle.Dispose()
            } catch {
                throw "A Cargo target profile is locked; cleanup refused: $lockFile"
            }
        }
    }
}

# Only these two verified, disposable Cargo cache paths are eligible.
# Keep release\deps, release\build, release\.fingerprint and the
# previous releases so subsequent incremental builds remain fast.
$targets = @(
    (Join-Path $root "target\debug")
    (Join-Path $root "target\release\examples")
)
$report = @()
foreach ($target in $targets) {
    $full = [IO.Path]::GetFullPath($target)
    if (-not (
        $full.Equals([IO.Path]::GetFullPath((Join-Path $root "target\debug")),
            [StringComparison]::OrdinalIgnoreCase) -or
        $full.Equals([IO.Path]::GetFullPath((Join-Path $root "target\release\examples")),
            [StringComparison]::OrdinalIgnoreCase)
    )) {
        throw "Unexpected cleanup target: $full"
    }
    if (-not (Test-Path -LiteralPath $full)) {
        $report += [pscustomobject]@{path=$full;files=0;bytes=0;deleted=$false;absent=$true}
        continue
    }
    $top = Get-Item -LiteralPath $full -Force
    if (($top.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
        throw "Refusing reparse point at cleanup target: $full"
    }
    $all = @(Get-ChildItem -LiteralPath $full -Recurse -Force)
    if (@($all | Where-Object {
        ($_.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0
    }).Count -gt 0) {
        throw "Refusing to follow reparse points beneath: $full"
    }
    $files = @($all | Where-Object { -not $_.PSIsContainer })
    $bytes = [long](($files | Measure-Object -Property Length -Sum).Sum)
    $count = $files.Count
    $deleted = $false
    if ($Apply) {
        Remove-Item -LiteralPath $full -Recurse -Force
        if (Test-Path -LiteralPath $full) {
            throw "Cleanup target still exists: $full"
        }
        $deleted = $true
    }
    $report += [pscustomobject]@{
        path=$full; files=$count; bytes=$bytes;
        deleted=$deleted; absent=$false
    }
}

# Preserve the deployed executable byte-for-byte even if cleanup runs.
foreach ($file in @($release, $rootRelease, $distRelease)) {
    if ((Get-FileHash -LiteralPath $file -Algorithm SHA256).Hash -ne $hashes[0]) {
        throw "Protected Release changed unexpectedly: $file"
    }
}
$summary = [pscustomobject]@{
    status=if ($Apply) { "NSRP_CARGO_GENERATED_CLEANUP_VERIFIED" } else { "NSRP_CARGO_GENERATED_DRY_RUN" }
    release_sha256=$hashes[0]
    paths=$report
    files_total=[int](($report | Measure-Object -Property files -Sum).Sum)
    logical_bytes_total=[long](($report | Measure-Object -Property bytes -Sum).Sum)
    protected_sample_and_keys_untouched=$true
    release_verified_3_of_3=$true
}
$summary | ConvertTo-Json -Depth 5
