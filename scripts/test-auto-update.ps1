param([switch]$RunDelayedFailure)
$ErrorActionPreference = 'Stop'
$root = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
$installer = Join-Path $root 'scripts\apply-update.ps1'
$officialExe = Join-Path $root 'dist\nsrp.exe'
$officialManifest = Join-Path $root 'dist\nsrp-manifest.json'
$newHash = (Get-FileHash -LiteralPath $officialExe -Algorithm SHA256).Hash
$tag = (Get-Content -LiteralPath $officialManifest -Raw | ConvertFrom-Json).commit
$scratch = Join-Path ([IO.Path]::GetTempPath()) ('NSRP_update_test_' + [guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $scratch -Force | Out-Null

function New-Sample([string]$name,[string]$layout) {
    $base = Join-Path $scratch $name
    $binDir = switch ($layout) {
        'portable' { $base }
        'dist' { Join-Path $base 'dist' }
        'target' { Join-Path $base 'target\release' }
        default { throw 'Unsupported test layout' }
    }
    New-Item -ItemType Directory -Path $binDir -Force | Out-Null
    $oldExe = Join-Path $binDir 'nsrp.exe'
    [IO.File]::WriteAllText($oldExe, "old sandbox executable $name", [Text.UTF8Encoding]::new($false))
    $oldHash = (Get-FileHash $oldExe -Algorithm SHA256).Hash
    $originalManifest = @{application='NSRP';commit=('a'*40);platform='windows-x86_64';version='2.0.1';sha256=@{'nsrp.exe'=$oldHash.ToLowerInvariant()}} | ConvertTo-Json -Depth 7
    [IO.File]::WriteAllText((Join-Path $binDir 'nsrp-manifest.json'),$originalManifest,[Text.UTF8Encoding]::new($false))
    $sentinels = @{}
    foreach ($rel in @('library.db','config.json','nsrp_config.json','prod.keys','title.keys','titledb\keep.json','downloads\keep.bin')) {
        $file = Join-Path $base $rel
        New-Item -ItemType Directory -Path (Split-Path $file) -Force | Out-Null
        [IO.File]::WriteAllText($file, "protected sentinel: $name/$rel",[Text.UTF8Encoding]::new($false))
        $sentinels[$rel] = (Get-FileHash $file -Algorithm SHA256).Hash
    }
    $task = Join-Path $base 'temp\nsrp_update_sandbox'
    $package = Join-Path $task 'package'
    New-Item -ItemType Directory -Path $package -Force | Out-Null
    Copy-Item -LiteralPath $officialExe -Destination (Join-Path $package 'nsrp.exe')
    Copy-Item -LiteralPath $officialManifest -Destination (Join-Path $package 'nsrp-manifest.json')
    return @{base=$base;binDir=$binDir;oldHash=$oldHash;oldManifest=$originalManifest;task=$task;package=$package;sentinels=$sentinels}
}

function Run-Installer($case,[int]$waitPid) {
    # The independent PowerShell process may exit with code 1 on purpose.
    # Save stdout/stderr without changing the parent test's error policy.
    $log = Join-Path $case.task 'qa.log'
    $arguments = @(
        '-NoProfile','-NonInteractive','-ExecutionPolicy','Bypass',
        '-File',('"' + $installer + '"'),
        '-BaseDir',('"' + $case.binDir + '"'),
        '-TaskDir',('"' + $case.task + '"'),
        '-NoRestart','-WaitForPid',([string]$waitPid)
    )
    $errorLog = Join-Path $case.task 'qa-error.log'
    $process = Start-Process -FilePath 'powershell.exe' -ArgumentList $arguments -Wait -PassThru -NoNewWindow -RedirectStandardOutput $log -RedirectStandardError $errorLog
    return @{code=$process.ExitCode;log=((Get-Content $log -Raw -ErrorAction SilentlyContinue)+' '+(Get-Content $errorLog -Raw -ErrorAction SilentlyContinue))}
}

function Assert-Sentinels($case) {
    foreach ($rel in $case.sentinels.Keys) {
        $actual = (Get-FileHash (Join-Path $case.base $rel) -Algorithm SHA256).Hash
        if ($actual -cne $case.sentinels[$rel]) { throw "User data changed: $rel" }
    }
}

try {
    foreach ($layout in @('portable','dist','target')) {
        $case = New-Sample "valid-$layout" $layout
        $result = Run-Installer $case 0
        if ($result.code -ne 0) { throw "Valid $layout update failed: $($result.log)" }
        $actual = (Get-FileHash (Join-Path $case.binDir 'nsrp.exe') -Algorithm SHA256).Hash
        $backup = (Get-FileHash (Join-Path $case.task 'backup\nsrp.exe') -Algorithm SHA256).Hash
        $manifest = Get-Content (Join-Path $case.binDir 'nsrp-manifest.json') -Raw | ConvertFrom-Json
        if ($actual -cne $newHash -or $backup -cne $case.oldHash -or $manifest.commit -cne $tag) { throw "Invalid upgrade/backup for $layout" }
        $ready = Join-Path $case.task 'apply-ready.flag'
        if (-not (Test-Path -LiteralPath $ready -PathType Leaf) -or
            (Get-Content -LiteralPath $ready -Raw) -cne $tag) {
            throw "Update helper failed to acknowledge staged content for $layout"
        }
        Assert-Sentinels $case
        Write-Output "PASS: real release installer layout=$layout, original backup valid, user data preserved"
    }
    $case = New-Sample 'tampered-update' 'portable'
    [IO.File]::AppendAllText((Join-Path $case.package 'nsrp.exe'),'a malicious suffix')
    $result = Run-Installer $case 0
    if ($result.code -eq 0 -or (Get-FileHash (Join-Path $case.binDir 'nsrp.exe') -Algorithm SHA256).Hash -cne $case.oldHash) { throw 'Tampered package was installed' }
    if (-not (Test-Path -LiteralPath (Join-Path $case.task 'update-error.log'))) { throw 'Corrupted update did not leave a diagnostic log' }
    if (Test-Path -LiteralPath (Join-Path $case.task 'apply-ready.flag')) { throw 'Corrupted update must not acknowledge readiness' }
    Assert-Sentinels $case
    Write-Output 'PASS: modified staged executable rejected before replacing installed files'

    $case = New-Sample 'invalid-manifest' 'dist'
    $manifestFile = Join-Path $case.package 'nsrp-manifest.json'
    $json = Get-Content $manifestFile -Raw | ConvertFrom-Json
    $json.commit = 'invalid'
    [IO.File]::WriteAllText($manifestFile,($json|ConvertTo-Json -Depth 7),[Text.UTF8Encoding]::new($false))
    $result = Run-Installer $case 0
    if ($result.code -eq 0 -or (Get-FileHash (Join-Path $case.binDir 'nsrp.exe') -Algorithm SHA256).Hash -cne $case.oldHash) { throw 'Invalid manifest was installed' }
    if (-not (Test-Path -LiteralPath (Join-Path $case.task 'update-error.log'))) { throw 'Invalid manifest did not leave a diagnostic log' }
    if (Test-Path -LiteralPath (Join-Path $case.task 'apply-ready.flag')) { throw 'Invalid manifest must not acknowledge readiness' }
    Assert-Sentinels $case
    Write-Output 'PASS: invalid staged manifest rejected before replacing installed files'

    $case = New-Sample 'exit-wait' 'target'
    $timer = [Diagnostics.Stopwatch]::StartNew()
    $sleeper = Start-Process powershell.exe -ArgumentList '-NoProfile','-NonInteractive','-Command','Start-Sleep -Seconds 3' -PassThru -WindowStyle Hidden
    try {
        $result = Run-Installer $case $sleeper.Id
    } finally {
        if (-not $sleeper.HasExited) { $null = $sleeper.WaitForExit(10000) }
        $sleeper.Dispose()
    }
    $timer.Stop()
    if ($result.code -ne 0 -or $timer.Elapsed.TotalSeconds -lt 2.2) { throw "Exit-wait failed: elapsed $($timer.Elapsed.TotalSeconds) / $($result.log)" }
    Assert-Sentinels $case
    Write-Output ('PASS: waits for old process exit, {0:N2}s' -f $timer.Elapsed.TotalSeconds)

    if ($RunDelayedFailure) {
        $case = New-Sample 'late-failure' 'portable'
        Remove-Item -LiteralPath (Join-Path $case.binDir 'nsrp-manifest.json')
        New-Item -ItemType Directory -Path (Join-Path $case.binDir 'nsrp-manifest.json') | Out-Null
        $result = Run-Installer $case 0
        if ($result.code -eq 0) { throw 'Simulated late manifest error was accepted' }
        if ((Get-FileHash (Join-Path $case.binDir 'nsrp.exe') -Algorithm SHA256).Hash -cne $case.oldHash) { throw 'Rollback did not restore the original executable' }
        if (-not (Test-Path -LiteralPath (Join-Path $case.task 'update-error.log'))) { throw 'Rollback error log missing' }
        Assert-Sentinels $case
        Write-Output 'PASS: executable rollback after later manifest replacement failure'
    }
    Write-Output 'AUTO_UPDATE_SANDBOX_QA=PASS'
} finally {
    Remove-Item -LiteralPath $scratch -Recurse -Force -ErrorAction SilentlyContinue
}
