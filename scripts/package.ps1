[CmdletBinding()]
param([string]$ExecutableOverride = '')

# Source-project release packaging. Never pack the user/project root, sample
# ROMs, keys or settings. Only these reviewed filenames may enter the ZIP.
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
$root = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
$dist = Join-Path $root 'dist'
$staging = Join-Path $root 'build\package'
$candidate = Join-Path $root 'build\nsrp-win64.verify.zip'
$exe = if($ExecutableOverride){
    (Resolve-Path -LiteralPath $ExecutableOverride -ErrorAction Stop).Path
}else{
    Join-Path $root 'target\release\nsrp.exe'
}
if(-not(Test-Path -LiteralPath $exe -PathType Leaf)){
    throw "Release EXE not found: $exe"
}
$manifestText = Get-Content -LiteralPath (Join-Path $root 'Cargo.toml') -Raw
if($manifestText -notmatch '(?m)^version\s*=\s*"([^"]+)"'){
    throw 'No Cargo package version found'
}
$version=$Matches[1]
$sha=(& git -C $root rev-parse HEAD).Trim().ToLowerInvariant()
if($LASTEXITCODE -ne 0 -or $sha -notmatch '^[0-9a-f]{40}$'){
    throw 'A full source commit hash is required for a public release'
}
if($env:GITHUB_SHA -and $sha -cne $env:GITHUB_SHA.ToLowerInvariant()){
    throw 'The checked-out commit differs from the GitHub workflow commit'
}
$sources=@(
    @{path=$exe;name='nsrp.exe'},
    @{path=(Join-Path $root 'LICENSE');name='LICENSE'},
    @{path=(Join-Path $root 'THIRD_PARTY_NOTICES.md');name='THIRD_PARTY_NOTICES.md'},
    @{path=(Join-Path $root 'licenses\hacbuild-MIT.txt');name='licenses\hacbuild-MIT.txt'},
    @{path=(Join-Path $root 'licenses\hactool-ISC.txt');name='licenses\hactool-ISC.txt'},
    @{path=(Join-Path $root 'licenses\Slint-Royalty-free-2.0.md');name='licenses\Slint-Royalty-free-2.0.md'},
    @{path=(Join-Path $root 'bin\LibHac_LICENSE.txt');name='licenses\LibHac-MIT.txt'}
)
foreach($item in $sources){
    if(-not(Test-Path -LiteralPath $item.path -PathType Leaf)){
        throw "Required public release input is missing: $($item.name)"
    }
}
# Never clean the user's dist or any parent folder; the only deletable
# directory is our own known generated build/package staging tree.
if(Test-Path -LiteralPath $staging){
    Remove-Item -LiteralPath $staging -Recurse -Force
}
New-Item -ItemType Directory -Force -Path $staging,(Join-Path $staging 'licenses')|Out-Null
foreach($item in $sources){
    Copy-Item -LiteralPath $item.path -Destination (Join-Path $staging $item.name)
}
$manifest=[ordered]@{
    application='NSRP';version=$version;commit=$sha;platform='windows-x86_64';
    sha256=[ordered]@{'nsrp.exe'=(Get-FileHash -LiteralPath (Join-Path $staging 'nsrp.exe') -Algorithm SHA256).Hash.ToLowerInvariant()}
}|ConvertTo-Json -Depth 8
$utf8=[Text.UTF8Encoding]::new($false)
[IO.File]::WriteAllText((Join-Path $staging 'nsrp-manifest.json'),$manifest,$utf8)

if(Test-Path -LiteralPath $candidate){Remove-Item -LiteralPath $candidate -Force}
Add-Type -AssemblyName System.IO.Compression.FileSystem
[IO.Compression.ZipFile]::CreateFromDirectory($staging,$candidate,[IO.Compression.CompressionLevel]::Optimal,$false)
& (Join-Path $PSScriptRoot 'verify-package.ps1') -PackageZip $candidate -StagingDir $staging
if($LASTEXITCODE -ne 0 -or -not $?){throw 'Distribution verification failed'}

# Publication of local dist never copies user data from project folders.
New-Item -ItemType Directory -Force -Path $dist|Out-Null
foreach($file in @('nsrp.exe','nsrp-manifest.json')){
    $from=Join-Path $staging $file
    $to=Join-Path $dist $file
    $temp=Join-Path $dist ('.nsrp-'+$file+'-staged.tmp')
    Copy-Item -LiteralPath $from -Destination $temp -Force
    if([IO.File]::Exists($to)){
        $back=Join-Path $dist ('.nsrp-'+$file+'-prior.tmp')
        [IO.File]::Replace($temp,$to,$back,$true)
        Remove-Item -LiteralPath $back -Force
    }else{
        [IO.File]::Move($temp,$to)
    }
}
$archive=Join-Path $dist 'nsrp-win64.zip'
Move-Item -LiteralPath $candidate -Destination $archive -Force
$ziphash=(Get-FileHash -LiteralPath $archive -Algorithm SHA256).Hash.ToLowerInvariant()
[IO.File]::WriteAllText((Join-Path $dist 'SHA256SUMS.txt'),"$ziphash  nsrp-win64.zip`n",$utf8)
& (Join-Path $PSScriptRoot 'verify-package.ps1') -PackageZip $archive -StagingDir $staging
if($LASTEXITCODE -ne 0 -or -not $?){throw 'Published archive verification failed'}
Write-Output "NSRP_PACKAGE_VERIFIED version=$version commit=$sha zip_sha256=$ziphash"
