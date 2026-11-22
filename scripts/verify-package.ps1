[CmdletBinding()]
param(
    [Parameter(Mandatory=$true)][string]$PackageZip,
    [Parameter(Mandatory=$true)][string]$StagingDir
)
$ErrorActionPreference='Stop'
Set-StrictMode -Version Latest
Add-Type -AssemblyName System.IO.Compression.FileSystem
$root=(Resolve-Path (Join-Path $PSScriptRoot '..')).Path
$staging=(Resolve-Path -LiteralPath $StagingDir -ErrorAction Stop).Path.TrimEnd('\','/')
$archive=(Resolve-Path -LiteralPath $PackageZip -ErrorAction Stop).Path
$allowed=@(
    'nsrp.exe','nsrp-manifest.json','LICENSE','THIRD_PARTY_NOTICES.md',
    'licenses/hacbuild-MIT.txt','licenses/hactool-ISC.txt',
    'licenses/LibHac-MIT.txt','licenses/Slint-Royalty-free-2.0.md'
)
$expected=[Collections.Generic.Dictionary[string,string]]::new([StringComparer]::OrdinalIgnoreCase)
foreach($entry in Get-ChildItem -LiteralPath $staging -File -Recurse){
    $rel=$entry.FullName.Substring($staging.Length+1).Replace('\','/')
    if($allowed -cnotcontains $rel){throw "Unreviewed file in release staging: $rel"}
    $expected.Add($rel,$entry.FullName)
}
if($expected.Count -ne $allowed.Count){throw 'Public release allowlist and staged file count differ'}
foreach($rel in $allowed){if(-not$expected.ContainsKey($rel)){throw "Required release input missing: $rel"}}
$manifest=Get-Content -LiteralPath (Join-Path $staging 'nsrp-manifest.json') -Raw|ConvertFrom-Json
$commit=(& git -C $root rev-parse HEAD).Trim().ToLowerInvariant()
if($manifest.application -cne 'NSRP' -or
    $manifest.platform -cne 'windows-x86_64' -or
    $manifest.commit -cne $commit -or
    $manifest.commit -notmatch '^[0-9a-f]{40}$' -or
    $manifest.version -notmatch '^\d+\.\d+\.\d+'){
    throw 'Invalid release package metadata / commit'
}
if($env:GITHUB_SHA -and $commit -cne $env:GITHUB_SHA.ToLowerInvariant()){
    throw 'GitHub workflow commit SHA mismatch'
}
$exeHash=(Get-FileHash -LiteralPath (Join-Path $staging 'nsrp.exe') -Algorithm SHA256).Hash.ToLowerInvariant()
if($manifest.sha256.'nsrp.exe' -cne $exeHash){throw 'Release EXE does not match SHA-256 manifest'}
$seen=[Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
$zip=[IO.Compression.ZipFile]::OpenRead($archive)
try{
    foreach($entry in $zip.Entries){
        $name=$entry.FullName.Replace('\','/')
        if([string]::IsNullOrEmpty($entry.Name)){
            if($name -cne 'licenses/'){throw "Unexpected directory in public ZIP: $name"}
            continue
        }
        if($allowed -cnotcontains $name -or -not $expected.ContainsKey($name)){
            throw "Unexpected public ZIP content: $name"
        }
        if(-not $seen.Add($name)){throw "Duplicate entry in public ZIP: $name"}
        $stream=$entry.Open()
        $hasher=[Security.Cryptography.SHA256]::Create()
        try{
            $sum=[BitConverter]::ToString($hasher.ComputeHash($stream)).Replace('-','')
        }finally{
            $hasher.Dispose()
            $stream.Dispose()
        }
        $actual=(Get-FileHash -LiteralPath $expected[$name] -Algorithm SHA256).Hash
        if($sum -cne $actual){throw "ZIP entry SHA-256 differs from staging: $name"}
    }
}finally{
    $zip.Dispose()
}
if($seen.Count -ne $expected.Count){throw 'ZIP is missing one or more allowlisted files'}
Write-Output "NSRP_ZIP_ALLOWLIST_SHA_VERIFIED files=$($seen.Count) commit=$commit"
