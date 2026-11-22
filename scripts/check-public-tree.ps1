[CmdletBinding()]
param()
$ErrorActionPreference='Stop'
Set-StrictMode -Version Latest
$root=(Resolve-Path (Join-Path $PSScriptRoot '..')).Path
$tracked=@(& git -C $root ls-files --cached --others --exclude-standard)
if($LASTEXITCODE -ne 0){throw 'Failed to inspect Git source-tree allowlist'}
$required=@(
    'Cargo.toml','Cargo.lock','rust-toolchain.toml','LICENSE','README.md',
    'THIRD_PARTY_NOTICES.md','src/updater.rs','src/update_ui.rs',
    '.github/workflows/windows-build.yml','scripts/package.ps1',
    'scripts/apply-update.ps1','scripts/test-auto-update.ps1'
)
foreach($item in $required){
    if(-not(Test-Path -LiteralPath (Join-Path $root $item) -PathType Leaf)){
        throw "Public source required item missing: $item"
    }
}
$publicBinaries=@(
    'bin/hacbuild.exe','bin/hactool.exe','bin/hactoolnet.exe'
)
$blockedRegex='(?i)(^|/)(?:prod\.keys|title\.keys|keys\.dat|nsrp_config\.json|config\.json|\.env[^/]*|[^/]+\.(?:keys|pem|pfx|p12|kdbx|nsp|nsz|xci|xcz|nca|ncz|chd|gdi|hdi|iso|db|sqlite|zip|7z|rar|log))$'
$errors=[Collections.Generic.List[string]]::new()
$gplHistory=@(& git -C $root rev-list --objects HEAD)
if($LASTEXITCODE -ne 0){throw 'Failed to inspect Git HEAD object history'}
# Deleting the GPL binary from the working tree is insufficient when an
# ancestor of the public branch still contains it. Do not scan --all here:
# old developer branches deliberately stay private and must never be pushed.
foreach($object in $gplHistory){
    if($object -match '(?i)\s(?:bin/hacpack\.exe|licenses/hacpack-GPL-2\.0\.txt)$'){
        $errors.Add('GPL packer is reachable in the public branch Git ancestry')
        break
    }
}
foreach($file in $tracked){
    $name=$file.Replace('\','/')
    if($name -match $blockedRegex -or
       $name -match '(?i)(^|/)(?:target|dist|build|_qa|qa|temp|screenshots|downloads|old)/' -or
       $name -match '(?i)(^|/)(?:HANDOFF_|QA_|NEW_CHAT_HANDOFF)' -or
       $name -match '(?i)(^|/)(?:backup|secrets?)/'){
        $errors.Add("Protected/unwanted path would be published: $name")
    }
    if($name -match '(?i)\.exe$' -and $publicBinaries -cnotcontains $name){
        $errors.Add("Unreviewed binary would be published: $name")
    }
    $path=Join-Path $root $file
    if(Test-Path -LiteralPath $path -PathType Leaf){
        $bytes=(Get-Item -LiteralPath $path).Length
        if($bytes -gt 15MB){$errors.Add("Unreviewed large file ($bytes bytes): $name")}
    }
}
if($errors.Count -gt 0){
    $errors|ForEach-Object{Write-Output $_}
    throw "NSRP public-source security audit failed: $($errors.Count) path(s)"
}
& (Join-Path $PSScriptRoot 'verify_embedded_inputs.ps1')
if($LASTEXITCODE -ne 0 -or -not $?){throw 'Reviewed binary input SHA-256 audit failed'}
Write-Output "NSRP_PUBLIC_SOURCE_PATHS_VERIFIED files=$($tracked.Count) approved_binaries=$($publicBinaries.Count) secrets=0"
