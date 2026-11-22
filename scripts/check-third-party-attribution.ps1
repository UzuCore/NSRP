[CmdletBinding()]
param()

# Reviewable static release gate for the original framework attribution and
# retained external-tool notices. The runtime GUI test separately checks that
# the Help menu actually opens a visible AboutSlint widget.
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
$root = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
$slint = Join-Path $root 'licenses\Slint-Royalty-free-2.0.md'
$ui = Join-Path $root 'ui\main.slint'
$rust = Join-Path $root 'src\main.rs'
$notice = Join-Path $root 'THIRD_PARTY_NOTICES.md'

foreach ($path in @($slint, $ui, $rust, $notice,
    (Join-Path $root 'licenses\hactool-ISC.txt'),
    (Join-Path $root 'licenses\hacbuild-MIT.txt'),
    (Join-Path $root 'bin\LibHac_LICENSE.txt'))) {
    if (-not(Test-Path -LiteralPath $path -PathType Leaf)) {
        throw "Missing attribution input: $path"
    }
}

# Exact upstream license as shipped with the pinned Slint 1.17.1 crate.
$expected = '5167F5056E850419106AB6265EFBDCA7CBA4D99C849D1445CA0BBF6A1E2315FE'
$actual = (Get-FileHash -LiteralPath $slint -Algorithm SHA256).Hash
if ($actual -cne $expected) {
    throw "Slint Royalty-free v2 license changed: $actual"
}
$licenseText = [IO.File]::ReadAllText($slint)
if (-not $licenseText.Contains('AboutSlint') -or
    -not $licenseText.Contains('Slint Royalty-free Desktop, Mobile, and Web Applications License')) {
    throw 'Required unmodified Slint attribution terms missing'
}
$cargo = [IO.File]::ReadAllText((Join-Path $root 'Cargo.toml'))
if ($cargo -notmatch 'slint\s*=\s*\{\s*version\s*=\s*"1\.17\.1"') {
    throw 'Pinned Slint version changed; verify new upstream license first'
}
$uiText = [IO.File]::ReadAllText($ui)
$rustText = [IO.File]::ReadAllText($rust)
if (-not $uiText.Contains('import { AboutSlint,') -or
    -not $uiText.Contains('AboutSlint {') -or
    -not $uiText.Contains('if root.about-open : Rectangle {') -or
    -not $uiText.Contains('root.show-about();') -or
    -not $rustText.Contains('window.on_show_about(move ||') -or
    -not $rustText.Contains('ui.set_about_open(true);')) {
    throw 'Slint Help > About widget must remain linked to the GUI'
}
$noticeText = [IO.File]::ReadAllText($notice)
foreach ($marker in @('Slint-Royalty-free-2.0.md',
    'licenses/hactool-ISC.txt','licenses/hacbuild-MIT.txt',
    'licenses/LibHac-MIT.txt')) {
    if (-not $noticeText.Contains($marker)) {
        throw "Missing third-party notice: $marker"
    }
}

Write-Output '[OK] Slint 1.17.1 royalty-free v2: exact license + AboutSlint Help dialog wired'
Write-Output '[OK] hactool ISC / hacbuild MIT / hactoolnet LibHac MIT notices retained'
