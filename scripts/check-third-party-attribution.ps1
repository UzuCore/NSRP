[CmdletBinding()]
param()

# Reviewable static release gate for the original framework attribution and
# retained external-tool notices. The runtime GUI test separately checks that
# the Help menu actually opens a visible AboutSlint widget.
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
$root = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
$slint = Join-Path $root 'licenses\Slint-Royalty-free-2.0.md'
$mbedtls = Join-Path $root 'licenses\mbedtls-Apache-2.0.txt'
$sevenz = Join-Path $root 'licenses\sevenz-rust2-Apache-2.0.txt'
$ui = Join-Path $root 'ui\main.slint'
$rust = Join-Path $root 'src\main.rs'
$notice = Join-Path $root 'THIRD_PARTY_NOTICES.md'

foreach ($path in @($slint, $mbedtls, $sevenz, $ui, $rust, $notice,
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
$expectedMbedTLS = 'CFC7749B96F63BD31C3C42B5C471BF756814053E847C10F3EB003417BC523D30'
$actualMbedTLS = (Get-FileHash -LiteralPath $mbedtls -Algorithm SHA256).Hash
if ($actualMbedTLS -cne $expectedMbedTLS) {
    throw "Mbed TLS Apache-2.0 license changed: $actualMbedTLS"
}
$expected7zLicense = '43070E2D4E532684DE521B885F385D0841030EFA2B1A20BAFB76133A5E1379C1'
if ((Get-FileHash -LiteralPath $sevenz -Algorithm SHA256).Hash -cne $expected7zLicense) {
    throw 'Pinned sevenz-rust2 Apache-2.0 license changed'
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
if ($cargo -notmatch 'sevenz-rust2\s*=\s*\{\s*version\s*=\s*"=0\.25\.0"') {
    throw 'Pinned sevenz-rust2 version changed; review its license before shipping'
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
    'licenses/LibHac-MIT.txt','licenses/mbedtls-Apache-2.0.txt',
    'licenses/sevenz-rust2-Apache-2.0.txt')) {
    if (-not $noticeText.Contains($marker)) {
        throw "Missing third-party notice: $marker"
    }
}

Write-Output '[OK] Slint 1.17.1 royalty-free v2: exact license + AboutSlint Help dialog wired'
Write-Output '[OK] hactool ISC / hacbuild MIT / hactoolnet LibHac MIT notices retained'
Write-Output '[OK] hactool Mbed TLS: pinned Apache-2.0 notice retained'
