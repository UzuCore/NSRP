# Third-party tools and attribution

NSRP is built from its own Rust sources. Some legacy compatibility paths
invoke separate external executables, embedded as byte-identical data in the
Windows binary and extracted to a private per-user runtime directory. These
tools are **not** original Rust implementations by NSRP's authors.

| Component | Source reference | License notice |
| --- | --- | --- |
| hactool | <https://github.com/SciresM/hactool> | `licenses/hactool-ISC.txt` (ISC) |
| hactoolnet / LibHac | <https://gitlab.com/ryujinx-classic/LibHac> (recorded build commit `fefa38ff`) | `licenses/LibHac-MIT.txt` (MIT) |
| hacbuild | Original tool license and copyright preserved in `licenses/hacbuild-MIT.txt` | MIT |

The build source includes the original helper binaries, a fixed-size gamecard
preset and an icon for *byte-identical* local reproduction. Every input is
protected by `scripts/embedded_files.sha256`. No console keys, copyrighted
game images, game content or user configuration are part of these inputs.

**GPL removal:** Starting with the native-only NCA repacker, this repository
no longer contains, executes, packages or embeds `hacpack.exe` or its GPL-2.0
license payload. The older executable is retained only in an *unpublished
local QA backup* and older local Git branches; those old commits **must not
be pushed** to the public GitHub repository. Nonstandard Program/Control
NCA layouts that require unsupported operations now fail closed instead of
silently calling the removed external builder.

**Independent license review:** the other three external tools remain in the
application binary. Their origin, copyright notices and permitted license
obligations must still be checked before making any public distribution;
the removal of GPL software does not automatically clear the other tools.

**GUI framework licensing:** the pinned Slint 1.17.1 Cargo package declares
`GPL-3.0-only OR LicenseRef-Slint-Royalty-free-2.0 OR
LicenseRef-Slint-Software-3.0`. Its alternative licenses have their own
conditions. Removing the old GPL-2.0 packer does **not** determine which
Slint license NSRP can or should rely on; verify the chosen Slint license
and all attribution requirements separately before a public release.

NSRP and bundled tools do not supply or derive private Switch console keys.
Users must supply their own legitimately obtained key material when needed.
