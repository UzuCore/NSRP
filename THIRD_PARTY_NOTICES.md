# Third-party tools and attribution

NSRP is built from its own Rust sources. Some legacy compatibility paths
invoke separate external executables, embedded as byte-identical data in the
Windows binary and extracted to a private per-user runtime directory. These
tools are **not** original Rust implementations by NSRP's authors.

| Component | Source reference | License notice |
| --- | --- | --- |
| hactool | <https://github.com/SciresM/hactool> | `licenses/hactool-ISC.txt` (ISC) |
| Mbed TLS (bundled cryptography used by hactool) | <https://github.com/SciresM/hactool/tree/master/mbedtls> | `licenses/mbedtls-Apache-2.0.txt` (Apache-2.0; selected over GPL) |
| hactoolnet / LibHac | <https://gitlab.com/ryujinx-classic/LibHac> (recorded source commit `fefa38ff`) | `licenses/LibHac-MIT.txt` in ZIP (`bin/LibHac_LICENSE.txt` in source, MIT) |
| hacbuild | <https://github.com/LucaCorigliano/hacbuild> (archived upstream) | `licenses/hacbuild-MIT.txt` (MIT, Copyright (c) 2018 Luca Corigliano) |
| Slint 1.17.1 (UI framework) | <https://github.com/slint-ui/slint> | `licenses/Slint-Royalty-free-2.0.md` (Slint Royalty-free Desktop, Mobile, and Web Applications License, v2.0) |
| sevenz-rust2 0.25.0 (7z decoding and AES-256, native Rust) | <https://github.com/hasenbanck/sevenz-rust2> | `licenses/sevenz-rust2-Apache-2.0.txt` (Apache-2.0) |

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

**Remaining binary provenance:** hactool's upstream license is ISC and hacbuild's
upstream is MIT. `hactoolnet.exe` records a LibHac source revision in
`bin/hactoolnet_BUILD_INFO.txt`. The embedded EXEs are SHA-256 pinned, and
their copyright/license notices are included. The exact corresponding
upstream release/build artifacts for the three existing binaries have **not**
all been independently matched by checksum or fully reproduced from source.
Do not describe this as a comprehensive independent supply-chain audit.
The `hactool` source tree also carries Mbed TLS cryptography, whose upstream
license file elects Apache-2.0; the original Apache-2.0 license is included
separately for its bundled implementation. This does not assert an exact
source-to-binary provenance match for the historical hactool executable.

**Slint license election:** Slint 1.17.1 declares
`GPL-3.0-only OR LicenseRef-Slint-Royalty-free-2.0 OR
LicenseRef-Slint-Software-3.0`. For this **Windows desktop application**,
NSRP elects the *Slint Royalty-free License 2.0* rather than GPLv3. Its
attribution condition section 2(a) is implemented using the genuine `AboutSlint`
widget in the Slint **Help > About** dialog. `ui/main.slint` imports it from
`std-widgets.slint` and `src/main.rs` wires the Help menu to that dialog.
The unmodified Slint 1.17.1 license text is retained in source and packaged
in the distribution ZIP. The build's attribution gate rejects removal of
the widget or unexpected edits to the license text. This election is limited
to conventional desktop usage, not embedded systems or a separately
distributed Slint library. Third-party crates and assets keep their own
licenses and conditions; check them before wider public release.

NSRP and bundled tools do not supply or derive private Switch console keys.
Users must supply their own legitimately obtained key material when needed.
