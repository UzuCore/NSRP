# NSRP — Nintendo Switch ROM Processor

NSRP is a Windows GUI and Rust library for inspecting and processing
user-supplied Nintendo Switch package/container files. It contains native
streaming container readers/writers and isolated external-tool compatibility
fallbacks. The source does **not** include game images, tickets, console keys
or third-party user databases.

**Application version:** defined by `Cargo.toml`. The precise build is identified by
the 40-character Git commit embedded at compile time and shown as a short
commit next to the version in the program title and About dialog.

## Source tree

```text
NSRP/
├── .github/workflows/windows-build.yml  # opt-in Windows Actions build
├── src/                                # Rust GUI + processing library
│   ├── formats/                        # PFS0, HFS0, NCA, NCZ, BKTR
│   ├── ops/                            # conversion, merge, patch, recovery
│   ├── updater.rs                       # trusted GitHub release/ZIP verification
│   ├── update_ui.rs                      # menu and progress integration
│   └── workspace.rs                      # private per-user runtime
├── ui/                                 # Slint Windows UI and compiled assets
├── bin/                                # checksum-verified external tool inputs
├── assets/                             # public app icon
├── licenses/                           # required third-party notices
├── scripts/                            # build, package, audit, rollback tests
├── docs/architecture/                   # architecture overview
├── Cargo.toml / Cargo.lock              # pinned Rust dependencies
├── rust-toolchain.toml                  # pinned compiler
├── build.bat                            # reproducible public source build
├── LICENSE / THIRD_PARTY_NOTICES.md     # copyright/licensing
└── README.md
```

The local Windows development workspace may additionally keep private keys,
test ROMs, generated outputs and archived QA outside this Git repository.
Those files are not required for a public **source build**, and must never be
committed. Three legacy read/extract/XCI-layout tools remain as compatibility
inputs; Program and Control NCA repacking no longer executes a GPL packer.
See `THIRD_PARTY_NOTICES.md` for attribution and independent-license review.

**GUI attribution:** NSRP chooses Slint 1.17.1's Royalty-free Desktop License
2.0 and shows the unmodified `AboutSlint` attribution widget from the top
menu's **Help > About** dialog. The corresponding license is included as
`licenses/Slint-Royalty-free-2.0.md`; `scripts/check-third-party-attribution.ps1`
checks both the widget wiring and exact license SHA as a build precondition.
This application does not distribute the Slint framework independently.

## Build from the source root

On Windows with Rust/Cargo and PowerShell installed:

```cmd
build.bat
```

This validates seven embedded inputs by SHA-256, runs a locked Release build,
and packages a strictly allowlisted `dist/nsrp-win64.zip`. The self-contained
source tree does **not** need a parent `bin/` or `assets/` directory.

Run the checks separately:

```cmd
cargo fmt --all --check
cargo clippy --locked --all-targets -- -D warnings
cargo test --locked --lib
cargo test --locked --bin nsrp
cargo test --locked --bin nsrp stage60_drop_output_state_and_tab_epoch_are_preserved -- --ignored --test-threads=1
cargo test --locked --bin nsrp stage63_help_about_opens_slint_attribution_dialog -- --ignored --test-threads=1
powershell.exe -NoProfile -ExecutionPolicy Bypass -File scripts\test-auto-update.ps1 -RunDelayedFailure
powershell.exe -NoProfile -ExecutionPolicy Bypass -File scripts\check-third-party-attribution.ps1
```

Slint/Winit supports one event-loop instance per test process. The special
Stage60 GUI test is intentionally run as an isolated test rather than mixed
into the default Windows GUI regression process.

## Versions, CI and updates

Version numbers are defined **once** in `Cargo.toml`. Each compiled executable
also embeds its source Git commit. GitHub Actions runs via **manual
`workflow_dispatch`**, as in NSL; normal `git push` does not publish a binary.
The Actions workflow formats/checks/tests, builds `nsrp.exe`, packages and
verifies the ZIP, tests sandboxed replacement/rollback, and uploads an
artifact. Public GitHub Release creation requires the separately selected
`publish_release` checkbox **after third-party licensing review**.

**Native-only NCA packaging:** Program patches and Control title/icon edits
use Rust builders for standard IVFC/PFS0, size changes and verified supported
BKTR flattening. Unrecognized sparse, compressed or unusual storage forms
fail closed rather than falling back to `hacpack.exe`; existing output and
original input remain unchanged. This is a compatibility limitation, not a
claim of universal NCA support. No GPL executable is bundled in the current
source or binary, but earlier unpublished local branches and old release
backups must not be pushed with their history.

Published release tags follow `build-YYYYMMDD-HHMMSS-KST-rN` and contain
`nsrp-win64.zip` with an `nsrp-manifest.json` (Git commit and SHA-256). The
Help > Update menu checks the official UzuCore/NSRP GitHub release, compares
source commits to avoid downgrades, downloads the exact official asset, and
verifies its allowlisted contents and SHA before requesting installation.

The helper waits for the current NSRP process to exit and replaces **only**
`nsrp.exe` plus `nsrp-manifest.json` in that specific executable's directory.
Previous files are backed up and restored on failure; user keys, settings,
games, samples and unknown files are not touched. No arbitrary release EXEs,
installer scripts or other ZIP contents are executed.

See `BUILD_RELEASE.md` and `docs/architecture/NSRP_MODULES.md` for details.

## Scope and safety

This code is for processing content you have permission to use. Do not
publish real `prod.keys`, `title.keys`, private tickets or ROM samples.
The project does not bypass signature/rights checks to install content on
hardware. Synthetic or emulator GUI tests do not establish real hardware
compatibility.
