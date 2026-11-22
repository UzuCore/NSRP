# NSRP: release, versioning and updater verification

This is the self-contained public Git source directory. On the Windows
development machine the source and local deployment root are both
`D:\NSW.dev\NSRP` (no `rust_port` subdirectory). A public GitHub checkout
does not require private keys or game samples.

## Version policy

1. Change `version` **only** in `Cargo.toml` for a semantic release.
2. `build.rs` embeds the 40-character Git HEAD (`GITHUB_SHA` on Actions)
   and the commit timestamp in each executable. The title/About menu uses
   `v<crate-version> (<seven-character-commit>)`.
3. Commit all sources **before** the final Release build so the embedded
   revision matches Git HEAD; re-run the build after a new commit.
4. Manual GitHub Actions releases use
   `build-YYYYMMDD-HHMMSS-KST-r<run-number>` tags. No auto-release on push.
5. The package `nsrp-win64.zip` contains `nsrp.exe`,
   `nsrp-manifest.json` (version, full commit and SHA-256), the project
   license and reviewed third-party license notices.

## Local build

```bat
build.bat
```

For builds with the pinned dependencies already cached:

```bat
set NSRP_BUILD_OFFLINE=1
build.bat
```

Build output:

    target\release\nsrp.exe
    dist\nsrp.exe
    dist\nsrp-manifest.json
    dist\nsrp-win64.zip
    dist\SHA256SUMS.txt

All compiler resources are inside this repository (`bin`, `assets`, `ui`).
The SHA verifier checks exact binary blobs before compiling:

    powershell.exe -NoProfile -ExecutionPolicy Bypass -File scripts\verify_embedded_inputs.ps1

The third-party gate verifies the exact pinned Slint 1.17.1 royalty-free
license text and genuine top-menu Help > About `AboutSlint` UI wiring:

    powershell.exe -NoProfile -ExecutionPolicy Bypass -File scripts\check-third-party-attribution.ps1

The ZIP is built in `build/package`, checked against a hardcoded allowlist
and streamed SHA-256 verification, then published to this source tree's
ignored `dist` directory. **No user key, config, ROM, screenshots, test
archives or local root files are copied into the ZIP.**

## Regression suite

```bat
cargo fmt --all --check
cargo clippy --locked --all-targets -- -D warnings
cargo test --locked --lib
cargo test --locked --bin nsrp
cargo test --locked --bin nsrp stage60_drop_output_state_and_tab_epoch_are_preserved -- --ignored --test-threads=1
cargo test --locked --bin nsrp stage63_help_about_opens_slint_attribution_dialog -- --ignored --test-threads=1
powershell.exe -NoProfile -ExecutionPolicy Bypass -File scripts\verify-package.ps1 -PackageZip dist\nsrp-win64.zip -StagingDir build\package
powershell.exe -NoProfile -ExecutionPolicy Bypass -File scripts\check-third-party-attribution.ps1
powershell.exe -NoProfile -ExecutionPolicy Bypass -File scripts\test-auto-update.ps1 -RunDelayedFailure
```

Slint/Winit's GUI event loop cannot be recreated multiple times in the
same test process; the explicitly ignored Stage60 GUI test must be run in
its own fresh test process. This does **not** mean the test is skipped in
GitHub Actions: the workflow runs it separately.

## Local workstation Release mirroring

`D:\NSW.dev\NSRP\build.bat` is now the repository's own versioned, standalone
build entry point; it compiles `target\release\nsrp.exe` and packages the
allowlisted ZIP under `dist`. The optional local publisher
`scripts\publish_release.ps1` (or `scripts\build_release.ps1`) publishes
identical EXEs to `NSRP\nsrp.exe`, `NSRP\dist\nsrp.exe` and
`NSRP\target\release\nsrp.exe`, with rollback protection. The publisher
never writes into the parent `D:\NSW.dev` directory. GitHub Actions does
not invoke this local publisher.

## Safe in-app automatic update

Help > Update checks only official `UzuCore/NSRP` manual Releases and accepts
only the exact `nsrp-win64.zip` asset, a full source SHA and a valid dated
build tag. It compares commits to prevent downgrades, downloads over HTTPS
with size/time limits, rejects unknown archive paths and verifies the
manifest SHA-256 before showing installation confirmation.

The extracted update resides in the private user `LOCALAPPDATA/NSRP/Workspace/updates`
tree, not under the executable directory. The helper verifies/stages and
acknowledges readiness **before** the running GUI exits. It then waits for
the exact requesting PID, atomically replaces only `nsrp.exe` and
`nsrp-manifest.json` in that executable's folder, and rolls back on failure.
Existing keys, settings, games, title databases, unrelated files and
other NSRP installations are not changed.

`scripts/test-auto-update.ps1` tests portable, dist and target layouts,
corrupted update, invalid manifest, process-exit waiting, and delayed
replacement failure with SHA-protected disposable user-data sentinels.

## GitHub safety and third-party licensing

- GitHub default branch: `main`; source root contains Cargo, src, ui,
  scripts, assets, licenses, workflow and docs, like NSL.
- Build is manual; publishing a public GitHub Release is an additional
  **opt-in** input (`publish_release`, default false).
- `git push` never bundles personal keys, settings, game images or historical
  QA/handoff files; review the Git staged path allowlist before pushing.
- Native Program/Control repacking no longer includes or invokes `hacpack.exe`.
  The three remaining external helper tools have separate attribution and
  license notices (including hactool's Mbed TLS Apache-2.0): see
  `THIRD_PARTY_NOTICES.md`. Slint's desktop
  royalty-free license is explicitly elected and its `AboutSlint` badge is
  implemented in the Help menu. Verify those conditions before Release.
  Unsupported NCA structures
  fail safely instead of invoking an unverified fallback.
- **Do not push old local `master` or archived Stage61 publication branches:**
  they contain a historic GPL binary. The public `main` must descend solely
  from the remote initial README and a clean GPL-free source snapshot.

Historical handoff documents and workstation-only notes are archived under
the Git-ignored `old\` directory. Current working instructions remain here
and in the latest local handoff; archived QA fixtures are not required for a
normal public source build.
