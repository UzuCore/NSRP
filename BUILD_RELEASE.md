# NSRP: release, versioning and updater verification

This is the self-contained public Git source directory. The Windows local
workspace may still put it at `D:\NSW.dev\NSRP\rust_port`; a public GitHub
checkout does not require the parent folder, private keys, or game samples.

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
powershell.exe -NoProfile -ExecutionPolicy Bypass -File scripts\verify-package.ps1 -PackageZip dist\nsrp-win64.zip -StagingDir build\package
powershell.exe -NoProfile -ExecutionPolicy Bypass -File scripts\test-auto-update.ps1 -RunDelayedFailure
```

Slint/Winit's GUI event loop cannot be recreated multiple times in the
same test process; the explicitly ignored Stage60 GUI test must be run in
its own fresh test process. This does **not** mean the test is skipped in
GitHub Actions: the workflow runs it separately.

## Local workstation Release mirroring

`D:\NSW.dev\NSRP\build.bat` (outside the public repo) delegates to the
versioned `scripts/build_release.ps1` and publishes identical EXEs to
`NSRP\nsrp.exe`, `NSRP\dist\nsrp.exe` and
`NSRP\rust_port\target\release\nsrp.exe`, retaining rollback capability.
Do not run this local publisher as part of Actions; the repository root's
`build.bat` packages a standalone ZIP without touching its parent directory.

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
  license notices: see `THIRD_PARTY_NOTICES.md`. Slint's own multi-license
  terms require a separate review. Unsupported NCA structures
  fail safely instead of invoking an unverified fallback.
- **Do not push old local `master` or archived Stage61 publication branches:**
  they contain a historic GPL binary. The public `main` must descend solely
  from the remote initial README and a clean GPL-free source snapshot.

Old Stage31–47 extended build/QA commentary is retained **locally only** at
`D:\NSW.dev\NSRP\_qa\stage61_github_source\source_before\BUILD_RELEASE_STAGES_31_47.md`.
Historical probe examples are likewise archived below that QA folder and
remain recoverable from local Git history.
