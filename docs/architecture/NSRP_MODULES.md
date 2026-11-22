# NSRP source modules

NSRP keeps its public Git root at the Rust source root. Local development
history/QA in the parent workspace is **not** part of the GitHub source.

## Main program

`src/main.rs` wires the Slint GUI and job pipeline. It delegates to:

- `src/drop_support.rs`, `drop_runtime.rs`, `native_drop_win.rs`: file/folder
  drop routing, native Windows messages and tab-epoch validation.
- `src/gui_scale.rs`: Windows DPI/window boundary handling.
- `src/recovery_ui.rs`: recovery journal rendering and guarded actions.
- `src/updater.rs`: trusted release metadata, commit comparison, bounded ZIP
  extraction, SHA-256 manifest verification and staged installer handshake.
- `src/update_ui.rs`: Help menu's update UX; no file writes on the Slint thread.

## Processing library

`src/lib.rs` exposes the independent Rust processing modules.

- `src/formats/` includes strict NCA, NCZ, PFS0, HFS0 and BKTR parsing.
- `src/ops/` contains patch, conversion, compression, native XCI,
  source-safe copy/recovery and streaming modules.
- `src/ops/native_nca_builder.rs`: native Program/Control NCA rebuild,
  IVFC hash regeneration, ExeFS PFS0 reconstruction and verified BKTR
  flattening. Unhandled layouts are rejected without publishing output;
  the older GPL NCA builder is not included.
- `src/crypto.rs`, `keys.rs`: in-memory key/crypto operations; *real key files
  are runtime inputs and never tracked in Git*.
- `src/disk_space.rs`: early output free-space checks.
- `src/workspace.rs`: embedded resources and per-user local workspaces;
  data discovery prefers the actual private key location over source assets.

## Distribution boundary

`build.rs` embeds the full 40-character Git commit and package version into
the binary, compiles Slint and adds the Windows icon. `scripts/embedded_files.sha256`
verifies exact helper binaries before building.

`scripts/package.ps1` creates a clean allowlisted ZIP; `verify-package.ps1`
independently hashes every ZIP entry; `test-auto-update.ps1` exercises the
real installer on a disposable directory and checks rollback and data safety.

`scripts/publish_release.ps1` is a separate **local workstation** publisher
that copies a built source release to the parent NSRP workspace root and dist.
The GitHub Actions source `build.bat` does not invoke that local publisher.
