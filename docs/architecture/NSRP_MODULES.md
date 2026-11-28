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
  Changed runtime resources are written to a synced same-directory temporary
  file before atomic publication; an interrupted write cannot truncate a
  previously installed helper.

## Native-first routing and remaining compatibility boundary

| Operation | Native path | Compatibility path retained |
| --- | --- | --- |
| CNMT inspection | Bounded NCA/NCZ region reader, declared PartitionFS data-layer bounds | hactool / LibHac for unsupported metadata storage |
| Ordinary Program extraction | Selective RomFS/ExeFS reader in `native_fs.rs` | hactool / LibHac for unsupported filesystems |
| BKTR Program extraction | Native verified overlays, including ExeFS-only selection and supported compressed storage | LibHac for unsupported variants and the existing large uncompressed RomFS policy |
| Control metadata and RomFS | Native NCA region reader | hactool / LibHac for unsupported sections |
| CNMT payload edits | Existing title/patch path | hactool / LibHac plaintext extraction remains |
| Default XCI packaging | Native direct or virtual streaming, including one to three secure NCAs | hacbuild for custom/unverified layout or capacity |

The external tools are still embedded and licensed; native-first is not a
claim of complete external-tool independence. Requested Program trees must
all contain verified regular files before publication. A failed external
extract must never be treated as a successful partial extraction.

The PFS0 index validates the full table size against its bounded container
before allocating entry and string tables. Sparse QA files exercise 64-bit
offsets without writing a full multi-GiB archive. These tests complement,
rather than replace, actual package and emulator compatibility checks.

Stage 96-120 hardening: PFS0 readers reject overlapping nonempty payloads;
writers bound their name tables, honor early cancellation, and sync staged
files before publication. Program and title patch assembly stream unchanged
regions from private normalized snapshots instead of creating a second NCA
tree. XCZ intermediates use unique task-owned directories. CNMT inspection
reads the documented 32-bit system-version field only for application/patch
metadata; the adjacent application-version or extended-data-length field
must remain intact. Legacy metadata helpers now require a successful exit,
bounded source-sized output, and an exact match to the selected payload.
Complete native metadata reconstruction remains unverified and is not
claimed by this change. Recovery logs and compressed NACP title tables
have hard read/decompression bounds; an incomplete final recovery record
is preserved for manual inspection rather than interpreted as completion.

NSL maintains a separate vendored `nsrp-core`. Its integration API, patches
and build requirements must be reviewed and tested before selectively porting
new NSRP changes; replacing that fork wholesale is not a supported update.

## Distribution boundary

`build.rs` embeds the full 40-character Git commit and package version into
the binary, compiles Slint and adds the Windows icon. `scripts/embedded_files.sha256`
verifies exact helper binaries before building.

`scripts/package.ps1` creates a clean allowlisted ZIP; `verify-package.ps1`
independently hashes every ZIP entry; `test-auto-update.ps1` exercises the
real installer on a disposable directory and checks rollback and data safety.

`scripts/check-third-party-attribution.ps1` enforces Slint Royalty-free 2.0
desktop attribution (`AboutSlint` in Help > About) and source/ZIP license
notices. The exact pinned upstream Slint license is included alongside other
external-tool licenses. This is distinct from proving exact binary build
provenance for older hactool/hactoolnet/hacbuild tools.

`scripts/publish_release.ps1` is a separate **local workstation** publisher
that copies a built source release to the parent NSRP workspace root and dist.
The GitHub Actions source `build.bat` does not invoke that local publisher.
