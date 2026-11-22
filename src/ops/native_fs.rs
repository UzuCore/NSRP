//! Original read-only NCA filesystem extraction.
//!
//! This module interprets NCA FS headers, PFS0 and Switch RomFS directly.
//! Verified BKTR Program overlays and metadata-only Manual updates are
//! supported, including bounded streaming NCZ-compressed Manual source NCAs. Unknown
//! BKTR, sparse, compressed or skip-layer-hash storage variants are rejected
//! in favor of the established external-tool fallback, never guessed.

use crate::disk_space::ensure_disk_space;
use crate::{
    formats::{
        bktr::collect_relocations_from_reader,
        nca::{NCA_XTS_HEADER_SIZE, NcaInfo, NcaSection, decrypt_header, derive_section_key},
        ncz_stream::decompress_ncz_region_to_nca,
        pfs0::Pfs0Index,
    },
    keys::KeySet,
    ops::{
        container::{self, ContainerEntry},
        native_bktr::BktrVirtualReader,
        native_compressed::CompressedBktrReader,
        native_meta::SectionReader,
        native_repack::{IvfcLevel, ivfc_levels, verify_ivfc},
    },
};
use anyhow::{Context, Result, bail, ensure};
use rayon::prelude::*;
use sha2::{Digest, Sha256};
use std::{
    cell::RefCell,
    collections::HashSet,
    fs::{self, File, OpenOptions},
    io::{self, Read, Seek, SeekFrom, Write},
    path::{Path, PathBuf},
    sync::atomic::{AtomicBool, Ordering},
    time::Instant,
};

const MAX_TREE_ENTRIES: usize = 200_000;
const MAX_NAME_BYTES: u32 = 1024;
const MAX_TABLE_SIZE: u64 = 256 * 1024 * 1024;
// Bound cache memory, but avoid one virtual BKTR seek per metadata field.
const MAX_PREFETCH_METADATA: u64 = 32 * 1024 * 1024;
const COPY_BUFFER: usize = 2 * 1024 * 1024;
const PARALLEL_FILE_CHUNK: u64 = 32 * 1024 * 1024;
const MAX_PARALLEL_TASKS: usize = 300_000;
const MAX_MANUAL_BKTR_VIRTUAL: u64 = 16 * 1024 * 1024;
// A 16 MiB IVFC mapping can be backed by a much larger NCA container.
// Keep an explicit ceiling on temporary disk writes without truncating
// otherwise valid >64 MiB Manual NCZ source candidates.
const MAX_MANUAL_BASE_NCA: u64 = 512 * 1024 * 1024;
const MAX_MANUAL_COMPRESSED_ENTRY: u64 = MAX_MANUAL_BASE_NCA + 32 * 1024 * 1024;
const MAX_MANUAL_CANDIDATES: usize = 4096;
const EMPTY_NODE: u32 = u32::MAX;

thread_local! {
    // A worker can extract dozens of files/chunks. Reuse its I/O buffer
    // rather than allocating and zeroing a new multi-megabyte Vec per task.
    static COPY_SCRATCH: RefCell<Vec<u8>> = const { RefCell::new(Vec::new()) };
}

#[derive(Debug, Clone, Copy, Default)]
pub struct NativeFsStats {
    pub romfs_files: usize,
    pub pfs0_files: usize,
}

impl NativeFsStats {
    pub fn total(self) -> usize {
        self.romfs_files + self.pfs0_files
    }
}

/// Extract standard RomFS, ExeFS, and PartitionFS sections from an existing
/// uncompressed NCA. Caller must supply a disposable, isolated output folder:
/// if an unsupported layout is encountered, the caller removes this folder
/// before trying its external-tool fallback.
pub fn unpack_nca(
    nca: &Path,
    output: &Path,
    keys: &KeySet,
    cancel: &AtomicBool,
) -> Result<NativeFsStats> {
    let nca_size = fs::metadata(nca)?.len();
    unpack_nca_region(nca, 0, nca_size, output, keys, cancel)
}

/// Extract a native NCA directly from its bounded byte range in an existing
/// NSP/XCI container. Control-title lookups can avoid materializing even the
/// isolated Control NCA. Any unsupported filesystem falls back unchanged.
pub(crate) fn unpack_nca_region(
    container: &Path,
    nca_base: u64,
    nca_size: u64,
    output: &Path,
    keys: &KeySet,
    cancel: &AtomicBool,
) -> Result<NativeFsStats> {
    let mut file = File::open(container)?;
    let container_size = file.metadata()?.len();
    ensure!(
        nca_base
            .checked_add(nca_size)
            .is_some_and(|end| end <= container_size),
        "NCA region exceeds source container"
    );
    ensure!(
        nca_size >= NCA_XTS_HEADER_SIZE as u64,
        "NCA header truncated"
    );
    file.seek(SeekFrom::Start(nca_base))?;
    let mut header = [0u8; NCA_XTS_HEADER_SIZE];
    file.read_exact(&mut header)?;
    let info = decrypt_header(&header, keys)?;
    ensure!(!info.sections.is_empty(), "NCA has no filesystem sections");
    // Refuse unsupported mixed sections *before* extracting any files.
    // In update Programs, an ExeFS section often precedes a BKTR RomFS:
    // extracting ExeFS first would just waste time before fallback.
    for section in &info.sections {
        ensure!(
            section
                .offset
                .checked_add(section.size)
                .is_some_and(|end| end <= nca_size),
            "NCA section exceeds file"
        );
        let start = 0x400 + section.index * 0x200;
        let fs = &info.decrypted_header[start..start + 0x200];
        ensure!(
            matches!(fs[4], 1 | 3)
                && fs[4] == section.encryption_type
                && matches!((fs[2], fs[3]), (0, 3) | (1, 2)),
            "NCA has a filesystem section requiring legacy fallback"
        );
    }
    let mut stats = NativeFsStats::default();

    for section in &info.sections {
        ensure!(
            section
                .offset
                .checked_add(section.size)
                .is_some_and(|end| end <= nca_size),
            "NCA section is outside file"
        );
        let fs_offset = 0x400 + section.index * 0x200;
        let fs_header = &info.decrypted_header[fs_offset..fs_offset + 0x200];
        let crypt_type = fs_header[4];
        // Encryption type 5/6 and BKTR require a layer-aware reader.
        // The plain AES-CTR reader must NEVER be used for those sections.
        ensure!(
            matches!(crypt_type, 1 | 3) && crypt_type == section.encryption_type,
            "NCA filesystem encryption requires legacy fallback"
        );
        let key = (crypt_type == 3)
            .then(|| derive_section_key(&info, keys))
            .transpose()?;
        let mut reader = SectionReader::new(&mut file, nca_base, section, key);
        extract_section(
            &mut reader,
            fs_header,
            section.size,
            output,
            cancel,
            &mut stats,
            true,
            true,
        )?;
    }
    ensure!(stats.total() > 0, "native NCA produced no files");
    Ok(stats)
}

/// Base/update overlays are decoded on demand. The virtual IVFC image never
/// needs to be materialized to disk. Unsupported AES-CTR-EX skip-layer-hash
/// and uncommon filesystem layouts fail closed to the LibHac fallback.
pub fn unpack_patched_nca(
    patch_path: &Path,
    base_path: &Path,
    output: &Path,
    keys: &KeySet,
    cancel: &AtomicBool,
    want_romfs: bool,
    want_exefs: bool,
) -> Result<NativeFsStats> {
    ensure!(
        want_romfs || want_exefs,
        "No patch filesystem was requested"
    );
    let mut patch = File::open(patch_path)?;
    let patch_size = patch.metadata()?.len();
    let mut patch_header = [0u8; NCA_XTS_HEADER_SIZE];
    patch.read_exact(&mut patch_header)?;
    let patch_info = decrypt_header(&patch_header, keys)?;
    let mut base = File::open(base_path)?;
    let base_size = base.metadata()?.len();
    let mut base_header = [0u8; NCA_XTS_HEADER_SIZE];
    base.read_exact(&mut base_header)?;
    let base_info = decrypt_header(&base_header, keys)?;
    let base_romfs = base_info
        .sections
        .iter()
        .find(|section| {
            let fs = &base_info.decrypted_header
                [0x400 + section.index * 0x200..0x600 + section.index * 0x200];
            fs[2] == 0 && fs[3] == 3 && matches!(section.encryption_type, 1 | 3)
        })
        .context("Base Program has no supported RomFS section")?;
    let mut has_patch_section = false;
    for section in &patch_info.sections {
        ensure!(
            section
                .offset
                .checked_add(section.size)
                .is_some_and(|v| v <= patch_size),
            "Patch NCA section exceeds the file"
        );
        let fs = &patch_info.decrypted_header
            [0x400 + section.index * 0x200..0x600 + section.index * 0x200];
        ensure!(
            matches!((fs[2], fs[3]), (0, 3) | (1, 2))
                && fs[4] == section.encryption_type
                && matches!(section.encryption_type, 1 | 3 | 4),
            "Patch NCA section type requires legacy fallback"
        );
        if section.encryption_type == 4 {
            ensure!(fs[2] == 0 && fs[3] == 3, "BKTR section is not RomFS IVFC");
            let hash_at = 0x280 + section.index * 0x20;
            ensure!(
                patch_info.decrypted_header[hash_at..hash_at + 32] == Sha256::digest(fs)[..],
                "BKTR filesystem header SHA256 does not match NCA section descriptor"
            );
            has_patch_section = true;
        }
    }
    ensure!(
        has_patch_section,
        "NCA has no supported BKTR update section"
    );
    ensure!(
        base_romfs
            .offset
            .checked_add(base_romfs.size)
            .is_some_and(|v| v <= base_size),
        "Base NCA RomFS exceeds the file"
    );
    let patch_key = derive_section_key(&patch_info, keys)?;
    let base_key = match base_romfs.encryption_type {
        1 => None,
        3 => Some(derive_section_key(&base_info, keys)?),
        _ => bail!("Base NCA encryption needs a fallback"),
    };

    let mut stats = NativeFsStats::default();
    for section in &patch_info.sections {
        ensure_not_cancelled(cancel)?;
        let fs = &patch_info.decrypted_header
            [0x400 + section.index * 0x200..0x600 + section.index * 0x200];
        if section.encryption_type == 4 {
            if !want_romfs {
                continue;
            }
            let mut reader = BktrVirtualReader::open(
                base_path, patch_path, base_romfs, section, fs, base_key, patch_key,
            )?;
            let virtual_size = reader.virtual_size();
            // All workers decode the same BKTR mappings. Parse and validate
            // them once, then give each worker independent source handles.
            let reader_template = reader.shared_template(base_path, patch_path, base_key)?;
            if fs[0x178..0x1a0].iter().any(|byte| *byte != 0) {
                // The raw BKTR overlay contains the compressed physical
                // image. CompressionStorage maps the final IVFC data level
                // into the *logical* RomFS, so use its independent size.
                let mut compressed =
                    CompressedBktrReader::open_from_verified_bktr(reader, fs, virtual_size)?;
                let logical = compressed.logical_size();
                let compressed_index = compressed.shared_index(virtual_size);
                stats.romfs_files += extract_romfs_parallel(
                    &mut compressed,
                    0,
                    logical,
                    &output.join("romfs"),
                    cancel,
                    || {
                        let overlay = reader_template.open()?;
                        if std::env::var("NSRP_BKTR_BENCH_COMPRESSED_INDEX")
                            .ok()
                            .as_deref()
                            == Some("reparse")
                        {
                            CompressedBktrReader::open_from_verified_bktr(overlay, fs, virtual_size)
                        } else {
                            CompressedBktrReader::open_shared(
                                overlay,
                                &compressed_index,
                                virtual_size,
                            )
                        }
                    },
                )?;
            } else {
                let (offset, size) = ivfc_image_bounds(fs, virtual_size)?;
                stats.romfs_files += extract_romfs_parallel(
                    &mut reader,
                    offset,
                    size,
                    &output.join("romfs"),
                    cancel,
                    || reader_template.open(),
                )?;
            }
        } else {
            let key = (section.encryption_type == 3).then_some(patch_key);
            let mut reader = SectionReader::new(&mut patch, 0, section, key);
            extract_section(
                &mut reader,
                fs,
                section.size,
                output,
                cancel,
                &mut stats,
                want_romfs,
                want_exefs,
            )?;
        }
    }
    ensure!(
        stats.total() > 0,
        "Native BKTR extraction produced no files"
    );
    Ok(stats)
}

/// Limit the *decompressed* output even when an untrusted NCZ header or
/// Zstandard stream claims a much larger Manual NCA than expected.
struct LimitedManualNcaWriter<'a> {
    target: &'a mut File,
    remaining: u64,
}

impl Write for LimitedManualNcaWriter<'_> {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        if bytes.len() as u64 > self.remaining {
            return Err(io::Error::other(
                "Manual NCZ decompressed size exceeds the configured safety ceiling",
            ));
        }
        let count = self.target.write(bytes)?;
        self.remaining -= count as u64;
        Ok(count)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.target.flush()
    }
}

/// One source-independent verifier for normal NCA and NCZ-decoded Manual
/// candidates. The master hash is only a fast filter: accept the base only
/// after checking every IVFC hash level against the actual decrypted bytes.
#[allow(clippy::too_many_arguments)]
fn manual_ivfc_matches(
    reader: &mut File,
    nca_base: u64,
    info: &NcaInfo,
    section: &NcaSection,
    keys: &KeySet,
    fs: &[u8],
    levels: &[IvfcLevel],
    source_offset: u64,
    virtual_size: u64,
) -> Result<bool> {
    let key = (section.encryption_type == 3)
        .then(|| derive_section_key(info, keys))
        .transpose()?;
    let mut image = vec![0u8; usize::try_from(virtual_size)?];
    let mut section_reader = SectionReader::new(reader, nca_base, section, key);
    section_reader.seek(SeekFrom::Start(source_offset))?;
    section_reader.read_exact(&mut image)?;
    verify_ivfc(&image, fs, levels)
}

/// Select a Manual update's base NCA/NCZ by the complete IVFC hash
/// hierarchy, then extract the empty-patch BKTR overlay. Never pick a base
/// by directory order, filename, size, or the Program ID alone: a package
/// can contain multiple different Manual NCAs for the same title.
///
/// The scope is deliberately narrow: an ordinary Manual NCA or NCZ
/// source (up to 512 MiB), a single base-only relocation, and a zero-offset 64 KiB BKTR
/// metadata-only patch. All other layouts retain the external fallback.
#[allow(clippy::too_many_arguments)]
pub fn unpack_patched_manual_from_package(
    patch_path: &Path,
    package: &Path,
    entries: &[ContainerEntry],
    scratch: &Path,
    output: &Path,
    keys: &KeySet,
    cancel: &AtomicBool,
) -> Result<(NativeFsStats, String)> {
    ensure_not_cancelled(cancel)?;
    ensure!(
        entries.len() <= MAX_MANUAL_CANDIDATES,
        "Manual source package contains too many entries"
    );
    let mut patch = File::open(patch_path)?;
    let patch_size = patch.metadata()?.len();
    ensure!(
        patch_size >= NCA_XTS_HEADER_SIZE as u64,
        "Manual patch NCA header is truncated"
    );
    let mut header = [0u8; NCA_XTS_HEADER_SIZE];
    patch.read_exact(&mut header)?;
    let patch_info = decrypt_header(&header, keys)?;
    ensure!(
        patch_info.content_type == 3 && patch_info.sections.len() == 1,
        "NCA is not a supported Manual BKTR update"
    );
    let section = &patch_info.sections[0];
    let fs =
        &patch_info.decrypted_header[0x400 + section.index * 0x200..0x600 + section.index * 0x200];
    ensure!(
        section.encryption_type == 4
            && (fs[2], fs[3], fs[4], fs[5]) == (0, 3, 4, 0)
            && &fs[8..12] == b"IVFC"
            && fs[0x100..0x108].iter().all(|byte| *byte == 0)
            && fs[0x148..0x200].iter().all(|byte| *byte == 0)
            && section
                .offset
                .checked_add(section.size)
                .is_some_and(|end| end <= patch_size),
        "Manual BKTR storage is not the verified empty-patch variant"
    );
    let hash_offset = 0x280 + section.index * 0x20;
    ensure!(
        patch_info.decrypted_header[hash_offset..hash_offset + 32] == Sha256::digest(fs)[..],
        "Manual BKTR FS header SHA-256 mismatch"
    );
    let relocation = collect_relocations_from_reader(
        &mut patch,
        0,
        patch_size,
        section.offset,
        section.size,
        fs,
        &derive_section_key(&patch_info, keys)?,
    )?;
    ensure!(
        relocation.entries.len() == 1
            && relocation.entries[0].virtual_offset == 0
            && !relocation.entries[0].from_patch
            && relocation.entries[0].source_offset == 0
            && (0x50..=MAX_MANUAL_BKTR_VIRTUAL).contains(&relocation.virtual_size),
        "Manual BKTR is not a small base-only virtual section"
    );
    let levels = ivfc_levels(fs, relocation.virtual_size)?;
    let source_offset = relocation.entries[0].source_offset;
    let program_id = &patch_info.decrypted_header[0x210..0x218];
    let mut source = File::open(package)?;
    let package_size = source.metadata()?.len();
    let work = tempfile::Builder::new()
        .prefix("nsrp_manual_bktr_")
        .tempdir_in(scratch)?;
    let mut matched: Option<&ContainerEntry> = None;
    let mut matched_ncz: Option<tempfile::NamedTempFile> = None;
    for entry in entries.iter().filter(|entry| {
        let name = entry.name.to_ascii_lowercase();
        (name.ends_with(".nca") || name.ends_with(".ncz"))
            && (NCA_XTS_HEADER_SIZE as u64..=MAX_MANUAL_COMPRESSED_ENTRY).contains(&entry.size)
    }) {
        ensure_not_cancelled(cancel)?;
        ensure!(
            entry
                .offset
                .checked_add(entry.size)
                .is_some_and(|end| end <= package_size),
            "Manual source NCA/NCZ exceeds container bounds"
        );
        source.seek(SeekFrom::Start(entry.offset))?;
        let mut candidate_header = [0u8; NCA_XTS_HEADER_SIZE];
        source.read_exact(&mut candidate_header)?;
        let Ok(info) = decrypt_header(&candidate_header, keys) else {
            continue;
        };
        if info.content_type != 3
            || info.decrypted_header[0x210..0x218] != *program_id
            || info.sections.len() != 1
        {
            continue;
        }
        let base_section = &info.sections[0];
        let compressed = entry.name.to_ascii_lowercase().ends_with(".ncz");
        let declared_size = u64::from_le_bytes(info.decrypted_header[0x208..0x210].try_into()?);
        let base_fs = &info.decrypted_header
            [0x400 + base_section.index * 0x200..0x600 + base_section.index * 0x200];
        if (base_fs[2], base_fs[3]) != (0, 3)
            || !matches!(base_section.encryption_type, 1 | 3)
            // A zero-offset base-only overlay maps the original IVFC root
            // unchanged. This cheap check avoids decrypting every unrelated
            // Manual NCA for the same title; full IVFC verification follows.
            || base_fs[0xc8..0xe8] != fs[0xc8..0xe8]
            || info.decrypted_header[0x280 + base_section.index * 0x20
                ..0x2a0 + base_section.index * 0x20] != Sha256::digest(base_fs)[..]
            || base_section.offset.checked_add(base_section.size).is_none_or(|end| {
                end > if compressed { declared_size } else { entry.size }
            })
            || !(0x4000..=MAX_MANUAL_BASE_NCA).contains(&declared_size)
            || (!compressed && entry.size > MAX_MANUAL_BASE_NCA)
            || source_offset
                .checked_add(relocation.virtual_size)
                .is_none_or(|end| end > base_section.size)
        {
            continue;
        }
        // NCZ preserves the original encrypted 0x4000-byte NCA header.
        // Decompress only a *matching* Manual candidate, into a bounded
        // disposable file; no other NCA or multi-gigabyte game is copied.
        let mut staged = if compressed {
            // Preflight on the scratch volume, not the user's final output.
            // The stream decoder enforces the same ceiling while writing.
            ensure_disk_space(work.path(), declared_size)?;
            let mut temporary = tempfile::Builder::new()
                .prefix("ncz_manual_")
                .tempfile_in(work.path())?;
            let written = {
                let mut limited = LimitedManualNcaWriter {
                    target: temporary.as_file_mut(),
                    remaining: MAX_MANUAL_BASE_NCA,
                };
                let written = decompress_ncz_region_to_nca(
                    &mut source,
                    entry.offset,
                    entry.size,
                    &mut limited,
                    cancel,
                    |_, _| {},
                )?;
                limited.flush()?;
                written
            };
            ensure!(
                written == declared_size && temporary.as_file().metadata()?.len() == declared_size,
                "Manual NCZ decoded NCA size disagrees with its authenticated header"
            );
            ensure_not_cancelled(cancel)?;
            Some(temporary)
        } else {
            None
        };
        let matches = if let Some(temporary) = staged.as_mut() {
            manual_ivfc_matches(
                temporary.as_file_mut(),
                0,
                &info,
                base_section,
                keys,
                fs,
                &levels,
                source_offset,
                relocation.virtual_size,
            )?
        } else {
            manual_ivfc_matches(
                &mut source,
                entry.offset,
                &info,
                base_section,
                keys,
                fs,
                &levels,
                source_offset,
                relocation.virtual_size,
            )?
        };
        if matches {
            ensure!(
                matched.is_none(),
                "Multiple Manual NCAs match the BKTR IVFC hash; refusing ambiguous base"
            );
            matched = Some(entry);
            matched_ncz = staged;
        }
    }
    let base_entry = matched.context("No Manual base NCA matches the full BKTR IVFC hashes")?;
    let base_path = if let Some(temporary) = matched_ncz.as_ref() {
        temporary.path().to_path_buf()
    } else {
        let path = work.path().join("verified_manual_base.nca");
        container::extract_entry(package, base_entry, &path, cancel)?;
        path
    };
    let stats = unpack_patched_nca(patch_path, &base_path, output, keys, cancel, true, false)?;
    ensure!(
        stats.romfs_files > 0 && stats.pfs0_files == 0,
        "Manual BKTR extraction did not produce RomFS files"
    );
    Ok((stats, base_entry.name.clone()))
}

#[allow(clippy::too_many_arguments)]
fn extract_section<R: Read + Seek>(
    reader: &mut R,
    fs_header: &[u8],
    logical_size: u64,
    output: &Path,
    cancel: &AtomicBool,
    stats: &mut NativeFsStats,
    want_romfs: bool,
    want_exefs: bool,
) -> Result<()> {
    let fs_type = fs_header[2];
    let hash_type = fs_header[3];
    if !want_romfs && fs_type == 0 || !want_exefs && fs_type == 1 {
        return Ok(());
    }
    let files = match (fs_type, hash_type) {
        (0, 3) => {
            let (offset, size) = ivfc_image_bounds(fs_header, logical_size)?;
            stats.romfs_files +=
                extract_romfs(reader, offset, size, &output.join("romfs"), cancel)?;
            return Ok(());
        }
        (1, 2) => {
            let pfs_offset = read_u64(fs_header, 0x40)?;
            let pfs_size = read_u64(fs_header, 0x48)?;
            ensure!(pfs_size >= 16, "PartitionFS is empty");
            check_region(pfs_offset, pfs_size, logical_size)?;
            extract_pfs0(reader, pfs_offset, pfs_size, output, cancel)?
        }
        _ => bail!("NCA filesystem type={fs_type} hash={hash_type} requires fallback"),
    };
    stats.pfs0_files += files;
    Ok(())
}

fn ivfc_image_bounds(header: &[u8], logical_size: u64) -> Result<(u64, u64)> {
    ensure!(
        header.get(0x08..0x0c) == Some(&b"IVFC"[..]),
        "RomFS IVFC magic mismatch"
    );
    let levels = read_u32(header, 0x14)?;
    // maxLayers includes one master-hash level; the last of maxLayers - 1
    // descriptors contains the plain RomFS image.
    ensure!((2..=7).contains(&levels), "invalid IVFC level count");
    let at = 0x18 + usize::try_from(levels - 2)? * 0x18;
    ensure!(at + 0x18 <= 0x100, "IVFC descriptor out of bounds");
    let offset = read_u64(header, at)?;
    let size = read_u64(header, at + 8)?;
    ensure!(size >= 0x50, "RomFS image too small");
    check_region(offset, size, logical_size)?;
    Ok((offset, size))
}

/// Return checked paths, offsets and sizes within a decrypted Control NCA
/// filesystem section, reusing the exact parser used by the extraction tab.
pub(crate) fn romfs_file_index(
    decrypted_section: &[u8],
    romfs_offset: u64,
    romfs_size: u64,
) -> Result<Vec<(PathBuf, u64, u64, u64)>> {
    let plan = scan_romfs(
        &mut std::io::Cursor::new(decrypted_section),
        romfs_offset,
        romfs_size,
    )?;
    plan.files
        .into_iter()
        .map(|f| {
            let absolute = romfs_offset
                .checked_add(f.offset)
                .context("Control RomFS file offset overflow")?;
            let table_record = romfs_offset
                .checked_add(f.table_record)
                .context("RomFS file record overflow")?;
            Ok((f.relative, absolute, f.size, table_record))
        })
        .collect()
}

fn extract_pfs0<R: Read + Seek>(
    reader: &mut R,
    offset: u64,
    size: u64,
    output: &Path,
    cancel: &AtomicBool,
) -> Result<usize> {
    let index = Pfs0Index::parse_reader(reader, offset, size)?;
    let exefs = index
        .entries
        .iter()
        .any(|entry| matches!(entry.name.as_str(), "main" | "main.npdm" | "rtld" | "sdk"));
    let dest = output.join(if exefs { "exefs" } else { "section0" });
    // Validate *all* names before creating a single output file.
    for entry in &index.entries {
        safe_name(&entry.name)?;
    }
    fs::create_dir_all(&dest)?;
    let total_bytes = index
        .entries
        .iter()
        .try_fold(0u64, |sum, entry| sum.checked_add(entry.size))
        .context("PFS0 output size overflow")?;
    ensure_disk_space(&dest, total_bytes)?;
    for entry in &index.entries {
        ensure_not_cancelled(cancel)?;
        reader.seek(SeekFrom::Start(
            index
                .data_start
                .checked_add(entry.offset)
                .context("PFS0 file offset overflow")?,
        ))?;
        let mut file = File::create(dest.join(&entry.name))?;
        copy_exact(reader, &mut file, entry.size, cancel)?;
    }
    Ok(index.entries.len())
}

#[derive(Debug)]
struct RomfsPlan {
    dirs: Vec<PathBuf>,
    files: Vec<RomfsFile>,
}

#[derive(Debug)]
struct RomfsFile {
    relative: PathBuf,
    offset: u64,
    size: u64,
    /// File-table record offset, relative to the beginning of RomFS.
    table_record: u64,
}

#[derive(Debug)]
struct RomfsHeader {
    dir_table: u64,
    dir_size: u64,
    file_table: u64,
    file_size: u64,
    data: u64,
}

/// One verified RomFS file copy shared by the serial, BKTR serial fallback,
/// and independent-file worker strategies. A worker owns its source cursor
/// and output file for the entire operation; chunk tasks remain separate.
fn copy_romfs_entry<R: Read + Seek>(
    reader: &mut R,
    base: u64,
    entry: &RomfsFile,
    output: &Path,
    cancel: &AtomicBool,
) -> Result<()> {
    ensure_not_cancelled(cancel)?;
    let path = output.join(&entry.relative);
    // Serial and parallel extraction precreate all directories in the
    // checked RomFS plan. Avoid repeated CreateDirectoryW metadata I/O
    // for each of 10k+ files. A missing parent must fail closed instead.
    let absolute = base
        .checked_add(entry.offset)
        .context("RomFS file absolute offset overflow")?;
    reader.seek(SeekFrom::Start(absolute))?;
    let mut file = File::create(path)?;
    copy_exact(reader, &mut file, entry.size, cancel)
}

fn extract_romfs<R: Read + Seek>(
    reader: &mut R,
    base: u64,
    size: u64,
    output: &Path,
    cancel: &AtomicBool,
) -> Result<usize> {
    // Scan the complete directory/file tree before writing; malformed names,
    // cycles and out-of-bounds entries must not leave partial files behind.
    let plan = scan_romfs(reader, base, size)?;
    fs::create_dir_all(output)?;
    let total_bytes = plan
        .files
        .iter()
        .try_fold(0u64, |sum, file| sum.checked_add(file.size))
        .context("RomFS output size overflow")?;
    ensure_disk_space(output, total_bytes)?;
    for dir in &plan.dirs {
        ensure_not_cancelled(cancel)?;
        fs::create_dir_all(output.join(dir))?;
    }
    for entry in &plan.files {
        copy_romfs_entry(reader, base, entry, output, cancel)?;
    }
    Ok(plan.files.len())
}

/// Extract independent files without competing writes to the same file.
/// Large single-file RomFS assets still use disjoint 32 MiB chunk tasks.
/// Each worker owns its source reader to avoid shared file-position races.
fn prefer_whole_file_tasks(files: &[RomfsFile], total_size: u64, workers: usize) -> bool {
    // Leave enough independent tasks for work stealing. One dominant large
    // asset carrying over half the image should still use the proven
    // disjoint chunk path. A threshold of one third was too conservative:
    // the verified 61-file BKTR sample has one 36.7% asset.
    files.len() >= workers.saturating_mul(4)
        && files.iter().all(|entry| entry.size <= total_size / 2)
}

fn romfs_worker_pool(workers: usize) -> Result<rayon::ThreadPool> {
    Ok(rayon::ThreadPoolBuilder::new()
        .num_threads(workers)
        .thread_name(|index| format!("nsrp-bktr-{index}"))
        .build()?)
}

fn extract_romfs_parallel<R, F>(
    scanner: &mut R,
    base: u64,
    size: u64,
    output: &Path,
    cancel: &AtomicBool,
    create_reader: F,
) -> Result<usize>
where
    R: Read + Seek + Send,
    F: Fn() -> Result<R> + Sync + Send,
{
    let plan_start = Instant::now();
    let plan = scan_romfs(scanner, base, size)?;
    let scan_ms = plan_start.elapsed().as_millis();
    let extract_start = Instant::now();
    // Distinct Switch RomFS names can alias on a case-insensitive Windows
    // filesystem. Reject them before parallel writes to prevent tasks from
    // accidentally targeting the same output file.
    let mut seen = HashSet::with_capacity(plan.files.len());
    for entry in &plan.files {
        ensure!(
            seen.insert(entry.relative.to_string_lossy().to_lowercase()),
            "BKTR RomFS has conflicting Windows output paths"
        );
    }
    fs::create_dir_all(output)?;
    for dir in &plan.dirs {
        ensure_not_cancelled(cancel)?;
        fs::create_dir_all(output.join(dir))?;
    }
    let total_size = plan
        .files
        .iter()
        .fold(0u64, |sum, f| sum.saturating_add(f.size));
    ensure_disk_space(output, total_size)?;
    let workers = std::env::var("NSRP_BKTR_BENCH_WORKERS")
        .ok()
        .and_then(|raw| raw.parse::<usize>().ok())
        .filter(|n| (1..=4).contains(n))
        .unwrap_or_else(|| num_cpus::get().min(4));
    let per_file = match std::env::var("NSRP_BKTR_BENCH_TASK_MODE").ok().as_deref() {
        Some("files") => true,
        Some("chunks") => false,
        _ => prefer_whole_file_tasks(&plan.files, total_size, workers),
    };
    let source_order = std::env::var("NSRP_BKTR_BENCH_IO_ORDER").ok().as_deref() == Some("source");
    let mut mode = "serial";
    let mut setup_ms = 0u128;
    let mut task_count = plan.files.len();
    if workers < 2 || (plan.files.len() < 32 && total_size < 32 * 1024 * 1024) {
        for entry in &plan.files {
            copy_romfs_entry(scanner, base, entry, output, cancel)?;
        }
    } else if per_file && plan.files.len() >= workers {
        mode = "files";
        let pool = romfs_worker_pool(workers)?;
        // Source-order work submission is a benchmark opt-in until actual
        // BKTR A/B evidence supports making it the general default. Output
        // boundaries and authenticated mappings remain unchanged.
        let mut jobs = plan.files.iter().collect::<Vec<_>>();
        if source_order {
            jobs.sort_unstable_by_key(|entry| entry.offset);
        }
        pool.install(|| {
            jobs.par_iter()
                .try_for_each_init(&create_reader, |state, &entry| -> Result<()> {
                    let worker = state
                        .as_mut()
                        .map_err(|error| anyhow::anyhow!("BKTR worker start failed: {error:#}"))?;
                    copy_romfs_entry(worker, base, entry, output, cancel)
                })
        })?;
    } else {
        mode = "chunks";
        // Preallocate all output files before workers begin writing. Every
        // task writes a disjoint byte range within exactly one output file.
        // A task index is bounded so malicious overlapping records cannot
        // cause a massive work-queue allocation.
        let started = Instant::now();
        let mut tasks = Vec::new();
        for (file_index, entry) in plan.files.iter().enumerate() {
            ensure_not_cancelled(cancel)?;
            let path = output.join(&entry.relative);
            // Parent directories were already created from the validated
            // RomFS plan, just as for the whole-file worker strategy.
            File::create(&path)?.set_len(entry.size)?;
            let mut start = 0u64;
            while start < entry.size {
                ensure!(
                    tasks.len() < MAX_PARALLEL_TASKS,
                    "BKTR extraction task limit exceeded"
                );
                let length = (entry.size - start).min(PARALLEL_FILE_CHUNK);
                tasks.push((file_index, start, length));
                start += length;
            }
        }
        setup_ms = started.elapsed().as_millis();
        // Source-order scheduling did not outperform directory-tree ordering
        // consistently in the Stage 14 real BKTR A/B benchmark. Preserve
        // the established default and keep opt-in ordering for future tests.
        if source_order {
            tasks.sort_unstable_by_key(|&(file_index, from, _)| {
                plan.files[file_index].offset.saturating_add(from)
            });
        }
        let pool = romfs_worker_pool(workers)?;
        task_count = tasks.len();
        pool.install(|| {
            tasks.par_iter().try_for_each_init(
                create_reader,
                |state, &(file_index, from, length)| {
                    let worker = state
                        .as_mut()
                        .map_err(|error| anyhow::anyhow!("BKTR worker start failed: {error:#}"))?;
                    ensure_not_cancelled(cancel)?;
                    let entry = &plan.files[file_index];
                    let virtual_offset = base
                        .checked_add(entry.offset)
                        .and_then(|position| position.checked_add(from))
                        .context("BKTR parallel task offset overflow")?;
                    worker.seek(SeekFrom::Start(virtual_offset))?;
                    let mut file = OpenOptions::new()
                        .write(true)
                        .open(output.join(&entry.relative))?;
                    file.seek(SeekFrom::Start(from))?;
                    copy_exact(worker, &mut file, length, cancel)
                },
            )
        })?;
    }
    if std::env::var_os("NSRP_STAGE14_PROFILE").is_some() {
        eprintln!(
            "STAGE14_BKTR_EXTRACT_PROFILE scan_ms={scan_ms} output_ms={} workers={workers} files={} tasks={task_count} bytes={total_size}",
            extract_start.elapsed().as_millis(),
            plan.files.len()
        );
    }
    if std::env::var_os("NSRP_STAGE16_PROFILE").is_some() {
        eprintln!(
            "STAGE16_BKTR_OUTPUT_PROFILE mode={mode} scan_ms={scan_ms} total_ms={} setup_ms={setup_ms} workers={workers} files={} tasks={task_count} bytes={total_size} max_file_bytes={}",
            extract_start.elapsed().as_millis(),
            plan.files.len(),
            plan.files.iter().map(|file| file.size).max().unwrap_or(0),
        );
    }
    Ok(plan.files.len())
}

fn scan_romfs<R: Read + Seek>(reader: &mut R, base: u64, size: u64) -> Result<RomfsPlan> {
    let head = read_bounded(reader, base, size, 0, 0x50)?;
    ensure!(read_u64(&head, 0)? == 0x50, "RomFS header size is not 0x50");
    let h = RomfsHeader {
        dir_table: read_u64(&head, 0x18)?,
        dir_size: read_u64(&head, 0x20)?,
        file_table: read_u64(&head, 0x38)?,
        file_size: read_u64(&head, 0x40)?,
        data: read_u64(&head, 0x48)?,
    };
    for (off, len) in [
        (read_u64(&head, 0x08)?, read_u64(&head, 0x10)?),
        (h.dir_table, h.dir_size),
        (read_u64(&head, 0x28)?, read_u64(&head, 0x30)?),
        (h.file_table, h.file_size),
    ] {
        ensure!(len <= MAX_TABLE_SIZE, "RomFS metadata table too large");
        check_region(off, len, size)?;
    }
    ensure!(
        h.dir_size >= 0x18 && h.data <= size,
        "RomFS layout is invalid"
    );
    let cached = if h
        .dir_size
        .checked_add(h.file_size)
        .is_some_and(|total| total <= MAX_PREFETCH_METADATA)
    {
        Some((
            read_bounded(
                reader,
                base,
                size,
                h.dir_table,
                usize::try_from(h.dir_size)?,
            )?,
            read_bounded(
                reader,
                base,
                size,
                h.file_table,
                usize::try_from(h.file_size)?,
            )?,
        ))
    } else {
        None
    };

    let mut seen_dirs = HashSet::new();
    let mut seen_files = HashSet::new();
    let mut seen_paths = HashSet::new();
    let mut dir_queue = vec![(0u32, PathBuf::new())];
    let mut dirs = Vec::new();
    let mut files = Vec::new();

    while let Some((entry_offset, parent)) = dir_queue.pop() {
        ensure!(
            seen_dirs.insert(entry_offset) && seen_dirs.len() <= MAX_TREE_ENTRIES,
            "RomFS directory cycle or excessive entry count"
        );
        let at = u64::from(entry_offset);
        check_region(at, 0x18, h.dir_size)?;
        let dir = if let Some((table, _)) = &cached {
            table
                .get(usize::try_from(at)?..usize::try_from(at + 0x18)?)
                .context("RomFS cached directory record truncated")?
                .to_vec()
        } else {
            read_bounded(reader, base, size, h.dir_table + at, 0x18)?
        };
        let sibling = read_u32(&dir, 4)?;
        let child_dir = read_u32(&dir, 8)?;
        let child_file = read_u32(&dir, 12)?;
        let name_size = read_u32(&dir, 20)?;
        ensure!(name_size <= MAX_NAME_BYTES, "RomFS directory name too long");
        check_region(at, 0x18 + u64::from(name_size), h.dir_size)?;
        let relative = if entry_offset == 0 {
            ensure!(name_size == 0, "RomFS root must have an empty name");
            parent.clone()
        } else {
            let name = if let Some((table, _)) = &cached {
                decode_name(
                    table
                        .get(
                            usize::try_from(at + 0x18)?
                                ..usize::try_from(at + 0x18 + u64::from(name_size))?,
                        )
                        .context("RomFS cached directory name truncated")?,
                )?
            } else {
                read_name(reader, base, size, h.dir_table + at + 0x18, name_size)?
            };
            let relative = parent.join(name);
            let folded = relative.to_string_lossy().to_lowercase();
            ensure!(seen_paths.insert(folded), "RomFS duplicate path");
            dirs.push(relative.clone());
            relative
        };
        if sibling != EMPTY_NODE {
            dir_queue.push((sibling, parent));
        }
        if child_dir != EMPTY_NODE {
            dir_queue.push((child_dir, relative.clone()));
        }
        let mut current = child_file;
        while current != EMPTY_NODE {
            ensure!(
                seen_files.insert(current)
                    && seen_files.len() + seen_dirs.len() <= MAX_TREE_ENTRIES,
                "RomFS file cycle or excessive entry count"
            );
            let entry_at = u64::from(current);
            check_region(entry_at, 0x20, h.file_size)?;
            let f = if let Some((_, table)) = &cached {
                table
                    .get(usize::try_from(entry_at)?..usize::try_from(entry_at + 0x20)?)
                    .context("RomFS cached file record truncated")?
                    .to_vec()
            } else {
                read_bounded(reader, base, size, h.file_table + entry_at, 0x20)?
            };
            let next = read_u32(&f, 4)?;
            let data_off = read_u64(&f, 8)?;
            let data_size = read_u64(&f, 0x10)?;
            let name_size = read_u32(&f, 0x1c)?;
            ensure!(name_size <= MAX_NAME_BYTES, "RomFS filename too long");
            check_region(entry_at, 0x20 + u64::from(name_size), h.file_size)?;
            let name = if let Some((_, table)) = &cached {
                decode_name(
                    table
                        .get(
                            usize::try_from(entry_at + 0x20)?
                                ..usize::try_from(entry_at + 0x20 + u64::from(name_size))?,
                        )
                        .context("RomFS cached filename truncated")?,
                )?
            } else {
                read_name(
                    reader,
                    base,
                    size,
                    h.file_table + entry_at + 0x20,
                    name_size,
                )?
            };
            let path = relative.join(name);
            ensure!(
                seen_paths.insert(path.to_string_lossy().to_lowercase()),
                "RomFS duplicate output name"
            );
            let file_offset = h
                .data
                .checked_add(data_off)
                .context("RomFS data overflow")?;
            check_region(file_offset, data_size, size)?;
            files.push(RomfsFile {
                relative: path,
                offset: file_offset,
                size: data_size,
                table_record: h.file_table + entry_at,
            });
            current = next;
        }
    }
    Ok(RomfsPlan { dirs, files })
}

fn read_name<R: Read + Seek>(
    reader: &mut R,
    base: u64,
    size: u64,
    offset: u64,
    count: u32,
) -> Result<String> {
    let bytes = read_bounded(reader, base, size, offset, usize::try_from(count)?)?;
    decode_name(&bytes)
}

fn decode_name(bytes: &[u8]) -> Result<String> {
    let name = std::str::from_utf8(bytes).context("RomFS filename is not UTF-8")?;
    safe_name(name)?;
    Ok(name.to_owned())
}

fn safe_name(name: &str) -> Result<()> {
    let invalid = name.is_empty()
        || matches!(name, "." | "..")
        || name.ends_with([' ', '.'])
        || name.chars().any(|c| {
            c.is_control() || matches!(c, '<' | '>' | ':' | '"' | '/' | '\\' | '|' | '?' | '*')
        });
    ensure!(!invalid, "unsafe filesystem entry name");
    let stem = name.split('.').next().unwrap_or("").to_ascii_uppercase();
    ensure!(
        !matches!(stem.as_str(), "CON" | "PRN" | "AUX" | "NUL")
            && !matches!(
                stem.as_str(),
                "COM1"
                    | "COM2"
                    | "COM3"
                    | "COM4"
                    | "COM5"
                    | "COM6"
                    | "COM7"
                    | "COM8"
                    | "COM9"
                    | "LPT1"
                    | "LPT2"
                    | "LPT3"
                    | "LPT4"
                    | "LPT5"
                    | "LPT6"
                    | "LPT7"
                    | "LPT8"
                    | "LPT9"
            ),
        "Windows-reserved filesystem entry name"
    );
    Ok(())
}

fn read_bounded<R: Read + Seek>(
    reader: &mut R,
    base: u64,
    limit: u64,
    relative: u64,
    count: usize,
) -> Result<Vec<u8>> {
    check_region(relative, count as u64, limit)?;
    let absolute = base
        .checked_add(relative)
        .context("NCA read address overflow")?;
    reader.seek(SeekFrom::Start(absolute))?;
    let mut bytes = vec![0u8; count];
    reader.read_exact(&mut bytes)?;
    Ok(bytes)
}

fn check_region(offset: u64, size: u64, limit: u64) -> Result<()> {
    ensure!(
        offset.checked_add(size).is_some_and(|end| end <= limit),
        "filesystem region exceeds its bounds"
    );
    Ok(())
}

fn read_u32(data: &[u8], offset: usize) -> Result<u32> {
    Ok(u32::from_le_bytes(
        data.get(offset..offset + 4)
            .context("filesystem u32 outside header")?
            .try_into()?,
    ))
}

fn read_u64(data: &[u8], offset: usize) -> Result<u64> {
    Ok(u64::from_le_bytes(
        data.get(offset..offset + 8)
            .context("filesystem u64 outside header")?
            .try_into()?,
    ))
}

fn ensure_not_cancelled(cancel: &AtomicBool) -> Result<()> {
    ensure!(!cancel.load(Ordering::Relaxed), "작업이 중단되었습니다");
    Ok(())
}

fn copy_exact<R: Read, W: Write>(
    reader: &mut R,
    writer: &mut W,
    mut size: u64,
    cancel: &AtomicBool,
) -> Result<()> {
    COPY_SCRATCH.with(|scratch| -> Result<()> {
        let mut buf = scratch.borrow_mut();
        if buf.len() < COPY_BUFFER {
            buf.resize(COPY_BUFFER, 0);
        }
        while size > 0 {
            ensure_not_cancelled(cancel)?;
            let take = size.min(buf.len() as u64) as usize;
            reader.read_exact(&mut buf[..take])?;
            writer.write_all(&buf[..take])?;
            size -= take as u64;
        }
        Ok(())
    })?;
    writer.flush()?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        crypto::{aes_ecb_encrypt_block, nca_ctr_xcrypt_range, nca_xts_transform},
        formats::pfs0::build_from_paths,
    };
    use sha2::{Digest, Sha256};
    use std::collections::HashMap;
    use std::io::Cursor;
    use std::sync::Arc;

    #[test]
    fn bounded_manual_ncz_writer_rejects_output_overflow() -> Result<()> {
        let mut temp = tempfile::NamedTempFile::new()?;
        {
            let mut writer = LimitedManualNcaWriter {
                target: temp.as_file_mut(),
                remaining: 8,
            };
            assert_eq!(writer.write(&[0x23; 5])?, 5);
            assert!(
                writer.write_all(&[0x88; 4]).is_err(),
                "A decompression stream cannot write past its declared size limit"
            );
            assert_eq!(writer.write(&[0x45; 3])?, 3);
            assert!(
                writer.write_all(&[0x46]).is_err(),
                "Remaining bytes must not wrap or become unbounded"
            );
            writer.flush()?;
        }
        assert_eq!(temp.as_file().metadata()?.len(), 8);
        Ok(())
    }

    #[cfg(windows)]
    #[test]
    fn stage53_injected_disk_full_write_fails_without_touching_previous_file() -> Result<()> {
        // Simulated Windows ERROR_DISK_FULL, not real quota exhaustion.
        // A verified prior output is not the worker's writer: it must remain
        // intact if the staged copy fails after a short WriteFile.
        struct QuotaWriter {
            remaining: usize,
            written: Vec<u8>,
        }
        impl Write for QuotaWriter {
            fn write(&mut self, data: &[u8]) -> io::Result<usize> {
                if self.remaining == 0 {
                    return Err(io::Error::from_raw_os_error(112));
                }
                let take = data.len().min(self.remaining);
                self.written.extend_from_slice(&data[..take]);
                self.remaining -= take;
                Ok(take)
            }
            fn flush(&mut self) -> io::Result<()> {
                Ok(())
            }
        }
        let root = tempfile::tempdir()?;
        let previous = root.path().join("verified_before.xci");
        fs::write(&previous, b"unchanged verified output")?;
        let mut input = std::io::Cursor::new(b"new output that exceeds quota");
        let mut target = QuotaWriter {
            remaining: 8,
            written: Vec::new(),
        };
        let error = copy_exact(&mut input, &mut target, 29, &AtomicBool::new(false))
            .expect_err("Disk-full injected writer must fail instead of publishing partial output");
        let os_error = error
            .root_cause()
            .downcast_ref::<io::Error>()
            .and_then(io::Error::raw_os_error);
        assert_eq!(os_error, Some(112));
        assert_eq!(target.written.len(), 8);
        assert_eq!(fs::read(&previous)?, b"unchanged verified output");
        assert_eq!(fs::read_dir(root.path())?.count(), 1);
        Ok(())
    }

    fn sample_image(name: &str, size_override: Option<u64>) -> Vec<u8> {
        let mut image = vec![0u8; 0x120];
        image[0..8].copy_from_slice(&0x50u64.to_le_bytes());
        for (at, value) in [
            (0x08, 0x50u64),
            (0x10, 4),
            (0x18, 0x60),
            (0x20, 0x18),
            (0x28, 0x78),
            (0x30, 4),
            (0x38, 0x80),
            (0x40, 0x20 + name.len() as u64),
            (0x48, 0x100),
        ] {
            image[at..at + 8].copy_from_slice(&value.to_le_bytes());
        }
        for pos in [0x60usize, 0x64, 0x68, 0x70] {
            image[pos..pos + 4].copy_from_slice(&EMPTY_NODE.to_le_bytes());
        }
        // Root directory has exactly one child file at table offset 0.
        image[0x6c..0x70].copy_from_slice(&0u32.to_le_bytes());
        image[0x80..0x84].copy_from_slice(&0u32.to_le_bytes());
        image[0x84..0x88].copy_from_slice(&EMPTY_NODE.to_le_bytes());
        image[0x88..0x90].copy_from_slice(&0u64.to_le_bytes());
        image[0x90..0x98].copy_from_slice(&size_override.unwrap_or(5).to_le_bytes());
        image[0x98..0x9c].copy_from_slice(&EMPTY_NODE.to_le_bytes());
        image[0x9c..0xa0].copy_from_slice(&(name.len() as u32).to_le_bytes());
        image[0xa0..0xa0 + name.len()].copy_from_slice(name.as_bytes());
        image[0x100..0x105].copy_from_slice(b"hello");
        image
    }

    fn many_file_image(file_count: usize) -> Vec<u8> {
        const DATA_START: usize = 0x1000;
        const FILE_BYTES: usize = 1024;
        const FILE_RECORD: usize = 0x28;
        let mut image = vec![0u8; DATA_START + file_count * FILE_BYTES];
        for (at, value) in [
            (0usize, 0x50u64),
            (0x08, 0x50),
            (0x10, 4),
            (0x18, 0x60),
            (0x20, 0x18),
            (0x28, 0x78),
            (0x30, 4),
            (0x38, 0x80),
            (0x40, (file_count * FILE_RECORD) as u64),
            (0x48, DATA_START as u64),
        ] {
            image[at..at + 8].copy_from_slice(&value.to_le_bytes());
        }
        for pos in [0x60, 0x64, 0x68, 0x70] {
            image[pos..pos + 4].copy_from_slice(&EMPTY_NODE.to_le_bytes());
        }
        image[0x6c..0x70].copy_from_slice(&0u32.to_le_bytes());
        for i in 0..file_count {
            let record = 0x80 + i * FILE_RECORD;
            let next = if i + 1 == file_count {
                EMPTY_NODE
            } else {
                ((i + 1) * FILE_RECORD) as u32
            };
            image[record + 4..record + 8].copy_from_slice(&next.to_le_bytes());
            image[record + 8..record + 16]
                .copy_from_slice(&((i * FILE_BYTES) as u64).to_le_bytes());
            image[record + 16..record + 24].copy_from_slice(&(FILE_BYTES as u64).to_le_bytes());
            image[record + 24..record + 28].copy_from_slice(&EMPTY_NODE.to_le_bytes());
            image[record + 28..record + 32].copy_from_slice(&8u32.to_le_bytes());
            image[record + 32..record + 40].copy_from_slice(format!("f{i:03}.bin").as_bytes());
            for (j, byte) in image[DATA_START + i * FILE_BYTES..DATA_START + (i + 1) * FILE_BYTES]
                .iter_mut()
                .enumerate()
            {
                *byte = (i ^ j) as u8;
            }
        }
        image
    }

    #[test]
    fn extracts_small_romfs_without_external_tools() -> Result<()> {
        let bytes = sample_image("hello.txt", None);
        let temp = tempfile::tempdir()?;
        let n = extract_romfs(
            &mut Cursor::new(&bytes),
            0,
            bytes.len() as u64,
            temp.path(),
            &AtomicBool::new(false),
        )?;
        assert_eq!(n, 1);
        assert_eq!(fs::read(temp.path().join("hello.txt"))?, b"hello");
        Ok(())
    }

    #[cfg(windows)]
    #[test]
    fn refuses_impossible_disk_requirement_before_creating_game_files() -> Result<()> {
        let root = tempfile::tempdir()?;
        let output = root.path().join("extract");
        fs::create_dir_all(&output)?;
        ensure_disk_space(&output, 1024)?;
        assert!(ensure_disk_space(&output, u64::MAX).is_err());
        assert_eq!(fs::read_dir(&output)?.count(), 0);
        Ok(())
    }

    #[test]
    fn cancelled_romfs_extract_does_not_create_partial_game_files() -> Result<()> {
        let bytes = sample_image("hello.txt", None);
        let temp = tempfile::tempdir()?;
        let output = temp.path().join("cancelled");
        let cancelled = AtomicBool::new(true);
        assert!(
            extract_romfs(
                &mut Cursor::new(&bytes),
                0,
                bytes.len() as u64,
                &output,
                &cancelled
            )
            .is_err()
        );
        assert!(!output.join("hello.txt").exists());
        Ok(())
    }

    #[test]
    fn parallel_romfs_large_single_file_disjoint_chunks_match_source() -> Result<()> {
        // A single large asset must be split among workers rather than
        // leaving AES-CTR decryption serialized on just one Rayon worker.
        let length = 48 * 1024 * 1024usize;
        let mut image = sample_image("big.bin", Some(length as u64));
        image.resize(0x100 + length, 0);
        for (index, byte) in image[0x100..].iter_mut().enumerate() {
            *byte = (index % 251) as u8;
        }
        let shared: Arc<[u8]> = Arc::from(image);
        let mut scanner = Cursor::new(shared.clone());
        let temp = tempfile::tempdir()?;
        let extracted = extract_romfs_parallel(
            &mut scanner,
            0,
            shared.len() as u64,
            temp.path(),
            &AtomicBool::new(false),
            || Ok(Cursor::new(shared.clone())),
        )?;
        assert_eq!(extracted, 1);
        let actual = fs::read(temp.path().join("big.bin"))?;
        assert_eq!(actual.len(), length);
        assert_eq!(
            Sha256::digest(&actual)[..],
            Sha256::digest(&shared[0x100..])[..]
        );
        Ok(())
    }

    #[test]
    fn many_independent_romfs_files_roundtrip_and_auto_select() -> Result<()> {
        let shared: Arc<[u8]> = Arc::from(many_file_image(40));
        let mut scanner = Cursor::new(shared.clone());
        let plan = scan_romfs(&mut scanner, 0, shared.len() as u64)?;
        assert_eq!(plan.files.len(), 40);
        assert!(prefer_whole_file_tasks(&plan.files, 40 * 1024, 4));
        let temp = tempfile::tempdir()?;
        let count = extract_romfs_parallel(
            &mut scanner,
            0,
            shared.len() as u64,
            temp.path(),
            &AtomicBool::new(false),
            || Ok(Cursor::new(shared.clone())),
        )?;
        assert_eq!(count, 40);
        for i in 0..40 {
            let content = fs::read(temp.path().join(format!("f{i:03}.bin")))?;
            assert_eq!(content.len(), 1024);
            for (j, byte) in content.iter().enumerate() {
                assert_eq!(*byte, (i ^ j) as u8);
            }
        }
        let mut dominant = plan.files;
        dominant[0].size = 64 * 1024 * 1024;
        assert!(!prefer_whole_file_tasks(
            &dominant,
            dominant.iter().map(|file| file.size).sum(),
            4,
        ));
        Ok(())
    }

    #[test]
    fn stage52_romfs_file_workers_require_precreated_directories() -> Result<()> {
        let root = tempfile::tempdir()?;
        let source = b"stage52 validated file payload";
        let entry = RomfsFile {
            relative: PathBuf::from("nested").join("inside.bin"),
            offset: 0,
            size: source.len() as u64,
            table_record: 0,
        };
        let cancelled = AtomicBool::new(false);
        let mut input = Cursor::new(source);
        assert!(
            copy_romfs_entry(&mut input, 0, &entry, root.path(), &cancelled).is_err(),
            "A worker must not create an unplanned parent directory"
        );
        assert!(!root.path().join("nested").exists());
        fs::create_dir_all(root.path().join("nested"))?;
        copy_romfs_entry(&mut input, 0, &entry, root.path(), &cancelled)?;
        assert_eq!(fs::read(root.path().join("nested/inside.bin"))?, source);
        Ok(())
    }

    #[test]
    fn parallel_multi_file_cancel_rejects_before_creating_files() -> Result<()> {
        let shared: Arc<[u8]> = Arc::from(many_file_image(40));
        let mut scanner = Cursor::new(shared.clone());
        let temp = tempfile::tempdir()?;
        let cancelled = AtomicBool::new(true);
        let result = extract_romfs_parallel(
            &mut scanner,
            0,
            shared.len() as u64,
            temp.path(),
            &cancelled,
            || Ok(Cursor::new(shared.clone())),
        );
        assert!(result.is_err());
        assert_eq!(fs::read_dir(temp.path())?.count(), 0);
        Ok(())
    }

    #[test]
    fn rejects_unsafe_romfs_names_before_writing() -> Result<()> {
        let bytes = sample_image("..\\evil", None);
        let temp = tempfile::tempdir()?;
        assert!(
            extract_romfs(
                &mut Cursor::new(&bytes),
                0,
                bytes.len() as u64,
                temp.path(),
                &AtomicBool::new(false)
            )
            .is_err()
        );
        assert_eq!(fs::read_dir(temp.path())?.count(), 0);
        Ok(())
    }

    #[test]
    fn rejects_out_of_bounds_romfs_file() -> Result<()> {
        let bytes = sample_image("good.bin", Some(0xffff_ffff));
        let temp = tempfile::tempdir()?;
        assert!(
            extract_romfs(
                &mut Cursor::new(&bytes),
                0,
                bytes.len() as u64,
                temp.path(),
                &AtomicBool::new(false)
            )
            .is_err()
        );
        assert_eq!(fs::read_dir(temp.path())?.count(), 0);
        Ok(())
    }

    #[test]
    fn extracts_ctr_encrypted_exefs_from_nca() -> Result<()> {
        let temp = tempfile::tempdir()?;
        let source = temp.path().join("main.npdm");
        fs::write(&source, b"native-exefs-test")?;
        let pfs_path = temp.path().join("pfs0.bin");
        build_from_paths(&[("main.npdm".into(), source)], &pfs_path)?;
        let pfs = fs::read(&pfs_path)?;
        let pfs_offset = 0x20usize;
        let section_offset = 0x4000usize;
        let section_size = (pfs_offset + pfs.len()).div_ceil(0x200) * 0x200;
        let section_key = [0x42u8; 16];
        let mut prod = HashMap::new();
        prod.insert("header_key".into(), (0..32u8).collect());
        prod.insert("key_area_key_application_00".into(), vec![0x31u8; 16]);
        let keys = KeySet {
            prod,
            title: HashMap::new(),
        };
        let enc_key = aes_ecb_encrypt_block(
            &section_key,
            keys.prod_key("key_area_key_application_00").unwrap(),
        )?;
        let mut header = [0u8; NCA_XTS_HEADER_SIZE];
        header[0x200..0x204].copy_from_slice(b"NCA3");
        header[0x205] = 0;
        header[0x206] = 1;
        header[0x240..0x244].copy_from_slice(&((section_offset as u32) / 0x200).to_le_bytes());
        header[0x244..0x248]
            .copy_from_slice(&(((section_offset + section_size) as u32) / 0x200).to_le_bytes());
        header[0x320..0x330].copy_from_slice(&enc_key);
        header[0x402] = 1;
        header[0x403] = 2;
        header[0x404] = 3;
        header[0x440..0x448].copy_from_slice(&(pfs_offset as u64).to_le_bytes());
        header[0x448..0x450].copy_from_slice(&(pfs.len() as u64).to_le_bytes());
        header[0x540..0x548].copy_from_slice(&[0x12, 0x34, 0x56, 0x78, 0x90, 0xab, 0xcd, 0xef]);
        nca_xts_transform(&mut header, keys.prod_key("header_key").unwrap(), true)?;
        let mut section = vec![0u8; section_size];
        section[pfs_offset..pfs_offset + pfs.len()].copy_from_slice(&pfs);
        let counter = [
            0xef, 0xcd, 0xab, 0x90, 0x78, 0x56, 0x34, 0x12, 0, 0, 0, 0, 0, 0, 0, 0,
        ];
        nca_ctr_xcrypt_range(&mut section, &section_key, &counter, section_offset as u64)?;
        let mut nca = vec![0u8; section_offset];
        nca[..NCA_XTS_HEADER_SIZE].copy_from_slice(&header);
        nca.extend_from_slice(&section);
        let nca_path = temp.path().join("program.nca");
        fs::write(&nca_path, nca)?;
        let dest = temp.path().join("out");
        let result = unpack_nca(&nca_path, &dest, &keys, &AtomicBool::new(false))?;
        assert_eq!(result.pfs0_files, 1);
        assert_eq!(
            fs::read(dest.join("exefs/main.npdm"))?,
            b"native-exefs-test"
        );
        // The same encrypted NCA embedded inside another container must
        // decode with an explicit bounded base offset, without extracting it.
        let raw = fs::read(&nca_path)?;
        let mut wrapped = vec![0x89u8; 0x600];
        wrapped.extend_from_slice(&raw);
        let embedded = temp.path().join("embedded.nsp");
        fs::write(&embedded, wrapped)?;
        let region_output = temp.path().join("region_out");
        let region_stats = unpack_nca_region(
            &embedded,
            0x600,
            raw.len() as u64,
            &region_output,
            &keys,
            &AtomicBool::new(false),
        )?;
        assert_eq!(region_stats.pfs0_files, 1);
        assert_eq!(
            fs::read(region_output.join("exefs/main.npdm"))?,
            b"native-exefs-test"
        );
        assert!(
            unpack_nca_region(
                &embedded,
                0x600,
                raw.len() as u64 + 1,
                &temp.path().join("invalid_region"),
                &keys,
                &AtomicBool::new(false),
            )
            .is_err()
        );
        Ok(())
    }
}
