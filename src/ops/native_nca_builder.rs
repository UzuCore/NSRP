//! Bounded-memory Program/Control NCA rebuild with fresh RomFS and ExeFS.
//!
//! The original encrypted NCA and all input assets are read-only. Supports
//! normal AES-CTR/unencrypted sections with IVFC RomFS and SHA256 PFS0.
//! A fully extracted BKTR update RomFS can be flattened to a standard
//! AES-CTR IVFC section, including bounded multi-leaf compression indexes.
//! Sparse, deep-root compressed storage and skip-layer-hash NCAs still fail
//! closed without altering existing output. Nintendo signatures cannot be re-issued.

#[cfg(test)]
#[path = "native_nca_builder_stage62_tests.rs"]
mod stage62_tests;

use crate::{
    crypto::{nca_ctr_xcrypt_range, nca_xts_transform},
    formats::{
        bktr::{collect_relocations_from_reader, verify_patch_metadata_integrity},
        nca::{NCA_XTS_HEADER_SIZE, NcaSection, decrypt_header, derive_section_key},
        pfs0::{Pfs0Index, build_from_paths},
    },
    keys::KeySet,
    ops::{
        native_compressed::validate_compressed_bktr_layout_after_verified_patch,
        native_meta::SectionReader,
        native_repack::{IvfcLevel, ivfc_levels},
        native_romfs::{RomfsBuildStats, build_romfs},
    },
};
use anyhow::{Context, Result, ensure};
use sha2::{Digest, Sha256};
use std::{
    collections::HashSet,
    fs::{self, File, OpenOptions},
    io::{Read, Seek, SeekFrom, Write},
    path::{Path, PathBuf},
    sync::atomic::{AtomicBool, Ordering},
};

const SECTOR: u64 = 0x200;
const COPY_BUFFER: usize = 1024 * 1024;
const MAX_OUTPUT: u64 = 16 * 1024 * 1024 * 1024;

#[derive(Debug, Clone, Copy)]
pub struct NcaRebuildStats {
    pub romfs_files: usize,
    pub exefs_files: usize,
    pub bytes: u64,
}

struct RebuiltSection {
    index: usize,
    image: PathBuf,
    fs_header: Vec<u8>,
}

fn check(cancel: &AtomicBool) -> Result<()> {
    ensure!(!cancel.load(Ordering::Relaxed), "작업이 중단되었습니다");
    Ok(())
}

fn aligned(value: u64, unit: u64) -> Result<u64> {
    value
        .checked_add(unit - 1)
        .map(|n| n / unit * unit)
        .context("NCA section alignment overflow")
}

fn set64(bytes: &mut [u8], at: usize, value: u64) {
    bytes[at..at + 8].copy_from_slice(&value.to_le_bytes());
}

/// A BKTR section has two physical lookup-table regions. Converting its
/// already-extracted logical RomFS to a standalone IVFC image is safe only
/// when both descriptors are valid and all storage extensions are understood.
fn validate_bktr_header(header: &[u8], physical_size: u64) -> Result<()> {
    ensure!(
        header.len() == 0x200
            && (header[2], header[3], header[4]) == (0, 3, 4)
            && matches!(header[5], 0 | 1)
            && &header[8..12] == b"IVFC"
            && header[0x148..0x178].iter().all(|b| *b == 0)
            && (header[5] != 0 || header[0x1a0..0x1d0].iter().all(|b| *b == 0))
            && header[0x1d0..0x200].iter().all(|b| *b == 0),
        "BKTR RomFS has unsupported filesystem storage"
    );
    // Real metadata-hashed base-only updates may have no encryption tree.
    // Accept only their observed exact zero-patch geometry. Full IVFC
    // authentication is mandatory later, before parsing lookup entries.
    if header[5] == 1 && u64::from_le_bytes(header[0x100..0x108].try_into()?) == 0 {
        ensure!(
            physical_size == (3 * 0x4000 + 0x200)
                && u64::from_le_bytes(header[0x108..0x110].try_into()?) == 0x8000
                && &header[0x110..0x114] == b"BKTR"
                && u32::from_le_bytes(header[0x118..0x11c].try_into()?) == 1
                && u64::from_le_bytes(header[0x120..0x128].try_into()?) == 0x8000
                && u64::from_le_bytes(header[0x128..0x130].try_into()?) == 0
                && header[0x130..0x140].iter().all(|&byte| byte == 0)
                && u64::from_le_bytes(header[0x1a0..0x1a8].try_into()?) == 0xc000
                && u64::from_le_bytes(header[0x1a8..0x1b0].try_into()?) == 0xe8,
            "unsupported zero-physical-patch metadata-hash BKTR shape"
        );
        return Ok(());
    }
    let mut previous_end = 0u64;
    for at in [0x100, 0x120] {
        ensure!(
            &header[at + 0x10..at + 0x14] == b"BKTR",
            "BKTR lookup metadata magic mismatch"
        );
        let offset = u64::from_le_bytes(header[at..at + 8].try_into()?);
        let size = u64::from_le_bytes(header[at + 8..at + 16].try_into()?);
        ensure!(
            offset >= previous_end
                && offset >= SECTOR
                && size >= SECTOR
                && offset
                    .checked_add(size)
                    .is_some_and(|end| end <= physical_size),
            "BKTR lookup metadata is outside the physical section"
        );
        previous_end = offset + size;
    }
    Ok(())
}

/// CompressionInfo describes a BucketTree layered over the *decrypted*
/// IVFC RomFS data level. It is not a physical patch section offset.
/// Once a complete RomFS directory has been extracted (and decompressed),
/// the new standalone IVFC image must not inherit this compression mapping.
///
/// Only accept compression metadata supported by the actual native extractor.
/// Header geometry is shared so the builder cannot silently accept a layout
/// the reader would reject. The full encrypted index and every data block
/// are checked by the extraction stage before calling this builder.
fn validate_bktr_compression(header: &[u8], virtual_size: u64) -> Result<bool> {
    ensure!(header.len() == 0x200, "BKTR filesystem header truncated");
    let compression = &header[0x178..0x1a0];
    if compression.iter().all(|byte| *byte == 0) {
        return Ok(false);
    }
    // The only production caller has already authenticated the patch's
    // metadata SHA and the complete lookup IVFC tree before this rebuild.
    let _ = validate_compressed_bktr_layout_after_verified_patch(header, virtual_size)?;
    let levels = ivfc_levels(header, virtual_size)?;
    ensure!(!levels.is_empty(), "compressed BKTR IVFC level missing");
    Ok(true)
}

fn flattened_bktr_header(header: &[u8]) -> Vec<u8> {
    let mut result = header.to_vec();
    // The original patch uses AES-CTR-EX (4) with indirect/encryption trees.
    // The newly materialized full section instead uses ordinary AES-CTR (3).
    // Keep the original CTR nonce and IVFC geometry, but remove both trees
    // and the obsolete compression mapping over the IVFC data level.
    result[4] = 3;
    result[5] = 0;
    result[0x100..0x140].fill(0);
    result[0x178..0x1a0].fill(0);
    result[0x1a0..0x1d0].fill(0);
    result
}

fn stream_copy<R: Read, W: Write>(
    reader: &mut R,
    writer: &mut W,
    mut size: u64,
    cancel: &AtomicBool,
) -> Result<()> {
    let mut buffer = vec![0u8; COPY_BUFFER];
    while size > 0 {
        check(cancel)?;
        let n = usize::try_from(size.min(buffer.len() as u64))?;
        reader.read_exact(&mut buffer[..n])?;
        writer.write_all(&buffer[..n])?;
        size -= n as u64;
    }
    Ok(())
}

fn write_ivfc_hashes(
    output: &mut File,
    header: &mut [u8],
    levels: &[IvfcLevel],
    cancel: &AtomicBool,
) -> Result<()> {
    for child_index in (1..levels.len()).rev() {
        let (child_start, child_size, log) = levels[child_index];
        let (parent_start, parent_size, _) = levels[child_index - 1];
        let block = 1u64 << log;
        let count = child_size.div_ceil(block);
        ensure!(
            count.checked_mul(32).is_some_and(|v| v <= parent_size),
            "IVFC hash overflow"
        );
        let mut buffer = vec![0u8; block as usize];
        for index in 0..count {
            check(cancel)?;
            buffer.fill(0);
            let read_size = usize::try_from(block.min(child_size - index * block))?;
            output.seek(SeekFrom::Start(child_start + index * block))?;
            output.read_exact(&mut buffer[..read_size])?;
            let hash = Sha256::digest(&buffer);
            output.seek(SeekFrom::Start(parent_start + index * 32))?;
            output.write_all(&hash)?;
        }
    }
    let (start, length, _) = levels[0];
    let mut digest = Sha256::new();
    let mut remaining = length;
    let mut buffer = vec![0u8; COPY_BUFFER];
    output.seek(SeekFrom::Start(start))?;
    while remaining > 0 {
        let take = usize::try_from(remaining.min(buffer.len() as u64))?;
        output.read_exact(&mut buffer[..take])?;
        digest.update(&buffer[..take]);
        remaining -= take as u64;
    }
    header[0xc8..0xe8].copy_from_slice(&digest.finalize());
    Ok(())
}

fn rebuild_romfs_section(
    original: &[u8],
    original_size: u64,
    image: &Path,
    destination: &Path,
    cancel: &AtomicBool,
) -> Result<Vec<u8>> {
    ensure!(
        (original[2], original[3]) == (0, 3) && &original[8..12] == b"IVFC",
        "NCA RomFS is not IVFC"
    );
    let old = ivfc_levels(original, original_size)?;
    ensure!(old.len() >= 2, "NCA IVFC hierarchy too shallow");
    let mut levels = old.clone();
    levels.last_mut().context("missing IVFC data level")?.1 = fs::metadata(image)?.len();
    // Allocate every hash layer from the actual bottom-up hash requirements,
    // rather than assuming that old NCA hash-tree storage can be reused.
    for index in (1..levels.len()).rev() {
        let bytes = levels[index]
            .1
            .div_ceil(1u64 << levels[index].2)
            .checked_mul(32)
            .context("IVFC hierarchy length overflow")?;
        // Switch IVFC hashes each complete, zero-padded block. Allocating
        // only the used 32-byte hashes changes the master-hash semantics
        // expected by hactool/LibHac, even if our own file parser works.
        levels[index - 1].1 = aligned(bytes, 1u64 << levels[index - 1].2)?;
    }
    let mut position = 0u64;
    for level in &mut levels {
        position = aligned(position, 1u64 << level.2)?;
        level.0 = position;
        position = position
            .checked_add(level.1)
            .context("IVFC level offset overflow")?;
    }
    let total = aligned(position, SECTOR)?;
    ensure!(total <= MAX_OUTPUT, "NCA IVFC section exceeds safety limit");
    let mut section = OpenOptions::new()
        .read(true)
        .write(true)
        .create_new(true)
        .open(destination)?;
    section.set_len(total)?;
    let last = *levels.last().context("missing RomFS image level")?;
    section.seek(SeekFrom::Start(last.0))?;
    let mut src = File::open(image)?;
    stream_copy(&mut src, &mut section, last.1, cancel)?;
    let mut header = original.to_vec();
    for (index, (off, len, _)) in levels.iter().enumerate() {
        let at = 0x18 + index * 0x18;
        set64(&mut header, at, *off);
        set64(&mut header, at + 8, *len);
    }
    write_ivfc_hashes(&mut section, &mut header, &levels, cancel)?;
    section.flush()?;
    Ok(header)
}

fn rebuild_exefs_section(
    original: &[u8],
    image: &Path,
    destination: &Path,
    cancel: &AtomicBool,
) -> Result<Vec<u8>> {
    ensure!(
        (original[2], original[3]) == (1, 2),
        "NCA ExeFS is not SHA256 PFS0"
    );
    let block = u32::from_le_bytes(original[0x28..0x2c].try_into()?);
    ensure!(
        block.is_power_of_two() && (0x200..=0x100000).contains(&block),
        "unsupported ExeFS hash block"
    );
    let mut header = original.to_vec();
    let length = fs::metadata(image)?.len();
    let hash_length = length
        .div_ceil(u64::from(block))
        .checked_mul(32)
        .context("ExeFS hash table overflow")?;
    let pfs_start = aligned(hash_length, SECTOR)?;
    let total = aligned(
        pfs_start
            .checked_add(length)
            .context("ExeFS section overflow")?,
        SECTOR,
    )?;
    ensure!(total <= MAX_OUTPUT, "ExeFS section exceeds safety limit");
    let mut output = OpenOptions::new()
        .read(true)
        .write(true)
        .create_new(true)
        .open(destination)?;
    output.set_len(total)?;
    output.seek(SeekFrom::Start(pfs_start))?;
    stream_copy(&mut File::open(image)?, &mut output, length, cancel)?;
    let mut buffer = vec![0u8; block as usize];
    for index in 0..length.div_ceil(u64::from(block)) {
        check(cancel)?;
        let take = usize::try_from((length - index * u64::from(block)).min(u64::from(block)))?;
        buffer.fill(0);
        output.seek(SeekFrom::Start(pfs_start + index * u64::from(block)))?;
        output.read_exact(&mut buffer[..take])?;
        // Unlike IVFC, SHA-256 PFS0 hashes only the remaining bytes in the
        // final block (NCA hierarchical SHA256 has full_block=false).
        let hash = Sha256::digest(&buffer[..take]);
        output.seek(SeekFrom::Start(index * 32))?;
        output.write_all(&hash)?;
    }
    let mut hash_table = Sha256::new();
    let mut remaining = hash_length;
    output.seek(SeekFrom::Start(0))?;
    while remaining > 0 {
        let take = usize::try_from(remaining.min(buffer.len() as u64))?;
        output.read_exact(&mut buffer[..take])?;
        hash_table.update(&buffer[..take]);
        remaining -= take as u64;
    }
    header[0x08..0x28].copy_from_slice(&hash_table.finalize());
    set64(&mut header, 0x30, 0);
    set64(&mut header, 0x38, hash_length);
    set64(&mut header, 0x40, pfs_start);
    set64(&mut header, 0x48, length);
    output.flush()?;
    Ok(header)
}

fn build_exefs_input(dir: &Path, out: &Path) -> Result<usize> {
    let mut paths = Vec::new();
    let mut seen = HashSet::new();
    for entry in fs::read_dir(dir)? {
        let entry = entry?;
        let meta = fs::symlink_metadata(entry.path())?;
        ensure!(!meta.file_type().is_symlink(), "ExeFS symlinks unsupported");
        #[cfg(windows)]
        {
            use std::os::windows::fs::MetadataExt;
            ensure!(
                meta.file_attributes() & 0x400 == 0,
                "ExeFS reparse points unsupported"
            );
        }
        ensure!(
            meta.is_file(),
            "ExeFS directories and special files unsupported"
        );
        let name = entry
            .file_name()
            .into_string()
            .map_err(|_| anyhow::anyhow!("non-UTF8 ExeFS file"))?;
        ensure!(seen.insert(name.to_lowercase()), "duplicate ExeFS name");
        paths.push((name, entry.path()));
    }
    ensure!(!paths.is_empty(), "ExeFS directory is empty");
    paths.sort_by(|a, b| a.0.cmp(&b.0));
    build_from_paths(&paths, out)?;
    Ok(paths.len())
}

fn original_is_exefs(
    source: &mut File,
    section: &NcaSection,
    fs_header: &[u8],
    key: Option<[u8; 16]>,
) -> Result<bool> {
    let at = u64::from_le_bytes(fs_header[0x40..0x48].try_into()?);
    let size = u64::from_le_bytes(fs_header[0x48..0x50].try_into()?);
    ensure!(
        at.checked_add(size).is_some_and(|end| end <= section.size),
        "PFS0 section outside NCA"
    );
    let mut reader = SectionReader::new(source, 0, section, key);
    let index = Pfs0Index::parse_reader(&mut reader, at, size)?;
    Ok(index
        .entries
        .iter()
        .any(|e| matches!(e.name.as_str(), "main" | "main.npdm" | "rtld")))
}

fn copy_nca_section(
    original: &mut File,
    output: &mut File,
    section: &NcaSection,
    new_offset: u64,
    key: Option<&[u8; 16]>,
    cancel: &AtomicBool,
) -> Result<()> {
    original.seek(SeekFrom::Start(section.offset))?;
    let mut buffer = vec![0u8; COPY_BUFFER];
    let mut written = 0u64;
    while written < section.size {
        check(cancel)?;
        let take = usize::try_from((section.size - written).min(buffer.len() as u64))?;
        original.read_exact(&mut buffer[..take])?;
        if new_offset != section.offset
            && let Some(key) = key
        {
            nca_ctr_xcrypt_range(
                &mut buffer[..take],
                key,
                &section.counter,
                section.offset + written,
            )?;
            nca_ctr_xcrypt_range(
                &mut buffer[..take],
                key,
                &section.counter,
                new_offset + written,
            )?;
        }
        output.write_all(&buffer[..take])?;
        written += take as u64;
    }
    Ok(())
}

/// Full rebuild of standard Program or Control sections, including a fully
/// materialized BKTR update RomFS. Unrecognized storage is rejected before
/// any result becomes externally visible.
pub fn repack_nca(
    source: &Path,
    modified_romfs: Option<&Path>,
    modified_exefs: Option<&Path>,
    output: &Path,
    keys: &KeySet,
    cancel: &AtomicBool,
) -> Result<NcaRebuildStats> {
    ensure!(
        modified_romfs.is_some() || modified_exefs.is_some(),
        "No filesystem input provided"
    );
    ensure!(
        !output.exists(),
        "Native NCA builder refuses to overwrite output"
    );
    let parent = output.parent().context("NCA output has no parent")?;
    fs::create_dir_all(parent)?;
    ensure!(source != output, "NCA source equals output");
    let mut input = File::open(source)?;
    let nca_size = input.metadata()?.len();
    ensure!(
        (NCA_XTS_HEADER_SIZE as u64..=MAX_OUTPUT).contains(&nca_size),
        "NCA source exceeds safety limit"
    );
    let mut encrypted_header = [0u8; NCA_XTS_HEADER_SIZE];
    input.read_exact(&mut encrypted_header)?;
    let info = decrypt_header(&encrypted_header, keys)?;
    ensure!(
        matches!(info.content_type, 0 | 2),
        "Native builder supports only Program/Control NCAs"
    );
    ensure!(!info.sections.is_empty(), "NCA has no sections");
    let mut sections = info.sections.clone();
    sections.sort_by_key(|s| s.offset);
    let mut prior_end = NCA_XTS_HEADER_SIZE as u64;
    let mut bktr_logical_sizes = [None::<u64>; 4];
    for section in &sections {
        ensure!(
            section.offset >= prior_end
                && section.offset.is_multiple_of(SECTOR)
                && section.size.is_multiple_of(SECTOR)
                && section
                    .offset
                    .checked_add(section.size)
                    .is_some_and(|end| end <= nca_size),
            "NCA section boundaries invalid"
        );
        prior_end = section.offset + section.size;
        let off = 0x400 + section.index * 0x200;
        let fs = &info.decrypted_header[off..off + 0x200];
        let normal = matches!(section.encryption_type, 1 | 3)
            && matches!((fs[2], fs[3]), (0, 3) | (1, 2))
            && fs[0x100..0x140].iter().all(|value| *value == 0)
            && fs[0x148..0x1d0].iter().all(|value| *value == 0);
        let flatten_bktr = section.encryption_type == 4
            && info.content_type == 0
            && modified_romfs.is_some()
            && (fs[2], fs[3]) == (0, 3);
        // Metadata hash type 1 is supported *only* on a BKTR section whose
        // complete authenticated lookup IVFC is subsequently verified.
        // Normal ExeFS/RomFS sections still require type 0.
        let metadata_type_supported = if flatten_bktr {
            matches!(fs[5], 0 | 1)
        } else {
            fs[5] == 0
        };
        ensure!(
            (normal || flatten_bktr) && section.encryption_type == fs[4] && metadata_type_supported,
            "NCA contains compressed, sparse or unsupported filesystem storage"
        );
        if flatten_bktr {
            validate_bktr_header(fs, section.size)?;
        }
        let at = 0x280 + section.index * 0x20;
        let expected: [u8; 32] = Sha256::digest(fs).into();
        ensure!(
            info.decrypted_header[at..at + 32] == expected,
            "NCA filesystem header hash mismatch"
        );
    }
    ensure!(
        prior_end == nca_size,
        "NCA contains unknown trailing storage"
    );
    let section_key = if sections.iter().any(|s| matches!(s.encryption_type, 3 | 4)) {
        Some(derive_section_key(&info, keys)?)
    } else {
        None
    };

    // BKTR IVFC descriptors describe *virtual* storage much larger than the
    // physical patch section. Validate its relocation tree and logical end
    // before using those descriptors to allocate the new standalone image.
    for section in &sections {
        if section.encryption_type != 4 {
            continue;
        }
        let at = 0x400 + section.index * 0x200;
        let fs_header = &info.decrypted_header[at..at + 0x200];
        // The newer patch metadata hash extension must authenticate both
        // physical lookup trees before flattening them to plain AES-CTR.
        verify_patch_metadata_integrity(
            &mut input,
            0,
            nca_size,
            section.offset,
            section.size,
            fs_header,
            &section_key.context("BKTR section key unavailable")?,
        )?;
        let relocations = collect_relocations_from_reader(
            &mut input,
            0,
            nca_size,
            section.offset,
            section.size,
            fs_header,
            &section_key.context("BKTR section key unavailable")?,
        )?;
        ensure!(
            !relocations.entries.is_empty() && relocations.virtual_size <= MAX_OUTPUT,
            "BKTR has an invalid logical image size"
        );
        ivfc_levels(fs_header, relocations.virtual_size)?;
        validate_bktr_compression(fs_header, relocations.virtual_size)?;
        bktr_logical_sizes[section.index] = Some(relocations.virtual_size);
    }

    let scratch = tempfile::Builder::new()
        .prefix("nsrp_native_build_")
        .tempdir_in(parent)?;
    let mut images = Vec::new();
    let mut romfs_stats = None::<RomfsBuildStats>;
    let mut exefs_files = 0;
    let mut used_romfs = false;
    let mut used_exefs = false;
    for section in &sections {
        check(cancel)?;
        let off = 0x400 + section.index * 0x200;
        let fs_header = &info.decrypted_header[off..off + 0x200];
        let key = if section.encryption_type == 3 {
            Some(section_key.context("NCA crypto key missing")?)
        } else {
            None
        };
        let is_exefs = fs_header[2] == 1 && original_is_exefs(&mut input, section, fs_header, key)?;
        if let Some(romfs_dir) = modified_romfs.filter(|_| fs_header[2] == 0) {
            ensure!(!used_romfs, "NCA has multiple RomFS sections");
            used_romfs = true;
            let image = scratch.path().join("romfs.img");
            romfs_stats = Some(build_romfs(romfs_dir, &image, cancel)?);
            let dest = scratch
                .path()
                .join(format!("section_{}.bin", section.index));
            let normalized = if section.encryption_type == 4 {
                flattened_bktr_header(fs_header)
            } else {
                fs_header.to_vec()
            };
            let logical_size = bktr_logical_sizes[section.index].unwrap_or(section.size);
            let header = rebuild_romfs_section(&normalized, logical_size, &image, &dest, cancel)?;
            images.push(RebuiltSection {
                index: section.index,
                image: dest,
                fs_header: header,
            });
        } else if let Some(exefs_dir) = modified_exefs.filter(|_| is_exefs) {
            ensure!(!used_exefs, "NCA has multiple ExeFS sections");
            used_exefs = true;
            let image = scratch.path().join("exefs.img");
            exefs_files = build_exefs_input(exefs_dir, &image)?;
            let dest = scratch
                .path()
                .join(format!("section_{}.bin", section.index));
            let header = rebuild_exefs_section(fs_header, &image, &dest, cancel)?;
            images.push(RebuiltSection {
                index: section.index,
                image: dest,
                fs_header: header,
            });
        }
    }
    ensure!(
        modified_romfs.is_none() || used_romfs,
        "NCA has no supported RomFS section"
    );
    ensure!(
        modified_exefs.is_none() || used_exefs,
        "NCA has no supported ExeFS section"
    );
    let mut new_header = info.decrypted_header.clone();
    let mut staged = tempfile::NamedTempFile::new_in(parent)?;
    let out = staged.as_file_mut();
    let first_start = sections[0].offset;
    input.seek(SeekFrom::Start(0))?;
    stream_copy(&mut input, out, first_start, cancel)?;
    let mut next = first_start;
    for section in &sections {
        check(cancel)?;
        let start = aligned(next, SECTOR)?;
        ensure!(start <= MAX_OUTPUT, "NCA rebuild exceeds safety limit");
        out.set_len(start)?;
        out.seek(SeekFrom::Start(start))?;
        let changed = images.iter().find(|entry| entry.index == section.index);
        let size = if let Some(rebuilt) = changed {
            let size = fs::metadata(&rebuilt.image)?.len();
            let mut image = File::open(&rebuilt.image)?;
            let mut buffer = vec![0u8; COPY_BUFFER];
            let mut copied = 0u64;
            while copied < size {
                check(cancel)?;
                let take = usize::try_from((size - copied).min(buffer.len() as u64))?;
                image.read_exact(&mut buffer[..take])?;
                if matches!(section.encryption_type, 3 | 4) {
                    nca_ctr_xcrypt_range(
                        &mut buffer[..take],
                        &section_key.context("NCA crypto key missing")?,
                        &section.counter,
                        start + copied,
                    )?;
                }
                out.write_all(&buffer[..take])?;
                copied += take as u64;
            }
            let fs_start = 0x400 + section.index * 0x200;
            new_header[fs_start..fs_start + 0x200].copy_from_slice(&rebuilt.fs_header);
            let hash_at = 0x280 + section.index * 0x20;
            new_header[hash_at..hash_at + 32].copy_from_slice(&Sha256::digest(&rebuilt.fs_header));
            size
        } else {
            ensure!(
                section.encryption_type != 4,
                "BKTR sections cannot be copied into a standalone NCA"
            );
            let unchanged_key = if section.encryption_type == 3 {
                Some(section_key.as_ref().context("NCA crypto key missing")?)
            } else {
                None
            };
            copy_nca_section(&mut input, out, section, start, unchanged_key, cancel)?;
            section.size
        };
        next = start
            .checked_add(size)
            .context("NCA section end overflow")?;
        ensure!(next <= MAX_OUTPUT, "NCA rebuilt image exceeds safety limit");
        let entry = 0x240 + section.index * 0x10;
        new_header[entry..entry + 4].copy_from_slice(&u32::try_from(start / SECTOR)?.to_le_bytes());
        new_header[entry + 4..entry + 8]
            .copy_from_slice(&u32::try_from(next / SECTOR)?.to_le_bytes());
    }
    set64(&mut new_header, 0x208, next);
    // The retail RSA signatures cover the original NCA header and cannot be
    // regenerated without Nintendo's signing keys. A rebuilt unsigned NCA
    // must not retain the original, now misleading signature bytes.
    new_header[..0x200].fill(0);
    nca_xts_transform(
        &mut new_header,
        keys.prod_key("header_key").context("header_key missing")?,
        true,
    )?;
    out.seek(SeekFrom::Start(0))?;
    out.write_all(&new_header)?;
    out.flush()?;
    ensure!(
        out.metadata()?.len() == next,
        "NCA rebuilt size does not match header"
    );
    staged.persist_noclobber(output)?;
    Ok(NcaRebuildStats {
        romfs_files: romfs_stats.map_or(0, |v| v.files),
        exefs_files,
        bytes: next,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn example_bktr_header() -> Vec<u8> {
        let mut fs = vec![0u8; 0x200];
        fs[2..6].copy_from_slice(&[0, 3, 4, 0]);
        fs[8..12].copy_from_slice(b"IVFC");
        fs[0x140..0x148].copy_from_slice(&[1, 2, 3, 4, 5, 6, 7, 8]);
        for (at, offset) in [(0x100, 0x23000u64), (0x120, 0x2b000u64)] {
            set64(&mut fs, at, offset);
            set64(&mut fs, at + 8, 0x8000);
            fs[at + 0x10..at + 0x14].copy_from_slice(b"BKTR");
        }
        fs
    }

    #[test]
    fn bktr_header_converts_to_independent_standard_ctr_romfs() -> Result<()> {
        let original = example_bktr_header();
        validate_bktr_header(&original, 0x33000)?;
        let flattened = flattened_bktr_header(&original);
        assert_eq!(&flattened[2..6], &[0, 3, 3, 0]);
        assert!(flattened[0x100..0x140].iter().all(|b| *b == 0));
        assert_eq!(&flattened[0x140..0x148], &[1, 2, 3, 4, 5, 6, 7, 8]);
        assert_eq!(&flattened[8..12], b"IVFC");
        assert_eq!(&original[4..5], &[4]);
        Ok(())
    }

    #[test]
    fn metadata_hashed_bktr_header_is_fully_stripped_during_flatten() -> Result<()> {
        let mut header = example_bktr_header();
        header[5] = 1;
        header[0x1a0..0x1a8].copy_from_slice(&0x33000u64.to_le_bytes());
        header[0x1a8..0x1b0].copy_from_slice(&0xe8u64.to_le_bytes());
        header[0x1b0..0x1d0].fill(0xa5);
        validate_bktr_header(&header, 0x33000)?;
        let flattened = flattened_bktr_header(&header);
        assert_eq!(&flattened[2..6], &[0, 3, 3, 0]);
        assert!(flattened[0x100..0x140].iter().all(|&b| b == 0));
        assert!(flattened[0x1a0..0x1d0].iter().all(|&b| b == 0));
        let mut unsupported = header;
        unsupported[0x1d0] = 1;
        assert!(validate_bktr_header(&unsupported, 0x33000).is_err());
        Ok(())
    }

    #[test]
    fn metadata_hash_empty_patch_requires_exact_authenticated_geometry() -> Result<()> {
        let mut fs = example_bktr_header();
        fs[5] = 1;
        set64(&mut fs, 0x100, 0);
        set64(&mut fs, 0x108, 0x8000);
        fs[0x118..0x11c].copy_from_slice(&1u32.to_le_bytes());
        set64(&mut fs, 0x120, 0x8000);
        set64(&mut fs, 0x128, 0);
        fs[0x130..0x140].fill(0);
        set64(&mut fs, 0x1a0, 0xc000);
        set64(&mut fs, 0x1a8, 0xe8);
        validate_bktr_header(&fs, 0xc200)?;
        let flattened = flattened_bktr_header(&fs);
        assert_eq!(&flattened[2..6], &[0, 3, 3, 0]);
        assert!(flattened[0x100..0x140].iter().all(|&v| v == 0));
        assert!(flattened[0x1a0..0x1d0].iter().all(|&v| v == 0));
        let mut wrong = fs.clone();
        set64(&mut wrong, 0x128, 0x8000);
        assert!(validate_bktr_header(&wrong, 0xc200).is_err());
        wrong = fs.clone();
        wrong[0x118..0x11c].copy_from_slice(&2u32.to_le_bytes());
        assert!(validate_bktr_header(&wrong, 0xc200).is_err());
        wrong = fs;
        set64(&mut wrong, 0x1a0, 0xb000);
        assert!(validate_bktr_header(&wrong, 0xc200).is_err());
        Ok(())
    }

    #[test]
    fn bktr_header_rejects_bad_layouts_and_storage_extensions() {
        let original = example_bktr_header();
        assert!(validate_bktr_header(&original, 0x32fff).is_err());
        let mut corrupt = original.clone();
        corrupt[0x130..0x134].copy_from_slice(b"FAIL");
        assert!(validate_bktr_header(&corrupt, 0x33000).is_err());
        let mut sparse = original.clone();
        sparse[0x150] = 1;
        assert!(validate_bktr_header(&sparse, 0x33000).is_err());
        let mut overlapping = original;
        set64(&mut overlapping, 0x120, 0x23000);
        assert!(validate_bktr_header(&overlapping, 0x33000).is_err());
    }

    fn compressed_example_header() -> Vec<u8> {
        let mut header = example_bktr_header();
        header[0x14..0x18].copy_from_slice(&3u32.to_le_bytes());
        set64(&mut header, 0x18, 0);
        set64(&mut header, 0x20, 0x4000);
        header[0x28..0x2c].copy_from_slice(&14u32.to_le_bytes());
        set64(&mut header, 0x30, 0x4000);
        set64(&mut header, 0x38, 0x21000);
        header[0x40..0x44].copy_from_slice(&14u32.to_le_bytes());
        set64(&mut header, 0x178, 0x19000);
        set64(&mut header, 0x180, 0x8000);
        header[0x188..0x18c].copy_from_slice(b"BKTR");
        header[0x18c..0x190].copy_from_slice(&1u32.to_le_bytes());
        header[0x190..0x194].copy_from_slice(&2u32.to_le_bytes());
        header
    }

    #[test]
    fn compressed_bktr_single_bucket_flatten_clears_both_storage_layers() -> Result<()> {
        let header = compressed_example_header();
        validate_bktr_header(&header, 0x33000)?;
        assert!(validate_bktr_compression(&header, 0x25000)?);
        let normal = flattened_bktr_header(&header);
        assert_eq!(normal[4], 3);
        assert!(normal[0x100..0x140].iter().all(|byte| *byte == 0));
        assert!(normal[0x178..0x1a0].iter().all(|byte| *byte == 0));
        assert_eq!(&normal[0x140..0x148], &header[0x140..0x148]);
        Ok(())
    }

    #[test]
    fn stage24_compressed_bktr_multiple_leaves_flatten_with_shared_bounds() -> Result<()> {
        // Real Double Dragon Gaiden uses 26,164 records in 39 leaves,
        // plus one index root = 0xa0000 bytes.
        let mut header = compressed_example_header();
        let table_size = 0xa0000u64;
        let virtual_size = 0x4000 + 0x19000 + table_size;
        set64(&mut header, 0x180, table_size);
        set64(&mut header, 0x38, 0x19000 + table_size);
        header[0x190..0x194].copy_from_slice(&26_164u32.to_le_bytes());
        validate_bktr_header(&header, 0x33000)?;
        assert!(validate_bktr_compression(&header, virtual_size)?);
        let flattened = flattened_bktr_header(&header);
        assert_eq!(flattened[4], 3);
        assert!(flattened[0x100..0x140].iter().all(|&b| b == 0));
        assert!(flattened[0x178..0x1a0].iter().all(|&b| b == 0));
        assert_eq!(&flattened[0x140..0x148], &header[0x140..0x148]);

        let mut corrupted = header.clone();
        set64(&mut corrupted, 0x180, table_size - 0x4000);
        assert!(
            validate_bktr_compression(&corrupted, virtual_size).is_err(),
            "multi-leaf table length must match its exact geometry"
        );
        let mut misaligned = header.clone();
        set64(&mut misaligned, 0x178, 0x19001);
        assert!(
            validate_bktr_compression(&misaligned, virtual_size).is_err(),
            "a modified index offset must still end at the declared data boundary"
        );
        let mut unsupported = header.clone();
        unsupported[0x150] = 1;
        assert!(
            validate_bktr_compression(&unsupported, virtual_size).is_err(),
            "sparse and skip-layer storage must retain the safe fallback"
        );
        let mut too_many = header;
        too_many[0x190..0x194].copy_from_slice(&1_000_001u32.to_le_bytes());
        assert!(
            validate_bktr_compression(&too_many, virtual_size).is_err(),
            "untrusted entry count must be capped before allocations"
        );
        Ok(())
    }

    #[test]
    fn compressed_bktr_rejects_invalid_magic_count_and_boundary() -> Result<()> {
        let header = compressed_example_header();
        assert!(validate_bktr_compression(&header, 0x24000).is_err());
        let mut bad = header.clone();
        bad[0x188..0x18c].copy_from_slice(b"FAIL");
        assert!(validate_bktr_compression(&bad, 0x25000).is_err());
        let mut bad = header.clone();
        bad[0x190..0x194].copy_from_slice(&u32::MAX.to_le_bytes());
        assert!(validate_bktr_compression(&bad, 0x25000).is_err());
        let mut bad = header.clone();
        bad[0x198] = 1;
        assert!(validate_bktr_compression(&bad, 0x25000).is_err());
        let mut bad = header;
        set64(&mut bad, 0x178, 0x18000);
        assert!(validate_bktr_compression(&bad, 0x25000).is_err());
        Ok(())
    }
}
