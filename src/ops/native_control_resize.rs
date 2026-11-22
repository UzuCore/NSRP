//! Rust-native Control NCA repack when *existing* RomFS file sizes change.
//!
//! Retains the original RomFS directory/file/hash tables and file names,
//! relocates the file data, and rebuilds the NCA IVFC hash hierarchy.
//! This avoids copying third-party NCA builders, but intentionally delegates
//! new/deleted files, structural changes and oversized hash trees to the
//! independent Rust full NCA builder.

use crate::{
    crypto::{nca_ctr_xcrypt_range, nca_xts_transform},
    formats::nca::{NCA_XTS_HEADER_SIZE, decrypt_header, derive_section_key},
    keys::KeySet,
    ops::{
        native_fs::romfs_file_index,
        native_repack::{MAX_CONTROL_NCA, ivfc_levels, rebuild_ivfc, verify_ivfc},
    },
};
use anyhow::{Context, Result, ensure};
use sha2::{Digest, Sha256};
use std::{
    collections::HashSet,
    fs,
    io::Write,
    path::Path,
    sync::atomic::{AtomicBool, Ordering},
};

const FILE_ALIGNMENT: usize = 16;
const SECTOR_SIZE: u64 = 0x200;

/// A fixed-name Control RomFS can grow/shrink without an external packer.
/// The source is read-only; output is atomically created and never overwritten.
/// Returns the count of changed files; unchanged inputs are rejected to avoid
/// needlessly changing their byte layout.
pub fn repack_control_resized(
    source: &Path,
    modified_romfs: &Path,
    output: &Path,
    keys: &KeySet,
    cancel: &AtomicBool,
) -> Result<usize> {
    let source_size = fs::metadata(source)?.len();
    ensure!(
        (NCA_XTS_HEADER_SIZE as u64..=MAX_CONTROL_NCA).contains(&source_size),
        "Control NCA exceeds native rebuild size limit"
    );
    ensure!(
        !output.exists(),
        "Control rebuild refuses to overwrite existing NCA"
    );

    let mut contents = fs::read(source)?;
    let info = decrypt_header(&contents[..NCA_XTS_HEADER_SIZE], keys)?;
    ensure!(info.content_type == 2, "Not a Control NCA");
    ensure!(
        info.sections.len() == 1,
        "Only one-section Control NCAs supported"
    );
    let section = &info.sections[0];
    ensure!(
        section.encryption_type == 3,
        "Unsupported Control encryption"
    );
    let sec_start = usize::try_from(section.offset)?;
    let sec_end = usize::try_from(
        section
            .offset
            .checked_add(section.size)
            .context("NCA section length overflow")?,
    )?;
    ensure!(
        sec_end == contents.len(),
        "Control has unexpected trailing storage"
    );
    ensure!(
        section.offset.is_multiple_of(SECTOR_SIZE),
        "Unaligned Control section"
    );

    let mut header = info.decrypted_header.clone();
    let fs_start = 0x400 + section.index * 0x200;
    let mut fs_header = header[fs_start..fs_start + 0x200].to_vec();
    ensure!(
        (fs_header[2], fs_header[3], fs_header[4]) == (0, 3, 3) && &fs_header[8..12] == b"IVFC",
        "Unsupported Control IVFC layout"
    );
    let fs_hash_at = 0x280 + section.index * 0x20;
    let fs_hash: [u8; 32] = Sha256::digest(&fs_header).into();
    ensure!(
        header[fs_hash_at..fs_hash_at + 32] == fs_hash,
        "Original Control filesystem SHA-256 mismatch"
    );
    let key = derive_section_key(&info, keys)?;
    let mut plain = contents[sec_start..sec_end].to_vec();
    nca_ctr_xcrypt_range(&mut plain, &key, &section.counter, section.offset)?;
    let mut levels = ivfc_levels(&fs_header, section.size)?;
    ensure!(
        verify_ivfc(&plain, &fs_header, &levels)?,
        "Control IVFC original hashes failed verification"
    );
    let bottom = *levels.last().context("Missing Control RomFS level")?;
    ensure!(bottom.1 >= 0x50, "Control RomFS header is truncated");
    let romfs_start = usize::try_from(bottom.0)?;
    let romfs_end = usize::try_from(bottom.0 + bottom.1)?;
    ensure!(romfs_end <= plain.len(), "Control RomFS is truncated");
    let data_offset = usize::try_from(u64::from_le_bytes(
        plain[romfs_start + 0x48..romfs_start + 0x50].try_into()?,
    ))?;
    ensure!(
        (0x50..=usize::try_from(bottom.1)?).contains(&data_offset),
        "Control RomFS data offset invalid"
    );
    let files = romfs_file_index(&plain, bottom.0, bottom.1)?;
    ensure!(!files.is_empty(), "Control RomFS has no files");

    // RomFS commonly keeps *file data before the metadata tables*.
    // Preserve the metadata bytes and relative tree links, but move the
    // complete hash + directory + file tables after the resized data.
    // The four table offsets are absolute within RomFS; each file's
    // data offset is relative to the value at header+0x48.
    let old_image = &plain[romfs_start..romfs_end];
    let mut tables = Vec::new();
    for field in [0x08usize, 0x18, 0x28, 0x38] {
        let old_offset =
            usize::try_from(u64::from_le_bytes(old_image[field..field + 8].try_into()?))?;
        let old_size = usize::try_from(u64::from_le_bytes(
            old_image[field + 8..field + 16].try_into()?,
        ))?;
        ensure!(
            old_offset
                .checked_add(old_size)
                .is_some_and(|end| end <= old_image.len()),
            "Original Control metadata table is outside RomFS"
        );
        tables.push((field, old_image[old_offset..old_offset + old_size].to_vec()));
    }
    let old_file_table = usize::try_from(u64::from_le_bytes(old_image[0x38..0x40].try_into()?))?;
    let mut image = plain[romfs_start..romfs_start + data_offset].to_vec();
    let mut seen = HashSet::new();
    let mut changed_count = 0usize;
    let mut resized_count = 0usize;
    for (relative, original_offset, original_size, record) in &files {
        ensure!(!cancel.load(Ordering::Relaxed), "작업이 중단되었습니다");
        let key_path = relative.to_string_lossy().replace('\\', "/").to_lowercase();
        ensure!(seen.insert(key_path), "Duplicate Control RomFS path");
        let updated = fs::read(modified_romfs.join(relative))
            .with_context(|| format!("Control input missing: {}", relative.display()))?;
        if updated.len() as u64 != *original_size {
            resized_count += 1;
        }
        let old_start = usize::try_from(*original_offset)?;
        let old_end = old_start
            .checked_add(usize::try_from(*original_size)?)
            .context("Control old file range overflow")?;
        ensure!(
            old_end <= plain.len(),
            "Control original file outside RomFS"
        );
        if plain[old_start..old_end] != updated {
            changed_count += 1;
        }
        image.resize(image.len().next_multiple_of(FILE_ALIGNMENT), 0);
        let relative_offset = image
            .len()
            .checked_sub(data_offset)
            .context("RomFS data offset underflow")?;
        let record_relative = usize::try_from(
            record
                .checked_sub(bottom.0)
                .context("RomFS record before image")?,
        )?
        .checked_sub(old_file_table)
        .context("RomFS record is before file metadata table")?;
        ensure!(
            record_relative
                .checked_add(0x20)
                .is_some_and(|v| v <= tables[3].1.len()),
            "Control file entry is outside metadata tables"
        );
        tables[3].1[record_relative + 8..record_relative + 16]
            .copy_from_slice(&(relative_offset as u64).to_le_bytes());
        tables[3].1[record_relative + 0x10..record_relative + 0x18]
            .copy_from_slice(&(updated.len() as u64).to_le_bytes());
        ensure!(
            image
                .len()
                .checked_add(updated.len())
                .is_some_and(|v| v <= MAX_CONTROL_NCA as usize),
            "Control data exceeds native rebuild size limit"
        );
        image.extend_from_slice(&updated);
    }
    for (field, bytes) in &tables {
        image.resize(image.len().next_multiple_of(FILE_ALIGNMENT), 0);
        let at = image.len() as u64;
        image[*field..*field + 8].copy_from_slice(&at.to_le_bytes());
        image[*field + 8..*field + 16].copy_from_slice(&(bytes.len() as u64).to_le_bytes());
        ensure!(
            image
                .len()
                .checked_add(bytes.len())
                .is_some_and(|v| v <= MAX_CONTROL_NCA as usize),
            "Control metadata exceeds NCA size limit"
        );
        image.extend_from_slice(bytes);
    }
    ensure!(
        resized_count > 0 && changed_count > 0,
        "Native resized Control path requires a file-size change"
    );
    let mut seen_files = 0usize;
    for entry in walkdir::WalkDir::new(modified_romfs).follow_links(false) {
        let entry = entry?;
        ensure!(
            !entry.file_type().is_symlink(),
            "Control symlinks are unsupported"
        );
        if !entry.file_type().is_file() {
            continue;
        }
        let relative = entry
            .path()
            .strip_prefix(modified_romfs)?
            .to_string_lossy()
            .replace('\\', "/")
            .to_lowercase();
        ensure!(seen.contains(&relative), "Control RomFS includes new files");
        seen_files += 1;
    }
    ensure!(seen_files == files.len(), "Control RomFS file list changed");

    let logical_end = bottom
        .0
        .checked_add(image.len() as u64)
        .context("Control resized image length overflow")?;
    let new_sec_size = section.size.max(logical_end).next_multiple_of(SECTOR_SIZE);
    let new_total_size = section
        .offset
        .checked_add(new_sec_size)
        .context("NCA resized section length overflow")?;
    ensure!(
        new_total_size <= MAX_CONTROL_NCA,
        "Control NCA grows beyond size limit"
    );
    // Preserve all intermediate hash levels; only the last level grows.
    // If parent hash blocks are insufficient, use full-rebuild fallback.
    let parent = levels[levels.len() - 2];
    let needed_hashes = (image.len() as u64)
        .div_ceil(1u64 << bottom.2)
        .checked_mul(32)
        .context("Control hash storage overflow")?;
    ensure!(
        needed_hashes <= parent.1,
        "Control IVFC needs an expanded hash hierarchy"
    );
    levels.last_mut().context("Missing final IVFC level")?.1 = image.len() as u64;

    plain.resize(usize::try_from(new_sec_size)?, 0);
    plain[romfs_start..].fill(0);
    plain[romfs_start..romfs_start + image.len()].copy_from_slice(&image);
    let last_level = 0x18 + (levels.len() - 1) * 0x18;
    fs_header[last_level + 8..last_level + 16].copy_from_slice(&(image.len() as u64).to_le_bytes());
    rebuild_ivfc(&mut plain, &mut fs_header, &levels, cancel)?;
    ensure!(
        verify_ivfc(&plain, &fs_header, &levels)?,
        "Rebuilt Control IVFC failed internal verification"
    );
    let new_fs_hash: [u8; 32] = Sha256::digest(&fs_header).into();
    header[fs_start..fs_start + 0x200].copy_from_slice(&fs_header);
    header[fs_hash_at..fs_hash_at + 32].copy_from_slice(&new_fs_hash);
    let section_entry = 0x240 + section.index * 0x10;
    let media_end = u32::try_from(new_total_size / SECTOR_SIZE)?;
    header[section_entry + 4..section_entry + 8].copy_from_slice(&media_end.to_le_bytes());
    header[0x208..0x210].copy_from_slice(&new_total_size.to_le_bytes());
    let header_key = keys
        .prod_key("header_key")
        .context("header_key unavailable")?;
    nca_xts_transform(&mut header, header_key, true)?;
    nca_ctr_xcrypt_range(&mut plain, &key, &section.counter, section.offset)?;
    contents[..NCA_XTS_HEADER_SIZE].copy_from_slice(&header);
    contents.truncate(sec_start);
    contents.extend_from_slice(&plain);
    ensure!(
        contents.len() as u64 == new_total_size,
        "Repacked Control NCA length differs from declared size"
    );
    let parent_dir = output.parent().context("Output parent absent")?;
    fs::create_dir_all(parent_dir)?;
    let mut staged = tempfile::NamedTempFile::new_in(parent_dir)?;
    staged.write_all(&contents)?;
    staged.flush()?;
    staged.persist_noclobber(output)?;
    Ok(changed_count)
}
