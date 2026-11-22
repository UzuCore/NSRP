//! Fixed-layout Control NCA repack: no helper process or copied keys file.
//!
//! This module deliberately rejects changed file sizes, added/deleted files,
//! multiple NCA sections and uncommon crypto/layouts. Its narrow purpose is
//! native control.nacp edits; larger icon replacements and RomFS tree changes
//! go to the separate Rust full-rebuild path, which rejects unsupported
//! storage rather than invoking another program.

use crate::{
    crypto::{nca_ctr_xcrypt_range, nca_xts_transform},
    formats::nca::{NCA_XTS_HEADER_SIZE, decrypt_header, derive_section_key},
    keys::KeySet,
    ops::native_fs::romfs_file_index,
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

pub(crate) const MAX_CONTROL_NCA: u64 = 64 * 1024 * 1024;
pub(crate) type IvfcLevel = (u64, u64, u32);

/// Build a new Control NCA with the same physical layout as the input.
/// Hash tables and encryption are updated; the original file is read-only.
/// A new output is atomically published only when all checks succeed.
pub fn repack_control_same_size(
    source: &Path,
    updated_romfs: &Path,
    output: &Path,
    keys: &KeySet,
    cancel: &AtomicBool,
) -> Result<usize> {
    let len = fs::metadata(source)?.len();
    ensure!(
        (NCA_XTS_HEADER_SIZE as u64..=MAX_CONTROL_NCA).contains(&len),
        "Control NCA is outside the native repack size limit"
    );
    ensure!(
        !output.exists(),
        "Native repack refuses to overwrite an NCA"
    );
    let mut contents = fs::read(source)?;
    let info = decrypt_header(&contents[..NCA_XTS_HEADER_SIZE], keys)?;
    ensure!(info.content_type == 2, "NCA is not Control content");
    ensure!(
        info.sections.len() == 1,
        "Multisection Control requires full repack"
    );
    let section = &info.sections[0];
    ensure!(section.encryption_type == 3, "Unsupported Control crypto");
    let start = usize::try_from(section.offset)?;
    let end = usize::try_from(
        section
            .offset
            .checked_add(section.size)
            .context("Control section overflow")?,
    )?;
    ensure!(end <= contents.len(), "Control section outside source NCA");

    let fs_offset = 0x400 + section.index * 0x200;
    let mut header = info.decrypted_header.clone();
    let mut fs_header = header[fs_offset..fs_offset + 0x200].to_vec();
    ensure!(
        (fs_header[2], fs_header[3], fs_header[4]) == (0, 3, 3) && &fs_header[8..12] == b"IVFC",
        "Unsupported Control filesystem layout"
    );
    let hash_offset = 0x280 + section.index * 0x20;
    let old_fs_hash: [u8; 32] = Sha256::digest(&fs_header).into();
    ensure!(
        header[hash_offset..hash_offset + 32] == old_fs_hash,
        "Original filesystem header SHA-256 is invalid"
    );

    let key = derive_section_key(&info, keys)?;
    let mut plain = contents[start..end].to_vec();
    nca_ctr_xcrypt_range(&mut plain, &key, &section.counter, section.offset)?;
    let levels = ivfc_levels(&fs_header, plain.len() as u64)?;
    ensure!(
        verify_ivfc(&plain, &fs_header, &levels)?,
        "Original Control IVFC hashes are invalid"
    );
    let bottom = *levels.last().context("IVFC has no RomFS level")?;
    let files = romfs_file_index(&plain, bottom.0, bottom.1)?;
    let mut allowed = HashSet::new();
    let mut modified_count = 0usize;
    for (relative, offset, size, _) in &files {
        ensure!(!cancel.load(Ordering::Relaxed), "작업이 중단되었습니다");
        allowed.insert(relative.to_string_lossy().replace('\\', "/").to_lowercase());
        let updated = fs::read(updated_romfs.join(relative))
            .with_context(|| format!("Control file missing: {}", relative.display()))?;
        ensure!(
            updated.len() as u64 == *size,
            "Control RomFS file size changed"
        );
        let start = usize::try_from(*offset)?;
        let end = start
            .checked_add(updated.len())
            .context("Control file offset overflow")?;
        ensure!(end <= plain.len(), "Control file outside decrypted section");
        if plain[start..end] != updated {
            plain[start..end].copy_from_slice(&updated);
            modified_count += 1;
        }
    }
    let mut directory_files = 0usize;
    for entry in walkdir::WalkDir::new(updated_romfs).follow_links(false) {
        let entry = entry?;
        ensure!(
            !entry.file_type().is_symlink(),
            "Symlinks are forbidden in Control repack"
        );
        if !entry.file_type().is_file() {
            continue;
        }
        let relative = entry
            .path()
            .strip_prefix(updated_romfs)?
            .to_string_lossy()
            .replace('\\', "/")
            .to_lowercase();
        ensure!(
            allowed.contains(&relative),
            "Unexpected file in Control RomFS"
        );
        directory_files += 1;
    }
    ensure!(
        directory_files == files.len(),
        "Control RomFS entries differ from source"
    );
    ensure!(modified_count > 0, "No Control files changed");

    rebuild_ivfc(&mut plain, &mut fs_header, &levels, cancel)?;
    let new_fs_hash: [u8; 32] = Sha256::digest(&fs_header).into();
    header[fs_offset..fs_offset + 0x200].copy_from_slice(&fs_header);
    header[hash_offset..hash_offset + 32].copy_from_slice(&new_fs_hash);
    let header_key = keys
        .prod_key("header_key")
        .context("header_key unavailable")?;
    nca_xts_transform(&mut header, header_key, true)?;
    nca_ctr_xcrypt_range(&mut plain, &key, &section.counter, section.offset)?;
    contents[..NCA_XTS_HEADER_SIZE].copy_from_slice(&header);
    contents[start..end].copy_from_slice(&plain);
    let parent = output.parent().context("NCA output parent missing")?;
    fs::create_dir_all(parent)?;
    let mut staged = tempfile::NamedTempFile::new_in(parent)?;
    staged.write_all(&contents)?;
    staged.flush()?;
    staged.persist_noclobber(output)?;
    Ok(modified_count)
}

fn u32le(data: &[u8], at: usize) -> Result<u32> {
    Ok(u32::from_le_bytes(
        data.get(at..at + 4)
            .context("IVFC u32 truncated")?
            .try_into()?,
    ))
}
fn u64le(data: &[u8], at: usize) -> Result<u64> {
    Ok(u64::from_le_bytes(
        data.get(at..at + 8)
            .context("IVFC u64 truncated")?
            .try_into()?,
    ))
}

pub(crate) fn ivfc_levels(header: &[u8], storage_len: u64) -> Result<Vec<IvfcLevel>> {
    let count = u32le(header, 0x14)?;
    ensure!((2..=7).contains(&count), "Unsupported IVFC level count");
    let mut levels = Vec::new();
    for i in 0..count - 1 {
        let at = 0x18 + (i as usize) * 0x18;
        let offset = u64le(header, at)?;
        let size = u64le(header, at + 8)?;
        let block_log = u32le(header, at + 16)?;
        ensure!(
            size > 0
                && (9..=20).contains(&block_log)
                && offset.checked_add(size).is_some_and(|v| v <= storage_len),
            "IVFC region geometry invalid"
        );
        levels.push((offset, size, block_log));
    }
    Ok(levels)
}

pub(crate) fn verify_ivfc(section: &[u8], header: &[u8], levels: &[IvfcLevel]) -> Result<bool> {
    let top = levels[0];
    let off = usize::try_from(top.0)?;
    let end = usize::try_from(top.0 + top.1)?;
    let master: [u8; 32] = Sha256::digest(&section[off..end]).into();
    if header[0xc8..0xe8] != master {
        return Ok(false);
    }
    for i in 1..levels.len() {
        let (child_off, child_len, log) = levels[i];
        let (parent_off, parent_len, _) = levels[i - 1];
        let block = 1u64 << log;
        let count = child_len.div_ceil(block);
        if count.checked_mul(32).is_none_or(|size| size > parent_len) {
            return Ok(false);
        }
        let mut buffer = vec![0u8; block as usize];
        for j in 0..count {
            buffer.fill(0);
            let start = usize::try_from(child_off + j * block)?;
            let bytes = usize::try_from(block.min(child_len - j * block))?;
            buffer[..bytes].copy_from_slice(&section[start..start + bytes]);
            let hash: [u8; 32] = Sha256::digest(&buffer).into();
            let at = usize::try_from(parent_off + j * 32)?;
            if section[at..at + 32] != hash {
                return Ok(false);
            }
        }
    }
    Ok(true)
}

pub(crate) fn rebuild_ivfc(
    section: &mut [u8],
    header: &mut [u8],
    levels: &[IvfcLevel],
    cancel: &AtomicBool,
) -> Result<()> {
    for i in (1..levels.len()).rev() {
        let (child_off, child_len, log) = levels[i];
        let (parent_off, parent_len, _) = levels[i - 1];
        let block = 1u64 << log;
        let count = child_len.div_ceil(block);
        ensure!(
            count.checked_mul(32).is_some_and(|v| v <= parent_len),
            "IVFC parent hash level is too small"
        );
        let mut buffer = vec![0u8; block as usize];
        for j in 0..count {
            ensure!(!cancel.load(Ordering::Relaxed), "작업이 중단되었습니다");
            buffer.fill(0);
            let start = usize::try_from(child_off + j * block)?;
            let bytes = usize::try_from(block.min(child_len - j * block))?;
            buffer[..bytes].copy_from_slice(&section[start..start + bytes]);
            let hash: [u8; 32] = Sha256::digest(&buffer).into();
            let at = usize::try_from(parent_off + j * 32)?;
            section[at..at + 32].copy_from_slice(&hash);
        }
    }
    let top = levels[0];
    let start = usize::try_from(top.0)?;
    let end = usize::try_from(top.0 + top.1)?;
    let master: [u8; 32] = Sha256::digest(&section[start..end]).into();
    header[0xc8..0xe8].copy_from_slice(&master);
    Ok(())
}
