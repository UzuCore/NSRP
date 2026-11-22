//! Verified transaction boundary around the optional external XCI builder.
//!
//! An unsuccessful builder must never delete or truncate an existing user
//! output. Generate the XCI in a private sibling directory, validate its
//! HFS0 content index, and only then atomically replace the destination.
//! Both NSP->XCI conversion and multi-title XCI merge share this one path.

use crate::{
    disk_space::ensure_disk_space,
    formats::{
        hfs0::{self, Hfs0Index},
        ncz_stream::reconstructed_nca_size,
    },
    keys::KeySet,
    ops::{
        native_xci,
        xcz::{XczOptions, compress_xci},
    },
    process::run_tool,
};
use anyhow::{Context, Result, bail, ensure};
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeMap,
    ffi::OsString,
    fs::{self, File},
    io::{BufReader, BufWriter, Read, Write},
    path::Path,
    sync::atomic::{AtomicBool, Ordering},
};

/// Re-read a private output copy before publishing it. A valid size or HFS0
/// index does not by itself detect damaged NCA payload bytes; the digest
/// must match the bytes read from the source during the copy.
fn verify_staged_xci_copy(
    path: &Path,
    expected_bytes: u64,
    expected_hash: [u8; 32],
    cancel: &AtomicBool,
) -> Result<()> {
    ensure!(!cancel.load(Ordering::Relaxed), "작업이 중단되었습니다");
    ensure!(
        fs::metadata(path)?.len() == expected_bytes,
        "XCI copied output length mismatch before publication"
    );
    let mut input = BufReader::with_capacity(1024 * 1024, File::open(path)?);
    let mut hasher = Sha256::new();
    let mut buffer = vec![0u8; 1024 * 1024];
    let mut read_total = 0u64;
    loop {
        ensure!(!cancel.load(Ordering::Relaxed), "작업이 중단되었습니다");
        let amount = input.read(&mut buffer)?;
        if amount == 0 {
            break;
        }
        read_total = read_total
            .checked_add(amount as u64)
            .context("XCI staged verification size overflow")?;
        ensure!(
            read_total <= expected_bytes,
            "XCI staged copy expanded during verification"
        );
        hasher.update(&buffer[..amount]);
    }
    ensure!(
        read_total == expected_bytes && hasher.finalize().as_slice() == expected_hash,
        "XCI copied output SHA-256 differs from its source; refusing publication"
    );
    Ok(())
}

/// Snapshot the complete source hash only on the *exceptional* copy path.
/// A matching staged-file digest is not enough when another process changes
/// the source between validation and copying: the copied bytes could be
/// self-consistent but represent a different, partially updated source.
fn fingerprint_xci_source_for_copy(source: &Path, cancel: &AtomicBool) -> Result<(u64, [u8; 32])> {
    ensure!(!cancel.load(Ordering::Relaxed), "작업이 중단되었습니다");
    let mut reader = BufReader::with_capacity(1024 * 1024, File::open(source)?);
    let expected = reader.get_ref().metadata()?.len();
    let mut digest = Sha256::new();
    let mut read_total = 0u64;
    let mut buffer = vec![0u8; 1024 * 1024];
    loop {
        ensure!(!cancel.load(Ordering::Relaxed), "작업이 중단되었습니다");
        let read = reader.read(&mut buffer)?;
        if read == 0 {
            break;
        }
        read_total = read_total
            .checked_add(read as u64)
            .context("XCI source fingerprint size overflow")?;
        ensure!(
            read_total <= expected,
            "XCI source grew while fingerprinting; refusing publication"
        );
        digest.update(&buffer[..read]);
    }
    ensure!(
        read_total == expected,
        "XCI source shortened while fingerprinting; refusing publication"
    );
    Ok((expected, digest.finalize().into()))
}

/// Only used after the fast rename cannot be completed. This bounded,
/// digest-verified copy is never invoked during a successful same-volume
/// move and therefore does not slow down the normal publication path.
fn copy_xci_into_verified_staging(
    source: &Path,
    staged: &mut tempfile::NamedTempFile,
    cancel: &AtomicBool,
) -> Result<()> {
    copy_xci_into_verified_staging_with_hook(source, staged, cancel, |_| Ok(()))
}

/// The hook allows deterministic, isolated source-race fault injection.
/// Production calls compile to a no-op for each completed buffer.
fn copy_xci_into_verified_staging_with_hook<F>(
    source: &Path,
    staged: &mut tempfile::NamedTempFile,
    cancel: &AtomicBool,
    mut after_chunk: F,
) -> Result<()>
where
    F: FnMut(u64) -> Result<()>,
{
    ensure!(!cancel.load(Ordering::Relaxed), "작업이 중단되었습니다");
    let (source_snapshot_bytes, source_snapshot_hash) =
        fingerprint_xci_source_for_copy(source, cancel)?;
    let mut src = BufReader::with_capacity(1024 * 1024, File::open(source)?);
    let source_bytes = src.get_ref().metadata()?.len();
    ensure!(
        source_bytes == source_snapshot_bytes,
        "XCI source size changed before copying; refusing publication"
    );
    let mut dst = BufWriter::with_capacity(1024 * 1024, staged.as_file_mut());
    let mut hasher = Sha256::new();
    let mut buffer = vec![0u8; 1024 * 1024];
    let mut copied = 0u64;
    loop {
        ensure!(!cancel.load(Ordering::Relaxed), "작업이 중단되었습니다");
        let amount = src.read(&mut buffer)?;
        if amount == 0 {
            break;
        }
        copied = copied
            .checked_add(amount as u64)
            .context("XCI copied output size overflow")?;
        ensure!(
            copied <= source_bytes,
            "XCI source grew while staging; aborting publication"
        );
        hasher.update(&buffer[..amount]);
        dst.write_all(&buffer[..amount])?;
        after_chunk(copied)?;
    }
    ensure!(
        copied == source_bytes,
        "XCI source shortened while staging; aborting publication"
    );
    dst.flush()?;
    drop(dst);
    staged.as_file().sync_all()?;
    let copied_hash: [u8; 32] = hasher.finalize().into();
    ensure!(
        copied_hash == source_snapshot_hash,
        "XCI source SHA-256 changed while copying; refusing publication"
    );
    verify_staged_xci_copy(staged.path(), copied, copied_hash, cancel)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum XciBuilder {
    NativeRust,
    HacbuildFallback,
}

/// Attempt a direct-source XCI build without materializing intermediate NCA
/// files. An unsupported layout returns false without touching the output,
/// allowing the caller to enter the existing hacbuild fallback path.
pub(crate) fn build_xci_native_sources_verified(
    output: &Path,
    expected_ncas: &[(String, u64)],
    sources: &[native_xci::XciSource],
    game_info: &[u8],
    cancel: &AtomicBool,
) -> Result<bool> {
    ensure!(
        !expected_ncas.is_empty(),
        "XCI package has no expected NCAs"
    );
    ensure!(!cancel.load(Ordering::Relaxed), "작업이 중단되었습니다");
    if !native_xci::supports_sources(sources, game_info)? {
        return Ok(false);
    }
    // The source NCAs are not copied to the temporary work directory; only
    // one destination XCI is needed. Reserve conservative index/alignment
    // headroom in addition to the actual content, keeping the old finished
    // output allocated until atomic commit.
    let expected_bytes = sources
        .iter()
        .try_fold(0x10000u64, |total, source| total.checked_add(source.length))
        .and_then(|sum| sum.checked_add((sources.len() as u64).saturating_mul(1024)))
        .context("Native XCI 예상 출력 크기 오버플로")?;
    let parent = output.parent().context("XCI output has no parent")?;
    fs::create_dir_all(parent)?;
    ensure_disk_space(parent, expected_bytes)?;
    // Do NOT silently invoke the external builder on native I/O failures:
    // validation and transaction errors must be reported to the user.
    build_xci_verified(output, expected_ncas, cancel, |staged| {
        native_xci::build_default_xci_from_sources(staged, sources, game_info, cancel)
    })?;
    Ok(true)
}

/// Stream NCZ directly into a privately staged XCI. Only validated virtual
/// file sizes and the tested default card layout enter this path. The caller
/// can verify/recover a decoded NCA *before* HFS0 hashes are finalized.
pub(crate) fn build_xci_virtual_verified<F>(
    output: &Path,
    expected_ncas: &[(String, u64)],
    sources: &[(String, u64)],
    game_info: &[u8],
    cancel: &AtomicBool,
    mut write_entry: F,
) -> Result<bool>
where
    F: FnMut(usize, &mut File, &Path) -> Result<()>,
{
    ensure!(!cancel.load(Ordering::Relaxed), "작업이 중단되었습니다");
    if !native_xci::supports_virtual_sources(sources, game_info)? {
        return Ok(false);
    }
    let estimated = sources
        .iter()
        .try_fold(0x10000u64, |bytes, (_, len)| bytes.checked_add(*len))
        .and_then(|bytes| bytes.checked_add((sources.len() as u64).saturating_mul(1024)))
        .context("Direct NSZ→XCI expected size overflow")?;
    let parent = output.parent().context("XCI output has no parent")?;
    fs::create_dir_all(parent)?;
    ensure_disk_space(parent, estimated)?;
    build_xci_verified(output, expected_ncas, cancel, |staged| {
        native_xci::build_default_xci_from_virtual_sources(
            staged,
            sources,
            game_info,
            cancel,
            |index, file| write_entry(index, file, staged),
        )
    })?;
    Ok(true)
}

/// Shared builder: native for the verified default XCI layout, fallback for
/// unverified presets or geometries. A native error never triggers fallback.
/// The staging/validation boundary always protects existing user output.
pub(crate) fn build_xci_auto_verified(
    output: &Path,
    expected_ncas: &[(String, u64)],
    work_root: &Path,
    scratch_root: &Path,
    resource_dir: &Path,
    prod_keys: &Path,
    game_info: &[u8],
    cancel: &AtomicBool,
) -> Result<XciBuilder> {
    ensure!(
        !expected_ncas.is_empty(),
        "XCI package has no expected NCAs"
    );
    ensure!(!cancel.load(Ordering::Relaxed), "작업이 중단되었습니다");
    if native_xci::supports_layout(work_root, game_info)? {
        build_xci_verified(output, expected_ncas, cancel, |staged| {
            native_xci::build_default_xci(staged, work_root, cancel)
        })?;
        return Ok(XciBuilder::NativeRust);
    }
    // Unverified layouts retain the known external builder.
    fs::write(work_root.join("game_info.ini"), game_info)?;

    let tool_dir = scratch_root.join("tools");
    fs::create_dir_all(&tool_dir)?;
    let hacbuild = tool_dir.join("hacbuild.exe");
    fs::copy(resource_dir.join("bin").join("hacbuild.exe"), &hacbuild)
        .context("hacbuild.exe 복사 실패")?;
    fs::write(tool_dir.join("game_info_preset.ini"), game_info)?;
    fs::copy(prod_keys, tool_dir.join("keys.txt"))?;

    build_xci_verified(output, expected_ncas, cancel, |staged| {
        let args = vec![
            OsString::from("xci_auto"),
            work_root.as_os_str().to_owned(),
            staged.as_os_str().to_owned(),
        ];
        let tool = run_tool(&hacbuild, args, Some(&tool_dir), cancel)?;
        if !tool.success() || !staged.is_file() {
            bail!("XCI 빌드 실패: {}", tool.combined());
        }
        Ok(())
    })?;
    Ok(XciBuilder::HacbuildFallback)
}

/// Verify at least one identical physical NCA for every source NCA.
///
/// This is a structural, *not* cryptographic Nintendo signature check.
/// The generated HFS0 must also contain a readable secure partition.
fn validate_xci_payload(path: &Path, expected: &[(String, u64)]) -> Result<()> {
    let size = fs::metadata(path)?.len();
    ensure!(size >= 1024 * 1024, "XCI output is too small");
    let root = hfs0::find_xci_root(path)?;
    let secure = root
        .entry("secure")
        .context("generated XCI has no secure HFS0 partition")?;
    ensure!(secure.size > 0, "XCI secure partition is empty");
    let mut reader = BufReader::new(File::open(path)?);
    let secure_at = root
        .data_start
        .checked_add(secure.offset)
        .context("XCI secure partition offset overflow")?;
    let _ = Hfs0Index::parse_at(&mut reader, secure_at, size)
        .context("XCI secure partition HFS0 index invalid")?;
    let all_files = hfs0::collect_leaf_entries(path, false)?;
    let mut found = BTreeMap::<String, Vec<u64>>::new();
    for (name, _, len) in all_files {
        if name.to_ascii_lowercase().ends_with(".nca") {
            found
                .entry(name.to_ascii_lowercase())
                .or_default()
                .push(len);
        }
    }
    ensure!(!found.is_empty(), "generated XCI has no NCA content");
    for (name, len) in expected {
        ensure!(
            found
                .get(&name.to_ascii_lowercase())
                .is_some_and(|sizes| sizes.contains(len)),
            "generated XCI is missing or truncates source NCA {name}"
        );
    }
    Ok(())
}

/// Build in a same-volume temporary directory, validate, then publish.
/// On failure, the previous output remains byte-for-byte untouched.
pub(crate) fn build_xci_verified<F>(
    output: &Path,
    expected_ncas: &[(String, u64)],
    cancel: &AtomicBool,
    mut builder: F,
) -> Result<()>
where
    F: FnMut(&Path) -> Result<()>,
{
    ensure!(
        !expected_ncas.is_empty(),
        "XCI package has no expected NCAs"
    );
    ensure!(!cancel.load(Ordering::Relaxed), "작업이 중단되었습니다");
    let parent = output.parent().context("XCI destination has no parent")?;
    fs::create_dir_all(parent)?;
    // The old destination remains allocated until the new XCI has been
    // written and verified. Check the destination volume before allocating
    // even the first staging file. This also covers the work-root/hacbuild
    // callers, not just the direct-region and NCZ stream paths.
    let estimated_bytes = expected_ncas
        .iter()
        .try_fold(0x10000u64, |total, (_, len)| total.checked_add(*len))
        .and_then(|total| total.checked_add((expected_ncas.len() as u64).saturating_mul(1024)))
        .and_then(|total| total.checked_add(16 * 1024 * 1024))
        .context("XCI verified publisher estimated size overflow")?;
    ensure_disk_space(parent, estimated_bytes)?;
    let staging = tempfile::Builder::new()
        .prefix("nsrp_verified_xci_")
        .tempdir_in(parent)
        .context("XCI same-volume temporary directory creation failed")?;
    let staged = staging.path().join("validated_build.xci");
    builder(&staged)?;
    ensure!(!cancel.load(Ordering::Relaxed), "작업이 중단되었습니다");
    validate_xci_payload(&staged, expected_ncas)?;
    ensure!(!cancel.load(Ordering::Relaxed), "작업이 중단되었습니다");
    // Windows rename within the same volume replaces an existing destination
    // atomically; errors do not remove the user's prior output. No helper
    // EXE sees the final path before the file has passed validation.
    fs::rename(&staged, output).with_context(|| {
        format!(
            "verified XCI atomic publication failed: {}",
            output.display()
        )
    })?;
    Ok(())
}

/// Publish an already verified XCI from the operation workspace. A rename
/// on the same volume replaces the old output atomically. Across volumes,
/// copy to a private sibling in the destination directory, validate that
/// complete copy, and only then atomically publish it.
fn publish_xci_transactionally(
    source: &Path,
    destination: &Path,
    cancel: &AtomicBool,
    validate_structure: bool,
) -> Result<()> {
    ensure!(!cancel.load(Ordering::Relaxed), "작업이 중단되었습니다");
    ensure!(
        source != destination,
        "XCI source and destination must be different files"
    );
    #[cfg(windows)]
    if let (Ok(src), Ok(dst)) = (File::open(source), File::open(destination)) {
        use std::os::windows::io::AsRawHandle;
        use windows::Win32::{
            Foundation::HANDLE,
            Storage::FileSystem::{BY_HANDLE_FILE_INFORMATION, GetFileInformationByHandle},
        };
        // FileIndex on Rust's Windows MetadataExt is still unstable;
        // the Win32 by-handle identity works for hard links on NTFS.
        let mut source_info = BY_HANDLE_FILE_INFORMATION::default();
        let mut target_info = BY_HANDLE_FILE_INFORMATION::default();
        unsafe {
            GetFileInformationByHandle(HANDLE(src.as_raw_handle()), &mut source_info)?;
            GetFileInformationByHandle(HANDLE(dst.as_raw_handle()), &mut target_info)?;
        }
        ensure!(
            source_info.dwVolumeSerialNumber != target_info.dwVolumeSerialNumber
                || source_info.nFileIndexHigh != target_info.nFileIndexHigh
                || source_info.nFileIndexLow != target_info.nFileIndexLow,
            "XCI source and destination refer to the same underlying file"
        );
    }
    let expected = if validate_structure {
        let expected = hfs0::collect_leaf_entries(source, false)?
            .into_iter()
            .filter(|(name, _, _)| name.to_ascii_lowercase().ends_with(".nca"))
            .map(|(name, _, size)| (name, size))
            .collect::<Vec<_>>();
        ensure!(!expected.is_empty(), "XCI commit source contains no NCA");
        validate_xci_payload(source, &expected)?;
        expected
    } else {
        // The XCZ->XCI path has already reconstructed the original container.
        // Some older gamecards legitimately contain no NCAs in the synthetic
        // secure partition; do not introduce a new format restriction here.
        ensure!(
            fs::metadata(source)?.len() > 0,
            "reconstructed XCI is empty"
        );
        Vec::new()
    };
    ensure!(!cancel.load(Ordering::Relaxed), "작업이 중단되었습니다");
    if fs::rename(source, destination).is_ok() {
        return Ok(());
    }
    let parent = destination
        .parent()
        .context("XCI destination has no parent")?;
    fs::create_dir_all(parent)?;
    // A failed same-volume rename can require copying the entire source
    // into a private destination sibling. Check the caller's quota-aware
    // free space first; the previous complete destination stays allocated.
    ensure_disk_space(parent, fs::metadata(source)?.len())?;
    let mut staged = tempfile::Builder::new()
        .prefix("nsrp_xci_publish_")
        .tempfile_in(parent)?;
    copy_xci_into_verified_staging(source, &mut staged, cancel)?;
    if validate_structure {
        validate_xci_payload(staged.path(), &expected)?;
    } else {
        ensure!(
            fs::metadata(staged.path())?.len() == fs::metadata(source)?.len(),
            "reconstructed XCI copied length mismatch"
        );
    }
    ensure!(!cancel.load(Ordering::Relaxed), "작업이 중단되었습니다");
    fs::rename(staged.path(), destination)
        .with_context(|| format!("verified XCI publication failed: {}", destination.display()))?;
    Ok(())
}

/// Validate fresh NSP->XCI or merged XCI output before publishing.
pub(crate) fn publish_verified_xci(
    source: &Path,
    destination: &Path,
    cancel: &AtomicBool,
) -> Result<()> {
    publish_xci_transactionally(source, destination, cancel, true)
}

/// Publish a validated XCZ decompression without changing compatibility
/// semantics for legitimate noncanonical source XCI partitions.
pub(crate) fn publish_decoded_xci(
    source: &Path,
    destination: &Path,
    cancel: &AtomicBool,
) -> Result<()> {
    publish_xci_transactionally(source, destination, cancel, false)
}

/// Verify the compressed nested HFS0 table against the source gamecard.
/// Each resulting NCZ must declare exactly the original NCA logical size;
/// uncompressed members must still have the original length and filename.
/// This gate verifies structural integrity, *not* a retail RSA signature.
fn validate_xcz_against_xci(source: &Path, compressed: &Path, cancel: &AtomicBool) -> Result<()> {
    ensure!(!cancel.load(Ordering::Relaxed), "작업이 중단되었습니다");
    let (source_root, _) = hfs0::find_xci_root_with_header_base(source)?;
    let (compressed_root, _) = hfs0::find_xci_root_with_header_base(compressed)?;
    let source_partitions = source_root
        .entries
        .iter()
        .map(|entry| entry.name.to_ascii_lowercase())
        .collect::<Vec<_>>();
    let compressed_partitions = compressed_root
        .entries
        .iter()
        .map(|entry| entry.name.to_ascii_lowercase())
        .collect::<Vec<_>>();
    ensure!(
        source_partitions == compressed_partitions,
        "XCZ root partitions do not match the uncompressed source"
    );
    let source_leaves = hfs0::collect_leaf_entries(source, false)?;
    let compressed_leaves = hfs0::collect_leaf_entries(compressed, false)?;
    ensure!(
        !source_leaves.is_empty() && source_leaves.len() == compressed_leaves.len(),
        "XCZ leaf count does not match the source XCI"
    );
    let mut expected = BTreeMap::<String, Vec<u64>>::new();
    for (name, _, size) in source_leaves {
        expected
            .entry(name.to_ascii_lowercase())
            .or_default()
            .push(size);
    }
    let compressed_len = fs::metadata(compressed)?.len();
    let mut reader = BufReader::with_capacity(1024 * 1024, File::open(compressed)?);
    let mut found = BTreeMap::<String, Vec<u64>>::new();
    for (name, offset, size) in compressed_leaves {
        ensure!(!cancel.load(Ordering::Relaxed), "작업이 중단되었습니다");
        ensure!(
            offset
                .checked_add(size)
                .is_some_and(|end| end <= compressed_len),
            "XCZ leaf region exceeds compressed source: {name}"
        );
        let lower = name.to_ascii_lowercase();
        let (canonical, original_size) = if let Some(stem) = lower.strip_suffix(".ncz") {
            let restored = reconstructed_nca_size(&mut reader, offset, size)?;
            (format!("{stem}.nca"), restored)
        } else {
            (lower, size)
        };
        found.entry(canonical).or_default().push(original_size);
    }
    for values in expected.values_mut() {
        values.sort_unstable();
    }
    for values in found.values_mut() {
        values.sort_unstable();
    }
    ensure!(
        expected == found,
        "XCZ contents or reconstructed NCZ sizes do not match the source XCI"
    );
    Ok(())
}

/// Stage37 verified XCZ publisher for XCI merge+compress.
///
/// The existing XCI remains an operation-private source. Compress to a
/// different same-volume destination sibling first, validate the nested
/// HFS0 + decoded-size index, then perform exactly one atomic rename of the
/// validated XCZ. Cancellation, malformed output and disk I/O errors cannot
/// truncate or remove the user's previous XCZ.
pub(crate) fn compress_xci_verified(
    source: &Path,
    destination: &Path,
    keys: &mut KeySet,
    options: &XczOptions,
    cancel: &AtomicBool,
    log: &mut dyn FnMut(String),
) -> Result<()> {
    ensure!(!cancel.load(Ordering::Relaxed), "작업이 중단되었습니다");
    let parent = destination
        .parent()
        .context("XCZ destination has no parent")?;
    fs::create_dir_all(parent)?;
    let original_bytes = fs::metadata(source)?.len();
    ensure!(original_bytes > 0, "XCI source is empty");
    let reserve = original_bytes
        .checked_add(16 * 1024 * 1024)
        .context("XCZ reservation size overflow")?;
    ensure_disk_space(parent, reserve)?;
    let private_dir = tempfile::Builder::new()
        .prefix("nsrp_verified_xcz_")
        .tempdir_in(parent)
        .context("XCZ private output directory creation failed")?;
    let staged = private_dir.path().join("merged_output.xcz");
    let stats = compress_xci(source, &staged, keys, options, cancel, &mut |_| {}, log)?;
    ensure!(
        stats.input_size == original_bytes
            && stats.output_size == fs::metadata(&staged)?.len()
            && stats.output_size > 0,
        "XCZ compressor reported inconsistent byte lengths"
    );
    validate_xcz_against_xci(source, &staged, cancel)?;
    ensure!(!cancel.load(Ordering::Relaxed), "작업이 중단되었습니다");
    fs::rename(&staged, destination).with_context(|| {
        format!(
            "Verified XCZ atomic publication failed; previous file preserved: {}",
            destination.display()
        )
    })?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use std::path::PathBuf;

    /// Real NTFS 36 GiB sparse source, only from the marked Stage57 QA
    /// directory. Unsupported capacities must return false *before*
    /// creating any staging output or modifying an existing file.
    #[cfg(windows)]
    #[test]
    #[ignore = "requires explicitly created Stage57 NTFS sparse file in isolated QA root"]
    fn stage57_real_sparse_36gib_overlimit_keeps_previous_output() -> Result<()> {
        let path = PathBuf::from(
            std::env::var_os("NSRP_STAGE57_SPARSE_XCI")
                .context("missing NSRP_STAGE57_SPARSE_XCI QA fixture path")?,
        );
        ensure!(
            path.to_string_lossy()
                .starts_with(r"D:\NSW.dev\NSRP_STAGE57_SAFETY_20261122\qa\sparse_36gib\"),
            "refusing non-QA sparse input"
        );
        let source_meta = fs::symlink_metadata(&path)?;
        ensure!(
            source_meta.is_file()
                && !source_meta.file_type().is_symlink()
                && source_meta.len() == (36u64 << 30),
            "invalid sparse fixture"
        );
        let name = |index: u32| format!("{index:032x}.nca");
        let sources = (0..4u32)
            .map(|index| native_xci::XciSource {
                name: name(index),
                path: path.clone(),
                offset: 0,
                length: if index == 0 { 36u64 << 30 } else { 16 },
            })
            .collect::<Vec<_>>();
        let expected = sources
            .iter()
            .map(|source| (source.name.clone(), source.length))
            .collect::<Vec<_>>();
        let preset = include_bytes!("../../bin/game_info_preset.ini");
        assert!(!native_xci::supports_sources(&sources, preset)?);

        let owner = path.parent().context("QA sparse input has no parent")?;
        let temp = tempfile::tempdir_in(owner)?;
        let output = temp.path().join("existing_output.xci");
        let old = b"STAGE57_PREVIOUS_OUTPUT_DO_NOT_OVERWRITE";
        fs::write(&output, old)?;
        let selected = build_xci_native_sources_verified(
            &output,
            &expected,
            &sources,
            preset,
            &AtomicBool::new(false),
        )?;
        assert!(!selected, "unverified >32GiB tier must use fallback");
        assert_eq!(fs::read(&output)?, old);
        assert_eq!(fs::read_dir(temp.path())?.count(), 1);
        assert_eq!(fs::metadata(&path)?.len(), 36u64 << 30);
        Ok(())
    }

    #[test]
    fn stage40_storage_full_and_cancellation_after_partial_write_preserve_old_xci() -> Result<()> {
        let temp = tempfile::tempdir()?;
        let output = temp.path().join("existing.xci");
        let old = b"verified previous XCI must not be truncated";
        fs::write(&output, old)?;
        let expected = vec![("0123456789abcdef0123456789abcdef.nca".into(), 65536u64)];
        let cancel = AtomicBool::new(false);
        let err = build_xci_verified(&output, &expected, &cancel, |staged| {
            let mut out = File::create(staged)?;
            out.write_all(&vec![0x45u8; 8192])?;
            Err(std::io::Error::new(
                std::io::ErrorKind::StorageFull,
                "injected Stage40 disk-quota ENOSPC after partial XCI write",
            )
            .into())
        })
        .expect_err("ENOSPC injection must fail the publisher");
        assert!(format!("{err:#}").contains("ENOSPC"));
        assert_eq!(fs::read(&output)?, old);
        assert_eq!(fs::read_dir(temp.path())?.count(), 1);

        let err = build_xci_verified(&output, &expected, &cancel, |staged| {
            fs::write(staged, vec![0x99u8; 512 * 1024])?;
            cancel.store(true, Ordering::Relaxed);
            Ok(())
        })
        .expect_err("a late cancellation must stop publication");
        assert!(format!("{err:#}").contains("중단"));
        assert_eq!(fs::read(&output)?, old);
        assert_eq!(fs::read_dir(temp.path())?.count(), 1);

        cancel.store(false, Ordering::Relaxed);
        let no_output = temp.path().join("new.xci");
        assert!(
            build_xci_verified(&no_output, &expected, &cancel, |staged| {
                fs::write(staged, b"partial")?;
                Err(std::io::Error::new(
                    std::io::ErrorKind::StorageFull,
                    "injected Stage40 quota exceeded",
                )
                .into())
            })
            .is_err()
        );
        assert!(!no_output.exists());
        assert_eq!(fs::read_dir(temp.path())?.count(), 1);
        Ok(())
    }

    #[cfg(windows)]
    #[test]
    fn stage43_win32_disk_full_after_sync_preserves_existing_xci_and_unrelated_files() -> Result<()>
    {
        use std::io;
        let temp = tempfile::tempdir()?;
        let output = temp.path().join("old_complete.xci");
        let unrelated = temp.path().join("other_user_file.keep");
        let old = b"verified old card image data";
        let keep = b"unrelated user file must remain intact";
        fs::write(&output, old)?;
        fs::write(&unrelated, keep)?;
        let expected = vec![("0123456789abcdef0123456789abcdef.nca".into(), 65536u64)];
        let error = build_xci_verified(&output, &expected, &AtomicBool::new(false), |staged| {
            let mut file = File::create(staged)?;
            file.write_all(&vec![0x56; 2 * 1024 * 1024])?;
            file.sync_all()?;
            ensure!(
                file.metadata()?.len() >= 2 * 1024 * 1024,
                "Partial staging must be written before simulated failure"
            );
            // Win32 ERROR_DISK_FULL=112 is the real OS error code returned
            // by a failed WriteFile. Injecting it here avoids filling D:.
            Err(io::Error::from_raw_os_error(112).into())
        })
        .expect_err("Win32 disk-full must abort atomic publication");
        ensure!(
            error
                .chain()
                .filter_map(|e| e.downcast_ref::<io::Error>())
                .any(|err| err.raw_os_error() == Some(112)),
            "Win32 ERROR_DISK_FULL must be propagated to the caller"
        );
        assert_eq!(fs::read(&output)?, old);
        assert_eq!(fs::read(&unrelated)?, keep);
        assert_eq!(fs::read_dir(temp.path())?.count(), 2);
        Ok(())
    }

    #[test]
    fn stage44_native_32gib_gate_and_overlimit_preserve_old_output() -> Result<()> {
        let preset = include_bytes!("../../bin/game_info_preset.ini");
        let supported = (0..4u8)
            .map(|i| (format!("{i:032x}.nca"), 520 * 1024 * 1024u64))
            .collect::<Vec<_>>();
        assert!(
            native_xci::supports_virtual_sources(&supported, preset)?,
            "reference-verified 2 GiB-plus package should enter the 4 GiB tier"
        );
        let supported8 = (0..4u8)
            .map(|i| (format!("{i:032x}.nca"), 1040 * 1024 * 1024u64))
            .collect::<Vec<_>>();
        assert!(
            native_xci::supports_virtual_sources(&supported8, preset)?,
            "Stage42 independently verified 8 GiB card tier must select native writer"
        );
        let supported16 = (0..4u8)
            .map(|i| (format!("{i:032x}.nca"), 2080 * 1024 * 1024u64))
            .collect::<Vec<_>>();
        assert!(
            native_xci::supports_virtual_sources(&supported16, preset)?,
            "Stage43 independent reference confirms native 16 GiB tier"
        );
        let supported32 = (0..4u8)
            .map(|i| (format!("{i:032x}.nca"), 4160 * 1024 * 1024u64))
            .collect::<Vec<_>>();
        assert!(
            native_xci::supports_virtual_sources(&supported32, preset)?,
            "Stage44 independent reference must allow the native 32 GiB card tier"
        );
        let entries = (0..4u8)
            .map(|i| (format!("{i:032x}.nca"), 8320 * 1024 * 1024u64))
            .collect::<Vec<_>>();
        assert!(
            !native_xci::supports_virtual_sources(&entries, preset)?,
            "unknown >32 GiB card tier must remain on fallback path"
        );
        let temp = tempfile::tempdir()?;
        let output = temp.path().join("old.xci");
        fs::write(&output, b"previous valid XCI stays intact")?;
        let selected = build_xci_virtual_verified(
            &output,
            &entries,
            &entries,
            preset,
            &AtomicBool::new(false),
            |_, _, _| panic!("never call entry writer for unsupported card tier"),
        )?;
        assert!(
            !selected,
            "unsupported card tier needs the established external fallback"
        );
        assert_eq!(fs::read(&output)?, b"previous valid XCI stays intact");
        assert_eq!(fs::read_dir(temp.path())?.count(), 1);
        Ok(())
    }

    #[test]
    fn stage37_xcz_publication_preserves_previous_output_on_error_or_cancel() -> Result<()> {
        let temp = tempfile::tempdir()?;
        let work = temp.path().join("source_work");
        for part in ["secure", "normal", "update"] {
            fs::create_dir_all(work.join(part))?;
        }
        for number in 0..4u8 {
            fs::write(
                work.join("secure").join(format!("{number:032x}.nca")),
                vec![number + 1; 256 * 1024],
            )?;
        }
        let input = temp.path().join("source.xci");
        let cancel = AtomicBool::new(false);
        native_xci::build_default_xci(&input, &work, &cancel)?;
        let output = temp.path().join("existing.xcz");
        fs::write(&output, b"old xcz must survive until validated publication")?;
        let options = XczOptions::default();
        let mut keys = KeySet::default();
        let mut logs = Vec::<String>::new();
        compress_xci_verified(&input, &output, &mut keys, &options, &cancel, &mut |line| {
            logs.push(line)
        })?;
        validate_xcz_against_xci(&input, &output, &cancel)?;
        assert_eq!(fs::read(&input)?, fs::read(&output)?);
        assert!(!fs::read_dir(temp.path())?.any(|entry| {
            entry.ok().is_some_and(|entry| {
                entry
                    .file_name()
                    .to_string_lossy()
                    .starts_with("nsrp_verified_xcz_")
            })
        }));
        let published = fs::read(&output)?;

        let stopped = AtomicBool::new(true);
        assert!(
            compress_xci_verified(&input, &output, &mut keys, &options, &stopped, &mut |_| {},)
                .is_err()
        );
        assert_eq!(fs::read(&output)?, published);
        let damaged = temp.path().join("broken_input.xci");
        fs::write(&damaged, b"invalid HFS0")?;
        assert!(
            compress_xci_verified(&damaged, &output, &mut keys, &options, &cancel, &mut |_| {},)
                .is_err()
        );
        assert_eq!(fs::read(&output)?, published);
        assert!(validate_xcz_against_xci(&input, &damaged, &cancel).is_err());

        // Publication must fail closed if the destination cannot be replaced.
        let locked = temp.path().join("non_file.xcz");
        fs::create_dir_all(&locked)?;
        fs::write(locked.join("keep.txt"), b"untouched")?;
        assert!(
            compress_xci_verified(&input, &locked, &mut keys, &options, &cancel, &mut |_| {},)
                .is_err()
        );
        assert_eq!(fs::read(locked.join("keep.txt"))?, b"untouched");
        assert_eq!(fs::read(&output)?, published);
        assert!(!fs::read_dir(temp.path())?.any(|entry| {
            entry.ok().is_some_and(|entry| {
                entry
                    .file_name()
                    .to_string_lossy()
                    .starts_with("nsrp_verified_xcz_")
            })
        }));
        Ok(())
    }

    #[test]
    fn direct_nsp_to_xci_matches_staged_builder_without_hacbuild_or_keys() -> Result<()> {
        let temp = tempfile::tempdir()?;
        let root = temp.path();
        let work = root.join("reference_work");
        for part in ["secure", "normal", "update"] {
            fs::create_dir_all(work.join(part))?;
        }
        let mut files = Vec::new();
        for i in 0..4u8 {
            let name = format!("{i:032x}.nca");
            let path = work.join("secure").join(&name);
            fs::write(&path, vec![i.wrapping_mul(37); 384 * 1024])?;
            files.push((name, path));
        }
        let nsp = root.join("game.nsp");
        crate::formats::pfs0::build_from_paths(&files, &nsp)?;
        let resource_dir = root.join("resources");
        fs::create_dir_all(resource_dir.join("bin"))?;
        fs::write(
            resource_dir.join("bin").join("game_info_preset.ini"),
            include_bytes!("../../bin/game_info_preset.ini"),
        )?;
        let cancel = AtomicBool::new(false);
        let direct = root.join("direct.xci");
        let mut logs = Vec::<String>::new();
        crate::ops::convert::build_xci_from_nsp(
            &nsp,
            &direct,
            &resource_dir,
            &root.join("not-present.keys"),
            &cancel,
            &mut |line| logs.push(line),
        )?;
        assert!(
            logs.iter().any(|line| line.contains("NSP 직접 스트리밍")),
            "Stage33 direct engine was not selected: {logs:?}"
        );
        let staged = root.join("staged_reference.xci");
        native_xci::build_default_xci(&staged, &work, &cancel)?;
        let left = fs::read(&direct)?;
        let right = fs::read(&staged)?;
        assert_eq!(left.len(), right.len());
        assert_eq!(&left[0x100..], &right[0x100..]);
        assert_eq!(hfs0::collect_leaf_entries(&direct, false)?.len(), 4);
        assert!(!resource_dir.join("bin").join("hacbuild.exe").exists());
        Ok(())
    }

    #[test]
    fn invalid_or_cancelled_source_range_keeps_previous_xci_byte_exact() -> Result<()> {
        let temp = tempfile::tempdir()?;
        let old = temp.path().join("existing.xci");
        let original = b"existing output must never be truncated";
        fs::write(&old, original)?;
        let region = temp.path().join("small.nsp");
        fs::write(&region, [0x55u8; 64])?;
        let mut sources = Vec::new();
        for i in 0..4u8 {
            sources.push(native_xci::XciSource {
                name: format!("{i:032x}.nca"),
                path: region.clone(),
                offset: 60,
                length: 384 * 1024,
            });
        }
        let expected = sources
            .iter()
            .map(|s| (s.name.clone(), s.length))
            .collect::<Vec<_>>();
        let info = include_bytes!("../../bin/game_info_preset.ini");
        assert!(
            build_xci_native_sources_verified(
                &old,
                &expected,
                &sources,
                info,
                &AtomicBool::new(false),
            )
            .is_err()
        );
        assert_eq!(fs::read(&old)?, original);
        assert!(
            build_xci_native_sources_verified(
                &old,
                &expected,
                &sources,
                info,
                &AtomicBool::new(true),
            )
            .is_err()
        );
        assert_eq!(fs::read(&old)?, original);
        assert_eq!(fs::read_dir(temp.path())?.count(), 2);
        Ok(())
    }

    /// Explicit 128 MiB disk benchmark of equivalent Stage32 full extraction
    /// and Stage33 direct-source XCI packaging. Runs only by QA request.
    #[test]
    #[ignore = "manual 128 MiB disk I/O benchmark"]
    fn stage33_direct_vs_staged_xci_benchmark() -> Result<()> {
        use sha2::{Digest, Sha256};
        use std::{
            io::{Read as _, Seek as _, SeekFrom, Write as _},
            time::Instant,
        };
        let temp = tempfile::tempdir()?;
        let root = temp.path();
        let mut source_files = Vec::new();
        for i in 0..4u8 {
            let name = format!("{i:032x}.nca");
            let path = root.join(&name);
            let mut output = File::create(&path)?;
            let chunk = vec![i + 5; 1024 * 1024];
            for _ in 0..32 {
                output.write_all(&chunk)?;
            }
            source_files.push((name, path));
        }
        let nsp = root.join("bench.nsp");
        crate::formats::pfs0::build_from_paths(&source_files, &nsp)?;
        let index = crate::formats::pfs0::Pfs0Index::parse(&nsp)?;
        let cancel = AtomicBool::new(false);
        let expected = index
            .entries
            .iter()
            .map(|e| (e.name.clone(), e.size))
            .collect::<Vec<_>>();

        // Recreate the Stage32 pre-extraction with the same bounded buffer.
        let work = root.join("stage32");
        for partition in ["secure", "update", "normal"] {
            fs::create_dir_all(work.join(partition))?;
        }
        let before_copy = Instant::now();
        let mut container = BufReader::with_capacity(8 * 1024 * 1024, File::open(&nsp)?);
        let mut buffer = vec![0u8; 8 * 1024 * 1024];
        for entry in &index.entries {
            container.seek(SeekFrom::Start(index.data_start + entry.offset))?;
            let mut out = BufWriter::new(File::create(work.join("secure").join(&entry.name))?);
            let mut remaining = entry.size;
            while remaining > 0 {
                let take = remaining.min(buffer.len() as u64) as usize;
                container.read_exact(&mut buffer[..take])?;
                out.write_all(&buffer[..take])?;
                remaining -= take as u64;
            }
            out.flush()?;
        }
        let stage32_copy_ms = before_copy.elapsed().as_millis();
        let prior = root.join("stage32.xci");
        let before_old_build = Instant::now();
        build_xci_verified(&prior, &expected, &cancel, |staged| {
            native_xci::build_default_xci(staged, &work, &cancel)
        })?;
        let stage32_build_ms = before_old_build.elapsed().as_millis();

        // The same payload ranges are read once directly from the original NSP.
        let direct_sources = index
            .entries
            .iter()
            .map(|entry| native_xci::XciSource {
                name: entry.name.clone(),
                path: nsp.clone(),
                offset: index.data_start + entry.offset,
                length: entry.size,
            })
            .collect::<Vec<_>>();
        let direct = root.join("stage33.xci");
        let before_direct = Instant::now();
        assert!(build_xci_native_sources_verified(
            &direct,
            &expected,
            &direct_sources,
            include_bytes!("../../bin/game_info_preset.ini"),
            &cancel,
        )?);
        let stage33_total_ms = before_direct.elapsed().as_millis();

        fn hash_payload(path: &Path) -> Result<[u8; 32]> {
            let mut source = BufReader::new(File::open(path)?);
            source.seek(SeekFrom::Start(0x100))?;
            let mut digest = Sha256::new();
            let mut buffer = vec![0u8; 1024 * 1024];
            loop {
                let bytes = source.read(&mut buffer)?;
                if bytes == 0 {
                    break;
                }
                digest.update(&buffer[..bytes]);
            }
            Ok(digest.finalize().into())
        }
        assert_eq!(hash_payload(&prior)?, hash_payload(&direct)?);
        println!(
            "STAGE33_BENCH source_nca_bytes={} stage32_copy_ms={} stage32_builder_ms={} stage32_total_ms={} stage33_direct_total_ms={} avoided_temp_nca_bytes={} output_bytes={}",
            4u64 * 32 * 1024 * 1024,
            stage32_copy_ms,
            stage32_build_ms,
            stage32_copy_ms + stage32_build_ms,
            stage33_total_ms,
            4u64 * 32 * 1024 * 1024,
            fs::metadata(&direct)?.len()
        );
        Ok(())
    }

    #[test]
    fn default_card_is_built_natively_without_any_external_tools_or_keys() -> Result<()> {
        let temp = tempfile::tempdir()?;
        let work = temp.path().join("work");
        for part in ["secure", "normal", "update"] {
            fs::create_dir_all(work.join(part))?;
        }
        let mut expected = Vec::new();
        for i in 0..4u8 {
            let name = format!("{i:032x}.nca");
            let contents = vec![i; 320 * 1024];
            fs::write(work.join("secure").join(&name), contents)?;
            expected.push((name, 320 * 1024));
        }
        let output = temp.path().join("built.xci");
        let engine = build_xci_auto_verified(
            &output,
            &expected,
            &work,
            temp.path(),
            &temp.path().join("missing-all-tools"),
            &temp.path().join("missing-prod.keys"),
            include_bytes!("../../bin/game_info_preset.ini"),
            &AtomicBool::new(false),
        )?;
        assert_eq!(engine, XciBuilder::NativeRust);
        validate_xci_payload(&output, &expected)?;
        assert!(!temp.path().join("tools").exists());
        assert!(!work.join("game_info.ini").exists());
        Ok(())
    }

    #[test]
    fn unavailable_hacbuild_preserves_existing_output() -> Result<()> {
        let temp = tempfile::tempdir()?;
        let work = temp.path().join("work");
        fs::create_dir_all(&work)?;
        let output = temp.path().join("old.xci");
        fs::write(&output, b"previous output is still valid")?;
        let result = build_xci_auto_verified(
            &output,
            &[("game.nca".to_owned(), 42)],
            &work,
            temp.path(),
            &temp.path().join("missing-resources"),
            &temp.path().join("missing.keys"),
            b"[XCI_Header]\r\n",
            &AtomicBool::new(false),
        );
        assert!(result.is_err());
        assert_eq!(fs::read(&output)?, b"previous output is still valid");
        assert!(!work.join("secure").exists());
        Ok(())
    }

    #[test]
    fn cancelled_hacbuild_does_not_copy_keys_or_change_output() -> Result<()> {
        let temp = tempfile::tempdir()?;
        let work = temp.path().join("work");
        fs::create_dir_all(&work)?;
        let output = temp.path().join("old.xci");
        fs::write(&output, b"previous output is still valid")?;
        let result = build_xci_auto_verified(
            &output,
            &[("game.nca".to_owned(), 42)],
            &work,
            temp.path(),
            &temp.path().join("missing-resources"),
            &temp.path().join("missing.keys"),
            b"[XCI_Header]\r\n",
            &AtomicBool::new(true),
        );
        assert!(result.is_err());
        assert_eq!(fs::read(&output)?, b"previous output is still valid");
        assert!(!temp.path().join("tools").exists());
        assert!(!work.join("game_info.ini").exists());
        Ok(())
    }

    fn synthetic_xci(path: &Path, nca_name: &str, nca_size: usize) -> Result<()> {
        let mut file = fs::OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .open(path)?;
        file.write_all(&[0u8; 0x200])?;
        let cancel = AtomicBool::new(false);
        hfs0::build_to_stream(
            &["secure".to_owned()],
            &mut file,
            0x200,
            1,
            &cancel,
            |_, root| {
                hfs0::build_to_stream(
                    &[nca_name.to_owned()],
                    root,
                    0x200,
                    1,
                    &cancel,
                    |_, leaf| {
                        leaf.write_all(&vec![0x52u8; nca_size])?;
                        Ok(())
                    },
                )?;
                Ok(())
            },
        )?;
        file.set_len(1024 * 1024 + 0x400)?;
        Ok(())
    }

    #[test]
    fn broken_builder_does_not_destroy_existing_xci() -> Result<()> {
        let temp = tempfile::tempdir()?;
        let target = temp.path().join("reusable.xci");
        let before = b"previous finished output".to_vec();
        fs::write(&target, &before)?;
        let cancel = AtomicBool::new(false);
        let expected = vec![("game.nca".to_owned(), 0xC00)];
        let error = build_xci_verified(&target, &expected, &cancel, |staged| {
            fs::write(staged, b"partial builder output")?;
            anyhow::bail!("simulated hacbuild failure")
        });
        assert!(error.is_err());
        assert_eq!(fs::read(&target)?, before);
        assert_eq!(fs::read_dir(temp.path())?.count(), 1);
        Ok(())
    }

    #[test]
    fn invalid_or_incomplete_xci_is_never_published() -> Result<()> {
        let temp = tempfile::tempdir()?;
        let target = temp.path().join("reusable.xci");
        fs::write(&target, b"verified older output")?;
        let cancel = AtomicBool::new(false);
        let expected = vec![("game.nca".to_owned(), 0xC00)];
        assert!(
            build_xci_verified(&target, &expected, &cancel, |staged| {
                synthetic_xci(staged, "wrong.nca", 0xC00)
            })
            .is_err()
        );
        assert_eq!(fs::read(&target)?, b"verified older output");
        assert_eq!(fs::read_dir(temp.path())?.count(), 1);
        Ok(())
    }

    #[test]
    fn cancelled_xci_does_not_publish_or_run_builder() -> Result<()> {
        let temp = tempfile::tempdir()?;
        let target = temp.path().join("reusable.xci");
        fs::write(&target, b"verified older output")?;
        let cancel = AtomicBool::new(true);
        let result =
            build_xci_verified(&target, &[("game.nca".to_owned(), 0xC00)], &cancel, |_| {
                anyhow::bail!("builder should not have run")
            });
        assert!(result.is_err());
        assert_eq!(fs::read(&target)?, b"verified older output");
        Ok(())
    }

    #[test]
    fn valid_xci_is_published_only_after_validation() -> Result<()> {
        let temp = tempfile::tempdir()?;
        let target = temp.path().join("reusable.xci");
        fs::write(&target, b"verified older output")?;
        let cancel = AtomicBool::new(false);
        build_xci_verified(
            &target,
            &[("game.nca".to_owned(), 0xC00)],
            &cancel,
            |staged| synthetic_xci(staged, "game.nca", 0xC00),
        )?;
        validate_xci_payload(&target, &[("game.nca".to_owned(), 0xC00)])?;
        assert_eq!(fs::read_dir(temp.path())?.count(), 1);
        Ok(())
    }

    #[test]
    fn verified_xci_commit_keeps_old_output_if_source_invalid() -> Result<()> {
        let temp = tempfile::tempdir()?;
        let old = temp.path().join("existing.xci");
        let bad = temp.path().join("bad.xci");
        fs::write(&old, b"old valid completed output")?;
        fs::write(&bad, b"truncated input")?;
        assert!(publish_verified_xci(&bad, &old, &AtomicBool::new(false)).is_err());
        assert_eq!(fs::read(&old)?, b"old valid completed output");
        assert!(bad.exists());
        Ok(())
    }

    #[cfg(windows)]
    #[test]
    fn stage44_locked_output_copy_fallback_preserves_old_and_source() -> Result<()> {
        use std::os::windows::fs::OpenOptionsExt;

        let temp = tempfile::tempdir()?;
        let existing = temp.path().join("existing.xci");
        let source = temp.path().join("new_source.xci");
        let old = b"previous completed gamecard output";
        fs::write(&existing, old)?;
        synthetic_xci(&source, "main.nca", 0xC00)?;
        let before = fs::read(&source)?;
        let lock = std::fs::OpenOptions::new()
            .read(true)
            .share_mode(0)
            .open(&existing)?;
        // The first rename fails because the destination is locked.
        // The copy fallback must not overwrite the previous output,
        // delete the source, or leak a partial temporary sibling.
        assert!(publish_verified_xci(&source, &existing, &AtomicBool::new(false)).is_err());
        drop(lock);
        assert_eq!(fs::read(&existing)?, old);
        assert_eq!(fs::read(&source)?, before);
        assert_eq!(fs::read_dir(temp.path())?.count(), 2);
        Ok(())
    }

    #[cfg(windows)]
    #[test]
    fn stage45_read_locked_source_uses_sha_verified_copy_fallback() -> Result<()> {
        use std::os::windows::fs::OpenOptionsExt;

        let root = tempfile::tempdir()?;
        let source = root.path().join("source.xci");
        let output = root.path().join("completed.xci");
        synthetic_xci(&source, "main.nca", 0xC00)?;
        let expected = fs::read(&source)?;
        fs::write(&output, b"previously completed image")?;
        // Readable, but not shared for deletion. Windows must use the
        // validated copy fallback instead of renaming this input.
        let read_lock = fs::OpenOptions::new()
            .read(true)
            .share_mode(0x1)
            .open(&source)?;
        publish_verified_xci(&source, &output, &AtomicBool::new(false))?;
        drop(read_lock);
        assert_eq!(fs::read(&output)?, expected);
        assert_eq!(fs::read(&source)?, expected);
        assert_eq!(fs::read_dir(root.path())?.count(), 2);
        Ok(())
    }

    #[test]
    fn stage45_copied_xci_full_digest_detects_payload_corruption() -> Result<()> {
        use std::io::{Seek, SeekFrom};

        let root = tempfile::tempdir()?;
        let source = root.path().join("source.xci");
        let previous = root.path().join("previous.xci");
        let original = b"previous complete destination is preserved";
        fs::write(&previous, original)?;
        let data = (0..3 * 1024 * 1024)
            .map(|idx| ((idx * 17 + idx / 29) % 251) as u8)
            .collect::<Vec<_>>();
        fs::write(&source, &data)?;
        let mut staged = tempfile::NamedTempFile::new_in(root.path())?;
        let cancel = AtomicBool::new(false);
        copy_xci_into_verified_staging(&source, &mut staged, &cancel)?;
        let hash: [u8; 32] = Sha256::digest(&data).into();
        verify_staged_xci_copy(staged.path(), data.len() as u64, hash, &cancel)?;

        staged
            .as_file_mut()
            .seek(SeekFrom::Start(data.len() as u64 / 2))?;
        staged.as_file_mut().write_all(&[0xfe])?;
        staged.as_file().sync_all()?;
        let error = verify_staged_xci_copy(staged.path(), data.len() as u64, hash, &cancel)
            .expect_err("A single byte flip must invalidate the copied XCI");
        ensure!(
            error.to_string().contains("SHA-256"),
            "Missing copied-output integrity diagnostic: {error:#}"
        );
        ensure!(
            verify_staged_xci_copy(staged.path(), data.len() as u64 - 1, hash, &cancel).is_err(),
            "Mismatching length must be rejected"
        );
        assert_eq!(fs::read(&source)?, data);
        assert_eq!(fs::read(&previous)?, original);
        drop(staged);
        assert_eq!(fs::read_dir(root.path())?.count(), 2);
        Ok(())
    }

    #[test]
    fn stage45_staged_xci_pre_cancel_leaves_existing_destination_intact() -> Result<()> {
        let root = tempfile::tempdir()?;
        let source = root.path().join("source.xci");
        let output = root.path().join("output.xci");
        fs::write(&source, vec![0xa2u8; 65_536])?;
        let before = b"verified previous XCI";
        fs::write(&output, before)?;
        let mut staged = tempfile::NamedTempFile::new_in(root.path())?;
        let canceled = AtomicBool::new(true);
        assert!(
            copy_xci_into_verified_staging(&source, &mut staged, &canceled).is_err(),
            "Canceled copy must never begin writing"
        );
        assert_eq!(staged.as_file().metadata()?.len(), 0);
        drop(staged);
        assert_eq!(fs::read(&output)?, before);
        assert_eq!(fs::read_dir(root.path())?.count(), 2);
        Ok(())
    }

    #[test]
    fn stage46_same_length_source_mutation_during_copy_is_rejected() -> Result<()> {
        use std::io::{Seek, SeekFrom};

        let temp = tempfile::tempdir()?;
        let source = temp.path().join("candidate.xci");
        let old = temp.path().join("previous.xci");
        let original = b"previous complete XCI retained after source changes";
        fs::write(&old, original)?;
        let bytes = (0..4 * 1024 * 1024)
            .map(|i| ((i * 13 + i / 37) % 251) as u8)
            .collect::<Vec<_>>();
        fs::write(&source, &bytes)?;
        let mut staged = tempfile::NamedTempFile::new_in(temp.path())?;
        let mut changed = false;
        let failure = copy_xci_into_verified_staging_with_hook(
            &source,
            &mut staged,
            &AtomicBool::new(false),
            |copied| {
                if !changed && copied >= 1024 * 1024 {
                    let mut writer = fs::OpenOptions::new().write(true).open(&source)?;
                    writer.seek(SeekFrom::Start(3 * 1024 * 1024 + 17))?;
                    writer.write_all(&[0x9f])?;
                    writer.sync_all()?;
                    changed = true;
                }
                Ok(())
            },
        )
        .expect_err("Same-length payload modification during copy must fail closed");
        ensure!(changed, "The staged source mutation hook never fired");
        ensure!(
            failure.to_string().contains("source SHA-256 changed"),
            "Expected SHA mismatch, received {failure:#}"
        );
        assert_eq!(fs::metadata(&source)?.len(), bytes.len() as u64);
        assert_ne!(fs::read(&source)?, bytes);
        assert_eq!(fs::read(&old)?, original);
        drop(staged);
        assert_eq!(fs::read_dir(temp.path())?.count(), 2);
        Ok(())
    }

    #[test]
    fn stage46_source_truncation_during_copy_preserves_previous_output() -> Result<()> {
        let temp = tempfile::tempdir()?;
        let source = temp.path().join("candidate.xci");
        let old = temp.path().join("previous.xci");
        let original = b"previous complete XCI must survive";
        fs::write(&old, original)?;
        fs::write(&source, vec![0x61; 4 * 1024 * 1024])?;
        let mut staged = tempfile::NamedTempFile::new_in(temp.path())?;
        let mut truncated = false;
        let err = copy_xci_into_verified_staging_with_hook(
            &source,
            &mut staged,
            &AtomicBool::new(false),
            |copied| {
                if !truncated && copied >= 1024 * 1024 {
                    let file = fs::OpenOptions::new().write(true).open(&source)?;
                    file.set_len(2 * 1024 * 1024)?;
                    truncated = true;
                }
                Ok(())
            },
        )
        .expect_err("Truncated source must not produce a publishable output");
        assert!(truncated);
        ensure!(
            err.to_string().contains("source shortened"),
            "Expected source length diagnostic: {err:#}"
        );
        assert_eq!(fs::read(&old)?, original);
        drop(staged);
        assert_eq!(fs::read_dir(temp.path())?.count(), 2);
        Ok(())
    }

    #[test]
    fn stage46_same_source_and_destination_is_rejected_without_changes() -> Result<()> {
        let temp = tempfile::tempdir()?;
        let file = temp.path().join("same.xci");
        synthetic_xci(&file, "main.nca", 0xC00)?;
        let original = fs::read(&file)?;
        let err = publish_verified_xci(&file, &file, &AtomicBool::new(false))
            .expect_err("Publishing XCI onto itself must be disallowed");
        assert!(err.to_string().contains("different files"));
        assert_eq!(fs::read(&file)?, original);
        assert_eq!(fs::read_dir(temp.path())?.count(), 1);
        Ok(())
    }

    #[cfg(windows)]
    #[test]
    fn stage46_hardlink_alias_source_destination_is_rejected() -> Result<()> {
        let temp = tempfile::tempdir()?;
        let file = temp.path().join("first.xci");
        let alias = temp.path().join("same_inode.xci");
        synthetic_xci(&file, "main.nca", 0xC00)?;
        fs::hard_link(&file, &alias)?;
        let original = fs::read(&file)?;
        let err = publish_verified_xci(&file, &alias, &AtomicBool::new(false))
            .expect_err("Hard-linked alias of source must not be overwritten");
        ensure!(
            err.to_string().contains("same underlying file"),
            "Expected alias rejection, received {err:#}"
        );
        assert_eq!(fs::read(&file)?, original);
        assert_eq!(fs::read(&alias)?, original);
        assert_eq!(fs::read_dir(temp.path())?.count(), 2);
        Ok(())
    }

    #[test]
    fn verified_xci_commit_publishes_valid_candidate() -> Result<()> {
        let temp = tempfile::tempdir()?;
        let old = temp.path().join("existing.xci");
        let next = temp.path().join("next.xci");
        fs::write(&old, b"old valid completed output")?;
        synthetic_xci(&next, "main.nca", 0xC00)?;
        publish_verified_xci(&next, &old, &AtomicBool::new(false))?;
        validate_xci_payload(&old, &[("main.nca".to_owned(), 0xC00)])?;
        assert!(!next.exists());
        Ok(())
    }
}
