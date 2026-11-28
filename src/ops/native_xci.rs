//! Verified, conservative Rust XCI card-image writer.
//!
//! The default-game-info layout here was independently checked against
//! three disposable hacbuild v1.1 XCI images. The 0x70-byte encrypted
//! GameCard_Info fixture is not a secret key: it is the constant output of
//! hacbuild for NSRP's bundled public game_info_preset.ini. We only use it
//! when the preset bytes match exactly. Any custom game info, nonempty
//! system partition or unverified capacity uses the existing external tool.
//!
//! Just like hacbuild, this creates a *non-retail-signed* card header. It
//! does not forge a valid Nintendo RSA signature.

use crate::formats::hfs0::{self, Hfs0Index};
use anyhow::{Context, Result, bail, ensure};
use sha2::{Digest, Sha256};
use std::{
    collections::HashSet,
    fs::{self, File, OpenOptions},
    io::{Read, Seek, SeekFrom, Write},
    path::{Path, PathBuf},
    sync::atomic::{AtomicBool, Ordering},
};

const ROOT_OFFSET: u64 = 0xF000;
const ROOT_HASH_SIZE: u64 = 0x200;
const HEADER_SIZE: usize = 0x200;
const CARD_2GIB: u64 = 2 * 1024 * 1024 * 1024;
const CARD_4GIB: u64 = 4 * 1024 * 1024 * 1024;
const CARD_8GIB: u64 = 8 * 1024 * 1024 * 1024;
const CARD_16GIB: u64 = 16 * 1024 * 1024 * 1024;
const CARD_32GIB: u64 = 32 * 1024 * 1024 * 1024;
const CARD_HEADROOM: u64 = 8 * 1024 * 1024;
const SYSTEM_FILL_START: u64 = 0x7000;
const SYSTEM_FILL_BYTES: usize = 0x8000;
const GAMECARD_DEFAULT_INFO: &[u8; 0x70] = include_bytes!("default_xci_gamecard_info.bin");
const GAME_INFO_PRESET: &[u8] = include_bytes!("../../bin/game_info_preset.ini");
const PACKAGE_ID: u64 = 10_492_310_773_436_918_493;
const GAMECARD_IV: [u8; 16] = [
    0x6a, 0x6c, 0xca, 0x77, 0x93, 0x17, 0x52, 0x50, 0x4f, 0xf2, 0xa7, 0x48, 0x3c, 0xff, 0x81, 0x8a,
];
const INITIAL_DATA_HASH: [u8; 32] = [
    0x09, 0x47, 0xc7, 0x9d, 0x01, 0xc1, 0x93, 0xb3, 0xc9, 0xa7, 0x70, 0xf6, 0xe6, 0x23, 0x73, 0x4b,
    0xc6, 0x19, 0x18, 0x4a, 0xc4, 0xce, 0x48, 0x8d, 0x6f, 0x07, 0xab, 0xbb, 0xae, 0x53, 0xb9, 0x59,
];

/// The card-size codes are checked against independently built hacbuild
/// reference output. Stage40 verified 4 GiB (0xF0); Stage42 independently
/// observed 8 GiB (0xE0) on a 4,362,139,648-byte synthetic XCI. Stage43
/// independently observed 16 GiB (0xE1) on an 8,724,215,808-byte XCI.
/// Stage44 independently observed 32 GiB (0xE2) on a
/// 17,448,368,128-byte synthetic XCI.
/// Keep 8 MiB of headroom and fail closed in unverified capacity boundaries.
fn verified_card_tier(logical_bytes: u64) -> Option<(u64, u8)> {
    if logical_bytes <= CARD_2GIB - CARD_HEADROOM {
        Some((CARD_2GIB, 0xf8))
    } else if logical_bytes > CARD_2GIB && logical_bytes <= CARD_4GIB - CARD_HEADROOM {
        Some((CARD_4GIB, 0xf0))
    } else if logical_bytes > CARD_4GIB && logical_bytes <= CARD_8GIB - CARD_HEADROOM {
        Some((CARD_8GIB, 0xe0))
    } else if logical_bytes > CARD_8GIB && logical_bytes <= CARD_16GIB - CARD_HEADROOM {
        Some((CARD_16GIB, 0xe1))
    } else if logical_bytes > CARD_16GIB && logical_bytes <= CARD_32GIB - CARD_HEADROOM {
        Some((CARD_32GIB, 0xe2))
    } else {
        None
    }
}

/// Source bytes may live inside an existing NSP or in a standalone file.
/// Native output never materializes a second copy of these NCA bytes.
#[derive(Debug, Clone)]
pub(crate) struct XciSource {
    pub name: String,
    pub path: PathBuf,
    pub offset: u64,
    pub length: u64,
}

fn inspect_supported_sources(
    sources: &[XciSource],
    game_info: &[u8],
) -> Result<Option<Vec<XciSource>>> {
    // The encrypted default info bytes are valid only for the bundled preset.
    if game_info != GAME_INFO_PRESET || sources.is_empty() || sources.len() > 16_384 {
        return Ok(None);
    }
    let mut files = Vec::with_capacity(sources.len());
    let mut names = HashSet::new();
    let mut bytes = ROOT_OFFSET;
    let mut nca_count = 0usize;
    for source in sources {
        let metadata = fs::symlink_metadata(&source.path)?;
        if !metadata.is_file() || metadata.file_type().is_symlink() {
            return Ok(None);
        }
        let name = source.name.as_str();
        if name.is_empty()
            || name == "."
            || name == ".."
            || name.contains('/')
            || name.contains('\\')
        {
            return Ok(None);
        }
        let lower = name.to_ascii_lowercase();
        if !lower.ends_with(".nca") && !lower.ends_with(".tik") && !lower.ends_with(".cert") {
            return Ok(None);
        }
        let is_nca = lower.ends_with(".nca");
        if !names.insert(lower) {
            bail!("Duplicate XCI secure-partition file: {name}");
        }
        if is_nca {
            nca_count += 1;
        }
        let end = source
            .offset
            .checked_add(source.length)
            .context("XCI 원본 영역 오프셋 오버플로")?;
        ensure!(
            end <= metadata.len(),
            "XCI 원본 영역이 파일 크기를 벗어났습니다: {name}"
        );
        bytes = bytes
            .checked_add(source.length)
            .context("Native XCI file-size overflow")?;
        files.push(source.clone());
    }
    if nca_count == 0 {
        return Ok(None);
    }
    // Up to the independently observed 32 GiB tier is permitted only for
    // the verified default card layout.
    if verified_card_tier(bytes).is_none() {
        return Ok(None);
    }
    files.sort_by(|a, b| {
        a.name
            .to_ascii_lowercase()
            .cmp(&b.name.to_ascii_lowercase())
    });
    Ok(Some(files))
}

fn inspect_supported_layout(work_root: &Path, game_info: &[u8]) -> Result<Option<Vec<XciSource>>> {
    for part in ["update", "normal"] {
        let path = work_root.join(part);
        if !path.is_dir() || fs::read_dir(&path)?.next().is_some() {
            return Ok(None);
        }
    }
    if work_root.join("logo").exists() {
        return Ok(None);
    }
    let secure = work_root.join("secure");
    if !secure.is_dir() {
        return Ok(None);
    }
    let mut sources = Vec::new();
    for entry in fs::read_dir(&secure)? {
        let path = entry?.path();
        let Some(name) = path.file_name().and_then(|n| n.to_str()) else {
            return Ok(None);
        };
        sources.push(XciSource {
            name: name.to_owned(),
            length: fs::symlink_metadata(&path)?.len(),
            path,
            offset: 0,
        });
    }
    inspect_supported_sources(&sources, game_info)
}

/// Check whether native output is proven for this exact format. Call this
/// before attempting to publish; unsupported inputs use hacbuild unchanged.
pub(crate) fn supports_layout(work_root: &Path, game_info: &[u8]) -> Result<bool> {
    Ok(inspect_supported_layout(work_root, game_info)?.is_some())
}

pub(crate) fn supports_sources(sources: &[XciSource], game_info: &[u8]) -> Result<bool> {
    Ok(inspect_supported_sources(sources, game_info)?.is_some())
}

/// Virtual secure-partition sources are decoded directly into an XCI stream.
/// Each tuple is the on-card filename and *reconstructed* byte length. This
/// format gate is deliberately the same as the Stage32 native card tier.
fn inspect_virtual_sources(
    sources: &[(String, u64)],
    game_info: &[u8],
) -> Result<Option<Vec<usize>>> {
    if game_info != GAME_INFO_PRESET || sources.is_empty() || sources.len() > 16_384 {
        return Ok(None);
    }
    let mut names = HashSet::new();
    let mut ncas = 0usize;
    let mut total = ROOT_OFFSET;
    for (name, size) in sources {
        let lower = name.to_ascii_lowercase();
        if name.is_empty()
            || name == "."
            || name == ".."
            || name.contains('/')
            || name.contains('\\')
            || !matches!(
                lower.rsplit_once('.').map(|(_, extension)| extension),
                Some("nca" | "tik" | "cert")
            )
        {
            return Ok(None);
        }
        if !names.insert(lower) {
            bail!("Duplicate virtual XCI secure-partition entry: {name}");
        }
        if name.to_ascii_lowercase().ends_with(".nca") {
            ncas += 1;
        }
        total = total
            .checked_add(*size)
            .context("Native XCI virtual decoded-size overflow")?;
    }
    if ncas == 0 || verified_card_tier(total).is_none() {
        return Ok(None);
    }
    let mut order = (0..sources.len()).collect::<Vec<_>>();
    order.sort_by_key(|i| sources[*i].0.to_ascii_lowercase());
    Ok(Some(order))
}

pub(crate) fn supports_virtual_sources(
    sources: &[(String, u64)],
    game_info: &[u8],
) -> Result<bool> {
    Ok(inspect_virtual_sources(sources, game_info)?.is_some())
}

fn write_empty_partition(file: &mut File) -> Result<()> {
    file.write_all(b"HFS0")?;
    file.write_all(&0u32.to_le_bytes())?;
    // The empty 0x200-byte partition encodes the zero-padding as the
    // string-table size; this matches independently generated hacbuild HFS0.
    file.write_all(&0x1F0u32.to_le_bytes())?;
    file.write_all(&0u32.to_le_bytes())?;
    file.write_all(&[0u8; 0x1F0])?;
    Ok(())
}

fn pad_to_sector(file: &mut File) -> Result<()> {
    let position = file.stream_position()?;
    let padding = (0x200 - (position % 0x200)) % 0x200;
    if padding != 0 {
        file.write_all(&[0u8; 0x200][..padding as usize])?;
    }
    Ok(())
}

fn copy_file_verified(
    file: &mut File,
    source: &XciSource,
    cancel: &AtomicBool,
    buf: &mut [u8],
) -> Result<()> {
    let mut input = File::open(&source.path)?;
    input.seek(SeekFrom::Start(source.offset))?;
    let mut copied = 0u64;
    while copied < source.length {
        ensure!(!cancel.load(Ordering::Relaxed), "작업이 중단되었습니다");
        let chunk = (source.length - copied).min(buf.len() as u64) as usize;
        input.read_exact(&mut buf[..chunk])?;
        file.write_all(&buf[..chunk])?;
        copied = copied
            .checked_add(chunk as u64)
            .context("XCI copy overflow")?;
    }
    ensure!(copied == source.length, "XCI content was truncated");
    Ok(())
}

/// Build inside an exclusively owned staging file, *not* at a user path.
/// The common XCI publisher validates its secure HFS0 and atomically commits.
pub(crate) fn build_default_xci(
    staged: &Path,
    work_root: &Path,
    cancel: &AtomicBool,
) -> Result<()> {
    ensure!(!cancel.load(Ordering::Relaxed), "작업이 중단되었습니다");
    let files = inspect_supported_layout(work_root, GAME_INFO_PRESET)?
        .context("Native XCI layout not supported")?;
    build_default_xci_verified_files(staged, &files, cancel)
}

/// Write native XCI from bounded source regions rather than per-NCA copies.
pub(crate) fn build_default_xci_from_sources(
    staged: &Path,
    sources: &[XciSource],
    game_info: &[u8],
    cancel: &AtomicBool,
) -> Result<()> {
    ensure!(!cancel.load(Ordering::Relaxed), "작업이 중단되었습니다");
    let files = inspect_supported_sources(sources, game_info)?
        .context("Native XCI source layout not supported")?;
    build_default_xci_verified_files(staged, &files, cancel)
}

fn build_default_xci_verified_files(
    staged: &Path,
    files: &[XciSource],
    cancel: &AtomicBool,
) -> Result<()> {
    let names = files
        .iter()
        .map(|entry| entry.name.clone())
        .collect::<Vec<_>>();
    // Reuse one heap buffer for all NCA ranges instead of allocating a
    // BufReader and a second 1 MiB buffer for every individual entry.
    let mut buffer = vec![0u8; 1024 * 1024];
    build_default_xci_streamed_contents(staged, &names, cancel, |index, output| {
        copy_file_verified(output, &files[index], cancel, &mut buffer)
    })
}

/// Write secure NCA entries directly to the card image, without materializing
/// decoded NCZ files. The entry writer must finish at the exact declared
/// output position; HFS0 hashes are computed *after* it returns, so a
/// verified legacy NCA header can be patched while still in this callback.
pub(crate) fn build_default_xci_from_virtual_sources<F>(
    staged: &Path,
    sources: &[(String, u64)],
    game_info: &[u8],
    cancel: &AtomicBool,
    mut write_entry: F,
) -> Result<()>
where
    F: FnMut(usize, &mut File) -> Result<()>,
{
    let ordered = inspect_virtual_sources(sources, game_info)?
        .context("Native XCI virtual layout not supported")?;
    let names = ordered
        .iter()
        .map(|index| sources[*index].0.clone())
        .collect::<Vec<_>>();
    build_default_xci_streamed_contents(staged, &names, cancel, |sorted_index, out| {
        let original_index = ordered[sorted_index];
        let expected_size = sources[original_index].1;
        let start = out.stream_position()?;
        write_entry(original_index, out)?;
        let written = out
            .stream_position()?
            .checked_sub(start)
            .context("Virtual XCI writer moved backwards")?;
        ensure!(
            written == expected_size,
            "Virtual XCI NCA entry size mismatch: {} (expected {expected_size}, got {written})",
            sources[original_index].0
        );
        Ok(())
    })
}

fn build_default_xci_streamed_contents<F>(
    staged: &Path,
    secure_names: &[String],
    cancel: &AtomicBool,
    mut write_entry: F,
) -> Result<()>
where
    F: FnMut(usize, &mut File) -> Result<()>,
{
    ensure!(!cancel.load(Ordering::Relaxed), "작업이 중단되었습니다");
    let mut output = OpenOptions::new()
        .read(true)
        .write(true)
        .create_new(true)
        .open(staged)
        .context("Native XCI staging-file creation failed")?;

    output.set_len(ROOT_OFFSET)?;
    output.seek(SeekFrom::Start(SYSTEM_FILL_START))?;
    output.write_all(&[0xffu8; SYSTEM_FILL_BYTES])?;
    output.seek(SeekFrom::Start(ROOT_OFFSET))?;

    let partition_names = ["update".into(), "normal".into(), "secure".into()];
    let mut secure_start = None::<u64>;
    hfs0::build_to_stream(
        &partition_names,
        &mut output,
        0x200,
        0x200,
        cancel,
        |i, file| {
            match i {
                0 | 1 => write_empty_partition(file)?,
                2 => {
                    secure_start = Some(file.stream_position()?);
                    hfs0::build_to_stream(secure_names, file, 0x200, 0x200, cancel, |j, file| {
                        write_entry(j, file)
                    })?;
                    // The root secure entry includes trailing sector padding,
                    // while its individual ticket/certificate entries do not.
                    pad_to_sector(file)?;
                }
                _ => bail!("Unexpected XCI partition"),
            }
            Ok(())
        },
    )?;
    let end = output.stream_position()?;
    let secure_start = secure_start.context("XCI secure-partition start missing")?;
    let (capacity, card_size_code) = verified_card_tier(end)
        .context("Unverified XCI card capacity or insufficient capacity headroom")?;
    ensure!(
        end > ROOT_OFFSET && end <= capacity,
        "Unverified XCI card capacity"
    );
    ensure!(
        end.is_multiple_of(0x200),
        "Native XCI sector-alignment failure"
    );
    ensure!(
        secure_start.is_multiple_of(0x200),
        "Invalid secure XCI sector alignment"
    );

    output.seek(SeekFrom::Start(ROOT_OFFSET))?;
    let mut root_header = [0u8; ROOT_HASH_SIZE as usize];
    output.read_exact(&mut root_header)?;
    let root_hash = Sha256::digest(root_header);
    let last_sector = u32::try_from(end.div_ceil(0x200) - 1)?;
    let secure_sector = u32::try_from(secure_start / 0x200)?;
    let mut header = [0u8; HEADER_SIZE];
    // Reference hacbuild also emits a freshly random, invalid RSA signature
    // for each run. It is not a genuine cryptographic gamecard signature.
    getrandom::fill(&mut header[..0x100])
        .map_err(|err| anyhow::anyhow!("XCI signature filler RNG failure: {err}"))?;
    header[0x100..0x104].copy_from_slice(b"HEAD");
    header[0x104..0x108].copy_from_slice(&secure_sector.to_le_bytes());
    header[0x108..0x10c].fill(0xff);
    header[0x10d] = card_size_code;
    header[0x110..0x118].copy_from_slice(&PACKAGE_ID.to_le_bytes());
    header[0x118..0x11c].copy_from_slice(&last_sector.to_le_bytes());
    header[0x120..0x130].copy_from_slice(&GAMECARD_IV);
    header[0x130..0x138].copy_from_slice(&ROOT_OFFSET.to_le_bytes());
    header[0x138..0x140].copy_from_slice(&ROOT_HASH_SIZE.to_le_bytes());
    header[0x140..0x160].copy_from_slice(&root_hash);
    header[0x160..0x180].copy_from_slice(&INITIAL_DATA_HASH);
    header[0x180..0x184].copy_from_slice(&1u32.to_le_bytes());
    header[0x184..0x188].copy_from_slice(&2u32.to_le_bytes());
    header[0x18c..0x190].copy_from_slice(&secure_sector.to_le_bytes());
    header[0x190..0x200].copy_from_slice(GAMECARD_DEFAULT_INFO);
    ensure!(!cancel.load(Ordering::Relaxed), "작업이 중단되었습니다");
    output.seek(SeekFrom::Start(0))?;
    output.write_all(&header)?;
    output.flush()?;
    output.sync_all()?;

    // Verify the card-header/root linkage before handing the image to the
    // common authenticated source-list and atomic destination validation.
    let (root, header_base) = hfs0::find_xci_root_with_header_base(staged)?;
    ensure!(
        root.base == ROOT_OFFSET && header_base == Some(0),
        "Native XCI root mismatch"
    );
    let secure = root
        .entry("secure")
        .context("Native XCI has no secure partition")?;
    ensure!(
        root.data_start + secure.offset == secure_start,
        "XCI secure header offset mismatch"
    );
    let mut f = File::open(staged)?;
    let _ = Hfs0Index::parse_at(&mut f, secure_start, end)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::BufReader;

    #[test]
    fn stage44_card_capacity_boundaries_have_explicit_verified_tiers() {
        assert_eq!(
            verified_card_tier(CARD_2GIB - CARD_HEADROOM),
            Some((CARD_2GIB, 0xf8))
        );
        assert_eq!(verified_card_tier(CARD_2GIB - CARD_HEADROOM + 1), None);
        assert_eq!(verified_card_tier(CARD_2GIB), None);
        assert_eq!(verified_card_tier(CARD_2GIB + 1), Some((CARD_4GIB, 0xf0)));
        assert_eq!(
            verified_card_tier(CARD_4GIB - CARD_HEADROOM),
            Some((CARD_4GIB, 0xf0))
        );
        assert_eq!(verified_card_tier(CARD_4GIB - CARD_HEADROOM + 1), None);
        assert_eq!(verified_card_tier(CARD_4GIB), None);
        assert_eq!(verified_card_tier(CARD_4GIB + 1), Some((CARD_8GIB, 0xe0)));
        assert_eq!(
            verified_card_tier(CARD_8GIB - CARD_HEADROOM),
            Some((CARD_8GIB, 0xe0))
        );
        assert_eq!(verified_card_tier(CARD_8GIB - CARD_HEADROOM + 1), None);
        assert_eq!(verified_card_tier(CARD_8GIB), None);
        assert_eq!(verified_card_tier(CARD_8GIB + 1), Some((CARD_16GIB, 0xe1)));
        assert_eq!(
            verified_card_tier(CARD_16GIB - CARD_HEADROOM),
            Some((CARD_16GIB, 0xe1))
        );
        assert_eq!(verified_card_tier(CARD_16GIB - CARD_HEADROOM + 1), None);
        assert_eq!(verified_card_tier(CARD_16GIB), None);
        assert_eq!(verified_card_tier(CARD_16GIB + 1), Some((CARD_32GIB, 0xe2)));
        assert_eq!(
            verified_card_tier(CARD_32GIB - CARD_HEADROOM),
            Some((CARD_32GIB, 0xe2))
        );
        assert_eq!(verified_card_tier(CARD_32GIB - CARD_HEADROOM + 1), None);
        assert_eq!(verified_card_tier(CARD_32GIB), None);
        assert_eq!(verified_card_tier(u64::MAX), None);
    }

    /// Compare the complete signed-header-excluded native XCI against an
    /// independently generated hacbuild v1.1 reference, across any card tier.
    /// This does not claim Nintendo retail RSA validity or hardware boot.
    fn compare_default_card_reference(
        path: &Path,
        reference_name: &str,
        native_name: &str,
        lower: u64,
        upper: u64,
        expected_code: u8,
        marker: &str,
    ) -> Result<()> {
        ensure!(
            path.to_string_lossy().contains("SAFETY"),
            "Refusing to create a large synthetic XCI outside an isolated safety directory"
        );
        let reference = path.join(reference_name);
        let work = path.join("work");
        let reference_len = fs::metadata(&reference)?.len();
        ensure!(
            reference_len > lower && reference_len < upper,
            "Independent XCI reference length is outside requested card tier"
        );
        ensure!(
            supports_layout(&work, GAME_INFO_PRESET)?,
            "Native writer must select independently verified card tier"
        );
        // Confirm the reference's card code before spending I/O on a large
        // duplicate. The full comparison below authenticates that byte too.
        let mut reference_head = File::open(&reference)?;
        reference_head.seek(SeekFrom::Start(0x10d))?;
        let mut reference_code = [0u8];
        reference_head.read_exact(&mut reference_code)?;
        ensure!(
            reference_code[0] == expected_code,
            "Independent builder uses unexpected card capacity code"
        );
        let result = path.join(native_name);
        ensure!(
            !result.exists(),
            "Refusing to overwrite existing synthetic card-image QA output"
        );
        build_default_xci(&result, &work, &AtomicBool::new(false))?;
        ensure!(
            fs::metadata(&result)?.len() == reference_len,
            "Native and hacbuild size differ"
        );
        let mut expected = BufReader::with_capacity(1024 * 1024, File::open(&reference)?);
        let mut actual = BufReader::with_capacity(1024 * 1024, File::open(&result)?);
        expected.seek(SeekFrom::Start(0x100))?;
        actual.seek(SeekFrom::Start(0x100))?;
        let mut expected_chunk = vec![0u8; 1024 * 1024];
        let mut actual_chunk = vec![0u8; 1024 * 1024];
        let mut position = 0x100u64;
        while position < reference_len {
            let size = (reference_len - position).min(expected_chunk.len() as u64) as usize;
            expected.read_exact(&mut expected_chunk[..size])?;
            actual.read_exact(&mut actual_chunk[..size])?;
            if let Some(offset) = expected_chunk[..size]
                .iter()
                .zip(&actual_chunk[..size])
                .position(|(x, y)| x != y)
            {
                bail!(
                    "Native tier differs from independent hacbuild reference at offset {:#x}: native={:#x} reference={:#x}",
                    position + offset as u64,
                    actual_chunk[offset],
                    expected_chunk[offset]
                );
            }
            position += size as u64;
        }
        eprintln!(
            "{marker} bytes={reference_len} compared_from=0x100 card_code={expected_code:#x}"
        );
        Ok(())
    }

    /// Retained Stage40 regression; reference files are intentionally deleted
    /// after successful independent verification.
    #[test]
    #[ignore = "requires isolated Stage40 2 GiB-plus hacbuild reference directory"]
    fn stage40_native_4gib_xci_matches_hacbuild_reference_except_unsigned_signature() -> Result<()>
    {
        let root = PathBuf::from(
            std::env::var_os("NSRP_STAGE40_CARD_REFERENCE_DIR")
                .context("NSRP_STAGE40_CARD_REFERENCE_DIR QA directory required")?,
        );
        compare_default_card_reference(
            &root,
            "reference_over2gib.xci",
            "native_over2gib.xci",
            CARD_2GIB,
            CARD_4GIB,
            0xf0,
            "STAGE40_NATIVE_4GIB_HACBUILD_EXACT_MATCH",
        )
    }

    #[test]
    #[ignore = "requires independent Stage42 4GiB-plus hacbuild reference in isolated SAFETY directory"]
    fn stage42_native_8gib_xci_matches_hacbuild_reference_except_unsigned_signature() -> Result<()>
    {
        let root = PathBuf::from(
            std::env::var_os("NSRP_STAGE42_CARD_REFERENCE_DIR")
                .context("NSRP_STAGE42_CARD_REFERENCE_DIR QA directory required")?,
        );
        compare_default_card_reference(
            &root,
            "reference_over4gib.xci",
            "native_over4gib.xci",
            CARD_4GIB,
            CARD_8GIB,
            0xe0,
            "STAGE42_NATIVE_8GIB_HACBUILD_EXACT_MATCH",
        )
    }

    #[test]
    #[ignore = "requires independent Stage43 8GiB-plus hacbuild reference in isolated SAFETY directory"]
    fn stage43_native_16gib_xci_matches_hacbuild_reference_except_unsigned_signature() -> Result<()>
    {
        let root = PathBuf::from(
            std::env::var_os("NSRP_STAGE43_CARD_REFERENCE_DIR")
                .context("NSRP_STAGE43_CARD_REFERENCE_DIR QA directory required")?,
        );
        compare_default_card_reference(
            &root,
            "reference_over8gib.xci",
            "native_over8gib.xci",
            CARD_8GIB,
            CARD_16GIB,
            0xe1,
            "STAGE43_NATIVE_16GIB_HACBUILD_EXACT_MATCH",
        )
    }

    #[test]
    #[ignore = "requires Stage44 isolated independent 16GiB-plus hacbuild reference"]
    fn stage44_native_32gib_xci_matches_hacbuild_reference_except_unsigned_signature() -> Result<()>
    {
        let root = PathBuf::from(
            std::env::var_os("NSRP_STAGE44_CARD_REFERENCE_DIR")
                .context("NSRP_STAGE44_CARD_REFERENCE_DIR isolated QA directory required")?,
        );
        compare_default_card_reference(
            &root,
            "reference_over16gib.xci",
            "native_over16gib.xci",
            CARD_16GIB,
            CARD_32GIB,
            0xe2,
            "STAGE44_NATIVE_32GIB_HACBUILD_EXACT_MATCH",
        )
    }

    #[test]
    fn virtual_writer_recomputes_hfs0_after_in_place_header_recovery() -> Result<()> {
        let root = tempfile::tempdir()?;
        let sources = (0u8..4)
            .map(|n| (format!("{n:032x}.nca"), 320 * 1024u64))
            .collect::<Vec<_>>();
        let xci = root.path().join("virtual.xci");
        assert!(supports_virtual_sources(&sources, GAME_INFO_PRESET)?);
        build_default_xci_from_virtual_sources(
            &xci,
            &sources,
            GAME_INFO_PRESET,
            &AtomicBool::new(false),
            |i, file| {
                let start = file.stream_position()?;
                let bytes = vec![i as u8 + 31; sources[i].1 as usize];
                file.write_all(&bytes)?;
                if i == 0 {
                    // A legacy NCA header gets repaired before the HFS0
                    // writer calculates its 0x200-byte prefix hash.
                    file.seek(SeekFrom::Start(start))?;
                    file.write_all(b"VERIFIED")?;
                    file.seek(SeekFrom::Start(start + sources[i].1))?;
                }
                Ok(())
            },
        )?;
        let data = fs::read(&xci)?;
        let root_hfs = hfs0::find_xci_root(&xci)?;
        let secure = root_hfs.entry("secure").context("No secure partition")?;
        let mut reader = File::open(&xci)?;
        let index = Hfs0Index::parse_at(
            &mut reader,
            root_hfs.data_start + secure.offset,
            data.len() as u64,
        )?;
        let first = index.entry(&sources[0].0).context("Missing first NCA")?;
        let at = usize::try_from(index.data_start + first.offset)?;
        assert_eq!(&data[at..at + 8], b"VERIFIED");
        let digest: [u8; 32] = Sha256::digest(&data[at..at + 0x200]).into();
        assert_eq!(first.hash, digest);
        assert_eq!(
            &data[0x140..0x160],
            &Sha256::digest(&data[0xF000..0xF200])[..]
        );
        Ok(())
    }

    fn synthetic_work(root: &Path, blob_len: usize) -> Result<Vec<(String, u64)>> {
        for partition in ["secure", "normal", "update"] {
            fs::create_dir_all(root.join(partition))?;
        }
        let mut expected = Vec::new();
        for i in 0..4u8 {
            let name = format!("{i:032x}.nca");
            let contents = vec![i + 5; blob_len];
            fs::write(root.join("secure").join(&name), contents)?;
            expected.push((name, blob_len as u64));
        }
        Ok(expected)
    }

    #[test]
    fn builds_readable_signed_placeholder_gamecard_without_external_process() -> Result<()> {
        let temp = tempfile::tempdir()?;
        let work = temp.path().join("work");
        let entries = synthetic_work(&work, 320 * 1024)?;
        ensure!(
            supports_layout(&work, GAME_INFO_PRESET)?,
            "Native layout not recognized"
        );
        let xci = temp.path().join("native.xci");
        build_default_xci(&xci, &work, &AtomicBool::new(false))?;
        let data = fs::read(&xci)?;
        assert_eq!(&data[0x100..0x104], b"HEAD");
        assert_eq!(&data[0xF000..0xF004], b"HFS0");
        assert!(data[0x7000..0xF000].iter().all(|b| *b == 0xff));
        assert_eq!(
            u64::from_le_bytes(data[0x130..0x138].try_into()?),
            ROOT_OFFSET
        );
        assert_eq!(
            &data[0x140..0x160],
            &Sha256::digest(&data[0xF000..0xF200])[..]
        );
        let root = hfs0::find_xci_root(&xci)?;
        let secure = root.entry("secure").context("Missing secure partition")?;
        let mut reader = File::open(&xci)?;
        let secure_index = Hfs0Index::parse_at(
            &mut reader,
            root.data_start + secure.offset,
            data.len() as u64,
        )?;
        assert_eq!(secure_index.entries.len(), entries.len());
        for (i, (name, length)) in entries.into_iter().enumerate() {
            let entry = secure_index.entry(&name).context("NCA missing")?;
            assert_eq!(entry.size, length);
            let start = usize::try_from(secure_index.data_start + entry.offset)?;
            let hash = Sha256::digest(&data[start..start + 0x200]);
            assert_eq!(&entry.hash[..], &hash[..]);
            assert!(
                data[start..start + length as usize]
                    .iter()
                    .all(|b| *b == 5 + i as u8)
            );
        }
        Ok(())
    }

    #[test]
    fn rejects_unverified_custom_gamecard_info_and_system_partitions() -> Result<()> {
        let temp = tempfile::tempdir()?;
        let work = temp.path().join("work");
        synthetic_work(&work, 32)?;
        assert!(!supports_layout(&work, b"[XCI_Header]\r\ncustom")?);
        fs::write(work.join("normal").join("content.bin"), b"not empty")?;
        assert!(!supports_layout(&work, GAME_INFO_PRESET)?);
        fs::remove_file(work.join("normal").join("content.bin"))?;
        fs::write(
            work.join("secure").join("unexpected.dat"),
            b"not part of XCI",
        )?;
        assert!(!supports_layout(&work, GAME_INFO_PRESET)?);
        Ok(())
    }

    #[test]
    fn native_xci_copy_runs_on_a_small_windows_thread_stack() -> Result<()> {
        // The previous 1-MiB local buffer overflowed the real E2E main
        // thread, even though normal Rust test threads were large enough.
        let handle = std::thread::Builder::new()
            .name("stage32-small-stack-xci".into())
            .stack_size(512 * 1024)
            .spawn(|| -> Result<()> {
                let temp = tempfile::tempdir()?;
                let work = temp.path().join("work");
                synthetic_work(&work, 320 * 1024)?;
                build_default_xci(
                    &temp.path().join("native.xci"),
                    &work,
                    &AtomicBool::new(false),
                )?;
                Ok(())
            })?;
        handle
            .join()
            .map_err(|_| anyhow::anyhow!("Native XCI copy panicked on a small stack"))??;
        Ok(())
    }

    #[test]
    #[ignore = "requires independently generated 1-4 NCA hacbuild reference cards"]
    fn stage84_small_secure_layouts_match_independent_hacbuild() -> Result<()> {
        let dir = PathBuf::from(
            std::env::var_os("NSRP_STAGE84_REFERENCE_DIR")
                .context("Missing independent Stage84 reference directory")?,
        );
        let scratch = tempfile::tempdir()?;
        let cancel = AtomicBool::new(false);
        for count in 1..=4 {
            let work = dir.join(format!("work{count}"));
            let expected = fs::read(dir.join(format!("reference{count}.xci")))?;
            let path = scratch.path().join(format!("native{count}.xci"));
            assert!(supports_layout(&work, GAME_INFO_PRESET)?);
            build_default_xci(&path, &work, &cancel)?;
            let actual = fs::read(&path)?;
            assert_eq!(actual.len(), expected.len(), "NCA count {count}");
            if let Some(at) = (0x100..actual.len()).find(|&i| actual[i] != expected[i]) {
                bail!(
                    "NCA count {count}: reference differs at {at:#x}: {:#x} != {:#x}",
                    actual[at],
                    expected[at]
                );
            }
            println!(
                "STAGE84_HACBUILD_REFERENCE_MATCH count={count} bytes={}",
                actual.len()
            );
        }
        Ok(())
    }

    /// The reference input is synthetic and contains neither game assets nor
    /// keys. Its hacbuild and native output must match byte-for-byte after
    /// the independently randomized 0x100-byte unsigned signature.
    #[test]
    fn exact_hacbuild_synthetic_reference_when_available() -> Result<()> {
        let Some(dir) = std::env::var_os("NSRP_STAGE32_REFERENCE_DIR") else {
            return Ok(());
        };
        let dir = PathBuf::from(dir);
        for (work, reference) in [
            ("work", "reference.xci"),
            ("work2", "reference2.xci"),
            ("work3", "reference_tickets.xci"),
        ] {
            let expected = fs::read(dir.join(reference))?;
            let scratch = tempfile::tempdir()?;
            let actual_path = scratch.path().join("native_reference.xci");
            build_default_xci(&actual_path, &dir.join(work), &AtomicBool::new(false))?;
            let actual = fs::read(&actual_path)?;
            assert_eq!(actual.len(), expected.len(), "{reference}: lengths differ");
            if let Some(offset) = (0x100..actual.len()).find(|&i| actual[i] != expected[i]) {
                bail!(
                    "{reference}: hacbuild differs at {offset:#x}: native={:#04x} reference={:#04x}",
                    actual[offset],
                    expected[offset]
                );
            }
        }
        Ok(())
    }
}
