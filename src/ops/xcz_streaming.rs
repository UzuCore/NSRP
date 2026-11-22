//! Direct nested HFS0 writer for XCI/XCZ conversion.
//! Only the final, automatically cleaned temporary output is materialized.
//! NCA/NCZ files and nested partitions are never staged separately.

use super::{XczOptions, XczStats, collect_xci_ticket_keys, replace_extension};
use crate::{
    formats::{
        hfs0::{self, Hfs0Index},
        nca::{NCA_NCZ_HEADER_SIZE, NczPlan, make_ncz_plan_from_reader},
        ncz_stream::{decompress_ncz_region_to_nca, write_nca_region_to_ncz},
    },
    keys::KeySet,
};
use anyhow::{Context, Result, bail};
use byteorder::{LittleEndian, WriteBytesExt};
use sha2::{Digest, Sha256};
use std::{
    fs::{self, File},
    io::{BufReader, Read, Seek, SeekFrom, Write},
    path::Path,
    sync::atomic::{AtomicBool, Ordering},
};

const COPY_BUFFER: usize = 2 * 1024 * 1024;

fn copy_region<R: Read + Seek, W: Write>(
    source: &mut R,
    offset: u64,
    mut size: u64,
    output: &mut W,
    buffer: &mut [u8],
    cancel: &AtomicBool,
) -> Result<()> {
    source.seek(SeekFrom::Start(offset))?;
    while size > 0 {
        if cancel.load(Ordering::Relaxed) {
            bail!("작업이 중단되었습니다");
        }
        let count = size.min(buffer.len() as u64) as usize;
        source.read_exact(&mut buffer[..count])?;
        output.write_all(&buffer[..count])?;
        size -= count as u64;
    }
    Ok(())
}

fn sha256_range(
    file: &mut File,
    start: u64,
    size: u64,
    buffer: &mut [u8],
    cancel: &AtomicBool,
) -> Result<[u8; 32]> {
    let mut digest = Sha256::new();
    let mut remaining = size;
    file.seek(SeekFrom::Start(start))?;
    while remaining > 0 {
        if cancel.load(Ordering::Relaxed) {
            bail!("작업이 중단되었습니다");
        }
        let count = remaining.min(buffer.len() as u64) as usize;
        file.read_exact(&mut buffer[..count])?;
        digest.update(&buffer[..count]);
        remaining -= count as u64;
    }
    Ok(digest.finalize().into())
}

#[allow(clippy::too_many_arguments)]
pub(super) fn transform_xci_streamed(
    input: &Path,
    output: &Path,
    mut compress: Option<(&mut KeySet, &XczOptions)>,
    cancel: &AtomicBool,
    progress: &mut dyn FnMut(f32),
    log: &mut dyn FnMut(String),
) -> Result<XczStats> {
    let input_size = fs::metadata(input)?.len();
    let (root, header_base) = hfs0::find_xci_root_with_header_base(input)?;
    let output_parent = output.parent().unwrap_or_else(|| Path::new("."));
    fs::create_dir_all(output_parent)?;
    let mut temporary = tempfile::Builder::new()
        .prefix("nsrp_xcz_stream_")
        .tempfile_in(output_parent)
        .context("XCI 스트리밍 출력 임시파일 생성 실패")?;
    let mut source = BufReader::with_capacity(COPY_BUFFER, File::open(input)?);
    let mut scratch = vec![0u8; COPY_BUFFER];
    if let Some((keys, _)) = compress.as_mut() {
        collect_xci_ticket_keys(&mut source, input_size, &root, keys)?;
    }

    let mut stats = XczStats {
        input_size,
        ..Default::default()
    };
    // A gamecard can have no NCA that is compressible with the available
    // keys (or an XCZ can contain no NCZ). Rebuilding such a file would
    // normalize otherwise untouched headers, and then copying again would
    // waste multiple GiB of I/O. Inspect only the small nested headers first.
    let mut planned_changes = false;
    let mut inspected_ncas = 0usize;
    'partitions: for partition in &root.entries {
        if cancel.load(Ordering::Relaxed) {
            bail!("작업이 중단되었습니다");
        }
        let partition_abs = root
            .data_start
            .checked_add(partition.offset)
            .context("XCI partition offset overflow")?;
        let Ok(sub) = Hfs0Index::parse_at(&mut source, partition_abs, input_size) else {
            continue;
        };
        for entry in &sub.entries {
            if cancel.load(Ordering::Relaxed) {
                bail!("작업이 중단되었습니다");
            }
            let lower = entry.name.to_ascii_lowercase();
            if let Some((keys, _)) = compress.as_mut() {
                if !lower.ends_with(".nca") {
                    continue;
                }
                inspected_ncas += 1;
                if entry.size < NCA_NCZ_HEADER_SIZE as u64 {
                    continue;
                }
                let abs = sub
                    .data_start
                    .checked_add(entry.offset)
                    .context("XCI NCA offset overflow")?;
                let mut header = vec![0u8; NCA_NCZ_HEADER_SIZE];
                source.seek(SeekFrom::Start(abs))?;
                source.read_exact(&mut header)?;
                if make_ncz_plan_from_reader(&mut source, abs, entry.size, &header, keys).is_ok() {
                    planned_changes = true;
                    break 'partitions;
                }
            } else if lower.ends_with(".ncz") {
                planned_changes = true;
                break 'partitions;
            }
        }
    }
    if !planned_changes {
        let out = temporary.as_file_mut();
        source.seek(SeekFrom::Start(0))?;
        let mut copied = 0u64;
        while copied < input_size {
            if cancel.load(Ordering::Relaxed) {
                bail!("작업이 중단되었습니다");
            }
            let take = (input_size - copied).min(scratch.len() as u64) as usize;
            source.read_exact(&mut scratch[..take])?;
            out.write_all(&scratch[..take])?;
            copied += take as u64;
            progress(copied as f32 / input_size.max(1) as f32 * 0.99);
        }
        out.flush()?;
        if out.metadata()?.len() != input_size {
            bail!("Unchanged XCI copy size mismatch");
        }
        if cancel.load(Ordering::Relaxed) {
            bail!("작업이 중단되었습니다");
        }
        temporary
            .persist(output)
            .context("Unchanged XCI atomic output persistence failed")?;
        stats.nca_count = inspected_ncas;
        stats.output_size = fs::metadata(output)?.len();
        log("No NCA/NCZ was transformed; original XCI bytes preserved".to_owned());
        progress(1.0);
        return Ok(stats);
    }
    let payload = root.entries.iter().map(|e| e.size).sum::<u64>().max(1);
    let mut root_done = 0u64;
    let root_names = root
        .entries
        .iter()
        .map(|entry| entry.name.clone())
        .collect::<Vec<_>>();
    let out = temporary.as_file_mut();
    // Keep the gamecard prefix unchanged. Only the root HFS0 and the three
    // gamecard size/hash fields are rewritten, as in the legacy packager.
    copy_region(&mut source, 0, root.base, out, &mut scratch, cancel)?;
    let root_size = hfs0::build_to_stream(
        &root_names,
        out,
        0x200,
        1,
        cancel,
        |partition_index, out| {
            let partition = &root.entries[partition_index];
            let partition_abs = root
                .data_start
                .checked_add(partition.offset)
                .context("XCI 파티션 오프셋 오버플로")?;
            match Hfs0Index::parse_at(&mut source, partition_abs, input_size) {
                Ok(sub) => {
                    let mut plans = Vec::<Option<NczPlan>>::with_capacity(sub.entries.len());
                    let mut names = Vec::with_capacity(sub.entries.len());
                    for entry in &sub.entries {
                        if cancel.load(Ordering::Relaxed) {
                            bail!("작업이 중단되었습니다");
                        }
                        let mut name = entry.name.clone();
                        let mut plan = None;
                        let lower = entry.name.to_ascii_lowercase();
                        if let Some((keys, _)) = compress.as_mut() {
                            if lower.ends_with(".nca") {
                                stats.nca_count += 1;
                                let absolute = sub
                                    .data_start
                                    .checked_add(entry.offset)
                                    .context("XCI NCA 오프셋 오버플로")?;
                                let mut header =
                                    vec![0u8; entry.size.min(NCA_NCZ_HEADER_SIZE as u64) as usize];
                                source.seek(SeekFrom::Start(absolute))?;
                                source.read_exact(&mut header)?;
                                if header.len() >= NCA_NCZ_HEADER_SIZE
                                    && let Ok(candidate) = make_ncz_plan_from_reader(
                                        &mut source,
                                        absolute,
                                        entry.size,
                                        &header,
                                        keys,
                                    )
                                {
                                    name = replace_extension(&entry.name, "ncz");
                                    plan = Some(candidate);
                                }
                            }
                        } else if lower.ends_with(".ncz") {
                            name = replace_extension(&entry.name, "nca");
                        }
                        names.push(name);
                        plans.push(plan);
                    }
                    let sub_total = sub.entries.iter().map(|e| e.size).sum::<u64>().max(1);
                    let mut sub_done = 0u64;
                    hfs0::build_to_stream(&names, out, 0x200, 1, cancel, |entry_index, out| {
                        let entry = &sub.entries[entry_index];
                        let file_abs = sub
                            .data_start
                            .checked_add(entry.offset)
                            .context("XCI 파일 오프셋 오버플로")?;
                        let base_root = root_done;
                        let base_sub = sub_done;
                        if let Some(plan) = plans[entry_index].as_ref() {
                            let (_, options) = compress
                                .as_ref()
                                .context("NCZ plan present without compression options")?;
                            write_nca_region_to_ncz(
                                &mut source,
                                file_abs,
                                entry.size,
                                plan,
                                out,
                                options.level.clamp(1, 22),
                                options.threads.max(1),
                                options.block_mode,
                                options.long_mode,
                                cancel,
                                |cur, total| {
                                    let frac = if total == 0 {
                                        1.0
                                    } else {
                                        cur as f32 / total as f32
                                    };
                                    let sub_progress = base_sub as f32 + entry.size as f32 * frac;
                                    let overall = base_root as f32
                                        + partition.size as f32
                                            * (sub_progress / sub_total as f32).min(1.0);
                                    progress((overall / payload as f32) * 0.95);
                                },
                            )?;
                            stats.ncz_count += 1;
                            log(format!("NCZ 압축: {}", entry.name));
                        } else if compress.is_none()
                            && entry.name.to_ascii_lowercase().ends_with(".ncz")
                        {
                            decompress_ncz_region_to_nca(
                                &mut source,
                                file_abs,
                                entry.size,
                                out,
                                cancel,
                                |cur, total| {
                                    let frac = if total == 0 {
                                        1.0
                                    } else {
                                        cur as f32 / total as f32
                                    };
                                    let sub_progress =
                                        base_sub as f32 + entry.size as f32 * frac.min(1.0);
                                    let overall = base_root as f32
                                        + partition.size as f32
                                            * (sub_progress / sub_total as f32).min(1.0);
                                    progress((overall / payload as f32) * 0.95);
                                },
                            )?;
                            stats.ncz_count += 1;
                            log(format!("NCZ 해제: {}", entry.name));
                        } else {
                            copy_region(
                                &mut source,
                                file_abs,
                                entry.size,
                                out,
                                &mut scratch,
                                cancel,
                            )?;
                        }
                        sub_done = sub_done.saturating_add(entry.size);
                        Ok(())
                    })?;
                }
                Err(_) => {
                    // Preserve opaque gamecard partitions byte-for-byte.
                    copy_region(
                        &mut source,
                        partition_abs,
                        partition.size,
                        out,
                        &mut scratch,
                        cancel,
                    )?;
                }
            }
            root_done = root_done.saturating_add(partition.size);
            progress((root_done as f32 / payload as f32) * 0.95);
            Ok(())
        },
    )?;
    let root_hash = sha256_range(out, root.base, root_size, &mut scratch, cancel)?;
    if let Some(base) = header_base {
        out.seek(SeekFrom::Start(base + 0x138))?;
        out.write_u64::<LittleEndian>(root_size)?;
        out.seek(SeekFrom::Start(base + 0x118))?;
        let pages = (root.base + root_size) / 0x200;
        out.write_u32::<LittleEndian>(pages.min(u32::MAX as u64) as u32)?;
        out.seek(SeekFrom::Start(base + 0x140))?;
        out.write_all(&root_hash)?;
    }
    out.flush()?;
    if cancel.load(Ordering::Relaxed) {
        bail!("작업이 중단되었습니다");
    }
    let expected_length = root
        .base
        .checked_add(root_size)
        .context("XCI 크기 오버플로")?;
    if out.metadata()?.len() != expected_length {
        bail!("XCI 최종 길이 검증 실패");
    }
    if stats.ncz_count == 0 {
        // No NCA/NCZ payload changed. Rebuilding the HFS0 layout otherwise
        // normalizes existing hashes, padding and gamecard geometry fields,
        // making an unchanged XCI different even after an XCZ round trip.
        // Preserve *all* original bytes when there was no transformation.
        out.set_len(0)?;
        out.seek(SeekFrom::Start(0))?;
        copy_region(&mut source, 0, input_size, out, &mut scratch, cancel)?;
        out.flush()?;
        if out.metadata()?.len() != input_size {
            bail!("Unchanged XCI byte-preservation length mismatch");
        }
        log("No NCA/NCZ was transformed; original XCI bytes preserved".to_owned());
    }
    // Persist replaces an existing target atomically. Do not remove the old
    // output first: a failed rename (e.g. sharing violation) must leave it
    // intact. Temporary output is deleted automatically on earlier errors.
    temporary
        .persist(output)
        .context("XCI 결과파일 확정 실패")?;
    stats.output_size = fs::metadata(output)?.len();
    progress(1.0);
    Ok(stats)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unmodified_xci_xcz_roundtrip_retains_noncanonical_gamecard_header() -> Result<()> {
        let temp = tempfile::tempdir()?;
        let payload = temp.path().join("payload.nca");
        fs::write(&payload, b"XCI payload remains byte-identical")?;
        let secure = temp.path().join("secure.hfs0");
        hfs0::build_from_paths_layout(&[("payload.nca".to_owned(), payload)], &secure, 0x200, 1)?;
        let root = temp.path().join("root.hfs0");
        hfs0::build_from_paths_layout(&[("secure".to_owned(), secure)], &root, 0x200, 1)?;

        let mut original = vec![0u8; 0x200];
        original[0x100..0x104].copy_from_slice(b"HEAD");
        original[0x118..0x11c].copy_from_slice(&0x5a1234u32.to_le_bytes());
        original[0x130..0x138].copy_from_slice(&0x200u64.to_le_bytes());
        original[0x138..0x140].copy_from_slice(&0x85u64.to_le_bytes());
        original[0x140..0x160].fill(0xa7);
        original.extend_from_slice(&fs::read(&root)?);
        let input = temp.path().join("source.xci");
        fs::write(&input, &original)?;

        let compressed = temp.path().join("source.xcz");
        let restored = temp.path().join("restored.xci");
        let cancel = AtomicBool::new(false);
        let mut keys = KeySet::default();
        let stats = transform_xci_streamed(
            &input,
            &compressed,
            Some((&mut keys, &XczOptions::default())),
            &cancel,
            &mut |_| {},
            &mut |_| {},
        )?;
        assert_eq!(stats.ncz_count, 0);
        assert_eq!(stats.nca_count, 1);
        assert_eq!(fs::read(&compressed)?, original);

        let stats = transform_xci_streamed(
            &compressed,
            &restored,
            None,
            &cancel,
            &mut |_| {},
            &mut |_| {},
        )?;
        assert_eq!(stats.ncz_count, 0);
        assert_eq!(fs::read(&restored)?, original);
        Ok(())
    }
}
