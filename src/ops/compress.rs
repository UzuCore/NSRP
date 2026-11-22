use crate::{
    formats::{
        nca::{NCA_NCZ_HEADER_SIZE, NCA_XTS_HEADER_SIZE, make_ncz_plan_from_reader},
        ncz_stream::{decompress_ncz_region_to_nca, write_nca_region_to_ncz},
        pfs0::{Pfs0Index, build_from_streams},
    },
    keys::KeySet,
    ops::{
        cnmt::{discover_game_metadata, extract_and_parse_cnmts},
        container::list_entries,
    },
};
use anyhow::{Context, Result, bail};
use std::{
    fs::{self, File},
    io::{BufReader, Read, Seek, SeekFrom, Write},
    path::Path,
    sync::atomic::{AtomicBool, Ordering},
};

#[derive(Debug, Clone)]
pub struct CompressOptions {
    pub level: i32,
    pub threads: usize,
    pub block_mode: bool,
    pub long_mode: bool,
}

impl Default for CompressOptions {
    fn default() -> Self {
        Self {
            level: 18,
            threads: num_cpus::get().max(1),
            block_mode: true,
            long_mode: false,
        }
    }
}

#[derive(Debug, Clone, Default)]
pub struct CompressStats {
    pub nca_count: usize,
    pub ncz_count: usize,
    pub tickets_removed: usize,
    pub input_size: u64,
    pub output_size: u64,
}

pub fn compress_nsp(
    input: &Path,
    output: &Path,
    keys: &mut KeySet,
    options: &CompressOptions,
    cancel: &AtomicBool,
    progress: &mut dyn FnMut(f32),
    log: &mut dyn FnMut(String),
) -> Result<CompressStats> {
    if !input.is_file() {
        bail!("입력 NSP가 없습니다: {}", input.display());
    }
    let index = Pfs0Index::parse(input).context("NSP PFS0 파싱 실패")?;
    let input_size = fs::metadata(input)?.len();
    let ticket_count = keys.add_ticket_keys_from_nsp(input)?;
    if ticket_count > 0 {
        log(format!("티켓 {ticket_count}개에서 title key를 읽었습니다"));
    }
    let total_payload = index.entries.iter().map(|e| e.size).sum::<u64>().max(1);
    let mut source = BufReader::with_capacity(2 * 1024 * 1024, File::open(input)?);
    let mut names = Vec::with_capacity(index.entries.len());
    let mut plans = Vec::with_capacity(index.entries.len());
    let mut stats = CompressStats {
        input_size,
        ..Default::default()
    };

    // Plan the output table first. NCZ sizes are only known after encoding, so
    // the PFS0 writer backfills lengths while all payloads stream in place.
    for entry in &index.entries {
        if cancel.load(Ordering::Relaxed) {
            bail!("작업이 중단되었습니다");
        }
        let lower = entry.name.to_ascii_lowercase();
        let abs = index.data_start + entry.offset;
        let mut plan = None;
        let mut name = entry.name.clone();
        if lower.ends_with(".nca") {
            stats.nca_count += 1;
            if entry.size < NCA_XTS_HEADER_SIZE as u64 {
                bail!("NCA 엔트리가 너무 짧습니다: {}", entry.name);
            }
            let mut head = vec![0u8; entry.size.min(NCA_NCZ_HEADER_SIZE as u64) as usize];
            source.seek(SeekFrom::Start(abs))?;
            source.read_exact(&mut head)?;

            if head.len() >= NCA_NCZ_HEADER_SIZE {
                match make_ncz_plan_from_reader(&mut source, abs, entry.size, &head, keys) {
                    Ok(ncz_plan) => {
                        name = replace_last_extension(&entry.name, "ncz");
                        plan = Some(ncz_plan);
                        stats.ncz_count += 1;
                    }
                    Err(reason) => {
                        log(format!("NCA 유지(비압축): {} — {reason}", entry.name));
                    }
                }
            }
        }
        names.push(name);
        plans.push(plan);
    }

    let mut done_bytes = 0u64;
    let mut scratch = vec![0u8; 2 * 1024 * 1024];
    build_from_streams(&names, output, cancel, |i, out| {
        let entry = &index.entries[i];
        let abs = index.data_start + entry.offset;
        if let Some(plan) = plans[i].as_ref() {
            let base_done = done_bytes;
            write_nca_region_to_ncz(
                &mut source,
                abs,
                entry.size,
                plan,
                out,
                options.level.clamp(1, 22),
                options.threads.max(1),
                options.block_mode,
                options.long_mode,
                cancel,
                |current, total| {
                    let ratio = if total == 0 {
                        1.0
                    } else {
                        current as f32 / total as f32
                    };
                    let weighted = base_done as f32 + entry.size as f32 * ratio;
                    progress((weighted / total_payload as f32) * 0.94);
                },
            )?;
            log(format!("NCZ 압축: {}", entry.name));
        } else {
            // The unchanged encrypted NCA, ticket or XML must remain byte
            // identical to its source: rewriting a header breaks CNMT hashes.
            copy_plain_region(&mut source, abs, entry.size, out, &mut scratch, cancel)?;
        }
        done_bytes += entry.size;
        progress((done_bytes as f32 / total_payload as f32) * 0.94);
        Ok(())
    })
    .context("NSZ PFS0 패키징 실패")?;
    stats.output_size = fs::metadata(output)?.len();
    progress(1.0);
    Ok(stats)
}

pub fn decompress_nsz(
    input: &Path,
    output: &Path,
    cancel: &AtomicBool,
    progress: &mut dyn FnMut(f32),
    log: &mut dyn FnMut(String),
) -> Result<()> {
    let index = Pfs0Index::parse(input).context("NSZ PFS0 파싱 실패")?;
    let total_payload = index.entries.iter().map(|e| e.size).sum::<u64>().max(1);
    let mut source = BufReader::with_capacity(2 * 1024 * 1024, File::open(input)?);
    let names = index
        .entries
        .iter()
        .map(|entry| {
            if entry.name.to_ascii_lowercase().ends_with(".ncz") {
                replace_last_extension(&entry.name, "nca")
            } else {
                entry.name.clone()
            }
        })
        .collect::<Vec<_>>();
    let mut done_bytes = 0u64;
    let mut scratch = vec![0u8; 2 * 1024 * 1024];
    build_from_streams(&names, output, cancel, |i, out| {
        let entry = &index.entries[i];
        let abs = index.data_start + entry.offset;
        if entry.name.to_ascii_lowercase().ends_with(".ncz") {
            let base_done = done_bytes;
            decompress_ncz_region_to_nca(
                &mut source,
                abs,
                entry.size,
                out,
                cancel,
                |current, total| {
                    let ratio = if total == 0 {
                        1.0
                    } else {
                        current as f32 / total as f32
                    };
                    let weighted = base_done as f32 + entry.size as f32 * ratio.min(1.0);
                    progress((weighted / total_payload as f32) * 0.94);
                },
            )?;
            log(format!("NCZ 해제: {}", entry.name));
        } else {
            copy_plain_region(&mut source, abs, entry.size, out, &mut scratch, cancel)?;
        }
        done_bytes += entry.size;
        progress((done_bytes as f32 / total_payload as f32) * 0.94);
        Ok(())
    })
    .context("NSP PFS0 패키징 실패")?;
    progress(1.0);
    Ok(())
}

fn copy_plain_region<R: Read + Seek, W: Write>(
    source: &mut R,
    offset: u64,
    mut remaining: u64,
    out: &mut W,
    scratch: &mut [u8],
    cancel: &AtomicBool,
) -> Result<()> {
    source.seek(SeekFrom::Start(offset))?;
    while remaining > 0 {
        if cancel.load(Ordering::Relaxed) {
            bail!("작업이 중단되었습니다");
        }
        let count = remaining.min(scratch.len() as u64) as usize;
        source.read_exact(&mut scratch[..count])?;
        out.write_all(&scratch[..count])?;
        remaining -= count as u64;
    }
    Ok(())
}

/// NSZ를 NSP로 해제한 뒤, 구버전 NSRP가 ticketless로 변형해 둔 NCZ 헤더를
/// CNMT의 Title ID와 전체 content hash로 검증하면서 원래 rights 헤더로 복원한다.
pub fn decompress_nsz_repaired(
    input: &Path,
    output: &Path,
    hactool: &Path,
    prod_keys: &Path,
    cancel: &AtomicBool,
    progress: &mut dyn FnMut(f32),
    log: &mut dyn FnMut(String),
) -> Result<()> {
    decompress_nsz(input, output, cancel, &mut |p| progress(p * 0.92), log)?;
    repair_legacy_nsp_headers(
        output,
        hactool,
        prod_keys,
        cancel,
        &mut |p| progress(0.92 + p * 0.08),
        log,
    )?;
    progress(1.0);
    Ok(())
}

pub fn repair_legacy_nsp_headers(
    output: &Path,
    hactool: &Path,
    prod_keys: &Path,
    cancel: &AtomicBool,
    progress: &mut dyn FnMut(f32),
    log: &mut dyn FnMut(String),
) -> Result<()> {
    repair_legacy_container_headers(output, false, hactool, prod_keys, cancel, progress, log)
}

/// Only patch packaging uses this policy. Preserve working ticketless
/// headers when their original retail Rights IDs have no matching title keys.
#[allow(clippy::too_many_arguments)]
pub fn repair_legacy_nsp_headers_for_launch(
    output: &Path,
    hactool: &Path,
    prod_keys: &Path,
    available_keys: &KeySet,
    cancel: &AtomicBool,
    progress: &mut dyn FnMut(f32),
    log: &mut dyn FnMut(String),
) -> Result<()> {
    repair_legacy_container_headers_policy(
        output,
        false,
        hactool,
        prod_keys,
        Some(available_keys),
        cancel,
        progress,
        log,
    )
}

pub fn repair_legacy_container_headers(
    output: &Path,
    skip_system_partitions: bool,
    hactool: &Path,
    prod_keys: &Path,
    cancel: &AtomicBool,
    progress: &mut dyn FnMut(f32),
    log: &mut dyn FnMut(String),
) -> Result<()> {
    repair_legacy_container_headers_policy(
        output,
        skip_system_partitions,
        hactool,
        prod_keys,
        None,
        cancel,
        progress,
        log,
    )
}

#[allow(clippy::too_many_arguments)]
fn repair_legacy_container_headers_policy(
    output: &Path,
    skip_system_partitions: bool,
    hactool: &Path,
    prod_keys: &Path,
    available_keys: Option<&KeySet>,
    cancel: &AtomicBool,
    progress: &mut dyn FnMut(f32),
    log: &mut dyn FnMut(String),
) -> Result<()> {
    let temp = crate::workspace::temp_workspace("nsrp_nsz_repair_")?;
    let discovered = if skip_system_partitions {
        discover_game_metadata(
            output,
            &temp.path().join("metadata"),
            hactool,
            prod_keys,
            cancel,
        )
        .map(|(entries, cnmts, _)| (entries, cnmts))
    } else {
        let entries = list_entries(output, false)?;
        extract_and_parse_cnmts(
            output,
            &entries,
            &temp.path().join("cnmt"),
            hactool,
            prod_keys,
            cancel,
        )
        .map(|cnmts| (entries, cnmts))
    };
    let (entries, cnmts) = match discovered {
        Ok(value) => value,
        Err(err) => {
            log(format!(
                "레거시 NCZ 헤더 복원 건너뜀: CNMT를 확인할 수 없음 ({err})"
            ));
            progress(1.0);
            return Ok(());
        }
    };
    let title_keys = prod_keys
        .parent()
        .map(|parent| parent.join("title.keys"))
        .filter(|path| path.is_file());
    let loaded_keys = if available_keys.is_none() {
        Some(KeySet::load(prod_keys, title_keys.as_deref())?)
    } else {
        None
    };
    let keys = available_keys
        .or(loaded_keys.as_ref())
        .context("No key set available for legacy NCA header verification")?;
    let total = cnmts
        .iter()
        .map(|cnmt| cnmt.contents.len())
        .sum::<usize>()
        .max(1);
    let mut checked = 0usize;
    let mut repaired = 0usize;

    for cnmt in &cnmts {
        for content in &cnmt.contents {
            if cancel.load(Ordering::Relaxed) {
                bail!("작업이 중단되었습니다");
            }
            let name = format!("{}.nca", content.nca_id);
            if let Some(entry) = entries
                .iter()
                .find(|entry| entry.name.eq_ignore_ascii_case(&name))
            {
                let restored = if available_keys.is_some() {
                    crate::formats::nca::restore_legacy_rights_header_region_if_key_available(
                        output,
                        entry.offset,
                        entry.size,
                        &cnmt.title_id,
                        &content.hash,
                        keys,
                    )?
                } else {
                    crate::formats::nca::restore_legacy_rights_header_region_for_hash(
                        output,
                        entry.offset,
                        entry.size,
                        &cnmt.title_id,
                        &content.hash,
                        keys,
                    )?
                };
                if restored {
                    repaired += 1;
                    log(format!("레거시 NCZ rights 헤더 복원: {name}"));
                }
            }
            checked += 1;
            progress(checked as f32 / total as f32);
        }
    }
    if repaired > 0 {
        log(format!("레거시 NCZ 헤더 복원 완료: {repaired}개"));
    }
    progress(1.0);
    Ok(())
}

fn replace_last_extension(name: &str, extension: &str) -> String {
    match name.rsplit_once('.') {
        Some((stem, _)) => format!("{stem}.{extension}"),
        None => format!("{name}.{extension}"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        crypto::{aes_ecb_encrypt_block, nca_ctr_xcrypt_range, nca_xts_transform},
        formats::{nca::decrypt_header, pfs0::build_from_paths},
    };
    use std::collections::HashMap;

    fn synthetic_keys() -> KeySet {
        let mut prod = HashMap::new();
        prod.insert("header_key".into(), (0..32u8).collect());
        prod.insert("key_area_key_application_00".into(), vec![0x31; 16]);
        KeySet {
            prod,
            title: HashMap::new(),
        }
    }

    fn synthetic_nca(path: &Path, keys: &KeySet) -> Result<Vec<u8>> {
        let section_key = [0x42u8; 16];
        let kaek = keys.prod_key("key_area_key_application_00").unwrap();
        let enc_slot = aes_ecb_encrypt_block(&section_key, kaek)?;
        let mut header = vec![0u8; NCA_XTS_HEADER_SIZE];
        header[0x200..0x204].copy_from_slice(b"NCA3");
        header[0x205] = 0;
        header[0x206] = 1;
        header[0x207] = 0;
        header[0x208..0x210].copy_from_slice(&(0x8000u64).to_le_bytes());
        header[0x320..0x330].copy_from_slice(&enc_slot);
        header[0x240..0x244].copy_from_slice(&(0x20u32).to_le_bytes());
        header[0x244..0x248].copy_from_slice(&(0x40u32).to_le_bytes());
        header[0x404] = 3;
        header[0x540..0x548].copy_from_slice(&0x1122334455667788u64.to_le_bytes());
        let mut encrypted_header = header;
        nca_xts_transform(
            &mut encrypted_header,
            keys.prod_key("header_key").unwrap(),
            true,
        )?;

        let mut nca = vec![0u8; 0x8000];
        nca[..NCA_XTS_HEADER_SIZE].copy_from_slice(&encrypted_header);
        let info = decrypt_header(&nca, keys)?;
        let section = &info.sections[0];
        let mut body = (0..section.size as usize)
            .map(|i| ((i * 17 + 3) % 251) as u8)
            .collect::<Vec<_>>();
        nca_ctr_xcrypt_range(&mut body, &section_key, &section.counter, section.offset)?;
        nca[section.offset as usize..(section.offset + section.size) as usize]
            .copy_from_slice(&body);
        fs::write(path, &nca)?;
        Ok(nca)
    }

    fn roundtrip(block_mode: bool, long_mode: bool) -> Result<()> {
        let temp = tempfile::tempdir()?;
        let mut keys = synthetic_keys();
        let nca_path = temp.path().join("program.nca");
        let original = synthetic_nca(&nca_path, &keys)?;
        let nsp = temp.path().join("input.nsp");
        build_from_paths(&[("program.nca".into(), nca_path)], &nsp)?;
        let nsz = temp.path().join("output.nsz");
        let nsp2 = temp.path().join("roundtrip.nsp");
        let cancel = AtomicBool::new(false);
        let mut progress = |_| {};
        let mut log = |_| {};
        compress_nsp(
            &nsp,
            &nsz,
            &mut keys,
            &CompressOptions {
                level: 3,
                threads: 2,
                block_mode,
                long_mode,
            },
            &cancel,
            &mut progress,
            &mut log,
        )?;
        decompress_nsz(&nsz, &nsp2, &cancel, &mut progress, &mut log)?;
        let idx = Pfs0Index::parse(&nsp2)?;
        let entry = idx.entry("program.nca").context("roundtrip NCA 없음")?;
        let restored = idx.read_entry(&nsp2, entry)?;
        assert_eq!(restored, original);
        Ok(())
    }

    #[test]
    fn nsp_nsz_roundtrip_stream() -> Result<()> {
        roundtrip(false, false)
    }

    #[test]
    fn nsp_nsz_roundtrip_block() -> Result<()> {
        roundtrip(true, false)
    }

    #[test]
    fn nsp_nsz_roundtrip_long_stream() -> Result<()> {
        roundtrip(false, true)
    }

    #[test]
    fn nsp_nsz_roundtrip_long_block() -> Result<()> {
        roundtrip(true, true)
    }
}

#[cfg(test)]
#[path = "compress_bktr_tests.rs"]
mod bktr_tests;
