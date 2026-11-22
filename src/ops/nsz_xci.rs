//! Conservative Stage34 NSZ -> native XCI assembly without a full decoded NSP.
//!
//! Uncompressed NCA entries stay as bounded ranges in the source NSZ. Only
//! compressed NCZ payloads are decoded into private, disposable NCA files.
//! CNMT is authenticated without converting ticketless NCZ headers to
//! rights-managed headers that would no longer launch without a ticket.
//! Unsupported layouts fall back to the unchanged NSP workflow; malformed
//! NCZ decoding or failed native publication never silently falls back.

use crate::{
    disk_space::ensure_disk_space,
    formats::{
        nca::validate_legacy_ticketless_nca_region_for_hash,
        ncz_stream::{decompress_ncz_region_to_nca, reconstructed_nca_size},
        pfs0::Pfs0Index,
    },
    keys::KeySet,
    ops::{
        cnmt::{self, CnmtInfo},
        native_meta::read_cnmt_from_nca_region,
        native_xci::XciSource,
        xci_output::build_xci_native_sources_verified,
    },
};
use anyhow::{Context, Result, bail, ensure};
use sha2::{Digest, Sha256};
use std::{
    collections::{HashMap, HashSet},
    fs::{self, File},
    io::{BufReader, BufWriter, Read, Seek, SeekFrom, Write},
    path::Path,
    sync::atomic::{AtomicBool, Ordering},
};

const DEFAULT_INFO: &[u8] = include_bytes!("../../bin/game_info_preset.ini");
// Stage44 verified the same default card format in the 32-GiB tier. The
// native virtual-source gate below still rejects unverified capacity gaps.
const MAX_NATIVE_CAPACITY: u64 = 32 * 1024 * 1024 * 1024;
const NATIVE_HEADROOM: u64 = 8 * 1024 * 1024;

struct PlannedEntry {
    name: String,
    offset: u64,
    encoded_length: u64,
    decoded_length: u64,
    compressed: bool,
}

fn hash_bounded_region(source: &XciSource, cancel: &AtomicBool) -> Result<[u8; 32]> {
    let mut file = BufReader::with_capacity(1024 * 1024, File::open(&source.path)?);
    file.seek(SeekFrom::Start(source.offset))?;
    let mut scratch = vec![0u8; 1024 * 1024];
    let mut remaining = source.length;
    let mut hasher = Sha256::new();
    while remaining > 0 {
        ensure!(!cancel.load(Ordering::Relaxed), "작업이 중단되었습니다");
        let take = remaining.min(scratch.len() as u64) as usize;
        file.read_exact(&mut scratch[..take])?;
        hasher.update(&scratch[..take]);
        remaining -= take as u64;
    }
    Ok(hasher.finalize().into())
}

/// The fallback does not need any of the decoded working files. The parent
/// temp workspace owns them, so all error/cancel paths clean them automatically.
#[allow(clippy::too_many_arguments)]
pub(crate) fn try_native_nsz_to_xci(
    input: &Path,
    output: &Path,
    resource_dir: &Path,
    prod_keys: &Path,
    keys: &KeySet,
    work: &Path,
    cancel: &AtomicBool,
    progress: &mut dyn FnMut(f32),
    log: &mut dyn FnMut(String),
) -> Result<bool> {
    ensure!(!cancel.load(Ordering::Relaxed), "작업이 중단되었습니다");
    let preset = super::convert::game_info_preset_data(resource_dir)?;
    if preset != DEFAULT_INFO {
        log("NSZ→XCI: 사용자 지정 게임카드 정보는 기존 경로로 처리".to_owned());
        return Ok(false);
    }
    let index = Pfs0Index::parse(input).context("NSZ 직접 변환: PFS0 인덱스 오류")?;
    let mut source = BufReader::with_capacity(1024 * 1024, File::open(input)?);
    let mut planned = Vec::new();
    let mut names = HashSet::new();
    let mut total_bytes = 0u64;
    let mut decoded_bytes = 0u64;
    let mut packed_bytes = 0u64;
    for entry in &index.entries {
        let lowercase = entry.name.to_ascii_lowercase();
        let compressed = lowercase.ends_with(".ncz");
        if !compressed && !lowercase.ends_with(".nca") {
            continue;
        }
        let name = if compressed {
            let (stem, _) = entry
                .name
                .rsplit_once('.')
                .context("NSZ NCZ 확장자 형식 오류")?;
            format!("{stem}.nca")
        } else {
            entry.name.clone()
        };
        if !names.insert(name.to_ascii_lowercase()) {
            log(format!(
                "NSZ→XCI: 중복 복원 NCA 이름으로 기존 경로 사용: {name}"
            ));
            return Ok(false);
        }
        let offset = index
            .data_start
            .checked_add(entry.offset)
            .context("NSZ NCA 오프셋 오버플로")?;
        let decoded_length = if compressed {
            reconstructed_nca_size(&mut source, offset, entry.size)?
        } else {
            entry.size
        };
        total_bytes = total_bytes
            .checked_add(decoded_length)
            .context("NSZ 출력 NCA 총크기 오버플로")?;
        packed_bytes = packed_bytes
            .checked_add(entry.size)
            .context("NSZ 입력 크기 오버플로")?;
        if compressed {
            decoded_bytes = decoded_bytes
                .checked_add(decoded_length)
                .context("NSZ NCZ 복원 총크기 오버플로")?;
        }
        planned.push(PlannedEntry {
            name,
            offset,
            encoded_length: entry.size,
            decoded_length,
            compressed,
        });
    }
    // Do not expand files just to discover that the layout is unsupported.
    if planned.len() < 4 || total_bytes > MAX_NATIVE_CAPACITY - NATIVE_HEADROOM - 0xF000 {
        log("NSZ→XCI: 미검증 파일 수 또는 카드 용량, 기존 경로로 처리".to_owned());
        return Ok(false);
    }
    let virtual_sources = planned
        .iter()
        .map(|entry| (entry.name.clone(), entry.decoded_length))
        .collect::<Vec<_>>();
    if !super::native_xci::supports_virtual_sources(&virtual_sources, &preset)? {
        log("NSZ→XCI: 지원하지 않는 카드 용량/파일 형식, 기존 검증 경로 사용".to_owned());
        return Ok(false);
    }
    if !planned
        .iter()
        .any(|entry| entry.name.to_ascii_lowercase().ends_with(".cnmt.nca"))
    {
        log("NSZ→XCI: CNMT 정보가 없어 기존 무결성 복원 경로 사용".to_owned());
        return Ok(false);
    }
    fs::create_dir_all(work)?;
    // The XCI and temporary decoded NCAs coexist until atomic publication.
    // Check both allocations on the conversion output volume first.
    ensure_disk_space(
        work,
        total_bytes
            .checked_add(decoded_bytes)
            .and_then(|v| v.checked_add(NATIVE_HEADROOM))
            .context("NSZ→XCI 동시 출력 예상 크기 오버플로")?,
    )?;

    let decoded = work.join("stage34_ncz_only");
    fs::create_dir_all(&decoded)?;
    let mut sources = Vec::with_capacity(planned.len());
    let mut decoded_names = HashSet::new();
    let mut completed = 0u64;
    for (i, entry) in planned.iter().enumerate() {
        ensure!(!cancel.load(Ordering::Relaxed), "작업이 중단되었습니다");
        if entry.compressed {
            // Use only generated indexed names for scratch paths, never a
            // title-controlled filename or a path containing separators.
            let target = decoded.join(format!("nca_{i:05}.bin"));
            let mut out = BufWriter::with_capacity(1024 * 1024, File::create(&target)?);
            let base = completed;
            let actual = decompress_ncz_region_to_nca(
                &mut source,
                entry.offset,
                entry.encoded_length,
                &mut out,
                cancel,
                |done, total| {
                    let part = if total == 0 {
                        1.0
                    } else {
                        (done as f32 / total as f32).clamp(0.0, 1.0)
                    };
                    progress(
                        (base as f32 + (entry.encoded_length as f32 * part))
                            / packed_bytes.max(1) as f32
                            * 0.32,
                    );
                },
            )?;
            out.flush()?;
            drop(out);
            ensure!(
                actual == entry.decoded_length && fs::metadata(&target)?.len() == actual,
                "NSZ NCZ 복원 길이 검증 실패: {}",
                entry.name
            );
            decoded_names.insert(entry.name.to_ascii_lowercase());
            sources.push(XciSource {
                name: entry.name.clone(),
                path: target,
                offset: 0,
                length: actual,
            });
        } else {
            sources.push(XciSource {
                name: entry.name.clone(),
                path: input.to_path_buf(),
                offset: entry.offset,
                length: entry.decoded_length,
            });
        }
        completed += entry.encoded_length;
        progress((completed as f32 / packed_bytes.max(1) as f32) * 0.32);
    }

    // Extract CNMT from the verified NCA's secure section, not from guesses
    // about content ordering. Unsupported metadata uses the old flow.
    let mut cnmts = Vec::<CnmtInfo>::new();
    for (i, entry) in sources.iter().enumerate() {
        if !entry.name.to_ascii_lowercase().ends_with(".cnmt.nca") {
            continue;
        }
        let parsed = read_cnmt_from_nca_region(&entry.path, entry.offset, entry.length, keys)
            .and_then(|raw| cnmt::parse_cnmt(&raw, entry.name.clone()))
            .or_else(|_| {
                // Rare NCA layouts may need the existing hactool fallback;
                // materialize at most the metadata NCA, never the whole NSP.
                let meta_file = if entry.offset == 0 {
                    entry.path.clone()
                } else {
                    if entry.length > 64 * 1024 * 1024 {
                        bail!("Unverified oversized CNMT NCA");
                    }
                    let path = decoded.join(format!("meta_{i:05}.bin"));
                    let region = entry.clone();
                    let mut reader = BufReader::new(File::open(&region.path)?);
                    reader.seek(SeekFrom::Start(region.offset))?;
                    let mut writer = File::create(&path)?;
                    std::io::copy(&mut reader.take(region.length), &mut writer)?;
                    writer.flush()?;
                    path
                };
                cnmt::parse_cnmt_nca_file(
                    &meta_file,
                    &entry.name,
                    &work.join(format!("cnmt_{i}")),
                    &resource_dir.join("bin").join("hactool.exe"),
                    prod_keys,
                    cancel,
                )
            });
        match parsed {
            Ok(cnmt) => cnmts.push(cnmt),
            Err(error) => {
                ensure!(!cancel.load(Ordering::Relaxed), "작업이 중단되었습니다");
                log(format!(
                    "NSZ→XCI: CNMT 검증을 위한 판독 불가({error:#}), 기존 경로 사용"
                ));
                return Ok(false);
            }
        }
    }
    if cnmts.is_empty() {
        return Ok(false);
    }
    let mapped = sources
        .iter()
        .map(|entry| (entry.name.to_ascii_lowercase(), entry))
        .collect::<HashMap<_, _>>();
    let mut checked = 0usize;
    let mut legacy_verified = 0usize;
    for cnmt in &cnmts {
        for content in &cnmt.contents {
            ensure!(!cancel.load(Ordering::Relaxed), "작업이 중단되었습니다");
            let name = format!("{}.nca", content.nca_id);
            let Some(entry) = mapped.get(&name.to_ascii_lowercase()) else {
                log(format!(
                    "NSZ→XCI: CNMT 필수 NCA 누락({name}), 기존 경로 사용"
                ));
                return Ok(false);
            };
            if entry.length != content.size {
                log(format!(
                    "NSZ→XCI: CNMT NCA 크기 불일치({name}), 기존 경로 사용"
                ));
                return Ok(false);
            }
            if hash_bounded_region(entry, cancel)? != content.hash {
                if decoded_names.contains(&name.to_ascii_lowercase())
                    && validate_legacy_ticketless_nca_region_for_hash(
                        &entry.path,
                        entry.offset,
                        entry.length,
                        &cnmt.title_id,
                        &content.hash,
                        keys,
                        cancel,
                    )?
                {
                    legacy_verified += 1;
                } else {
                    log(format!(
                        "NSZ→XCI: CNMT NCA SHA 불일치({name}), 기존 경로 사용"
                    ));
                    return Ok(false);
                }
            }
            checked += 1;
        }
    }
    progress(0.35);
    if legacy_verified > 0 {
        log(format!(
            "NSZ→XCI: 레거시 CNMT 원본 헤더 가상 SHA {legacy_verified}개 검증 (실제 무티켓 헤더 보존)"
        ));
    }
    let expected = sources
        .iter()
        .map(|s| (s.name.clone(), s.length))
        .collect::<Vec<_>>();
    if !build_xci_native_sources_verified(output, &expected, &sources, &preset, cancel)? {
        log("NSZ→XCI: 미지원 XCI 구성으로 기존 변환 경로 사용".to_owned());
        return Ok(false);
    }
    log(format!(
        "NSZ→XCI: 직접 패키징 완료 (중간 NSP 없음, NCZ 복원 {}개, CNMT NCA SHA {checked}개 검증)",
        decoded_names.len()
    ));
    Ok(true)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::formats::pfs0::build_from_paths;

    fn empty_keys() -> KeySet {
        KeySet {
            prod: HashMap::new(),
            title: HashMap::new(),
        }
    }

    fn make_nsz(root: &Path, extension: &str, bytes: &[u8]) -> Result<std::path::PathBuf> {
        let mut files = Vec::new();
        for i in 0..4u8 {
            let name = format!("{i:032x}.{extension}");
            let path = root.join(format!("input_{i}"));
            fs::write(&path, bytes)?;
            files.push((name, path));
        }
        let nsz = root.join("input.nsz");
        build_from_paths(&files, &nsz)?;
        Ok(nsz)
    }

    #[test]
    fn no_cnmt_uses_compatible_fallback_without_mutating_output() -> Result<()> {
        let temp = tempfile::tempdir()?;
        let nsz = make_nsz(temp.path(), "nca", &[0xA5; 128])?;
        let output = temp.path().join("previous.xci");
        fs::write(&output, b"prior verified image")?;
        let work = temp.path().join("scratch");
        let used = try_native_nsz_to_xci(
            &nsz,
            &output,
            temp.path(),
            &temp.path().join("missing.keys"),
            &empty_keys(),
            &work,
            &AtomicBool::new(false),
            &mut |_| {},
            &mut |_| {},
        )?;
        assert!(!used);
        assert_eq!(fs::read(&output)?, b"prior verified image");
        assert!(!work.exists());
        Ok(())
    }

    #[test]
    fn cancelled_nsz_does_not_touch_output_or_workspace() -> Result<()> {
        let temp = tempfile::tempdir()?;
        let nsz = make_nsz(temp.path(), "nca", &[0xA5; 128])?;
        let output = temp.path().join("previous.xci");
        fs::write(&output, b"prior verified image")?;
        let work = temp.path().join("scratch");
        assert!(
            try_native_nsz_to_xci(
                &nsz,
                &output,
                temp.path(),
                &temp.path().join("missing.keys"),
                &empty_keys(),
                &work,
                &AtomicBool::new(true),
                &mut |_| {},
                &mut |_| {},
            )
            .is_err()
        );
        assert_eq!(fs::read(&output)?, b"prior verified image");
        assert!(!work.exists());
        Ok(())
    }

    #[test]
    fn malformed_ncz_rejected_before_output_modification() -> Result<()> {
        let temp = tempfile::tempdir()?;
        let nsz = make_nsz(temp.path(), "ncz", b"truncated NCZ region")?;
        let output = temp.path().join("previous.xci");
        fs::write(&output, b"prior verified image")?;
        let work = temp.path().join("scratch");
        assert!(
            try_native_nsz_to_xci(
                &nsz,
                &output,
                temp.path(),
                &temp.path().join("missing.keys"),
                &empty_keys(),
                &work,
                &AtomicBool::new(false),
                &mut |_| {},
                &mut |_| {},
            )
            .is_err()
        );
        assert_eq!(fs::read(&output)?, b"prior verified image");
        assert!(!work.exists());
        Ok(())
    }
}
