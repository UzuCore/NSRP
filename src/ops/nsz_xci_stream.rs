//! Stage35: decode compressed NCZ entries directly into the verified XCI.
//! No reconstructed NCZ->NCA scratch files, not even for small CNMT NCZs.
//! Metadata is decoded in a bounded RAM buffer before entering the builder.
//! If that metadata layout is unsupported, Stage34 remains the safe fallback.

use crate::{
    formats::{
        nca::restore_legacy_rights_header_region_for_hash,
        ncz_stream::{decompress_ncz_region_to_nca, reconstructed_nca_size},
        pfs0::Pfs0Index,
    },
    keys::KeySet,
    ops::{
        cnmt::{self, CnmtInfo},
        native_meta::{read_cnmt_from_nca_bytes, read_cnmt_from_nca_region},
        xci_output::build_xci_virtual_verified,
    },
};
use anyhow::{Context, Result, ensure};
use sha2::{Digest, Sha256};
use std::{
    collections::{HashMap, HashSet},
    fs::File,
    io::{BufReader, Read, Seek, SeekFrom, Write},
    path::Path,
    sync::atomic::{AtomicBool, Ordering},
};

const DEFAULT_INFO: &[u8] = include_bytes!("../../bin/game_info_preset.ini");
// The virtual-source card-tier check below remains authoritative; this
// coarse upper bound only avoids unnecessary NCZ metadata inspection.
const MAX_CARD_SIZE: u64 = 32 * 1024 * 1024 * 1024;
const CARD_HEADROOM: u64 = 8 * 1024 * 1024;
const MAX_IN_MEMORY_META_NCA: u64 = 64 * 1024 * 1024;

#[derive(Debug, Clone)]
struct VirtualEntry {
    name: String,
    offset: u64,
    encoded_len: u64,
    decoded_len: u64,
    is_ncz: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ExpectedNca {
    sha256: [u8; 32],
    size: u64,
    title_id: String,
}

fn is_cancelled(cancel: &AtomicBool) -> Result<()> {
    ensure!(!cancel.load(Ordering::Relaxed), "작업이 중단되었습니다");
    Ok(())
}

fn hash_region(path: &Path, offset: u64, size: u64, cancel: &AtomicBool) -> Result<[u8; 32]> {
    let mut file = BufReader::with_capacity(1024 * 1024, File::open(path)?);
    file.seek(SeekFrom::Start(offset))?;
    let mut remaining = size;
    let mut bytes = vec![0u8; 1024 * 1024];
    let mut hasher = Sha256::new();
    while remaining != 0 {
        is_cancelled(cancel)?;
        let count = remaining.min(bytes.len() as u64) as usize;
        file.read_exact(&mut bytes[..count])?;
        hasher.update(&bytes[..count]);
        remaining -= count as u64;
    }
    Ok(hasher.finalize().into())
}

/// Copy a noncompressed NCA directly from a range in the source NSZ and
/// authenticate it against CNMT *while* copying, without rereading it.
fn write_plain_nca(
    input: &mut BufReader<File>,
    entry: &VirtualEntry,
    output: &mut File,
    expected: Option<&ExpectedNca>,
    cancel: &AtomicBool,
) -> Result<()> {
    input.seek(SeekFrom::Start(entry.offset))?;
    let mut buffer = vec![0u8; 1024 * 1024];
    let mut remaining = entry.decoded_len;
    let mut hasher = expected.map(|_| Sha256::new());
    while remaining > 0 {
        is_cancelled(cancel)?;
        let take = remaining.min(buffer.len() as u64) as usize;
        input.read_exact(&mut buffer[..take])?;
        output.write_all(&buffer[..take])?;
        if let Some(digest) = &mut hasher {
            digest.update(&buffer[..take]);
        }
        remaining -= take as u64;
    }
    if let (Some(digest), Some(expected)) = (hasher, expected) {
        ensure!(
            digest.finalize().as_slice() == expected.sha256,
            "NSZ→XCI: CNMT SHA mismatch for uncompressed NCA {}",
            entry.name
        );
    }
    Ok(())
}

/// Conservative eligibility gate: preserve custom card layouts and metadata
/// requiring third-party tools by returning false before the XCI publisher.
/// A corrupted NCZ or I/O failure is never treated as a format fallback.
#[allow(clippy::too_many_arguments)]
pub(crate) fn try_streamed_nsz_to_xci(
    input: &Path,
    output: &Path,
    resource_dir: &Path,
    keys: &KeySet,
    cancel: &AtomicBool,
    progress: &mut dyn FnMut(f32),
    log: &mut dyn FnMut(String),
) -> Result<bool> {
    is_cancelled(cancel)?;
    let preset = super::convert::game_info_preset_data(resource_dir)?;
    if preset != DEFAULT_INFO {
        return Ok(false);
    }
    let index = Pfs0Index::parse(input).context("NSZ streaming: invalid PFS0")?;
    let mut input_reader = BufReader::with_capacity(1024 * 1024, File::open(input)?);
    let file_size = input_reader.get_ref().metadata()?.len();
    let mut entries = Vec::<VirtualEntry>::new();
    let mut seen_names = HashSet::new();
    let mut decoded_total = 0u64;
    let mut encoded_total = 0u64;
    for entry in &index.entries {
        let lower = entry.name.to_ascii_lowercase();
        let is_ncz = lower.ends_with(".ncz");
        if !is_ncz && !lower.ends_with(".nca") {
            continue;
        }
        let name = if is_ncz {
            let (base, _) = entry
                .name
                .rsplit_once('.')
                .context("NCZ filename missing extension")?;
            format!("{base}.nca")
        } else {
            entry.name.clone()
        };
        if !seen_names.insert(name.to_ascii_lowercase()) {
            return Ok(false);
        }
        let offset = index
            .data_start
            .checked_add(entry.offset)
            .context("NSZ region offset overflow")?;
        ensure!(
            offset
                .checked_add(entry.size)
                .is_some_and(|end| end <= file_size),
            "NSZ NCA/NCZ region outside source container"
        );
        let decoded_len = if is_ncz {
            reconstructed_nca_size(&mut input_reader, offset, entry.size)?
        } else {
            entry.size
        };
        decoded_total = decoded_total
            .checked_add(decoded_len)
            .context("Native XCI size overflow")?;
        encoded_total = encoded_total
            .checked_add(entry.size)
            .context("NSZ encoded NCA size overflow")?;
        entries.push(VirtualEntry {
            name,
            offset,
            encoded_len: entry.size,
            decoded_len,
            is_ncz,
        });
    }
    if entries.len() < 4 || decoded_total > MAX_CARD_SIZE - CARD_HEADROOM - 0xF000 {
        return Ok(false);
    }
    let virtual_sources = entries
        .iter()
        .map(|entry| (entry.name.clone(), entry.decoded_len))
        .collect::<Vec<_>>();
    // Verify cardinality, unique safe filenames, card-size tier, and preset
    // before doing any full NCZ decoding.
    if !crate::ops::native_xci::supports_virtual_sources(&virtual_sources, &preset)? {
        return Ok(false);
    }

    let mut cnmts = Vec::<CnmtInfo>::new();
    let mut meta_in_memory = 0usize;
    for entry in &entries {
        is_cancelled(cancel)?;
        if !entry.name.to_ascii_lowercase().ends_with(".cnmt.nca") {
            continue;
        }
        let raw = if entry.is_ncz {
            // An unbounded metadata NCZ must go through Stage34's proven
            // disk-backed metadata and external-tool fallback.
            if entry.decoded_len > MAX_IN_MEMORY_META_NCA {
                return Ok(false);
            }
            let mut decoded = Vec::with_capacity(usize::try_from(entry.decoded_len)?);
            let written = decompress_ncz_region_to_nca(
                &mut input_reader,
                entry.offset,
                entry.encoded_len,
                &mut decoded,
                cancel,
                |_, _| {},
            )?;
            ensure!(
                written == entry.decoded_len && decoded.len() as u64 == written,
                "NCZ metadata reconstruction length mismatch"
            );
            meta_in_memory += 1;
            read_cnmt_from_nca_bytes(&decoded, keys)
        } else {
            read_cnmt_from_nca_region(input, entry.offset, entry.decoded_len, keys)
        };
        // If this encrypted metadata section is not supported natively,
        // Stage34 will retain the established hactool/LibHac fallback.
        match raw.and_then(|raw| cnmt::parse_cnmt(&raw, entry.name.clone())) {
            Ok(cnmt) => cnmts.push(cnmt),
            Err(err) => {
                is_cancelled(cancel)?;
                log(format!(
                    "NSZ→XCI: 스트리밍 메타데이터 미지원({err:#}), 기존 검증 경로로 처리"
                ));
                return Ok(false);
            }
        }
    }
    if cnmts.is_empty() {
        return Ok(false);
    }
    let available = entries
        .iter()
        .map(|entry| (entry.name.to_ascii_lowercase(), entry.decoded_len))
        .collect::<HashMap<_, _>>();
    let mut expected = HashMap::<String, ExpectedNca>::new();
    for cnmt in &cnmts {
        for content in &cnmt.contents {
            let name = format!("{}.nca", content.nca_id).to_ascii_lowercase();
            if available.get(&name) != Some(&content.size) {
                log(format!(
                    "NSZ→XCI: CNMT 필수 NCA 누락/크기 불일치({name}), 기존 경로 사용"
                ));
                return Ok(false);
            }
            let candidate = ExpectedNca {
                sha256: content.hash,
                size: content.size,
                title_id: cnmt.title_id.clone(),
            };
            if let Some(previous) = expected.insert(name.clone(), candidate.clone())
                && previous != candidate
            {
                log(format!(
                    "NSZ→XCI: 중복 NCA CNMT 참조 불일치({name}), 기존 경로 사용"
                ));
                return Ok(false);
            }
        }
    }

    let mut verified = 0usize;
    let mut restored = 0usize;
    let mut decoded_nczs = 0usize;
    let mut encoded_done = 0u64;
    let expected_lengths = virtual_sources.clone();
    let built = build_xci_virtual_verified(
        output,
        &expected_lengths,
        &virtual_sources,
        &preset,
        cancel,
        |index, out, staged| {
            is_cancelled(cancel)?;
            let entry = &entries[index];
            let expected = expected.get(&entry.name.to_ascii_lowercase());
            let start = out.stream_position()?;
            if entry.is_ncz {
                let written = decompress_ncz_region_to_nca(
                    &mut input_reader,
                    entry.offset,
                    entry.encoded_len,
                    out,
                    cancel,
                    |current, total| {
                        let part = if total == 0 {
                            1.0
                        } else {
                            (current as f32 / total as f32).clamp(0.0, 1.0)
                        };
                        progress(
                            0.05 + ((encoded_done as f32 + entry.encoded_len as f32 * part)
                                / encoded_total.max(1) as f32)
                                * 0.65,
                        );
                    },
                )?;
                ensure!(
                    written == entry.decoded_len,
                    "Streamed NCZ->XCI NCA length mismatch: {}",
                    entry.name
                );
                decoded_nczs += 1;
                if let Some(expected) = expected {
                    let repaired = restore_legacy_rights_header_region_for_hash(
                        staged,
                        start,
                        entry.decoded_len,
                        &expected.title_id,
                        &expected.sha256,
                        keys,
                    )?;
                    if repaired {
                        restored += 1;
                    } else {
                        // Unmodified rights-managed or preexisting valid NCA:
                        // require the *entire* NCA SHA, never just the HFS0
                        // 0x200-byte header-prefix hash.
                        ensure!(
                            hash_region(staged, start, entry.decoded_len, cancel)?
                                == expected.sha256,
                            "Streamed NCZ CNMT SHA mismatch: {}",
                            entry.name
                        );
                    }
                    verified += 1;
                }
            } else {
                write_plain_nca(&mut input_reader, entry, out, expected, cancel)?;
                if expected.is_some() {
                    verified += 1;
                }
            }
            // The decoder or header-repair routine may use secondary file
            // handles. HFS0 only hashes the NCA prefix after we return.
            let expected_end = start
                .checked_add(entry.decoded_len)
                .context("XCI decoded position overflow")?;
            ensure!(
                out.stream_position()? == expected_end,
                "Native XCI entry cursor did not end after the decoded NCA"
            );
            encoded_done += entry.encoded_len;
            progress(0.05 + (encoded_done as f32 / encoded_total.max(1) as f32) * 0.65);
            Ok(())
        },
    )?;
    if built {
        progress(0.72);
        log(format!(
            "NSZ→XCI: NCZ 임시 NCA 0개 직접 스트리밍 완료 (중간 NSP 없음, NCZ {decoded_nczs}개, RAM CNMT {meta_in_memory}개, rights 복원 {restored}개, CNMT NCA SHA {verified}개 검증)"
        ));
    }
    Ok(built)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::formats::pfs0::build_from_paths;
    use std::fs;

    fn empty_keys() -> KeySet {
        KeySet {
            prod: HashMap::new(),
            title: HashMap::new(),
        }
    }

    #[test]
    fn missing_cnmt_falls_back_without_writing_an_xci_or_temp_nca() -> Result<()> {
        let temp = tempfile::tempdir()?;
        let mut inputs = Vec::new();
        for n in 0..4u8 {
            let path = temp.path().join(format!("blob{n}"));
            fs::write(&path, vec![n; 384 * 1024])?;
            inputs.push((format!("{n:032x}.nca"), path));
        }
        let nsz = temp.path().join("plain.nsz");
        build_from_paths(&inputs, &nsz)?;
        let old = temp.path().join("old.xci");
        fs::write(&old, b"original output")?;
        assert!(!try_streamed_nsz_to_xci(
            &nsz,
            &old,
            temp.path(),
            &empty_keys(),
            &AtomicBool::new(false),
            &mut |_| {},
            &mut |_| {}
        )?);
        assert_eq!(fs::read(&old)?, b"original output");
        assert_eq!(fs::read_dir(temp.path())?.count(), 6);
        Ok(())
    }

    #[test]
    fn cancelled_virtual_conversion_preserves_existing_output() -> Result<()> {
        let temp = tempfile::tempdir()?;
        let old = temp.path().join("old.xci");
        fs::write(&old, b"original output")?;
        let input = temp.path().join("empty.nsz");
        fs::write(&input, b"broken")?;
        assert!(
            try_streamed_nsz_to_xci(
                &input,
                &old,
                temp.path(),
                &empty_keys(),
                &AtomicBool::new(true),
                &mut |_| {},
                &mut |_| {}
            )
            .is_err()
        );
        assert_eq!(fs::read(&old)?, b"original output");
        Ok(())
    }

    #[test]
    fn invalid_container_cannot_replace_existing_xci() -> Result<()> {
        let temp = tempfile::tempdir()?;
        let old = temp.path().join("old.xci");
        fs::write(&old, b"original output")?;
        let input = temp.path().join("bad.nsz");
        fs::write(&input, b"bad NSZ")?;
        assert!(
            try_streamed_nsz_to_xci(
                &input,
                &old,
                temp.path(),
                &empty_keys(),
                &AtomicBool::new(false),
                &mut |_| {},
                &mut |_| {}
            )
            .is_err()
        );
        assert_eq!(fs::read(&old)?, b"original output");
        Ok(())
    }
}
