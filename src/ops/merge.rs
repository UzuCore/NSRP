use crate::{
    formats::{
        nca::restore_legacy_rights_header_region_for_hash,
        ncz_stream::{decompress_ncz_region_to_nca, reconstructed_nca_size},
        pfs0::build_from_paths,
    },
    keys::KeySet,
    ops::{
        cnmt::{
            self, CnmtInfo, ContentMetaType, base_title_id, discover_game_metadata,
            get_title_from_control_nca, parse_nacp_title, resolve_content_entry,
        },
        compress::{
            CompressOptions, compress_nsp, decompress_nsz, repair_legacy_container_headers,
            repair_legacy_nsp_headers,
        },
        container::{self, ContainerEntry},
        convert::game_info_preset_data,
        native_fs,
        native_xci::{self, XciSource},
        split::sanitize_filename,
        xci_output::{
            XciBuilder, build_xci_auto_verified, build_xci_native_sources_verified,
            build_xci_virtual_verified, compress_xci_verified, publish_verified_xci,
        },
        xcz::{XczOptions, decompress_xcz},
    },
};
use anyhow::{Context, Result, bail, ensure};
use rayon::prelude::*;
use sha2::{Digest, Sha256};
use std::{
    collections::{BTreeMap, HashSet},
    fs::{self, File},
    io::{BufReader, BufWriter, Read, Seek, SeekFrom, Write},
    path::{Path, PathBuf},
    sync::atomic::{AtomicBool, Ordering},
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MergeFormat {
    Nsp,
    Xci,
}

#[derive(Debug, Clone)]
pub struct MergeOptions {
    pub output_format: MergeFormat,
    pub compress_after: bool,
    pub use_game_title: bool,
    pub decompression_threads: usize,
    pub compression: CompressOptions,
}

#[derive(Debug, Clone)]
struct SourceInfo {
    original: PathBuf,
    path: PathBuf,
    entries: Vec<ContainerEntry>,
    cnmts: Vec<CnmtInfo>,
}

#[derive(Debug, Clone)]
struct Candidate {
    source: usize,
    cnmt: CnmtInfo,
}

/// A selected merge member retains the byte region in its parent NSP/XCI/NSZ
/// instead of creating group/item_00000 NCA copies. NCZ reconstruction is
/// written directly into the staged secure partition when supported.
#[derive(Clone, Debug)]
struct DirectMergeMember {
    name: String,
    path: PathBuf,
    offset: u64,
    encoded_len: u64,
    decoded_len: u64,
    ncz: bool,
    authenticated: Option<AuthenticatedMergeContent>,
}

#[derive(Clone, Debug)]
struct AuthenticatedMergeContent {
    sha256: [u8; 32],
    title_id: String,
}

pub fn merge_packages(
    inputs: &[PathBuf],
    output_dir: &Path,
    output_dir_explicit: bool,
    resource_dir: &Path,
    hactool: &Path,
    prod_keys: &Path,
    keys: &mut KeySet,
    options: &MergeOptions,
    cancel: &AtomicBool,
    progress: &mut dyn FnMut(f32),
    log: &mut dyn FnMut(String),
) -> Result<Vec<PathBuf>> {
    if inputs.len() < 2 {
        bail!("병합에는 최소 2개 입력 파일이 필요합니다");
    }
    fs::create_dir_all(output_dir)?;
    let temp = crate::workspace::temp_workspace("nsrp_merge_")?;
    let prepared_inputs = prepare_merge_inputs(
        inputs,
        temp.path(),
        options.decompression_threads,
        (options.output_format == MergeFormat::Xci).then_some(&*keys),
        cancel,
        log,
    )?;
    let mut sources = Vec::new();
    for (index, (original, path)) in prepared_inputs.iter().enumerate() {
        if cancel.load(Ordering::Relaxed) {
            bail!("작업이 중단되었습니다");
        }
        match original
            .extension()
            .and_then(|ext| ext.to_str())
            .unwrap_or("")
            .to_ascii_lowercase()
            .as_str()
        {
            // A native-supported NSZ remains byte-for-byte unchanged. Repair
            // any legacy rights header only in the staged XCI output.
            "nsz" if path != original => {
                repair_legacy_nsp_headers(path, hactool, prod_keys, cancel, &mut |_| {}, log)?
            }
            "xcz" if path != original => repair_legacy_container_headers(
                path,
                true,
                hactool,
                prod_keys,
                cancel,
                &mut |_| {},
                log,
            )?,
            _ => {}
        }
        let (entries, cnmts, legacy_partition_fallback) = discover_game_metadata(
            path,
            &temp.path().join(format!("metadata_{index}")),
            hactool,
            prod_keys,
            cancel,
        )
        .with_context(|| format!("컨테이너 분석 실패: {}", path.display()))?;
        if legacy_partition_fallback {
            log(format!(
                "구형 XCI 파티션 배치 감지: {} — Update/DLC 메타데이터를 추가 탐색했습니다",
                original
                    .file_name()
                    .and_then(|name| name.to_str())
                    .unwrap_or("input")
            ));
        }
        sources.push(SourceInfo {
            original: original.clone(),
            path: path.clone(),
            entries,
            cnmts,
        });
        progress(0.20 * (index + 1) as f32 / inputs.len() as f32);
    }

    let mut groups: BTreeMap<String, BTreeMap<String, Candidate>> = BTreeMap::new();
    for (source_index, source) in sources.iter().enumerate() {
        for cnmt in &source.cnmts {
            let base = base_title_id(&cnmt.title_id)?;
            let by_title = groups.entry(base).or_default();
            match by_title.get(&cnmt.title_id) {
                Some(old) if old.cnmt.version >= cnmt.version => {}
                _ => {
                    by_title.insert(
                        cnmt.title_id.clone(),
                        Candidate {
                            source: source_index,
                            cnmt: cnmt.clone(),
                        },
                    );
                }
            }
        }
    }
    let groups: Vec<(String, Vec<Candidate>)> = groups
        .into_iter()
        .filter_map(|(base, map)| {
            let values: Vec<_> = map.into_values().collect();
            let has_base = values
                .iter()
                .any(|c| c.cnmt.meta_type == ContentMetaType::Base);
            if has_base && has_multiple_sources(&values) {
                Some((base, values))
            } else {
                None
            }
        })
        .collect();
    if groups.is_empty() {
        bail!("본편과 업데이트/DLC가 함께 있는 병합 그룹을 찾지 못했습니다");
    }

    let mut outputs = Vec::new();
    let group_count = groups.len();
    for (group_index, (base_id, mut candidates)) in groups.into_iter().enumerate() {
        if cancel.load(Ordering::Relaxed) {
            bail!("작업이 중단되었습니다");
        }
        candidates.sort_by_key(|c| (meta_order(c.cnmt.meta_type), c.cnmt.title_id.clone()));
        let group_dir = temp.path().join(format!("group_{group_index}"));
        fs::create_dir_all(&group_dir)?;

        let group_output_dir = if output_dir_explicit {
            output_dir.to_path_buf()
        } else if let Some(base) = candidates
            .iter()
            .find(|candidate| candidate.cnmt.meta_type == ContentMetaType::Base)
        {
            sources[base.source]
                .original
                .parent()
                .unwrap_or_else(|| Path::new("."))
                .to_path_buf()
        } else {
            output_dir.to_path_buf()
        };
        fs::create_dir_all(&group_output_dir)?;

        let mut game_title = None;
        let mut title_control_staged = false;
        if options.use_game_title
            && let Some(base) = candidates
                .iter()
                .find(|c| c.cnmt.meta_type == ContentMetaType::Base)
            && let Some(control_name) = base.cnmt.control_nca_name()
        {
            let source = &sources[base.source];
            if let Some(entry) = resolve_content_entry(&source.entries, &control_name) {
                if options.output_format == MergeFormat::Xci
                    && !entry.name.to_ascii_lowercase().ends_with(".ncz")
                {
                    game_title = try_title_from_native_region(
                        source,
                        entry,
                        &group_dir.join("native_title"),
                        keys,
                        cancel,
                    )
                    .unwrap_or(None);
                    if game_title.is_some() {
                        log(
                            "XCI 병합: 제목용 Control NCA도 원본 바이트 영역에서 직접 읽음"
                                .to_owned(),
                        );
                    }
                }
                if game_title.is_none() {
                    ensure!(!cancel.load(Ordering::Relaxed), "작업이 중단되었습니다");
                    let title_dir = group_dir.join("native_title");
                    if title_dir.exists() {
                        fs::remove_dir_all(&title_dir)?;
                    }
                    let control = group_dir.join("control.nca");
                    materialize_entry(&source.path, entry, &control, cancel)?;
                    title_control_staged = true;
                    game_title = get_title_from_control_nca(
                        &control,
                        hactool,
                        prod_keys,
                        &group_dir.join("title"),
                        cancel,
                    )
                    .unwrap_or(None);
                }
            }
        }
        let fallback = candidates
            .iter()
            .find(|candidate| candidate.cnmt.meta_type == ContentMetaType::Base)
            .or_else(|| candidates.first())
            .and_then(|candidate| sources.get(candidate.source))
            .and_then(|source| source.original.file_stem().and_then(|stem| stem.to_str()))
            .map(strip_bracket_tags)
            .filter(|value| !value.is_empty())
            .unwrap_or_else(|| "Merged".to_owned());
        let game_title = sanitize_filename(game_title.as_deref().unwrap_or(&fallback));
        let tag = merge_content_tag(&candidates);
        let base_name = match tag {
            Some(tag) => sanitize_filename(&format!("[Merged] {game_title} {tag}")),
            None => sanitize_filename(&format!("[Merged] {game_title}")),
        };

        if options.output_format == MergeFormat::Xci {
            let preset = game_info_preset_data(resource_dir)?;
            if let Some(members) = plan_direct_xci_members(&candidates, &sources, &preset, cancel)?
            {
                let xci = group_dir.join(format!("{base_name}.xci"));
                write_direct_merged_xci(&xci, &members, &preset, keys, cancel)?;
                let ncz_count = members.iter().filter(|member| member.ncz).count();
                log(format!(
                    "XCI 병합: 원본 패키지 영역 직접 스트리밍 (콘텐츠 NCA 임시 추출 0개, 제목용 Control NCA 임시 {}, NCZ→XCI 직접 {ncz_count}개)",
                    if title_control_staged { 1 } else { 0 }
                ));
                let final_path = if options.compress_after {
                    let path = group_output_dir.join(format!("{base_name}.xcz"));
                    compress_xci_verified(
                        &xci,
                        &path,
                        keys,
                        &XczOptions {
                            level: options.compression.level,
                            threads: options.compression.threads,
                            block_mode: options.compression.block_mode,
                            long_mode: options.compression.long_mode,
                        },
                        cancel,
                        log,
                    )?;
                    path
                } else {
                    let path = group_output_dir.join(format!("{base_name}.xci"));
                    publish_verified_xci(&xci, &path, cancel)?;
                    path
                };
                outputs.push(final_path);
                progress(0.20 + 0.80 * (group_index + 1) as f32 / group_count as f32);
                continue;
            }
            log("XCI 병합: 미지원 카드 등급/구성으로 기존 병합 경로 사용".to_owned());
        }

        let mut files = Vec::<(String, PathBuf)>::new();
        let mut names = HashSet::<String>::new();
        for (candidate_index, candidate) in candidates.iter().enumerate() {
            let source = &sources[candidate.source];
            add_named_entry(
                &source.path,
                &source.entries,
                &candidate.cnmt.cnmt_nca_name,
                &group_dir,
                &mut files,
                &mut names,
                cancel,
            )?;
            for content in &candidate.cnmt.contents {
                let wanted = format!("{}.nca", content.nca_id);
                if !try_add_content(
                    &wanted,
                    candidate.source,
                    &sources,
                    &group_dir,
                    &mut files,
                    &mut names,
                    cancel,
                )? {
                    bail!("병합 필수 콘텐츠 누락: {wanted}");
                }
            }
            let prefix = candidate.cnmt.title_id[..16.min(candidate.cnmt.title_id.len())]
                .to_ascii_lowercase();
            for entry in source.entries.iter().filter(|e| {
                let n = e.name.to_ascii_lowercase();
                (n.ends_with(".tik") || n.ends_with(".cert")) && n.starts_with(&prefix)
            }) {
                let key = entry.name.to_ascii_lowercase();
                if names.insert(key) {
                    let path = group_dir.join(format!("extra_{candidate_index}_{}", files.len()));
                    materialize_raw(&source.path, entry, &path, cancel)?;
                    files.push((entry.name.clone(), path));
                }
            }
        }
        files.sort_by(|a, b| a.0.cmp(&b.0));
        let intermediate = match options.output_format {
            MergeFormat::Nsp => {
                let intermediate_nsp = group_dir.join(format!("{base_name}.nsp"));
                build_from_paths(&files, &intermediate_nsp)?;
                log(format!(
                    "병합 NSP 구성 완료: {base_id} ({}개 엔트리)",
                    files.len()
                ));
                intermediate_nsp
            }
            MergeFormat::Xci => {
                // A merged XCI is assembled directly from the selected NCA
                // sources. Building an unused intermediate NSP first doubles
                // its peak disk footprint and performs a full extra copy.
                log("XCI 병합: 사용하지 않는 중간 NSP 생성 생략".to_owned());
                let xci = group_dir.join(format!("{base_name}.xci"));
                build_merged_xci(
                    &xci,
                    &candidates,
                    &files,
                    resource_dir,
                    prod_keys,
                    cancel,
                    log,
                )?;
                xci
            }
        };
        let final_path = if options.compress_after {
            match options.output_format {
                MergeFormat::Nsp => {
                    let path = group_output_dir.join(format!("{base_name}.nsz"));
                    compress_nsp(
                        &intermediate,
                        &path,
                        keys,
                        &options.compression,
                        cancel,
                        &mut |_| {},
                        log,
                    )?;
                    path
                }
                MergeFormat::Xci => {
                    let path = group_output_dir.join(format!("{base_name}.xcz"));
                    compress_xci_verified(
                        &intermediate,
                        &path,
                        keys,
                        &XczOptions {
                            level: options.compression.level,
                            threads: options.compression.threads,
                            block_mode: options.compression.block_mode,
                            long_mode: options.compression.long_mode,
                        },
                        cancel,
                        log,
                    )?;
                    path
                }
            }
        } else {
            let ext = match options.output_format {
                MergeFormat::Nsp => "nsp",
                MergeFormat::Xci => "xci",
            };
            let path = group_output_dir.join(format!("{base_name}.{ext}"));
            if matches!(options.output_format, MergeFormat::Xci) {
                publish_verified_xci(&intermediate, &path, cancel)?;
            } else {
                if path.exists() {
                    fs::remove_file(&path)?;
                }
                move_file(&intermediate, &path)?;
            }
            path
        };
        outputs.push(final_path);
        progress(0.20 + 0.80 * (group_index + 1) as f32 / group_count as f32);
    }
    progress(1.0);
    Ok(outputs)
}

fn prepare_merge_inputs(
    inputs: &[PathBuf],
    temp_root: &Path,
    threads: usize,
    direct_nsz_keys: Option<&KeySet>,
    cancel: &AtomicBool,
    log: &mut dyn FnMut(String),
) -> Result<Vec<(PathBuf, PathBuf)>> {
    let compressed_count = inputs
        .iter()
        .filter(|path| {
            path.extension()
                .and_then(|value| value.to_str())
                .is_some_and(|ext| matches!(ext.to_ascii_lowercase().as_str(), "nsz" | "xcz"))
        })
        .count();
    if compressed_count == 0 {
        return Ok(inputs
            .iter()
            .cloned()
            .map(|path| (path.clone(), path))
            .collect());
    }

    let worker_count = threads.max(1).min(inputs.len().max(1));
    log(format!(
        "압축 파일 사전 해제: {compressed_count}개 (스레드: {worker_count})"
    ));
    let pool = rayon::ThreadPoolBuilder::new()
        .num_threads(worker_count)
        .build()
        .context("병합 압축 해제 스레드 풀 생성 실패")?;

    let results = pool.install(|| {
        inputs
            .par_iter()
            .enumerate()
            .map(|(index, input)| -> Result<(PathBuf, PathBuf)> {
                if cancel.load(Ordering::Relaxed) {
                    bail!("작업이 중단되었습니다");
                }
                let ext = input
                    .extension()
                    .and_then(|value| value.to_str())
                    .unwrap_or("")
                    .to_ascii_lowercase();
                match ext.as_str() {
                    "nsz" => {
                        if direct_nsz_keys.is_some_and(|keys| {
                            native_compressed_cnmts_readable(input, keys, cancel)
                        }) {
                            return Ok((input.clone(), input.clone()));
                        }
                        let output = temp_root.join(format!("prepared_{index}.nsp"));
                        decompress_nsz(input, &output, cancel, &mut |_| {}, &mut |_| {})?;
                        Ok((input.clone(), output))
                    }
                    "xcz" => {
                        if direct_nsz_keys.is_some_and(|keys| {
                            native_compressed_cnmts_readable(input, keys, cancel)
                        }) {
                            return Ok((input.clone(), input.clone()));
                        }
                        let output = temp_root.join(format!("prepared_{index}.xci"));
                        decompress_xcz(input, &output, cancel, &mut |_| {}, &mut |_| {})?;
                        Ok((input.clone(), output))
                    }
                    _ => Ok((input.clone(), input.clone())),
                }
            })
            .collect::<Vec<_>>()
    });

    let mut prepared = Vec::with_capacity(results.len());
    for result in results {
        let (original, path) = result?;
        if original != path {
            log(format!(
                "압축 해제 완료: {} → {}",
                original
                    .file_name()
                    .and_then(|name| name.to_str())
                    .unwrap_or("input"),
                path.file_name()
                    .and_then(|name| name.to_str())
                    .unwrap_or("prepared")
            ));
        } else if original
            .extension()
            .and_then(|ext| ext.to_str())
            .is_some_and(|ext| ext.eq_ignore_ascii_case("nsz") || ext.eq_ignore_ascii_case("xcz"))
        {
            log(format!(
                "XCI 병합: 압축 입력 원본 컨테이너 직접 사용 (전체 NSP/XCI 사전 해제 없음): {}",
                original.display()
            ));
        }
        prepared.push((original, path));
    }
    Ok(prepared)
}

/// Use the original NSZ/XCZ package only when *all* CNMT sections can be
/// read natively from its bounded PFS0/HFS0 regions. Compressed CNMT NCZ is
/// reconstructed in bounded memory; oversized/unknown layouts retain the
/// established decompression + repair path.
/// Never mutate the original compressed input.
fn native_compressed_cnmts_readable(input: &Path, keys: &KeySet, cancel: &AtomicBool) -> bool {
    if cancel.load(Ordering::Relaxed) {
        return false;
    }
    let Ok(entries) = container::list_entries(input, true) else {
        return false;
    };
    let mut count = 0usize;
    let mut names = HashSet::<String>::new();
    for entry in &entries {
        if !cnmt::is_cnmt_container_entry(&entry.name) {
            continue;
        }
        let parsed = cnmt::read_cnmt_from_container_entry(input, entry, keys, cancel);
        let Ok(info) = parsed else {
            return false;
        };
        // Reject ambiguous duplicate .cnmt.nca and .cnmt.ncz entries. Both
        // would map to the same output XCI filename.
        if !names.insert(info.cnmt_nca_name.to_ascii_lowercase()) {
            return false;
        }
        count += 1;
    }
    count != 0
}

/// Read a Control NCA directly from its byte range in NSP/XCI/NSZ. For
/// supported RomFS, the title is available without any intermediate .nca.
/// Unsupported/NCZ layouts keep the preexisting title-extraction fallback.
fn try_title_from_native_region(
    source: &SourceInfo,
    entry: &ContainerEntry,
    output_dir: &Path,
    keys: &KeySet,
    cancel: &AtomicBool,
) -> Result<Option<String>> {
    ensure!(!cancel.load(Ordering::Relaxed), "작업이 중단되었습니다");
    native_fs::unpack_nca_region(
        &source.path,
        entry.offset,
        entry.size,
        output_dir,
        keys,
        cancel,
    )?;
    let nacp = walkdir::WalkDir::new(output_dir.join("romfs"))
        .into_iter()
        .filter_map(|result| result.ok())
        .find(|entry| {
            entry.file_type().is_file()
                && entry
                    .file_name()
                    .to_str()
                    .is_some_and(|name| name.eq_ignore_ascii_case("control.nacp"))
        })
        .map(|entry| entry.into_path());
    match nacp {
        Some(path) => Ok(fs::read(path).ok().and_then(|data| parse_nacp_title(&data))),
        None => Ok(None),
    }
}

/// Inspect a single bounded PFS0/HFS0 entry before selecting it for direct
/// output. The source remains opened read-only; a compressed NCZ's declared
/// size is reconstructed from its bounded header, not guessed from its name.
fn make_direct_merge_member(
    name: &str,
    source: &SourceInfo,
    entry: &ContainerEntry,
    authenticated: Option<AuthenticatedMergeContent>,
) -> Result<DirectMergeMember> {
    let metadata = fs::symlink_metadata(&source.path)?;
    ensure!(
        metadata.is_file() && !metadata.file_type().is_symlink(),
        "병합 입력 파일 형식이 비정상입니다: {}",
        source.path.display()
    );
    ensure!(
        entry
            .offset
            .checked_add(entry.size)
            .is_some_and(|end| end <= metadata.len()),
        "병합 원본 파일 범위 초과: {}",
        entry.name
    );
    let ncz = entry.name.to_ascii_lowercase().ends_with(".ncz");
    let decoded_len = if ncz {
        let mut file = BufReader::new(File::open(&source.path)?);
        reconstructed_nca_size(&mut file, entry.offset, entry.size)?
    } else {
        entry.size
    };
    Ok(DirectMergeMember {
        name: name.to_owned(),
        path: source.path.clone(),
        offset: entry.offset,
        encoded_len: entry.size,
        decoded_len,
        ncz,
        authenticated,
    })
}

/// Collect precisely the members chosen by the existing CNMT precedence
/// algorithm without materializing any of the NCA/NCZ content. Same-named
/// NCAs referenced with contradictory CNMT sizes/hashes are rejected.
fn plan_direct_xci_members(
    candidates: &[Candidate],
    sources: &[SourceInfo],
    preset: &[u8],
    cancel: &AtomicBool,
) -> Result<Option<Vec<DirectMergeMember>>> {
    let mut planned = BTreeMap::<String, DirectMergeMember>::new();
    for candidate in candidates {
        ensure!(!cancel.load(Ordering::Relaxed), "작업이 중단되었습니다");
        let own = &sources[candidate.source];
        let name = &candidate.cnmt.cnmt_nca_name;
        let lower = name.to_ascii_lowercase();
        if let std::collections::btree_map::Entry::Vacant(slot) = planned.entry(lower) {
            let entry = resolve_content_entry(&own.entries, name)
                .with_context(|| format!("병합 필수 CNMT NCA 누락: {name}"))?;
            slot.insert(make_direct_merge_member(name, own, entry, None)?);
        }
        for content in &candidate.cnmt.contents {
            let name = format!("{}.nca", content.nca_id);
            let lower = name.to_ascii_lowercase();
            if let Some(prior) = planned.get(&lower) {
                ensure!(
                    prior.decoded_len == content.size
                        && prior
                            .authenticated
                            .as_ref()
                            .is_some_and(|verified| verified.sha256 == content.hash),
                    "CNMT references conflicting content NCA: {name}"
                );
                continue;
            }
            let preferred = std::iter::once(candidate.source)
                .chain((0..sources.len()).filter(|&index| index != candidate.source));
            let (source, entry) = preferred
                .filter_map(|i| {
                    resolve_content_entry(&sources[i].entries, &name)
                        .map(|entry| (&sources[i], entry))
                })
                .next()
                .with_context(|| format!("병합 필수 콘텐츠 누락: {name}"))?;
            let member = make_direct_merge_member(
                &name,
                source,
                entry,
                Some(AuthenticatedMergeContent {
                    sha256: content.hash,
                    title_id: candidate.cnmt.title_id.clone(),
                }),
            )?;
            ensure!(
                member.decoded_len == content.size,
                "CNMT NCA length mismatch: {name}"
            );
            planned.insert(lower, member);
        }
        let tid = candidate.cnmt.title_id.to_ascii_lowercase();
        let prefix = &tid[..16.min(tid.len())];
        for entry in own.entries.iter().filter(|entry| {
            let lower = entry.name.to_ascii_lowercase();
            (lower.ends_with(".tik") || lower.ends_with(".cert")) && lower.starts_with(prefix)
        }) {
            let lower = entry.name.to_ascii_lowercase();
            if let std::collections::btree_map::Entry::Vacant(slot) = planned.entry(lower) {
                slot.insert(make_direct_merge_member(&entry.name, own, entry, None)?);
            }
        }
    }
    let members = planned.into_values().collect::<Vec<_>>();
    let virtual_sources = members
        .iter()
        .map(|member| (member.name.clone(), member.decoded_len))
        .collect::<Vec<_>>();
    if !native_xci::supports_virtual_sources(&virtual_sources, preset)? {
        return Ok(None);
    }
    Ok(Some(members))
}

/// Write a bounded package region and calculate the CNMT SHA-256 in the same
/// pass. No second copy or entire NCA-sized heap allocation is required.
fn write_merge_raw_member(
    source: &DirectMergeMember,
    out: &mut File,
    cancel: &AtomicBool,
) -> Result<()> {
    let mut input = BufReader::with_capacity(1024 * 1024, File::open(&source.path)?);
    input.seek(SeekFrom::Start(source.offset))?;
    let mut hasher = source.authenticated.as_ref().map(|_| Sha256::new());
    let mut remaining = source.decoded_len;
    let mut scratch = vec![0u8; 1024 * 1024];
    while remaining != 0 {
        ensure!(!cancel.load(Ordering::Relaxed), "작업이 중단되었습니다");
        let take = remaining.min(scratch.len() as u64) as usize;
        input.read_exact(&mut scratch[..take])?;
        out.write_all(&scratch[..take])?;
        if let Some(digest) = hasher.as_mut() {
            digest.update(&scratch[..take]);
        }
        remaining -= take as u64;
    }
    if let (Some(hasher), Some(expected)) = (hasher, source.authenticated.as_ref()) {
        ensure!(
            hasher.finalize().as_slice() == expected.sha256,
            "병합 원본 NCA CNMT SHA 불일치: {}",
            source.name
        );
    }
    Ok(())
}

/// Stage36 native path: metadata and content bytes go from bounded NSP/XCI/
/// NSZ source regions into the one private XCI staging file. A legacy header
/// repair never writes to the original input. The HFS0 writer calculates its
/// hashes only after the whole-NCA CNMT verification is finished.
fn write_direct_merged_xci(
    output: &Path,
    members: &[DirectMergeMember],
    preset: &[u8],
    keys: &KeySet,
    cancel: &AtomicBool,
) -> Result<()> {
    let virtual_sources = members
        .iter()
        .map(|member| (member.name.clone(), member.decoded_len))
        .collect::<Vec<_>>();
    let expected_ncas = virtual_sources
        .iter()
        .filter(|(name, _)| name.to_ascii_lowercase().ends_with(".nca"))
        .cloned()
        .collect::<Vec<_>>();
    ensure!(
        build_xci_virtual_verified(
            output,
            &expected_ncas,
            &virtual_sources,
            preset,
            cancel,
            |index, out, staged| {
                ensure!(!cancel.load(Ordering::Relaxed), "작업이 중단되었습니다");
                let member = &members[index];
                if member.ncz {
                    let start = out.stream_position()?;
                    let mut input =
                        BufReader::with_capacity(1024 * 1024, File::open(&member.path)?);
                    let decoded = decompress_ncz_region_to_nca(
                        &mut input,
                        member.offset,
                        member.encoded_len,
                        out,
                        cancel,
                        |_, _| {},
                    )?;
                    ensure!(
                        decoded == member.decoded_len,
                        "병합 NCZ 복원 길이 불일치: {}",
                        member.name
                    );
                    if let Some(authenticated) = &member.authenticated {
                        let repaired = restore_legacy_rights_header_region_for_hash(
                            staged,
                            start,
                            member.decoded_len,
                            &authenticated.title_id,
                            &authenticated.sha256,
                            keys,
                        )?;
                        if !repaired {
                            let mut input =
                                BufReader::with_capacity(1024 * 1024, File::open(staged)?);
                            input.seek(SeekFrom::Start(start))?;
                            let mut hasher = Sha256::new();
                            let mut remaining = decoded;
                            let mut buf = vec![0u8; 1024 * 1024];
                            while remaining != 0 {
                                ensure!(!cancel.load(Ordering::Relaxed), "작업이 중단되었습니다");
                                let take = remaining.min(buf.len() as u64) as usize;
                                input.read_exact(&mut buf[..take])?;
                                hasher.update(&buf[..take]);
                                remaining -= take as u64;
                            }
                            ensure!(
                                hasher.finalize().as_slice() == authenticated.sha256,
                                "병합 복원 NCZ CNMT SHA 불일치: {}",
                                member.name
                            );
                        }
                    }
                } else {
                    write_merge_raw_member(member, out, cancel)?;
                }
                Ok(())
            },
        )?,
        "Native XCI merge was rejected after the supported-layout planning gate"
    );
    Ok(())
}

fn build_merged_xci(
    output: &Path,
    candidates: &[Candidate],
    files: &[(String, PathBuf)],
    resource_dir: &Path,
    prod_keys: &Path,
    cancel: &AtomicBool,
    log: &mut dyn FnMut(String),
) -> Result<()> {
    let file_map = files
        .iter()
        .map(|(name, path)| (name.to_ascii_lowercase(), (name, path)))
        .collect::<BTreeMap<_, _>>();
    let mut placed = HashSet::<String>::new();
    let mut planned = Vec::<(String, String, PathBuf)>::new();
    for candidate in candidates {
        let partition = partition_for_meta(candidate.cnmt.meta_type);
        let mut required = candidate.cnmt.required_nca_names();
        let tid_prefix =
            candidate.cnmt.title_id[..16.min(candidate.cnmt.title_id.len())].to_ascii_lowercase();
        required.extend(files.iter().filter_map(|(name, _)| {
            let lower = name.to_ascii_lowercase();
            ((lower.ends_with(".tik") || lower.ends_with(".cert"))
                && lower.starts_with(&tid_prefix))
            .then(|| name.clone())
        }));

        for wanted in required {
            let lower = wanted.to_ascii_lowercase();
            let Some((actual_name, source)) = file_map.get(&lower) else {
                bail!("XCI 파티션 구성에 필요한 파일이 없습니다: {wanted}");
            };
            let placement_key = format!("{partition}|{lower}");
            if !placed.insert(placement_key) {
                continue;
            }
            planned.push((
                partition.to_owned(),
                (*actual_name).clone(),
                (*source).clone(),
            ));
        }
    }

    if !planned
        .iter()
        .any(|(partition, _, _)| partition == "secure")
    {
        bail!("XCI secure 파티션이 비었습니다");
    }

    let preset_data = game_info_preset_data(resource_dir)?;
    let expected_ncas = files
        .iter()
        .filter(|(name, _)| name.to_ascii_lowercase().ends_with(".nca"))
        .map(|(name, path)| Ok((name.clone(), fs::metadata(path)?.len())))
        .collect::<Result<Vec<_>>>()?;
    if planned
        .iter()
        .all(|(partition, _, _)| partition == "secure")
    {
        let direct_sources = planned
            .iter()
            .map(|(_, name, path)| {
                Ok(XciSource {
                    name: name.clone(),
                    path: path.clone(),
                    offset: 0,
                    length: fs::metadata(path)?.len(),
                })
            })
            .collect::<Result<Vec<_>>>()?;
        if build_xci_native_sources_verified(
            output,
            &expected_ncas,
            &direct_sources,
            &preset_data,
            cancel,
        )? {
            log("XCI 병합: Rust 네이티브 빌더 (원본 NCA 직접 스트리밍)".to_owned());
            log(format!("XCI 생성 완료: {}", output.display()));
            return Ok(());
        }
    }
    // Preserve Stage32's hacbuild fallback for unknown partition layouts.
    // The copy/hardlink workspace is only built when it is actually needed.
    let temp = crate::workspace::temp_workspace("nsrp_merge_xci_")?;
    let work_root = temp.path().join("work");
    for partition in ["secure", "update", "normal"] {
        fs::create_dir_all(work_root.join(partition))?;
    }
    for (partition, name, source) in &planned {
        let target = work_root.join(partition).join(name);
        if fs::hard_link(source, &target).is_err() {
            fs::copy(source, &target)?;
        }
    }
    let engine = build_xci_auto_verified(
        output,
        &expected_ncas,
        &work_root,
        temp.path(),
        resource_dir,
        prod_keys,
        &preset_data,
        cancel,
    )?;
    log(match engine {
        XciBuilder::NativeRust => "XCI 병합: Rust 네이티브 빌더 사용".to_owned(),
        XciBuilder::HacbuildFallback => "XCI 병합: hacbuild 폴백".to_owned(),
    });
    log(format!("XCI 생성 완료: {}", output.display()));
    Ok(())
}

fn strip_bracket_tags(value: &str) -> String {
    let mut output = String::with_capacity(value.len());
    let mut depth = 0usize;
    for ch in value.chars() {
        match ch {
            '[' => depth += 1,
            ']' if depth > 0 => depth -= 1,
            _ if depth == 0 => output.push(ch),
            _ => {}
        }
    }
    output.split_whitespace().collect::<Vec<_>>().join(" ")
}

fn merge_content_tag(candidates: &[Candidate]) -> Option<String> {
    let has_base = candidates
        .iter()
        .any(|candidate| candidate.cnmt.meta_type == ContentMetaType::Base);
    let update_version = candidates
        .iter()
        .filter(|candidate| candidate.cnmt.meta_type == ContentMetaType::Update)
        .map(|candidate| candidate.cnmt.version)
        .max();
    let dlc_count = candidates
        .iter()
        .filter(|candidate| candidate.cnmt.meta_type == ContentMetaType::Dlc)
        .count();
    let mut parts = Vec::new();
    if has_base {
        parts.push("B".to_owned());
    }
    if let Some(version) = update_version {
        parts.push(format!("U{version}"));
    }
    if dlc_count > 0 {
        parts.push(format!("{dlc_count}DLC"));
    }
    (!parts.is_empty()).then(|| format!("[{}]", parts.join("+")))
}

fn partition_for_meta(meta_type: ContentMetaType) -> &'static str {
    // Game content belongs in the secure partition. XCI's update partition is
    // reserved for game-card system-update data; placing title Update/DLC there
    // makes NSRP and standard readers intentionally skip that content.
    let _ = meta_type;
    "secure"
}

fn has_multiple_sources(candidates: &[Candidate]) -> bool {
    candidates
        .iter()
        .map(|candidate| candidate.source)
        .collect::<HashSet<_>>()
        .len()
        >= 2
}

fn add_named_entry(
    source_path: &Path,
    entries: &[ContainerEntry],
    wanted: &str,
    dir: &Path,
    files: &mut Vec<(String, PathBuf)>,
    names: &mut HashSet<String>,
    cancel: &AtomicBool,
) -> Result<()> {
    let entry = entries
        .iter()
        .find(|e| e.name.eq_ignore_ascii_case(wanted))
        .with_context(|| format!("필수 엔트리 누락: {wanted}"))?;
    let key = wanted.to_ascii_lowercase();
    if names.insert(key) {
        let path = dir.join(format!("item_{}", files.len()));
        materialize_entry(source_path, entry, &path, cancel)?;
        files.push((wanted.to_owned(), path));
    }
    Ok(())
}

fn try_add_content(
    wanted: &str,
    preferred: usize,
    sources: &[SourceInfo],
    dir: &Path,
    files: &mut Vec<(String, PathBuf)>,
    names: &mut HashSet<String>,
    cancel: &AtomicBool,
) -> Result<bool> {
    if names.contains(&wanted.to_ascii_lowercase()) {
        return Ok(true);
    }
    let order = std::iter::once(preferred).chain((0..sources.len()).filter(|&i| i != preferred));
    for index in order {
        if let Some(entry) = resolve_content_entry(&sources[index].entries, wanted) {
            let path = dir.join(format!("item_{}", files.len()));
            materialize_entry(&sources[index].path, entry, &path, cancel)?;
            names.insert(wanted.to_ascii_lowercase());
            files.push((wanted.to_owned(), path));
            return Ok(true);
        }
    }
    Ok(false)
}

fn materialize_entry(
    input: &Path,
    entry: &ContainerEntry,
    output: &Path,
    cancel: &AtomicBool,
) -> Result<()> {
    if entry.name.to_ascii_lowercase().ends_with(".ncz") {
        let mut source = BufReader::with_capacity(8 * 1024 * 1024, File::open(input)?);
        let mut out = BufWriter::with_capacity(8 * 1024 * 1024, File::create(output)?);
        decompress_ncz_region_to_nca(
            &mut source,
            entry.offset,
            entry.size,
            &mut out,
            cancel,
            |_, _| {},
        )?;
        out.flush()?;
        Ok(())
    } else {
        materialize_raw(input, entry, output, cancel)
    }
}

fn materialize_raw(
    input: &Path,
    entry: &ContainerEntry,
    output: &Path,
    cancel: &AtomicBool,
) -> Result<()> {
    let mut source = BufReader::with_capacity(8 * 1024 * 1024, File::open(input)?);
    source.seek(SeekFrom::Start(entry.offset))?;
    let mut out = BufWriter::with_capacity(8 * 1024 * 1024, File::create(output)?);
    let mut remaining = entry.size;
    let mut buf = vec![0u8; 8 * 1024 * 1024];
    while remaining > 0 {
        if cancel.load(Ordering::Relaxed) {
            bail!("작업이 중단되었습니다");
        }
        let take = remaining.min(buf.len() as u64) as usize;
        source.read_exact(&mut buf[..take])?;
        out.write_all(&buf[..take])?;
        remaining -= take as u64;
    }
    out.flush()?;
    Ok(())
}

fn meta_order(value: ContentMetaType) -> u8 {
    match value {
        ContentMetaType::Base => 0,
        ContentMetaType::Update => 1,
        ContentMetaType::Dlc => 2,
        ContentMetaType::Other(_) => 3,
    }
}

fn move_file(src: &Path, dst: &Path) -> Result<()> {
    match fs::rename(src, dst) {
        Ok(()) => Ok(()),
        Err(_rename_error) => {
            fs::copy(src, dst)?;
            fs::remove_file(src)?;
            Ok(())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::formats::hfs0;
    use crate::formats::pfs0::Pfs0Index;
    use crate::ops::cnmt::CnmtContent;
    use crate::ops::cnmt::compressed_tests::fixture as encrypted_cnmt_fixture;
    use std::collections::HashMap;

    #[test]
    fn stage38_compressed_cnmt_direct_xci_merge_and_atomic_failure() -> Result<()> {
        let temp = tempfile::tempdir()?;
        let cancel = AtomicBool::new(false);
        let preset = include_bytes!("../../bin/game_info_preset.ini");
        for block in [false, true] {
            let f = encrypted_cnmt_fixture(temp.path(), block)?;
            assert!(native_compressed_cnmts_readable(&f.nsz, &f.keys, &cancel));
            assert!(native_compressed_cnmts_readable(&f.xcz, &f.keys, &cancel));
            let original_sha = Sha256::digest(fs::read(&f.nsz)?);
            let work = temp.path().join(format!("prepared_work_{block}"));
            fs::create_dir_all(&work)?;
            let prepared = prepare_merge_inputs(
                std::slice::from_ref(&f.nsz),
                &work,
                2,
                Some(&f.keys),
                &cancel,
                &mut |_| {},
            )?;
            assert_eq!(prepared[0], (f.nsz.clone(), f.nsz.clone()));
            assert!(!work.join("prepared_0.nsp").exists());

            let entries = container::list_entries(&f.nsz, true)?;
            let meta_entry = entries
                .iter()
                .find(|entry| entry.name == "base.cnmt.ncz")
                .context("Compressed metadata missing")?;
            let info = cnmt::read_cnmt_from_container_entry(&f.nsz, meta_entry, &f.keys, &cancel)?;
            let candidate = Candidate {
                source: 0,
                cnmt: info.clone(),
            };
            let source = SourceInfo {
                original: f.nsz.clone(),
                path: f.nsz.clone(),
                entries: entries.clone(),
                cnmts: vec![info],
            };
            let members = plan_direct_xci_members(
                std::slice::from_ref(&candidate),
                std::slice::from_ref(&source),
                preset,
                &cancel,
            )?
            .context("Supported Stage38 compressed CNMT was rejected")?;
            assert_eq!(members.len(), 4);
            assert!(members.iter().any(|m| m.name == f.meta_name && m.ncz));
            assert!(members.iter().all(|m| m.path == f.nsz));

            let merged = temp.path().join(format!("stage38_{block}.xci"));
            write_direct_merged_xci(&merged, &members, preset, &f.keys, &cancel)?;
            let leaf = hfs0::collect_leaf_entries(&merged, true)?;
            assert_eq!(leaf.len(), 4);
            for (name, offset, size) in &leaf {
                let mut file = File::open(&merged)?;
                file.seek(SeekFrom::Start(*offset))?;
                let mut bytes = vec![0u8; *size as usize];
                file.read_exact(&mut bytes)?;
                if name == &f.meta_name {
                    assert_eq!(bytes, f.nca);
                } else {
                    let source_path = f
                        .content_paths
                        .iter()
                        .find(|(n, _)| n == name)
                        .context("Unknown merged content")?;
                    assert_eq!(bytes, fs::read(&source_path.1)?);
                }
            }
            assert_eq!(Sha256::digest(fs::read(&f.nsz)?), original_sha);

            let protected = temp.path().join(format!("prior_{block}.xci"));
            fs::write(&protected, b"prior verified XCI must remain")?;
            let aborted = AtomicBool::new(true);
            assert!(
                write_direct_merged_xci(&protected, &members, preset, &f.keys, &aborted).is_err()
            );
            assert_eq!(fs::read(&protected)?, b"prior verified XCI must remain");

            // Corrupt the embedded content in a disposable copy, never the source.
            let damaged = temp.path().join(format!("damaged_{block}.nsz"));
            fs::copy(&f.nsz, &damaged)?;
            let corrupt_entry = entries
                .iter()
                .find(|e| e.name == f.content_paths[0].0)
                .context("Missing SHA-authenticated NCA")?;
            let mut edit = fs::OpenOptions::new().write(true).open(&damaged)?;
            edit.seek(SeekFrom::Start(corrupt_entry.offset + 0x200))?;
            edit.write_all(b"tamper")?;
            edit.flush()?;
            let mut damaged_source = source;
            damaged_source.path = damaged.clone();
            damaged_source.original = damaged;
            let damaged_members =
                plan_direct_xci_members(&[candidate], &[damaged_source], preset, &cancel)?
                    .context("Corrupted input should reach SHA verification")?;
            assert!(
                write_direct_merged_xci(&protected, &damaged_members, preset, &f.keys, &cancel)
                    .is_err()
            );
            assert_eq!(fs::read(protected)?, b"prior verified XCI must remain");
        }
        Ok(())
    }

    #[test]
    fn stage38_duplicate_plain_and_compressed_cnmt_disables_native_path() -> Result<()> {
        let temp = tempfile::tempdir()?;
        let f = encrypted_cnmt_fixture(temp.path(), false)?;
        let duplicate = temp.path().join("duplicate.nsz");
        build_from_paths(
            &[
                (f.meta_name, f.nca_path),
                ("base.cnmt.ncz".to_owned(), f.ncz_path),
            ],
            &duplicate,
        )?;
        assert!(!native_compressed_cnmts_readable(
            &duplicate,
            &f.keys,
            &AtomicBool::new(false)
        ));
        Ok(())
    }

    /// Exercise the same selected-CNMT precedence as a real multi-source
    /// game. The reference builder first copies four NCA payloads, while the
    /// Stage36 writer reads their original NSP container ranges directly.
    #[test]
    fn stage36_multi_package_direct_xci_matches_reference_with_zero_nca_staging() -> Result<()> {
        let work = tempfile::tempdir()?;
        let mut sources = Vec::<SourceInfo>::new();
        let mut candidates = Vec::<Candidate>::new();
        let mut reference = Vec::<(String, PathBuf)>::new();
        for i in 0..2u8 {
            let title_id = if i == 0 {
                "0100123456780000"
            } else {
                "0100123456780800"
            };
            let name = format!("{title_id}.cnmt.nca");
            let meta = work.path().join(format!("meta_{i}"));
            fs::write(&meta, vec![0x40 + i; 64 * 1024])?;
            reference.push((name.clone(), meta.clone()));
            let nca_id = format!("{:032x}", 0xdead_u32 + i as u32);
            let content_name = format!("{nca_id}.nca");
            let content_path = work.path().join(format!("content_{i}"));
            let bytes = vec![0x90 + i; 640 * 1024];
            let hash: [u8; 32] = Sha256::digest(&bytes).into();
            fs::write(&content_path, &bytes)?;
            reference.push((content_name.clone(), content_path.clone()));
            let nsp = work.path().join(format!("source_{i}.nsp"));
            build_from_paths(&[(name.clone(), meta), (content_name, content_path)], &nsp)?;
            let mut candidate = candidate(
                i as usize,
                title_id,
                if i == 0 {
                    ContentMetaType::Base
                } else {
                    ContentMetaType::Update
                },
            );
            candidate.cnmt.contents.push(CnmtContent {
                hash,
                nca_id,
                size: bytes.len() as u64,
                content_type: 1,
            });
            sources.push(SourceInfo {
                original: nsp.clone(),
                path: nsp.clone(),
                entries: container::list_entries(&nsp, true)?,
                cnmts: vec![candidate.cnmt.clone()],
            });
            candidates.push(candidate);
        }
        let preset = include_bytes!("../../bin/game_info_preset.ini");
        let cancel = AtomicBool::new(false);
        let planned = plan_direct_xci_members(&candidates, &sources, preset, &cancel)?
            .context("Stage36 synthetic default card unexpectedly unsupported")?;
        assert_eq!(planned.len(), 4);
        assert!(planned.iter().all(|member| !member.ncz));
        assert!(
            planned
                .iter()
                .all(|member| !member.path.starts_with(work.path().join("group")))
        );

        let keys = KeySet {
            prod: HashMap::new(),
            title: HashMap::new(),
        };
        let direct = work.path().join("native_direct.xci");
        write_direct_merged_xci(&direct, &planned, preset, &keys, &cancel)?;
        let staged = work.path().join("reference_work");
        for partition in ["secure", "normal", "update"] {
            fs::create_dir_all(staged.join(partition))?;
        }
        for (name, path) in reference {
            fs::copy(&path, staged.join("secure").join(name))?;
        }
        let baseline = work.path().join("native_staged.xci");
        native_xci::build_default_xci(&baseline, &staged, &cancel)?;
        let a = fs::read(&direct)?;
        let b = fs::read(&baseline)?;
        assert_eq!(a.len(), b.len());
        assert_eq!(&a[0x100..], &b[0x100..]);
        assert_eq!(hfs0::collect_leaf_entries(&direct, false)?.len(), 4);

        // Source tampering is a fatal CNMT SHA failure, NOT a silent
        // fallback or a truncation of the user's previous output.
        let protected = work.path().join("user_previous.xci");
        fs::write(&protected, b"keep the old verified output")?;
        // Mutate the *embedded* NSP region, not the loose source file that
        // was copied into the NSP earlier by the synthetic test fixture.
        let name = format!("{}.nca", candidates[1].cnmt.contents[0].nca_id);
        let entry = sources[1]
            .entries
            .iter()
            .find(|entry| entry.name == name)
            .context("Missing synthetic content NCA")?;
        let mut corrupted = fs::OpenOptions::new().write(true).open(&sources[1].path)?;
        corrupted.seek(SeekFrom::Start(entry.offset + 0x100))?;
        corrupted.write_all(&[0xfe])?;
        corrupted.flush()?;
        assert!(write_direct_merged_xci(&protected, &planned, preset, &keys, &cancel).is_err());
        assert_eq!(fs::read(&protected)?, b"keep the old verified output");
        let aborted = AtomicBool::new(true);
        assert!(write_direct_merged_xci(&protected, &planned, preset, &keys, &aborted).is_err());
        assert_eq!(fs::read(&protected)?, b"keep the old verified output");
        Ok(())
    }

    fn candidate(source: usize, title_id: &str, meta_type: ContentMetaType) -> Candidate {
        Candidate {
            source,
            cnmt: CnmtInfo {
                cnmt_nca_name: format!("{title_id}.cnmt.nca"),
                title_id: title_id.to_owned(),
                version: 1,
                meta_type,
                required_system_version: 0,
                contents: Vec::new(),
                raw: Vec::new(),
            },
        }
    }

    #[test]
    fn xci_game_content_stays_in_secure_partition() {
        assert_eq!(partition_for_meta(ContentMetaType::Base), "secure");
        assert_eq!(partition_for_meta(ContentMetaType::Update), "secure");
        assert_eq!(partition_for_meta(ContentMetaType::Dlc), "secure");
        assert_eq!(partition_for_meta(ContentMetaType::Other(0x90)), "secure");
    }

    #[test]
    fn already_integrated_single_source_is_not_a_merge_group() {
        let same_source = vec![
            candidate(0, "0100123456780000", ContentMetaType::Base),
            candidate(0, "0100123456780800", ContentMetaType::Update),
        ];
        assert!(!has_multiple_sources(&same_source));

        let separate_sources = vec![
            candidate(0, "0100123456780000", ContentMetaType::Base),
            candidate(1, "0100123456780800", ContentMetaType::Update),
        ];
        let multiple_sources = has_multiple_sources(&separate_sources);
        assert!(multiple_sources);

        assert_eq!(
            strip_bracket_tags("[0100123456780000] Example Game [v65536]"),
            "Example Game"
        );
        let mut update = candidate(1, "0100123456780800", ContentMetaType::Update);
        update.cnmt.version = 65536;
        let tagged = vec![
            candidate(0, "0100123456780000", ContentMetaType::Base),
            update,
            candidate(2, "0100123456781001", ContentMetaType::Dlc),
        ];
        assert_eq!(
            merge_content_tag(&tagged).as_deref(),
            Some("[B+U65536+1DLC]")
        );
    }

    #[test]
    fn compressed_merge_inputs_are_predecompressed() -> Result<()> {
        let temp = tempfile::tempdir()?;
        let payload = temp.path().join("payload.bin");
        fs::write(&payload, b"merge-predecompression")?;
        let nsz = temp.path().join("compressed.nsz");
        build_from_paths(&[("payload.bin".to_owned(), payload)], &nsz)?;
        let plain = temp.path().join("plain.nsp");
        fs::write(&plain, b"plain-input-marker")?;
        let work = temp.path().join("work");
        fs::create_dir_all(&work)?;
        let cancel = AtomicBool::new(false);
        let mut logs = Vec::new();
        let prepared = prepare_merge_inputs(
            &[nsz.clone(), plain.clone()],
            &work,
            2,
            None,
            &cancel,
            &mut |line| logs.push(line),
        )?;
        assert_eq!(prepared.len(), 2);
        assert_eq!(prepared[0].0, nsz);
        assert_ne!(prepared[0].1, prepared[0].0);
        assert_eq!(
            prepared[0].1.extension().and_then(|ext| ext.to_str()),
            Some("nsp")
        );
        let index = Pfs0Index::parse(&prepared[0].1)?;
        assert!(index.entry("payload.bin").is_some());
        assert_eq!(prepared[1], (plain.clone(), plain));
        assert!(logs.iter().any(|line| line.contains("스레드: 2")));
        Ok(())
    }
}
