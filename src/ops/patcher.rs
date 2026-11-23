use crate::{
    formats::{
        nca::{NCA_XTS_HEADER_SIZE, decrypt_header, derive_section_key},
        pfs0::build_from_paths,
    },
    keys::{KeySet, merge_ticket_keys_from_nsp_file, sanitize_title_keys_file},
    ops::{
        cnmt::{
            CnmtInfo, ContentMetaType, base_title_id, extract_and_parse_cnmts,
            resolve_content_entry,
        },
        compress::{
            CompressOptions, compress_nsp, decompress_nsz, repair_legacy_nsp_headers_for_launch,
        },
        container::{ContainerEntry, list_entries},
        convert::{build_xci_from_nsp, container_to_nsp},
        native_fs,
        program_recovery::{
            PROGRAM_RECOVERY_JOURNAL, PROGRAM_RECOVERY_README, ProgramRecoveryPhase,
            ensure_no_pending_program_output, record_program_recovery_phase,
            scan_patch_workspace_recovery, scan_program_recovery, write_program_publish_journal,
        },
        title_support::{find_cnmt_content_row, patch_cnmt_nca, sha256_file},
        xcz::{XczOptions, compress_xci},
    },
    process::run_tool,
};
use anyhow::{Context, Result, bail, ensure};
use std::{
    collections::{BTreeMap, BTreeSet},
    ffi::OsString,
    fs::{self, File},
    io::{self, BufReader, BufWriter, Read, Seek, SeekFrom, Write},
    path::{Component, Path, PathBuf},
    sync::atomic::{AtomicBool, Ordering},
};
use zip::ZipArchive;

#[derive(Debug, Clone, Default)]
pub struct PatchOptions {
    pub zip_password: Option<String>,
    pub required_system_version: Option<u64>,
    pub compression: CompressOptions,
}

#[derive(Debug, Clone)]
struct SourcePackage {
    original: PathBuf,
    normalized: PathBuf,
    entries: Vec<ContainerEntry>,
    cnmts: Vec<CnmtInfo>,
}

#[derive(Debug, Clone)]
struct MetaRef {
    source: usize,
    info: CnmtInfo,
}

pub fn analyze_packages_metadata(
    inputs: &[PathBuf],
    workspace: &Path,
    hactool: &Path,
    prod_keys: &Path,
    cancel: &AtomicBool,
    log: &mut dyn FnMut(String),
) -> Result<Vec<CnmtInfo>> {
    if inputs.is_empty() {
        return Ok(Vec::new());
    }
    fs::create_dir_all(workspace)?;
    let temp = tempfile::Builder::new()
        .prefix("nsrp_patch_analyze_")
        .tempdir_in(workspace)?;
    let mut all = Vec::new();
    for (index, input) in inputs.iter().enumerate() {
        if cancel.load(Ordering::Relaxed) {
            bail!("작업이 중단되었습니다");
        }
        let normalized = temp.path().join(format!("input_{index}.nsp"));
        normalize_to_nsp(
            input,
            &normalized,
            hactool,
            prod_keys,
            cancel,
            &mut |_| {},
            log,
        )?;
        let entries = list_entries(&normalized, false)?;
        let mut cnmts = extract_and_parse_cnmts(
            &normalized,
            &entries,
            &temp.path().join(format!("cnmt_{index}")),
            hactool,
            prod_keys,
            cancel,
        )?;
        all.append(&mut cnmts);
    }
    validate_metadata_set(&all)?;
    Ok(all)
}

fn prepare_patch_output_dir(output_dir: &Path, workspace_root: &Path) -> Result<()> {
    // Stage53: a prior unfinished publication must be reported without
    // silently creating even an empty caller output directory. This is
    // a read-only preflight, not a substitute for an interprocess lock.
    let orphaned = scan_patch_workspace_recovery(workspace_root)?;
    if let Some(unfinished) = orphaned.first() {
        bail!(
            "Previous patch publication requires manual recovery at {}. Inspect {} before starting another patch. No files were modified.",
            unfinished.staging.display(),
            unfinished.staging.join(PROGRAM_RECOVERY_JOURNAL).display()
        );
    }
    fs::create_dir_all(output_dir)?;
    Ok(())
}

pub fn patch_packages(
    inputs: &[PathBuf],
    patch_paths: &[PathBuf],
    output_dir: &Path,
    resource_dir: &Path,
    hactool: &Path,
    prod_keys: &Path,
    keys: &mut KeySet,
    options: &PatchOptions,
    cancel: &AtomicBool,
    progress: &mut dyn FnMut(f32),
    log: &mut dyn FnMut(String),
) -> Result<PathBuf> {
    if inputs.is_empty() {
        bail!("패치할 NSP/NSZ/XCI/XCZ가 없습니다");
    }
    if patch_paths.is_empty() {
        bail!("적용할 패치 파일/폴더가 없습니다");
    }
    prepare_patch_output_dir(output_dir, &crate::workspace::default_workspace_root())?;
    let temp = crate::workspace::temp_workspace("nsrp_patch_")?;

    let mut sources = Vec::new();
    for (index, input) in inputs.iter().enumerate() {
        if cancel.load(Ordering::Relaxed) {
            bail!("작업이 중단되었습니다");
        }
        let normalized = temp.path().join(format!("input_{index}.nsp"));
        normalize_to_nsp(
            input,
            &normalized,
            hactool,
            prod_keys,
            cancel,
            &mut |_| {},
            log,
        )?;
        let title_keys_path = prod_keys
            .parent()
            .unwrap_or_else(|| Path::new("."))
            .join("title.keys");
        if let Ok(count) = merge_ticket_keys_from_nsp_file(&normalized, &title_keys_path)
            && count > 0
        {
            log(format!("키 데이터베이스 갱신: {count}개 추가"));
        }
        keys.add_ticket_keys_from_nsp(&normalized)?;
        let entries = list_entries(&normalized, false)?;
        let cnmts = extract_and_parse_cnmts(
            &normalized,
            &entries,
            &temp.path().join(format!("cnmt_{index}")),
            hactool,
            prod_keys,
            cancel,
        )?;
        sources.push(SourcePackage {
            original: input.clone(),
            normalized,
            entries,
            cnmts,
        });
        progress(0.10 * (index + 1) as f32 / inputs.len() as f32);
    }

    let all_cnmts = sources
        .iter()
        .flat_map(|source| source.cnmts.iter().cloned())
        .collect::<Vec<_>>();
    validate_metadata_set(&all_cnmts)?;

    let (base, update, dlc_ids) = select_metadata(&sources)?;
    let base_id = base_title_id(&base.info.title_id)?;
    if let Some(update) = &update
        && base_title_id(&update.info.title_id)? != base_id
    {
        bail!("본편과 업데이트의 Title ID가 서로 다른 게임입니다");
    }
    let target = update.as_ref().unwrap_or(&base);
    let base_program =
        program_nca_name(&base.info).context("본편 Program NCA를 찾지 못했습니다")?;
    let update_program = update.as_ref().and_then(|m| program_nca_name(&m.info));
    let target_program = update_program
        .as_deref()
        .unwrap_or(&base_program)
        .to_owned();
    let repack_title_id = target.info.title_id.clone();
    log(format!(
        "패치 대상: {} v{} {}",
        target.info.title_id,
        target.info.version,
        target.info.meta_type.label()
    ));
    progress(0.15);

    let base_program_path = temp.path().join("base_program.nca");
    materialize_named(
        &sources[base.source],
        &base_program,
        &base_program_path,
        cancel,
    )?;
    let target_program_path = if let Some(update) = &update {
        let path = temp.path().join("update_program.nca");
        materialize_named(
            &sources[update.source],
            update_program.as_ref().unwrap(),
            &path,
            cancel,
        )?;
        path
    } else {
        base_program_path.clone()
    };

    let patch_romfs = temp.path().join("patch_romfs");
    let patch_exefs = temp.path().join("patch_exefs");
    fs::create_dir_all(&patch_romfs)?;
    fs::create_dir_all(&patch_exefs)?;
    for patch in patch_paths {
        if patch.is_dir() {
            apply_folder_patch(patch, &patch_romfs, &patch_exefs, cancel)?;
        } else {
            apply_zip_patch(
                patch,
                options.zip_password.as_deref(),
                &patch_romfs,
                &patch_exefs,
                cancel,
            )?;
        }
    }
    let romfs_patch_count = count_files(&patch_romfs);
    let exefs_patch_count = count_files(&patch_exefs);
    if romfs_patch_count == 0 && exefs_patch_count == 0 {
        bail!("패치에서 적용 가능한 파일을 찾지 못했습니다");
    }
    log(format!(
        "패치 파일: RomFS {romfs_patch_count}개 / ExeFS {exefs_patch_count}개"
    ));
    progress(0.25);

    let merged_romfs = temp.path().join("merged_romfs");
    let merged_exefs = temp.path().join("merged_exefs");
    fs::create_dir_all(&merged_romfs)?;
    fs::create_dir_all(&merged_exefs)?;
    let base_for_update = if update.is_some() {
        Some(base_program_path.as_path())
    } else {
        None
    };
    if let Err(error) = extract_program(
        &target_program_path,
        base_for_update,
        Some(&merged_romfs),
        None,
        hactool,
        prod_keys,
        keys,
        cancel,
    ) {
        return Err(preserve_patch_workspace_if_needed(temp, error));
    }
    overlay_tree(&patch_romfs, &merged_romfs)?;
    progress(0.38);

    if let Err(error) = extract_program(
        &target_program_path,
        base_for_update,
        None,
        Some(&merged_exefs),
        hactool,
        prod_keys,
        keys,
        cancel,
    ) {
        return Err(preserve_patch_workspace_if_needed(temp, error));
    }
    overlay_tree(&patch_exefs, &merged_exefs)?;
    patch_npdm_title_id(&merged_exefs.join("main.npdm"), &repack_title_id)?;
    progress(0.50);

    let repack_dir = temp.path().join("repack_program");
    fs::create_dir_all(&repack_dir)?;
    let native_output = repack_dir.join("native_program.nca");
    let native_exefs = merged_exefs
        .join("main.npdm")
        .is_file()
        .then_some(merged_exefs.as_path());
    let stats = crate::ops::native_nca_builder::repack_nca(
        &target_program_path,
        Some(&merged_romfs),
        native_exefs,
        &native_output,
        keys,
        cancel,
    )
    .context(
        "Program NCA의 안전한 Rust 재패킹을 완료하지 못했습니다. 지원하지 않는 NCA 형상이므로 기존 결과물은 보존합니다",
    )?;
    log(format!(
        "Program NCA Rust 네이티브 재패킹 완료: RomFS {}개 / ExeFS {}개",
        stats.romfs_files, stats.exefs_files
    ));
    let new_program = native_output;
    let new_hash = sha256_file(&new_program)?;
    let new_id = &new_hash[..16];
    let new_size = fs::metadata(&new_program)?.len();
    log(format!("Program NCA 재빌드 완료: {} bytes", new_size));
    progress(0.66);

    let mut patched_meta = BTreeMap::<String, PathBuf>::new();
    if let Some(update) = &update {
        let path = patch_one_cnmt(
            update,
            &sources,
            Some(&target_program),
            &new_hash,
            new_size,
            options.required_system_version,
            hactool,
            prod_keys,
            keys,
            temp.path(),
            cancel,
        )?;
        patched_meta.insert(update.info.cnmt_nca_name.to_ascii_lowercase(), path);
        if options.required_system_version.is_some() {
            let path = patch_one_cnmt(
                &base,
                &sources,
                None,
                &new_hash,
                new_size,
                options.required_system_version,
                hactool,
                prod_keys,
                keys,
                temp.path(),
                cancel,
            )?;
            patched_meta.insert(base.info.cnmt_nca_name.to_ascii_lowercase(), path);
        }
    } else {
        let path = patch_one_cnmt(
            &base,
            &sources,
            Some(&target_program),
            &new_hash,
            new_size,
            options.required_system_version,
            hactool,
            prod_keys,
            keys,
            temp.path(),
            cancel,
        )?;
        patched_meta.insert(base.info.cnmt_nca_name.to_ascii_lowercase(), path);
    }
    progress(0.78);

    let staging = temp.path().join("staging");
    fs::create_dir_all(&staging)?;
    let excluded_program = if update.is_some() {
        update_program.as_deref().unwrap()
    } else {
        &base_program
    };
    let mut selected = BTreeMap::<String, (usize, ContainerEntry)>::new();
    for (source_index, source) in sources.iter().enumerate() {
        for entry in &source.entries {
            selected.insert(
                entry.name.to_ascii_lowercase(),
                (source_index, entry.clone()),
            );
        }
    }
    let mut paths = Vec::<(String, PathBuf)>::new();
    for (name_key, (source_index, entry)) in selected {
        if name_key == excluded_program.to_ascii_lowercase() || patched_meta.contains_key(&name_key)
        {
            continue;
        }
        if name_key.ends_with(".tik") || name_key.ends_with(".cert") {
            let stem = name_key.split('.').next().unwrap_or("");
            if !dlc_ids
                .iter()
                .any(|tid| stem.starts_with(&tid.to_ascii_lowercase()))
            {
                continue;
            }
        }
        let out = staging.join(format!("orig_{}", paths.len()));
        materialize_raw(&sources[source_index].normalized, &entry, &out, cancel)?;
        paths.push((entry.name.clone(), out));
    }
    paths.push((format!("{}.nca", hex::encode(new_id)), new_program));
    for (name, path) in patched_meta {
        let original_name = sources
            .iter()
            .flat_map(|s| s.entries.iter())
            .find(|e| e.name.eq_ignore_ascii_case(&name))
            .map(|e| e.name.clone())
            .unwrap_or(name);
        paths.push((original_name, path));
    }
    paths.sort_by(|a, b| a.0.cmp(&b.0));
    let built_nsp = temp.path().join("patched.nsp");
    build_from_paths(&paths, &built_nsp)?;
    repair_legacy_nsp_headers_for_launch(
        &built_nsp,
        hactool,
        prod_keys,
        keys,
        cancel,
        &mut |_| {},
        log,
    )?;
    progress(0.90);

    let base_source = &sources[base.source];
    let stem = base_source
        .original
        .file_stem()
        .and_then(|s| s.to_str())
        .unwrap_or("NSRP");
    let ext = base_source
        .original
        .extension()
        .and_then(|s| s.to_str())
        .unwrap_or("nsp")
        .to_ascii_lowercase();
    let final_path = finalize_same_format(
        &built_nsp,
        &ext,
        &format!("[Patched] {stem}"),
        output_dir,
        resource_dir,
        prod_keys,
        keys,
        &options.compression,
        cancel,
        progress,
        log,
    )?;
    progress(1.0);
    Ok(final_path)
}

fn validate_metadata_set(cnmts: &[CnmtInfo]) -> Result<()> {
    if cnmts.is_empty() {
        bail!("콘텐츠 정보를 찾을 수 없습니다 (유효하지 않은 파일)");
    }
    let mut groups = BTreeSet::new();
    let mut base_count = 0usize;
    let mut update_count = 0usize;
    for info in cnmts {
        groups.insert(base_title_id(&info.title_id)?);
        match info.meta_type {
            ContentMetaType::Base => base_count += 1,
            ContentMetaType::Update => update_count += 1,
            ContentMetaType::Dlc | ContentMetaType::Other(_) => {}
        }
    }
    if groups.len() > 1 {
        bail!(
            "서로 다른 게임의 파일이 섞여 있습니다 (감지된 ID 그룹: {})",
            groups.into_iter().collect::<Vec<_>>().join(", ")
        );
    }
    if base_count == 0 {
        bail!("본편 파일이 등록되지 않았습니다");
    }
    if base_count > 1 {
        bail!("본편 파일이 중복 등록되었습니다");
    }
    if update_count > 1 {
        bail!("업데이트 파일이 중복 등록되었습니다");
    }
    Ok(())
}

fn select_metadata(
    sources: &[SourcePackage],
) -> Result<(MetaRef, Option<MetaRef>, BTreeSet<String>)> {
    let mut base_candidates = Vec::<MetaRef>::new();
    let mut update_candidates = Vec::<MetaRef>::new();
    let mut dlc_ids = BTreeSet::new();
    for (source, package) in sources.iter().enumerate() {
        for info in &package.cnmts {
            let item = MetaRef {
                source,
                info: info.clone(),
            };
            match info.meta_type {
                ContentMetaType::Base => base_candidates.push(item),
                ContentMetaType::Update => update_candidates.push(item),
                ContentMetaType::Dlc => {
                    dlc_ids.insert(info.title_id.clone());
                }
                ContentMetaType::Other(_) => {}
            }
        }
    }
    let base = base_candidates
        .into_iter()
        .max_by_key(|m| m.info.version)
        .context("본편(Base) CNMT를 찾지 못했습니다")?;
    let base_group = base_title_id(&base.info.title_id)?;
    let update = update_candidates
        .into_iter()
        .filter(|m| base_title_id(&m.info.title_id).ok().as_deref() == Some(base_group.as_str()))
        .max_by_key(|m| m.info.version);
    Ok((base, update, dlc_ids))
}

fn program_nca_name(info: &CnmtInfo) -> Option<String> {
    info.contents
        .iter()
        .find(|c| c.content_type == 1)
        .map(|c| format!("{}.nca", c.nca_id))
}

fn normalize_to_nsp(
    input: &Path,
    output: &Path,
    hactool: &Path,
    prod_keys: &Path,
    cancel: &AtomicBool,
    progress: &mut dyn FnMut(f32),
    log: &mut dyn FnMut(String),
) -> Result<()> {
    let ext = input
        .extension()
        .and_then(|s| s.to_str())
        .unwrap_or("")
        .to_ascii_lowercase();
    match ext.as_str() {
        "nsp" => {
            fs::copy(input, output)?;
            progress(1.0);
        }
        "nsz" => decompress_nsz(input, output, cancel, progress, log)?,
        "xci" | "xcz" => {
            container_to_nsp(input, output, hactool, prod_keys, cancel, progress, log)?
        }
        _ => bail!("지원하지 않는 입력 형식: {ext}"),
    }
    Ok(())
}

fn materialize_named(
    source: &SourcePackage,
    name: &str,
    output: &Path,
    cancel: &AtomicBool,
) -> Result<()> {
    let entry = resolve_content_entry(&source.entries, name)
        .with_context(|| format!("필수 NCA 누락: {name}"))?;
    if entry.name.to_ascii_lowercase().ends_with(".ncz") {
        let mut reader = BufReader::with_capacity(8 * 1024 * 1024, File::open(&source.normalized)?);
        let mut out = BufWriter::with_capacity(8 * 1024 * 1024, File::create(output)?);
        crate::formats::ncz_stream::decompress_ncz_region_to_nca(
            &mut reader,
            entry.offset,
            entry.size,
            &mut out,
            cancel,
            |_, _| {},
        )?;
        out.flush()?;
    } else {
        materialize_raw(&source.normalized, entry, output, cancel)?;
    }
    Ok(())
}

fn materialize_raw(
    input: &Path,
    entry: &ContainerEntry,
    output: &Path,
    cancel: &AtomicBool,
) -> Result<()> {
    let mut reader = BufReader::with_capacity(8 * 1024 * 1024, File::open(input)?);
    reader.seek(SeekFrom::Start(entry.offset))?;
    let mut out = BufWriter::with_capacity(8 * 1024 * 1024, File::create(output)?);
    let mut remaining = entry.size;
    let mut buf = vec![0u8; 8 * 1024 * 1024];
    while remaining > 0 {
        if cancel.load(Ordering::Relaxed) {
            bail!("작업이 중단되었습니다");
        }
        let take = remaining.min(buf.len() as u64) as usize;
        reader.read_exact(&mut buf[..take])?;
        out.write_all(&buf[..take])?;
        remaining -= take as u64;
    }
    out.flush()?;
    Ok(())
}

fn title_key_for_nca(path: &Path, keys: &KeySet) -> Result<Option<[u8; 16]>> {
    let mut header = vec![0u8; NCA_XTS_HEADER_SIZE];
    File::open(path)?.read_exact(&mut header)?;
    let info = decrypt_header(&header, keys)?;
    if info.rights_id.iter().all(|&b| b == 0) {
        return Ok(None);
    }
    Ok(Some(derive_section_key(&info, keys)?))
}

/// The native decoder and external fallback may both fail after writing files.
/// Neither backend is allowed to touch the caller's existing output directory.
/// The only visible transition is a verified directory rename after extraction.
/// A nested Program recovery folder does not survive if the patcher's outer
/// TempDir removes its entire tree. Retain that owner whenever the inner
/// publication had started, including when its journal cannot be inspected.
fn preserve_patch_workspace_if_needed(
    workspace: tempfile::TempDir,
    error: anyhow::Error,
) -> anyhow::Error {
    match scan_program_recovery(workspace.path()) {
        Ok(records) if records.is_empty() => error,
        _ => {
            let path = workspace.keep();
            error.context(format!(
                "The patch workspace contains recovery data and was retained at {}. Inspect all Program recovery journals before deleting it.",
                path.display()
            ))
        }
    }
}

fn extract_program(
    nca: &Path,
    base_nca: Option<&Path>,
    romfs: Option<&Path>,
    exefs: Option<&Path>,
    hactool: &Path,
    prod_keys: &Path,
    keys: &KeySet,
    cancel: &AtomicBool,
) -> Result<()> {
    let outputs = [("romfs", romfs), ("exefs", exefs)]
        .into_iter()
        .filter_map(|(name, target)| target.map(|path| (name, path)))
        .collect::<Vec<_>>();
    ensure!(!outputs.is_empty(), "No Program filesystem requested");
    ensure_distinct_program_targets(&outputs)?;
    for &(_, target) in &outputs {
        ensure_empty_extraction_target(target)?;
    }
    let parent = outputs[0]
        .1
        .parent()
        .context("Program extraction destination has no parent")?;
    // A previous invocation may have been terminated after publishing only
    // one of these directories. Never start a replacement extraction over
    // an output with unfinished on-disk recovery instructions.
    ensure_no_pending_program_output(
        parent,
        &outputs.iter().map(|(_, path)| *path).collect::<Vec<_>>(),
    )?;
    let isolated = tempfile::Builder::new()
        .prefix("nsrp_program_extract_")
        .tempdir_in(parent)?;
    for &(name, _) in &outputs {
        fs::create_dir(isolated.path().join(name))?;
    }
    let staged_romfs = romfs.map(|_| isolated.path().join("romfs"));
    let staged_exefs = exefs.map(|_| isolated.path().join("exefs"));
    extract_program_staged(
        nca,
        base_nca,
        staged_romfs.as_deref(),
        staged_exefs.as_deref(),
        hactool,
        prod_keys,
        keys,
        cancel,
    )?;
    publish_isolated_program_with(isolated, &outputs, cancel, |source, target| {
        fs::rename(source, target)
    })
}

/// A successfully published directory becomes accessible to other processes.
/// Even when the subsequent rollback rename succeeds, other programs may have
/// added files to it. Such a tree must NEVER be recursively destroyed by
/// TempDir after moving it back into the private staging area.
const PROGRAM_PUBLISH_STARTED_MARKER: &str = ".nsrp_program_publish_started";

fn publish_isolated_program_with(
    isolated: tempfile::TempDir,
    outputs: &[(&str, &Path)],
    cancel: &AtomicBool,
    publish: impl FnMut(&Path, &Path) -> io::Result<()>,
) -> Result<()> {
    let result = publish_staged_program_with(isolated.path(), outputs, cancel, publish);
    if let Err(error) = result {
        let publication_started =
            fs::symlink_metadata(isolated.path().join(PROGRAM_PUBLISH_STARTED_MARKER)).is_ok();
        // Keep the directory on inspection errors as well: an inaccessible
        // backup must not be interpreted as an empty, safe-to-delete stage.
        let previous_backup_remains = fs::read_dir(isolated.path()).map_or(true, |dir| {
            dir.into_iter().any(|item| {
                item.map_or(true, |item| {
                    item.file_name()
                        .to_string_lossy()
                        .starts_with("previous_empty_")
                })
            })
        });
        if publication_started || previous_backup_remains {
            let recovery = isolated.keep();
            let note = format!(
                "NSRP Program extraction did not complete.\n\
                 This folder may contain third-party files written into published output directories.\n\
                 Do NOT delete this recovery folder until its contents have been inspected.\n\
                 Original output destinations:\n{}\n\
                 Inspect romfs, exefs and previous_empty_N directories.\n\
                 The operation error was:\n{error:#}\n",
                outputs
                    .iter()
                    .map(|(name, target)| format!("  {name}: {}", target.display()))
                    .collect::<Vec<_>>()
                    .join("\n")
            );
            let guide = recovery.join(PROGRAM_RECOVERY_README);
            let guide_note = match fs::write(&guide, &note) {
                Ok(()) => format!("Recovery instructions: {}", guide.display()),
                Err(write_error) => {
                    format!("Unable to write recovery instructions: {write_error}")
                }
            };
            return Err(error.context(format!(
                "Program publication failed; recovery files were retained at {}. {guide_note}. Inspect the recovery folder before deleting it; publication journal: {}",
                recovery.display(),
                recovery.join(PROGRAM_RECOVERY_JOURNAL).display()
            )));
        }
        return Err(error);
    }
    Ok(())
}

fn ensure_no_reparse_components(path: &Path) -> Result<()> {
    let mut current = PathBuf::new();
    for component in path.components() {
        ensure!(
            !matches!(component, Component::ParentDir),
            "Program output parent traversal is unsupported: {}",
            path.display()
        );
        current.push(component.as_os_str());
        match fs::symlink_metadata(&current) {
            Ok(metadata) => ensure_not_reparse(&metadata, &current)?,
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(error) => return Err(error.into()),
        }
    }
    Ok(())
}

fn ensure_not_reparse(metadata: &fs::Metadata, path: &Path) -> Result<()> {
    ensure!(
        !metadata.file_type().is_symlink(),
        "Program output link is not allowed: {}",
        path.display()
    );
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt;
        ensure!(
            metadata.file_attributes() & 0x400 == 0,
            "Program output junction or reparse point is not allowed: {}",
            path.display()
        );
    }
    Ok(())
}

fn ensure_distinct_program_targets(outputs: &[(&str, &Path)]) -> Result<()> {
    let mut seen = BTreeSet::new();
    for &(_, target) in outputs {
        ensure_no_reparse_components(target)?;
        let parent = target.parent().context("Program output has no parent")?;
        ensure!(parent.is_dir(), "Program output parent is not a directory");
        let basename = target
            .file_name()
            .context("Program output has no directory name")?
            .to_string_lossy();
        ensure!(
            !basename.ends_with([' ', '.']) && !basename.contains(':'),
            "Program output has an ambiguous Windows directory name"
        );
        let canonical_parent = fs::canonicalize(parent)?;
        let key = canonical_parent.join(basename.as_ref());
        #[cfg(windows)]
        let key = key.to_string_lossy().to_lowercase();
        ensure!(
            seen.insert(key),
            "Program RomFS/ExeFS outputs name the same directory"
        );
    }
    Ok(())
}

fn ensure_empty_extraction_target(target: &Path) -> Result<()> {
    ensure_no_reparse_components(target)?;
    match fs::symlink_metadata(target) {
        Ok(metadata) => {
            ensure_not_reparse(&metadata, target)?;
            ensure!(
                metadata.is_dir() && !metadata.file_type().is_symlink(),
                "Program extraction destination is not a real directory: {}",
                target.display()
            );
            ensure!(
                fs::read_dir(target)?.next().is_none(),
                "Program extraction destination is not empty: {}",
                target.display()
            );
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        Err(error) => return Err(error.into()),
    }
    Ok(())
}

/// Reject untrusted links, Windows junctions and unreadable descendants before
/// any staged tree becomes visible under a caller's output directory.
fn validate_staged_program(target: &Path, cancel: &AtomicBool) -> Result<()> {
    const MAX_STAGED_ENTRIES: usize = 500_000;
    ensure_no_reparse_components(target)?;
    let mut files = 0usize;
    for (index, item) in walkdir::WalkDir::new(target)
        .follow_links(false)
        .into_iter()
        .enumerate()
    {
        ensure!(!cancel.load(Ordering::Relaxed), "작업이 중단되었습니다");
        ensure!(
            index < MAX_STAGED_ENTRIES,
            "Program extraction produced too many filesystem entries"
        );
        let item = item?;
        let meta = fs::symlink_metadata(item.path())?;
        ensure_not_reparse(&meta, item.path())?;
        ensure!(
            meta.is_file() || meta.is_dir(),
            "Program extraction produced an unsupported special entry"
        );
        files += usize::from(meta.is_file());
    }
    ensure!(files > 0, "Program extraction produced no regular files");
    Ok(())
}

/// Make two requested outputs a single rollback-capable transaction. Existing
/// empty folders are temporarily renamed, never recursively deleted; a failure
/// during either publication restores both original destination states.
fn publish_staged_program_with(
    staging: &Path,
    outputs: &[(&str, &Path)],
    cancel: &AtomicBool,
    mut publish: impl FnMut(&Path, &Path) -> io::Result<()>,
) -> Result<()> {
    struct Entry<'a> {
        staged: PathBuf,
        target: &'a Path,
        backup: Option<PathBuf>,
        was_existing: bool,
        published: bool,
    }
    let mut entries = Vec::with_capacity(outputs.len());
    ensure_distinct_program_targets(outputs)?;
    // Validate every output before moving the first one.
    for &(name, target) in outputs {
        let staged = staging.join(name);
        validate_staged_program(&staged, cancel).with_context(|| {
            format!("Program extraction did not create a safe {name} directory")
        })?;
        ensure_empty_extraction_target(target)?;
        entries.push(Entry {
            staged,
            target,
            backup: None,
            was_existing: false,
            published: false,
        });
    }
    ensure!(!cancel.load(Ordering::Relaxed), "작업이 중단되었습니다");
    // The journal is written and sync_all() completed before the first
    // rename. Following a hard termination, new invocations can discover
    // incomplete work without automatically touching user files.
    write_program_publish_journal(staging, outputs)?;
    // Written before the first potentially visible mutation. If any later
    // step fails, a published tree may have been edited by another process;
    // the owner must retain the entire staging area for safe manual recovery.
    fs::write(
        staging.join(PROGRAM_PUBLISH_STARTED_MARKER),
        b"NSRP Program publication started; preserve this stage on failure",
    )?;
    record_program_recovery_phase(staging, ProgramRecoveryPhase::PublicationStarted, None)?;
    let result = (|| -> Result<()> {
        for (index, entry) in entries.iter_mut().enumerate() {
            ensure!(!cancel.load(Ordering::Relaxed), "작업이 중단되었습니다");
            // Recheck to protect files created by another process since the
            // initial preflight. A non-empty folder is never removed.
            ensure_empty_extraction_target(entry.target)?;
            if fs::symlink_metadata(entry.target).is_ok() {
                let backup = staging.join(format!("previous_empty_{index}"));
                record_program_recovery_phase(
                    staging,
                    ProgramRecoveryPhase::BackupRenameStarted,
                    Some(index),
                )?;
                fs::rename(entry.target, &backup)?;
                entry.backup = Some(backup);
                entry.was_existing = true;
                record_program_recovery_phase(
                    staging,
                    ProgramRecoveryPhase::BackupRenamed,
                    Some(index),
                )?;
                // Check again after the rename, not just the earlier preflight.
                // A concurrent writer's files in the old folder are never
                // consumed as disposable scratch output.
                ensure_empty_extraction_target(entry.backup.as_ref().unwrap())?;
            }
            record_program_recovery_phase(
                staging,
                ProgramRecoveryPhase::PublishRenameStarted,
                Some(index),
            )?;
            publish(&entry.staged, entry.target)
                .with_context(|| format!("Unable to publish Program {}", entry.target.display()))?;
            entry.published = true;
            record_program_recovery_phase(staging, ProgramRecoveryPhase::Published, Some(index))?;
        }
        ensure!(!cancel.load(Ordering::Relaxed), "작업이 중단되었습니다");
        // Remove only empty old folders; do not let TempDir recursively
        // delete backups into which another process has written new files.
        for (index, entry) in entries.iter_mut().enumerate() {
            if let Some(backup) = &entry.backup {
                ensure_empty_extraction_target(backup)?;
                record_program_recovery_phase(
                    staging,
                    ProgramRecoveryPhase::BackupCleanupStarted,
                    Some(index),
                )?;
                fs::remove_dir(backup)?;
                entry.backup = None;
                record_program_recovery_phase(
                    staging,
                    ProgramRecoveryPhase::BackupRemoved,
                    Some(index),
                )?;
            }
        }
        record_program_recovery_phase(staging, ProgramRecoveryPhase::PublicationCompleted, None)?;
        Ok(())
    })();
    if let Err(error) = result {
        let mut rollback_errors = Vec::new();
        for (index, entry) in entries.iter().enumerate().rev() {
            if entry.published {
                if let Err(record) = record_program_recovery_phase(
                    staging,
                    ProgramRecoveryPhase::RollbackPublishStarted,
                    Some(index),
                ) {
                    rollback_errors.push(format!("rollback log: {record:#}"));
                }
                match fs::rename(entry.target, &entry.staged) {
                    Ok(()) => {
                        if let Err(record) = record_program_recovery_phase(
                            staging,
                            ProgramRecoveryPhase::RollbackPublished,
                            Some(index),
                        ) {
                            rollback_errors.push(format!("rollback log: {record:#}"));
                        }
                    }
                    Err(rollback) => {
                        rollback_errors.push(format!("{}: {rollback}", entry.target.display()));
                    }
                }
            }
            if let Some(backup) = &entry.backup {
                if let Err(record) = record_program_recovery_phase(
                    staging,
                    ProgramRecoveryPhase::RollbackBackupStarted,
                    Some(index),
                ) {
                    rollback_errors.push(format!("rollback log: {record:#}"));
                }
                match fs::rename(backup, entry.target) {
                    Ok(()) => {
                        if let Err(record) = record_program_recovery_phase(
                            staging,
                            ProgramRecoveryPhase::RollbackBackupRestored,
                            Some(index),
                        ) {
                            rollback_errors.push(format!("rollback log: {record:#}"));
                        }
                    }
                    Err(rollback) => {
                        rollback_errors.push(format!("{}: {rollback}", entry.target.display()));
                    }
                }
            } else if entry.was_existing
                && fs::symlink_metadata(entry.target)
                    .is_err_and(|error| error.kind() == io::ErrorKind::NotFound)
            {
                if let Err(record) = record_program_recovery_phase(
                    staging,
                    ProgramRecoveryPhase::RollbackEmptyCreateStarted,
                    Some(index),
                ) {
                    rollback_errors.push(format!("rollback log: {record:#}"));
                }
                match fs::create_dir(entry.target) {
                    Ok(()) => {
                        if let Err(record) = record_program_recovery_phase(
                            staging,
                            ProgramRecoveryPhase::RollbackEmptyRestored,
                            Some(index),
                        ) {
                            rollback_errors.push(format!("rollback log: {record:#}"));
                        }
                    }
                    Err(rollback) => {
                        rollback_errors.push(format!("{}: {rollback}", entry.target.display()));
                    }
                }
            }
        }
        if !rollback_errors.is_empty() {
            let _ =
                record_program_recovery_phase(staging, ProgramRecoveryPhase::RollbackFailed, None);
            bail!(
                "{error:#}; Program extraction rollback failed: {}",
                rollback_errors.join("; ")
            );
        }
        record_program_recovery_phase(staging, ProgramRecoveryPhase::RollbackFinished, None)?;
        return Err(error);
    }
    Ok(())
}

fn extract_program_staged(
    nca: &Path,
    base_nca: Option<&Path>,
    romfs: Option<&Path>,
    exefs: Option<&Path>,
    hactool: &Path,
    prod_keys: &Path,
    keys: &KeySet,
    cancel: &AtomicBool,
) -> Result<()> {
    let hactoolnet = hactool
        .parent()
        .unwrap_or_else(|| Path::new("."))
        .join("hactoolnet.exe");

    // A verified compressed BKTR RomFS uses native streaming LZ4/indirect
    // storage even when the base Program is large. For normal, uncompressed
    // BKTR keep the existing size-based choice until a faster extraction
    // benchmark supports switching all sizes to the native implementation.
    const SMALL_NATIVE_BKTR_BASE: u64 = 64 * 1024 * 1024;
    let compressed_bktr = (|| -> Result<bool> {
        let mut encrypted = [0u8; NCA_XTS_HEADER_SIZE];
        File::open(nca)?.read_exact(&mut encrypted)?;
        let info = decrypt_header(&encrypted, keys)?;
        Ok(info.sections.iter().any(|section| {
            let at = 0x400 + section.index * 0x200;
            section.encryption_type == 4
                && info.decrypted_header[at + 0x178..at + 0x1a0]
                    .iter()
                    .any(|byte| *byte != 0)
        }))
    })()
    .unwrap_or(false);
    if let Some(base) = base_nca
        && (!hactoolnet.is_file()
            || fs::metadata(base).is_ok_and(|m| m.len() <= SMALL_NATIVE_BKTR_BASE)
            || compressed_bktr)
    {
        // Stage in an isolated folder so an unsupported layout cannot
        // contaminate the legacy fallback output.
        let native_result = (|| -> Result<()> {
            let staging = tempfile::Builder::new()
                .prefix("nsrp_bktr_native_")
                .tempdir_in(nca.parent().unwrap_or_else(|| Path::new(".")))?;
            native_fs::unpack_patched_nca(
                nca,
                base,
                staging.path(),
                keys,
                cancel,
                romfs.is_some(),
                exefs.is_some(),
            )?;
            let mut outputs = Vec::new();
            for (name, target) in [("romfs", romfs), ("exefs", exefs)] {
                if let Some(target) = target {
                    let staged = staging.path().join(name);
                    if !staged.is_dir()
                        || fs::read_dir(&staged)?.next().is_none()
                        || (target.exists() && fs::read_dir(target)?.next().is_some())
                    {
                        bail!("BKTR native staging incomplete or destination not empty");
                    }
                    outputs.push((staged, target));
                }
            }
            for (staged, target) in outputs {
                if target.is_dir() {
                    fs::remove_dir(target)?;
                }
                fs::rename(staged, target)?;
            }
            Ok(())
        })();
        if native_result.is_ok() {
            return Ok(());
        }
        if cancel.load(Ordering::Relaxed) {
            bail!("작업이 중단되었습니다");
        }
    }

    // An unsupported BKTR layout must fail closed if the verified LibHac
    // fallback is unavailable. Generic hactool cannot safely overlay BKTR.
    if base_nca.is_some() && !hactoolnet.is_file() {
        bail!(
            "BKTR native extraction is unsupported or failed; LibHac (hactoolnet.exe) fallback is unavailable"
        );
    }

    // Special storage still uses LibHac, never hactool for BKTR overlays.
    if base_nca.is_some() && hactoolnet.is_file() {
        for path in [romfs, exefs].into_iter().flatten() {
            let _ = fs::remove_dir_all(path);
            fs::create_dir_all(path)?;
        }
        return extract_program_with_hactoolnet(
            nca,
            base_nca,
            romfs,
            exefs,
            &hactoolnet,
            prod_keys,
            cancel,
        );
    }

    let mut args = vec![
        OsString::from("-k"),
        prod_keys.as_os_str().to_owned(),
        OsString::from("-t"),
        OsString::from("nca"),
        OsString::from("--disablekeywarns"),
    ];
    if let Some(key) = title_key_for_nca(nca, keys)? {
        args.push(OsString::from(format!("--titlekey={}", hex::encode(key))));
    }
    if let Some(base) = base_nca {
        args.extend([OsString::from("--basenca"), base.as_os_str().to_owned()]);
    }
    if let Some(path) = romfs {
        fs::create_dir_all(path)?;
        args.extend([OsString::from("--romfsdir"), path.as_os_str().to_owned()]);
    }
    if let Some(path) = exefs {
        fs::create_dir_all(path)?;
        args.extend([OsString::from("--exefsdir"), path.as_os_str().to_owned()]);
    }
    args.push(nca.as_os_str().to_owned());
    let tool = run_tool(hactool, args, nca.parent(), cancel)?;
    let has_files = [romfs, exefs]
        .into_iter()
        .flatten()
        .any(|path| count_files(path) > 0);
    if tool.success() && has_files {
        return Ok(());
    }

    if hactoolnet.is_file() {
        for path in [romfs, exefs].into_iter().flatten() {
            let _ = fs::remove_dir_all(path);
            fs::create_dir_all(path)?;
        }
        if extract_program_with_hactoolnet(
            nca,
            base_nca,
            romfs,
            exefs,
            &hactoolnet,
            prod_keys,
            cancel,
        )
        .is_ok()
        {
            return Ok(());
        }
    }

    if !tool.success() {
        bail!("NCA 추출 실패: {}", tool.combined());
    }
    bail!("NCA 추출 결과가 비어 있습니다")
}

fn extract_program_with_hactoolnet(
    nca: &Path,
    base_nca: Option<&Path>,
    romfs: Option<&Path>,
    exefs: Option<&Path>,
    hactoolnet: &Path,
    prod_keys: &Path,
    cancel: &AtomicBool,
) -> Result<()> {
    let mut args = vec![
        OsString::from("-k"),
        prod_keys.as_os_str().to_owned(),
        OsString::from("--disablekeywarns"),
        OsString::from("-t"),
        OsString::from("nca"),
    ];
    let title_keys = prod_keys
        .parent()
        .unwrap_or_else(|| Path::new("."))
        .join("title.keys");
    let key_stage = tempfile::Builder::new()
        .prefix("nsrp_external_title_keys_")
        .tempdir_in(nca.parent().unwrap_or_else(|| Path::new(".")))?;
    if title_keys.is_file() {
        let staged = key_stage.path().join("title.keys");
        fs::copy(&title_keys, &staged)?;
        sanitize_title_keys_file(&staged)?;
        args.extend([OsString::from("--titlekeys"), staged.as_os_str().to_owned()]);
    }
    if let Some(base) = base_nca {
        args.extend([OsString::from("--basenca"), base.as_os_str().to_owned()]);
    }
    if let Some(path) = romfs {
        fs::create_dir_all(path)?;
        args.extend([OsString::from("--romfsdir"), path.as_os_str().to_owned()]);
    }
    if let Some(path) = exefs {
        fs::create_dir_all(path)?;
        args.extend([OsString::from("--exefsdir"), path.as_os_str().to_owned()]);
    }
    args.push(nca.as_os_str().to_owned());

    let tool = run_tool(hactoolnet, args, nca.parent(), cancel)?;
    if !tool.success() {
        bail!("LibHac NCA 추출 실패: {}", tool.combined());
    }
    let has_files = [romfs, exefs]
        .into_iter()
        .flatten()
        .any(|path| count_files(path) > 0);
    if !has_files {
        bail!("LibHac NCA 추출 결과가 비어 있습니다");
    }
    Ok(())
}

fn apply_folder_patch(
    source: &Path,
    romfs: &Path,
    exefs: &Path,
    cancel: &AtomicBool,
) -> Result<()> {
    let root_kind = source
        .file_name()
        .and_then(|name| name.to_str())
        .and_then(patch_area_from_component);
    let has_sub_structure = root_kind.is_some()
        || walkdir::WalkDir::new(source)
            .follow_links(false)
            .into_iter()
            .filter_map(|entry| entry.ok())
            .filter(|entry| entry.file_type().is_file())
            .any(|entry| {
                entry
                    .path()
                    .strip_prefix(source)
                    .ok()
                    .is_some_and(|rel| explicit_patch_route(rel).is_some())
            });

    for entry in walkdir::WalkDir::new(source)
        .follow_links(false)
        .into_iter()
        .filter_map(|e| e.ok())
    {
        if cancel.load(Ordering::Relaxed) {
            bail!("작업이 중단되었습니다");
        }
        if !entry.file_type().is_file() {
            continue;
        }
        let rel = entry.path().strip_prefix(source)?;
        let route = if let Some(kind) = root_kind {
            Some((kind, rel.to_path_buf()))
        } else if let Some(route) = explicit_patch_route(rel) {
            Some(route)
        } else if has_sub_structure {
            None
        } else {
            Some((PatchArea::RomFs, rel.to_path_buf()))
        };
        let Some((kind, routed)) = route else {
            continue;
        };
        if routed.as_os_str().is_empty() {
            continue;
        }
        let target = match kind {
            PatchArea::RomFs => romfs.join(routed),
            PatchArea::ExeFs => exefs.join(routed),
        };
        if let Some(parent) = target.parent() {
            fs::create_dir_all(parent)?;
        }
        fs::copy(entry.path(), target)?;
    }
    Ok(())
}

fn apply_zip_patch(
    zip_path: &Path,
    password: Option<&str>,
    romfs: &Path,
    exefs: &Path,
    cancel: &AtomicBool,
) -> Result<()> {
    if zip_path
        .extension()
        .and_then(|s| s.to_str())
        .map(|s| !s.eq_ignore_ascii_case("zip"))
        .unwrap_or(true)
    {
        bail!("지원하지 않는 패치 파일입니다: {}", zip_path.display());
    }
    let file = File::open(zip_path)?;
    let mut archive =
        ZipArchive::new(file).with_context(|| format!("ZIP 열기 실패: {}", zip_path.display()))?;
    let has_sub_structure = archive
        .file_names()
        .filter(|name| !name.ends_with('/'))
        .any(zip_name_has_patch_structure);
    for index in 0..archive.len() {
        if cancel.load(Ordering::Relaxed) {
            bail!("작업이 중단되었습니다");
        }
        if let Some(password) = password.filter(|p| !p.is_empty()) {
            let mut item = archive
                .by_index_decrypt(index, password.as_bytes())
                .with_context(|| format!("ZIP 암호 해제 실패: {}", zip_path.display()))?;
            extract_zip_item(&mut item, romfs, exefs, has_sub_structure)?;
        } else {
            let mut item = archive
                .by_index(index)
                .with_context(|| format!("ZIP 항목 읽기 실패: {}", zip_path.display()))?;
            extract_zip_item(&mut item, romfs, exefs, has_sub_structure)?;
        }
    }
    Ok(())
}

fn extract_zip_item<R: Read>(
    item: &mut zip::read::ZipFile<'_, R>,
    romfs: &Path,
    exefs: &Path,
    has_sub_structure: bool,
) -> Result<()> {
    if item.is_dir() {
        return Ok(());
    }
    let rel = item
        .enclosed_name()
        .context("ZIP 경로 탐색 공격으로 보이는 항목을 차단했습니다")?
        .to_path_buf();
    let route = if let Some(route) = explicit_patch_route(&rel) {
        Some(route)
    } else if has_sub_structure {
        None
    } else {
        Some((PatchArea::RomFs, rel.clone()))
    };
    let Some((kind, routed)) = route else {
        return Ok(());
    };
    if routed.as_os_str().is_empty() {
        return Ok(());
    }
    let target = match kind {
        PatchArea::RomFs => romfs.join(routed),
        PatchArea::ExeFs => exefs.join(routed),
    };
    if let Some(parent) = target.parent() {
        fs::create_dir_all(parent)?;
    }
    let mut out = BufWriter::new(File::create(target)?);
    std::io::copy(item, &mut out)?;
    out.flush()?;
    Ok(())
}

#[derive(Debug, Clone, Copy)]
enum PatchArea {
    RomFs,
    ExeFs,
}

fn patch_area_from_component(name: &str) -> Option<PatchArea> {
    match name.to_ascii_lowercase().as_str() {
        "romfs" | "homefs" => Some(PatchArea::RomFs),
        "exefs" => Some(PatchArea::ExeFs),
        _ => None,
    }
}

fn zip_name_has_patch_structure(name: &str) -> bool {
    name.replace('\\', "/")
        .split('/')
        .any(|component| patch_area_from_component(component).is_some())
}

fn explicit_patch_route(path: &Path) -> Option<(PatchArea, PathBuf)> {
    let components: Vec<_> = path
        .components()
        .filter_map(|c| match c {
            Component::Normal(v) => Some(v.to_os_string()),
            _ => None,
        })
        .collect();
    for (index, component) in components.iter().enumerate() {
        if let Some(kind) = patch_area_from_component(&component.to_string_lossy()) {
            return Some((kind, components[index + 1..].iter().collect()));
        }
    }
    None
}

#[cfg(test)]
fn route_patch_path(path: &Path) -> (PatchArea, PathBuf) {
    explicit_patch_route(path).unwrap_or_else(|| (PatchArea::RomFs, path.to_path_buf()))
}

fn overlay_tree(source: &Path, target: &Path) -> Result<()> {
    if !source.is_dir() {
        return Ok(());
    }
    for entry in walkdir::WalkDir::new(source)
        .follow_links(false)
        .into_iter()
        .filter_map(|e| e.ok())
    {
        if !entry.file_type().is_file() {
            continue;
        }
        let rel = entry.path().strip_prefix(source)?;
        let dst = target.join(rel);
        if let Some(parent) = dst.parent() {
            fs::create_dir_all(parent)?;
        }
        fs::copy(entry.path(), dst)?;
    }
    Ok(())
}

fn count_files(path: &Path) -> usize {
    if !path.is_dir() {
        return 0;
    }
    walkdir::WalkDir::new(path)
        .into_iter()
        .filter_map(|e| e.ok())
        .filter(|e| e.file_type().is_file())
        .count()
}

fn patch_npdm_title_id(npdm_path: &Path, title_id: &str) -> Result<()> {
    if !npdm_path.is_file() {
        return Ok(());
    }
    let tid = u64::from_str_radix(title_id.trim(), 16).context("NPDM Title ID 형식 오류")?;
    let bytes = tid.to_le_bytes();
    let mut data = fs::read(npdm_path)?;
    let mut changed = false;
    if let Some(pos) = data.windows(4).position(|w| w == b"ACI0")
        && pos + 0x18 <= data.len()
    {
        data[pos + 0x10..pos + 0x18].copy_from_slice(&bytes);
        changed = true;
    }
    if let Some(pos) = data.windows(4).position(|w| w == b"ACID")
        && pos + 0x48 <= data.len()
    {
        data[pos + 0x40..pos + 0x48].copy_from_slice(&bytes);
        changed = true;
    }
    if changed {
        fs::write(npdm_path, data)?;
    }
    Ok(())
}

fn patch_one_cnmt(
    meta: &MetaRef,
    sources: &[SourcePackage],
    replace_program_name: Option<&str>,
    new_hash: &[u8; 32],
    new_size: u64,
    required_system_version: Option<u64>,
    hactool: &Path,
    prod_keys: &Path,
    keys: &KeySet,
    temp_root: &Path,
    cancel: &AtomicBool,
) -> Result<PathBuf> {
    let source = &sources[meta.source];
    let entry = source
        .entries
        .iter()
        .find(|e| e.name.eq_ignore_ascii_case(&meta.info.cnmt_nca_name))
        .context("CNMT NCA 엔트리가 없습니다")?;
    let meta_path = temp_root.join(format!("meta_{}_{}.nca", meta.source, meta.info.title_id));
    materialize_raw(&source.normalized, entry, &meta_path, cancel)?;
    let mut new_cnmt = meta.info.raw.clone();
    if let Some(version) = required_system_version {
        if new_cnmt.len() < 0x30 {
            bail!("CNMT가 RequiredSystemVersion 필드보다 짧습니다");
        }
        new_cnmt[0x28..0x30].copy_from_slice(&version.to_le_bytes());
    }
    if let Some(program_name) = replace_program_name {
        let program_id = program_name.strip_suffix(".nca").unwrap_or(program_name);
        let row = find_cnmt_content_row(&new_cnmt, program_id)
            .or_else(|| find_program_row(&new_cnmt))
            .context("CNMT Program content entry를 찾지 못했습니다")?;
        new_cnmt[row..row + 0x20].copy_from_slice(new_hash);
        new_cnmt[row + 0x20..row + 0x30].copy_from_slice(&new_hash[..16]);
        new_cnmt[row + 0x30..row + 0x36].copy_from_slice(&new_size.to_le_bytes()[..6]);
    }
    let title_key = title_key_for_nca(&meta_path, keys)?;
    let out_dir = temp_root.join(format!(
        "patched_meta_{}_{}",
        meta.source, meta.info.title_id
    ));
    fs::create_dir_all(&out_dir)?;
    patch_cnmt_nca(
        &meta_path,
        &meta.info.raw,
        &new_cnmt,
        hactool,
        prod_keys,
        title_key.as_ref().map(|k| k.as_slice()),
        &out_dir,
        cancel,
    )
}

fn find_program_row(data: &[u8]) -> Option<usize> {
    if data.len() < 0x20 {
        return None;
    }
    let ext = u16::from_le_bytes(data[0x0e..0x10].try_into().ok()?) as usize;
    let count = u16::from_le_bytes(data[0x10..0x12].try_into().ok()?) as usize;
    let base = 0x20 + ext;
    for i in 0..count {
        let row = base + i * 0x38;
        if row + 0x38 <= data.len() && data[row + 0x36] == 1 {
            return Some(row);
        }
    }
    None
}

fn finalize_same_format(
    nsp: &Path,
    original_ext: &str,
    basename: &str,
    output_dir: &Path,
    resource_dir: &Path,
    prod_keys: &Path,
    keys: &mut KeySet,
    compression: &CompressOptions,
    cancel: &AtomicBool,
    progress: &mut dyn FnMut(f32),
    log: &mut dyn FnMut(String),
) -> Result<PathBuf> {
    match original_ext {
        "nsp" => {
            let out = output_dir.join(format!("{basename}.nsp"));
            move_file(nsp, &out, cancel)?;
            Ok(out)
        }
        "nsz" => {
            let out = output_dir.join(format!("{basename}.nsz"));
            compress_nsp(
                nsp,
                &out,
                keys,
                compression,
                cancel,
                &mut |p| progress(0.90 + p * 0.10),
                log,
            )?;
            Ok(out)
        }
        "xci" => {
            let out = output_dir.join(format!("{basename}.xci"));
            build_xci_from_nsp(nsp, &out, resource_dir, prod_keys, cancel, log)?;
            Ok(out)
        }
        "xcz" => {
            let xci = output_dir.join(format!(".{basename}.tmp.xci"));
            build_xci_from_nsp(nsp, &xci, resource_dir, prod_keys, cancel, log)?;
            let out = output_dir.join(format!("{basename}.xcz"));
            let result = compress_xci(
                &xci,
                &out,
                keys,
                &XczOptions {
                    level: compression.level,
                    threads: compression.threads,
                    block_mode: compression.block_mode,
                    long_mode: compression.long_mode,
                },
                cancel,
                &mut |p| progress(0.94 + p * 0.06),
                log,
            );
            let _ = fs::remove_file(&xci);
            result?;
            Ok(out)
        }
        other => bail!("지원하지 않는 원본 형식: {other}"),
    }
}

fn move_file(src: &Path, dst: &Path, cancel: &AtomicBool) -> Result<()> {
    crate::atomic_file::publish_generated_file(src, dst, cancel)
}

#[cfg(test)]
#[path = "patcher_stage48_tests.rs"]
mod stage48_tests;

#[cfg(test)]
#[path = "patcher_stage49_tests.rs"]
mod stage49_tests;

#[cfg(test)]
#[path = "patcher_stage50_tests.rs"]
mod stage50_tests;

#[cfg(test)]
#[path = "patcher_stage51_tests.rs"]
mod stage51_tests;

#[cfg(test)]
#[path = "patcher_stage53_tests.rs"]
mod stage53_tests;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stage47_unsupported_bktr_without_libhac_preserves_existing_output() -> Result<()> {
        let root = tempfile::tempdir()?;
        let nca = root.path().join("unverified_patch.nca");
        let base = root.path().join("base.nca");
        fs::write(&nca, b"invalid NCA test header")?;
        fs::write(&base, b"invalid base NCA")?;
        let output = root.path().join("romfs");
        fs::create_dir(&output)?;
        let keys = KeySet::default();
        let result = extract_program(
            &nca,
            Some(&base),
            Some(&output),
            None,
            &root.path().join("tools").join("missing_hactool.exe"),
            &root.path().join("prod.keys"),
            &keys,
            &AtomicBool::new(false),
        );
        let error = format!("{:#}", result.unwrap_err());
        assert!(error.contains("LibHac") && error.contains("unavailable"));
        assert!(output.is_dir());
        assert_eq!(fs::read_dir(&output)?.count(), 0);
        assert!(
            !fs::read_dir(root.path())?
                .filter_map(|entry| entry.ok())
                .any(|entry| entry
                    .file_name()
                    .to_string_lossy()
                    .starts_with("nsrp_program_extract_")),
            "failed native decoding must not leak staging folders"
        );
        Ok(())
    }

    #[test]
    fn stage47_existing_nonempty_output_is_not_touched_by_fallback() -> Result<()> {
        let root = tempfile::tempdir()?;
        let output = root.path().join("romfs");
        fs::create_dir(&output)?;
        fs::write(output.join("previous.bin"), b"keep-the-previous-output")?;
        let source = root.path().join("unverified.nca");
        fs::write(&source, b"broken NCA")?;
        let result = extract_program(
            &source,
            None,
            Some(&output),
            None,
            &root.path().join("missing_tool.exe"),
            &root.path().join("prod.keys"),
            &KeySet::default(),
            &AtomicBool::new(false),
        );
        assert!(result.is_err());
        assert_eq!(
            fs::read(output.join("previous.bin"))?,
            b"keep-the-previous-output"
        );
        Ok(())
    }

    #[test]
    fn stage47_two_staged_outputs_publish_together() -> Result<()> {
        let root = tempfile::tempdir()?;
        let stage = root.path().join("stage");
        fs::create_dir_all(stage.join("romfs"))?;
        fs::create_dir_all(stage.join("exefs"))?;
        fs::write(stage.join("romfs").join("data"), b"romfs")?;
        fs::write(stage.join("exefs").join("main"), b"exefs")?;
        let romfs = root.path().join("output_romfs");
        let exefs = root.path().join("output_exefs");
        fs::create_dir(&romfs)?;
        publish_staged_program_with(
            &stage,
            &[("romfs", &romfs), ("exefs", &exefs)],
            &AtomicBool::new(false),
            |source, target| fs::rename(source, target),
        )?;
        assert_eq!(fs::read(romfs.join("data"))?, b"romfs");
        assert_eq!(fs::read(exefs.join("main"))?, b"exefs");
        assert!(!stage.join("romfs").exists());
        assert!(!stage.join("exefs").exists());
        Ok(())
    }

    #[test]
    fn stage47_second_publish_error_rolls_back_both_destinations() -> Result<()> {
        let root = tempfile::tempdir()?;
        let stage = root.path().join("stage");
        fs::create_dir_all(stage.join("romfs"))?;
        fs::create_dir_all(stage.join("exefs"))?;
        fs::write(stage.join("romfs").join("data"), b"first-content")?;
        fs::write(stage.join("exefs").join("main"), b"second-content")?;
        let romfs = root.path().join("existing_empty");
        let exefs = root.path().join("initially_absent");
        fs::create_dir(&romfs)?;
        let mut calls = 0;
        let result = publish_staged_program_with(
            &stage,
            &[("romfs", &romfs), ("exefs", &exefs)],
            &AtomicBool::new(false),
            |src, dst| {
                calls += 1;
                if calls == 2 {
                    Err(io::Error::other("synthetic second rename failure"))
                } else {
                    fs::rename(src, dst)
                }
            },
        );
        assert!(format!("{:#}", result.unwrap_err()).contains("synthetic second rename failure"));
        assert!(romfs.is_dir());
        assert_eq!(fs::read_dir(&romfs)?.count(), 0);
        assert!(!exefs.exists());
        assert_eq!(
            fs::read(stage.join("romfs").join("data"))?,
            b"first-content"
        );
        assert_eq!(
            fs::read(stage.join("exefs").join("main"))?,
            b"second-content"
        );
        Ok(())
    }

    #[test]
    fn stage47_cancel_before_publication_preserves_destinations() -> Result<()> {
        let root = tempfile::tempdir()?;
        let stage = root.path().join("stage");
        fs::create_dir_all(stage.join("romfs"))?;
        fs::write(stage.join("romfs").join("data"), b"candidate")?;
        let target = root.path().join("existing_empty");
        fs::create_dir(&target)?;
        let result = publish_staged_program_with(
            &stage,
            &[("romfs", &target)],
            &AtomicBool::new(true),
            |source, target| fs::rename(source, target),
        );
        assert!(result.is_err());
        assert!(target.is_dir());
        assert_eq!(fs::read_dir(&target)?.count(), 0);
        assert!(stage.join("romfs").join("data").is_file());
        Ok(())
    }

    #[test]
    fn stage47_late_cancel_after_rename_rolls_back_original_folder() -> Result<()> {
        let root = tempfile::tempdir()?;
        let stage = root.path().join("stage");
        fs::create_dir_all(stage.join("romfs"))?;
        fs::write(stage.join("romfs").join("data"), b"never publish")?;
        let target = root.path().join("output");
        fs::create_dir(&target)?;
        let cancel = AtomicBool::new(false);
        let result = publish_staged_program_with(
            &stage,
            &[("romfs", &target)],
            &cancel,
            |source, destination| {
                fs::rename(source, destination)?;
                cancel.store(true, Ordering::Relaxed);
                Ok(())
            },
        );
        assert!(result.is_err());
        assert!(target.is_dir());
        assert_eq!(fs::read_dir(&target)?.count(), 0);
        assert_eq!(
            fs::read(stage.join("romfs").join("data"))?,
            b"never publish"
        );
        Ok(())
    }

    #[test]
    fn stage47_missing_staged_folder_fails_before_any_publication() -> Result<()> {
        let root = tempfile::tempdir()?;
        let stage = root.path().join("stage");
        fs::create_dir_all(stage.join("romfs"))?;
        fs::create_dir_all(stage.join("exefs"))?;
        fs::write(stage.join("romfs").join("data"), b"candidate")?;
        let romfs = root.path().join("romfs");
        let exefs = root.path().join("exefs");
        let result = publish_staged_program_with(
            &stage,
            &[("romfs", &romfs), ("exefs", &exefs)],
            &AtomicBool::new(false),
            |source, target| fs::rename(source, target),
        );
        assert!(result.is_err());
        assert!(!romfs.exists() && !exefs.exists());
        assert_eq!(fs::read(stage.join("romfs").join("data"))?, b"candidate");
        Ok(())
    }

    fn cnmt(title_id: &str, meta_type: ContentMetaType) -> CnmtInfo {
        CnmtInfo {
            cnmt_nca_name: format!("{title_id}.cnmt.nca"),
            title_id: title_id.to_owned(),
            version: 1,
            meta_type,
            required_system_version: 0,
            contents: Vec::new(),
            raw: Vec::new(),
        }
    }

    #[test]
    fn patch_input_validation_matches_legacy_rules() {
        let valid = vec![
            cnmt("0100123456780000", ContentMetaType::Base),
            cnmt("0100123456780800", ContentMetaType::Update),
            cnmt("0100123456781001", ContentMetaType::Dlc),
        ];
        assert!(validate_metadata_set(&valid).is_ok());

        let mixed = vec![
            cnmt("0100123456780000", ContentMetaType::Base),
            cnmt("0100ABCDEF120001", ContentMetaType::Dlc),
        ];
        assert!(validate_metadata_set(&mixed).is_err());

        let duplicate_base = vec![
            cnmt("0100123456780000", ContentMetaType::Base),
            cnmt("0100123456780000", ContentMetaType::Base),
        ];
        assert!(validate_metadata_set(&duplicate_base).is_err());

        let no_base = vec![cnmt("0100123456780800", ContentMetaType::Update)];
        assert!(validate_metadata_set(&no_base).is_err());
    }

    #[test]
    fn routes_atmosphere_romfs_and_exefs() {
        let (kind, path) = route_patch_path(Path::new("atmosphere/contents/0100/romfs/Data/a.bin"));
        assert!(matches!(kind, PatchArea::RomFs));
        assert_eq!(path, PathBuf::from("Data/a.bin"));
        let (kind, path) = route_patch_path(Path::new("root/exefs/main.npdm"));
        assert!(matches!(kind, PatchArea::ExeFs));
        assert_eq!(path, PathBuf::from("main.npdm"));
        assert!(explicit_patch_route(Path::new("README.txt")).is_none());
        assert!(zip_name_has_patch_structure("bundle/romfs/Data/a.bin"));
        assert!(zip_name_has_patch_structure("bundle\\exefs\\main"));
        assert!(!zip_name_has_patch_structure("README.txt"));
    }

    #[test]
    fn structured_folder_skips_unscoped_files_and_routes_both_areas() -> Result<()> {
        let temp = tempfile::tempdir()?;
        let source = temp.path().join("patch");
        fs::create_dir_all(source.join("romfs/Data"))?;
        fs::create_dir_all(source.join("exefs"))?;
        fs::write(source.join("romfs/Data/a.bin"), b"romfs")?;
        fs::write(source.join("exefs/main.npdm"), b"exefs")?;
        fs::write(source.join("README.txt"), b"documentation")?;

        let romfs = temp.path().join("out_romfs");
        let exefs = temp.path().join("out_exefs");
        apply_folder_patch(&source, &romfs, &exefs, &AtomicBool::new(false))?;

        assert_eq!(fs::read(romfs.join("Data/a.bin"))?, b"romfs");
        assert_eq!(fs::read(exefs.join("main.npdm"))?, b"exefs");
        assert!(!romfs.join("README.txt").exists());
        assert!(!exefs.join("README.txt").exists());
        Ok(())
    }

    #[test]
    fn direct_exefs_folder_stays_exefs() -> Result<()> {
        let temp = tempfile::tempdir()?;
        let source = temp.path().join("exefs");
        fs::create_dir_all(&source)?;
        fs::write(source.join("main.npdm"), b"exefs")?;

        let romfs = temp.path().join("out_romfs");
        let exefs = temp.path().join("out_exefs");
        apply_folder_patch(&source, &romfs, &exefs, &AtomicBool::new(false))?;

        assert_eq!(fs::read(exefs.join("main.npdm"))?, b"exefs");
        assert!(!romfs.join("main.npdm").exists());
        Ok(())
    }

    #[test]
    fn structured_zip_skips_unscoped_files() -> Result<()> {
        let temp = tempfile::tempdir()?;
        let zip_path = temp.path().join("patch.zip");
        let file = File::create(&zip_path)?;
        let mut writer = zip::ZipWriter::new(file);
        let options = zip::write::SimpleFileOptions::default();
        writer.start_file("romfs/Data/a.bin", options)?;
        writer.write_all(b"romfs")?;
        writer.start_file("exefs/main.npdm", options)?;
        writer.write_all(b"exefs")?;
        writer.start_file("README.txt", options)?;
        writer.write_all(b"documentation")?;
        writer.finish()?;

        let romfs = temp.path().join("out_romfs");
        let exefs = temp.path().join("out_exefs");
        apply_zip_patch(&zip_path, None, &romfs, &exefs, &AtomicBool::new(false))?;

        assert_eq!(fs::read(romfs.join("Data/a.bin"))?, b"romfs");
        assert_eq!(fs::read(exefs.join("main.npdm"))?, b"exefs");
        assert!(!romfs.join("README.txt").exists());
        assert!(!exefs.join("README.txt").exists());
        Ok(())
    }

    #[test]
    fn npdm_rewrites_both_title_id_fields() -> Result<()> {
        let temp = tempfile::tempdir()?;
        let path = temp.path().join("main.npdm");
        let mut data = vec![0u8; 0x200];
        data[0x20..0x24].copy_from_slice(b"ACI0");
        data[0x90..0x94].copy_from_slice(b"ACID");
        fs::write(&path, data)?;
        patch_npdm_title_id(&path, "0100123456789000")?;
        let data = fs::read(path)?;
        let expected = 0x0100123456789000u64.to_le_bytes();
        assert_eq!(&data[0x30..0x38], &expected);
        assert_eq!(&data[0xd0..0xd8], &expected);
        Ok(())
    }
}
