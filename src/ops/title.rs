use crate::ops::title_support::*;
use crate::{
    formats::pfs0::{Pfs0Index, build_from_paths},
    keys::KeySet,
    ops::{
        cnmt::{
            ContentMetaType, discover_game_metadata, extract_and_parse_cnmts,
            extract_control_romfs, resolve_content_entry,
        },
        compress::{
            CompressOptions, compress_nsp, decompress_nsz_repaired, repair_legacy_nsp_headers,
        },
        convert::{build_xci_from_nsp, container_to_nsp},
        native_control_resize, native_repack,
        xcz::{XczOptions, compress_xci},
    },
};
use anyhow::{Context, Result, bail};
use std::{
    fs::{self, File},
    io::BufReader,
    path::{Path, PathBuf},
    sync::atomic::AtomicBool,
};

#[derive(Debug, Clone)]
pub struct TitleInfo {
    pub english: String,
    pub japanese: String,
    pub korean: String,
    pub icon_path: Option<PathBuf>,
}

#[derive(Debug, Clone)]
pub struct TitlePatch {
    pub english: Option<String>,
    pub japanese: Option<String>,
    pub korean: Option<String>,
    pub icon_path: Option<PathBuf>,
    pub compression: CompressOptions,
}

pub fn analyze_title(
    input: &Path,
    temp_dir: &Path,
    hactool: &Path,
    prod_keys: &Path,
    cancel: &AtomicBool,
) -> Result<TitleInfo> {
    fs::create_dir_all(temp_dir)?;
    let (entries, cnmts, _) = discover_game_metadata(
        input,
        &temp_dir.join("metadata"),
        hactool,
        prod_keys,
        cancel,
    )?;
    let base = cnmts
        .iter()
        .filter(|c| c.meta_type == ContentMetaType::Base)
        .max_by_key(|c| c.version)
        .context("본편 CNMT를 찾지 못했습니다")?;
    let control_name = base
        .control_nca_name()
        .context("Control NCA를 찾지 못했습니다")?;
    let control_entry =
        resolve_content_entry(&entries, &control_name).context("Control NCA 엔트리가 없습니다")?;
    let control_path = temp_dir.join("control.nca");
    materialize_entry(input, control_entry, &control_path, cancel)?;
    let romfs = temp_dir.join("romfs");
    extract_control_romfs(&control_path, &romfs, hactool, prod_keys, cancel)?;
    let nacp_path = find_control_nacp_paths(&romfs)
        .into_iter()
        .next()
        .context("control.nacp를 찾지 못했습니다")?;
    let nacp = fs::read(&nacp_path)?;
    let icon_path = walkdir::WalkDir::new(&romfs)
        .max_depth(2)
        .into_iter()
        .filter_map(|e| e.ok())
        .find(|e| {
            let n = e.file_name().to_string_lossy().to_ascii_lowercase();
            e.file_type().is_file() && n.starts_with("icon_") && n.ends_with(".dat")
        })
        .map(|e| {
            let target = temp_dir.join("current_icon.jpg");
            let _ = fs::copy(e.path(), &target);
            target
        });
    Ok(TitleInfo {
        english: nacp_title(&nacp, 0),
        japanese: nacp_title(&nacp, 2),
        korean: nacp_title(&nacp, 12),
        icon_path,
    })
}

pub fn patch_title(
    input: &Path,
    output_dir: &Path,
    resource_dir: &Path,
    hactool: &Path,
    prod_keys: &Path,
    keys: &mut KeySet,
    patch: &TitlePatch,
    cancel: &AtomicBool,
    progress: &mut dyn FnMut(f32),
    log: &mut dyn FnMut(String),
) -> Result<PathBuf> {
    fs::create_dir_all(output_dir)?;
    let temp = crate::workspace::temp_workspace("nsrp_title_")?;
    let normalized = temp.path().join("input.nsp");
    normalize_to_nsp(
        input,
        &normalized,
        hactool,
        prod_keys,
        cancel,
        &mut |p| progress(p * 0.12),
        log,
    )?;
    let index = Pfs0Index::parse(&normalized)?;
    let entries = crate::ops::container::list_entries(&normalized, false)?;
    let cnmts = extract_and_parse_cnmts(
        &normalized,
        &entries,
        &temp.path().join("cnmt"),
        hactool,
        prod_keys,
        cancel,
    )?;
    let base = cnmts
        .iter()
        .filter(|c| c.meta_type == ContentMetaType::Base)
        .max_by_key(|c| c.version)
        .context("본편 CNMT를 찾지 못했습니다")?;
    let control_name = base
        .control_nca_name()
        .context("Control NCA를 찾지 못했습니다")?;
    let control_content = base
        .contents
        .iter()
        .find(|c| format!("{}.nca", c.nca_id).eq_ignore_ascii_case(&control_name))
        .context("CNMT Control 콘텐츠 행을 찾지 못했습니다")?;
    let control_entry =
        resolve_content_entry(&entries, &control_name).context("Control NCA가 없습니다")?;
    let meta_entry = entries
        .iter()
        .find(|e| e.name.eq_ignore_ascii_case(&base.cnmt_nca_name))
        .context("본편 CNMT NCA가 없습니다")?;
    progress(0.20);

    let control_path = temp.path().join("control.nca");
    materialize_entry(&normalized, control_entry, &control_path, cancel)?;
    let meta_path = temp.path().join("meta.cnmt.nca");
    materialize_entry(&normalized, meta_entry, &meta_path, cancel)?;
    let romfs = temp.path().join("control_romfs");
    extract_control_romfs(&control_path, &romfs, hactool, prod_keys, cancel)?;
    let nacp_paths = find_control_nacp_paths(&romfs);
    if nacp_paths.is_empty() {
        bail!("control.nacp가 없습니다");
    }
    for nacp_path in nacp_paths {
        let mut nacp = fs::read(&nacp_path)?;
        let format = patch_nacp_titles(
            &mut nacp,
            patch.english.as_deref(),
            patch.japanese.as_deref(),
            patch.korean.as_deref(),
        )?;
        if let Some(expected) = patch.english.as_deref().filter(|value| !value.is_empty())
            && nacp_title(&nacp, 0) != expected
        {
            bail!("NACP 영어 타이틀 수정 후 검증에 실패했습니다");
        }
        if let Some(expected) = patch.japanese.as_deref().filter(|value| !value.is_empty())
            && nacp_title(&nacp, 2) != expected
        {
            bail!("NACP 일본어 타이틀 수정 후 검증에 실패했습니다");
        }
        if let Some(expected) = patch.korean.as_deref().filter(|value| !value.is_empty())
            && nacp_title(&nacp, 12) != expected
        {
            bail!("NACP 한국어 타이틀 수정 후 검증에 실패했습니다");
        }
        fs::write(&nacp_path, &nacp)?;
        let relative = nacp_path.strip_prefix(&romfs).unwrap_or(&nacp_path);
        log(format!(
            "NACP 타이틀 수정: {} (Format{format})",
            relative.display()
        ));
    }
    if let Some(icon) = patch.icon_path.as_deref() {
        replace_icons(&romfs, icon)?;
    }
    progress(0.35);

    let repack = temp.path().join("repack_control");
    fs::create_dir_all(&repack)?;
    let native_out = repack.join("native_control.nca");
    let native_attempt =
        native_repack::repack_control_same_size(&control_path, &romfs, &native_out, keys, cancel)
            .map(|count| (count, "동일 크기"))
            .or_else(|fixed_error| {
                let _ = fs::remove_file(&native_out);
                native_control_resize::repack_control_resized(
                    &control_path,
                    &romfs,
                    &native_out,
                    keys,
                    cancel,
                )
                .map(|count| (count, "크기 변경"))
                .map_err(|resize_error| {
                    anyhow::anyhow!("고정크기={fixed_error:#}; 크기변경={resize_error:#}")
                })
            })
            .or_else(|previous_error| {
                let _ = fs::remove_file(&native_out);
                crate::ops::native_nca_builder::repack_nca(
                    &control_path,
                    Some(&romfs),
                    None,
                    &native_out,
                    keys,
                    cancel,
                )
                .map(|stats| (stats.romfs_files, "전체 RomFS"))
                .map_err(|error| anyhow::anyhow!("{previous_error:#}; 전체 RomFS={error:#}"))
            });
    let new_control = match native_attempt {
        Ok((count, method)) => {
            log(format!(
                "Control NCA 네이티브 재패킹({method}): {count}개 파일 처리"
            ));
            native_out
        }
        Err(reason) => {
            // No external packer: if every native path rejects an unusual
            // NCA, do not modify the original or an existing output file.
            return Err(reason).context(
                "Control NCA의 Rust 재패킹을 완료하지 못했습니다. 지원하지 않는 NCA 형상이므로 기존 결과물은 보존합니다",
            );
        }
    };
    progress(0.50);

    let new_hash = sha256_file(&new_control)?;
    let new_id = &new_hash[..16];
    let new_size = fs::metadata(&new_control)?.len();
    let mut cnmt_data = base.raw.clone();
    let row = find_cnmt_content_row(&cnmt_data, &control_content.nca_id)
        .context("CNMT Control 콘텐츠 위치를 찾지 못했습니다")?;
    cnmt_data[row..row + 0x20].copy_from_slice(&new_hash);
    cnmt_data[row + 0x20..row + 0x30].copy_from_slice(new_id);
    cnmt_data[row + 0x30..row + 0x36].copy_from_slice(&new_size.to_le_bytes()[..6]);
    let new_meta = patch_cnmt_nca(
        &meta_path,
        &base.raw,
        &cnmt_data,
        hactool,
        prod_keys,
        None,
        temp.path(),
        cancel,
    )?;
    progress(0.64);

    let staging = temp.path().join("staging");
    fs::create_dir_all(&staging)?;
    let mut source = BufReader::with_capacity(8 * 1024 * 1024, File::open(&normalized)?);
    let mut paths = Vec::<(String, PathBuf)>::new();
    for (i, entry) in index.entries.iter().enumerate() {
        if entry.name.eq_ignore_ascii_case(&base.cnmt_nca_name)
            || entry.name.eq_ignore_ascii_case(&control_name)
        {
            continue;
        }
        let path = staging.join(format!("copy_{i}"));
        copy_region(
            &mut source,
            index.data_start + entry.offset,
            entry.size,
            &path,
            cancel,
        )?;
        paths.push((entry.name.clone(), path));
    }
    paths.push((format!("{}.nca", hex::encode(new_id)), new_control));
    paths.push((base.cnmt_nca_name.clone(), new_meta));
    let patched_nsp = temp.path().join("patched.nsp");
    build_from_paths(&paths, &patched_nsp)?;
    progress(0.82);

    let original_stem = input.file_stem().and_then(|s| s.to_str()).unwrap_or("NSRP");
    let ext = input
        .extension()
        .and_then(|s| s.to_str())
        .unwrap_or("nsp")
        .to_ascii_lowercase();
    let final_path = finalize_same_format(
        &patched_nsp,
        &ext,
        original_stem,
        output_dir,
        resource_dir,
        prod_keys,
        keys,
        &patch.compression,
        cancel,
        progress,
        log,
    )?;
    progress(1.0);
    Ok(final_path)
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
        "nsz" => decompress_nsz_repaired(input, output, hactool, prod_keys, cancel, progress, log)?,
        "xci" => container_to_nsp(input, output, hactool, prod_keys, cancel, progress, log)?,
        "xcz" => {
            container_to_nsp(
                input,
                output,
                hactool,
                prod_keys,
                cancel,
                &mut |p| progress(p * 0.92),
                log,
            )?;
            repair_legacy_nsp_headers(
                output,
                hactool,
                prod_keys,
                cancel,
                &mut |p| progress(0.92 + p * 0.08),
                log,
            )?;
        }
        _ => bail!("지원하지 않는 입력 형식: {ext}"),
    }
    Ok(())
}

fn finalize_same_format(
    patched_nsp: &Path,
    original_ext: &str,
    original_stem: &str,
    output_dir: &Path,
    resource_dir: &Path,
    prod_keys: &Path,
    keys: &mut KeySet,
    compression: &CompressOptions,
    cancel: &AtomicBool,
    progress: &mut dyn FnMut(f32),
    log: &mut dyn FnMut(String),
) -> Result<PathBuf> {
    let base = format!("[Title_Patched] {original_stem}");
    match original_ext {
        "nsp" => {
            let out = output_dir.join(format!("{base}.nsp"));
            move_file(patched_nsp, &out, cancel)?;
            progress(1.0);
            Ok(out)
        }
        "nsz" => {
            let out = output_dir.join(format!("{base}.nsz"));
            compress_nsp(
                patched_nsp,
                &out,
                keys,
                compression,
                cancel,
                &mut |p| progress(0.82 + p * 0.18),
                log,
            )?;
            Ok(out)
        }
        "xci" => {
            let out = output_dir.join(format!("{base}.xci"));
            build_xci_from_nsp(patched_nsp, &out, resource_dir, prod_keys, cancel, log)?;
            progress(1.0);
            Ok(out)
        }
        "xcz" => {
            let temp_xci = output_dir.join(format!(".{base}.tmp.xci"));
            build_xci_from_nsp(patched_nsp, &temp_xci, resource_dir, prod_keys, cancel, log)?;
            progress(0.90);
            let out = output_dir.join(format!("{base}.xcz"));
            let result = compress_xci(
                &temp_xci,
                &out,
                keys,
                &XczOptions {
                    level: compression.level,
                    threads: compression.threads,
                    block_mode: compression.block_mode,
                    long_mode: compression.long_mode,
                },
                cancel,
                &mut |p| progress(0.90 + p * 0.10),
                log,
            );
            let _ = fs::remove_file(&temp_xci);
            result?;
            Ok(out)
        }
        other => bail!("지원하지 않는 출력 형식: {other}"),
    }
}

fn find_control_nacp_paths(romfs: &Path) -> Vec<PathBuf> {
    let mut paths = walkdir::WalkDir::new(romfs)
        .max_depth(4)
        .into_iter()
        .filter_map(|entry| entry.ok())
        .filter(|entry| {
            entry.file_type().is_file()
                && entry
                    .file_name()
                    .to_str()
                    .is_some_and(|name| name.eq_ignore_ascii_case("control.nacp"))
        })
        .map(|entry| entry.into_path())
        .collect::<Vec<_>>();
    paths.sort_by(|left, right| {
        let left_root = left.parent() == Some(romfs);
        let right_root = right.parent() == Some(romfs);
        right_root
            .cmp(&left_root)
            .then_with(|| left.to_string_lossy().cmp(&right.to_string_lossy()))
    });
    paths
}
