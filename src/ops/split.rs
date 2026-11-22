use crate::{
    formats::{
        ncz_stream::decompress_ncz_region_to_nca,
        pfs0::{Pfs0Index, build_from_paths},
    },
    keys::KeySet,
    ops::{
        cnmt::{
            ContentMetaType, discover_game_metadata, get_title_from_control_nca,
            resolve_content_entry, select_latest_by_title,
        },
        container::ContainerEntry,
    },
};
use anyhow::{Context, Result, bail};
use std::{
    fs::{self, File},
    io::{BufReader, BufWriter, Read, Seek, SeekFrom, Write},
    path::{Path, PathBuf},
    sync::atomic::{AtomicBool, Ordering},
};

pub fn split_package(
    input: &Path,
    output_dir: &Path,
    hactool: &Path,
    prod_keys: &Path,
    use_game_title: bool,
    cancel: &AtomicBool,
    progress: &mut dyn FnMut(f32),
    log: &mut dyn FnMut(String),
) -> Result<Vec<PathBuf>> {
    fs::create_dir_all(output_dir)?;
    let original_stem = input
        .file_stem()
        .and_then(|s| s.to_str())
        .unwrap_or("Split");
    let target_output_dir =
        output_dir.join(format!("{} [Split]", sanitize_filename(original_stem)));
    if target_output_dir.exists() {
        fs::remove_dir_all(&target_output_dir)?;
    }
    fs::create_dir_all(&target_output_dir)?;
    let temp = crate::workspace::temp_workspace("nsrp_split_")?;
    let (entries, discovered_cnmts, legacy_partition_fallback) = discover_game_metadata(
        input,
        &temp.path().join("metadata"),
        hactool,
        prod_keys,
        cancel,
    )?;
    if legacy_partition_fallback {
        log("구형 XCI 파티션 배치 감지: 전체 파티션에서 게임 메타데이터를 재탐색합니다".to_owned());
    }
    let repair_keys = KeySet::load(prod_keys, None)?;
    let mut cnmts = select_latest_by_title(&discovered_cnmts);
    cnmts.sort_by_key(|c| (meta_order(c.meta_type), c.title_id.clone()));
    if cnmts.is_empty() {
        bail!("분할 가능한 CNMT가 없습니다");
    }
    progress(0.15);

    let default_name = input
        .file_stem()
        .and_then(|s| s.to_str())
        .unwrap_or("Split");
    let mut display_name = sanitize_filename(default_name);
    if use_game_title
        && let Some(base) = cnmts
            .iter()
            .filter(|c| c.meta_type == ContentMetaType::Base)
            .max_by_key(|c| c.version)
        && let Some(control_name) = base.control_nca_name()
        && let Some(entry) = resolve_content_entry(&entries, &control_name)
    {
        let control_path = temp.path().join("control.nca");
        materialize_entry(input, entry, &control_path, cancel)?;
        if let Ok(Some(title)) = get_title_from_control_nca(
            &control_path,
            hactool,
            prod_keys,
            &temp.path().join("title"),
            cancel,
        ) {
            let clean = sanitize_filename(&title);
            if !clean.is_empty() {
                display_name = clean;
            }
        }
    }
    progress(0.25);

    let mut outputs = Vec::new();
    for (game_index, info) in cnmts.iter().enumerate() {
        if cancel.load(Ordering::Relaxed) {
            bail!("작업이 중단되었습니다");
        }
        let stage = temp.path().join(format!("stage_{game_index}"));
        fs::create_dir_all(&stage)?;
        let mut paths = Vec::<(String, PathBuf)>::new();

        let meta_entry = entries
            .iter()
            .find(|e| e.name.eq_ignore_ascii_case(&info.cnmt_nca_name))
            .with_context(|| format!("CNMT NCA 누락: {}", info.cnmt_nca_name))?;
        let meta_path = stage.join("meta.nca");
        materialize_entry(input, meta_entry, &meta_path, cancel)?;
        paths.push((info.cnmt_nca_name.clone(), meta_path));

        for (content_index, content) in info.contents.iter().enumerate() {
            let wanted = format!("{}.nca", content.nca_id);
            let entry = resolve_content_entry(&entries, &wanted)
                .with_context(|| format!("필수 콘텐츠 누락: {wanted}"))?;
            let path = stage.join(format!("content_{content_index}.nca"));
            materialize_entry(input, entry, &path, cancel)?;
            if entry.name.to_ascii_lowercase().ends_with(".ncz")
                && crate::formats::nca::restore_legacy_rights_header_for_hash(
                    &path,
                    &info.title_id,
                    &content.hash,
                    &repair_keys,
                )?
            {
                log(format!("레거시 NCZ rights 헤더 복원: {wanted}"));
            }
            paths.push((wanted, path));
        }

        let tid_prefix = info.title_id[..16.min(info.title_id.len())].to_ascii_lowercase();
        for (extra_index, entry) in entries
            .iter()
            .filter(|e| {
                let n = e.name.to_ascii_lowercase();
                (n.ends_with(".tik") || n.ends_with(".cert")) && n.starts_with(&tid_prefix)
            })
            .enumerate()
        {
            let path = stage.join(format!("extra_{extra_index}.bin"));
            materialize_raw(input, entry, &path, cancel)?;
            paths.push((entry.name.clone(), path));
        }

        let output_name = format!(
            "{} [{}][v{}][{}].nsp",
            display_name,
            info.title_id,
            info.version,
            info.meta_type.label()
        );
        let output = target_output_dir.join(output_name);
        build_from_paths(&paths, &output)?;
        let built = Pfs0Index::parse(&output)?;
        for (name, _) in &paths {
            if built.entry(name).is_none() {
                bail!("분할 결과 검증 실패: {name} 누락");
            }
        }
        log(format!(
            "분할 완료: {} v{} {}",
            info.title_id,
            info.version,
            info.meta_type.label()
        ));
        outputs.push(output);
        progress(0.25 + 0.75 * (game_index + 1) as f32 / cnmts.len() as f32);
    }
    progress(1.0);
    Ok(outputs)
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

pub fn sanitize_filename(value: &str) -> String {
    let filtered: String = value
        .chars()
        .filter_map(|c| {
            if matches!(c, '<' | '>' | ':' | '"' | '/' | '\\' | '|' | '?' | '*') {
                None
            } else if matches!(c, '\n' | '\r') {
                Some(' ')
            } else if c.is_control() {
                None
            } else {
                Some(c)
            }
        })
        .collect();
    filtered.split_whitespace().collect::<Vec<_>>().join(" ")
}
