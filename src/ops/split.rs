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
    // A split NSP must be usable on its own. Never reconstruct a retail
    // Rights ID merely to match a CNMT hash when the original package has no
    // matching ticket: the resulting NSP would require an unavailable
    // external title key (Eden loader error 0007-0012).
    let repair_keys = KeySet::load(prod_keys, None)?;
    let mut cnmts = select_latest_by_title(&discovered_cnmts);
    cnmts.sort_by_key(|c| (meta_order(c.meta_type), c.title_id.clone()));
    if cnmts.is_empty() {
        bail!("분할 가능한 CNMT가 없습니다");
    }
    // Never delete an earlier split directory before parsing the new input.
    // Build the entire result in a private, same-volume folder and publish it
    // only after every NSP passes its PFS0 validation. An existing folder may
    // contain user-modified files, so repeat splits use [Split 2], [Split 3]...
    // instead of destructively replacing [Split].
    let staged_output = tempfile::Builder::new()
        .prefix("nsrp_split_publish_")
        .tempdir_in(output_dir)?;
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

    let mut output_names = Vec::new();
    for (game_index, info) in cnmts.iter().enumerate() {
        if cancel.load(Ordering::Relaxed) {
            bail!("작업이 중단되었습니다");
        }
        let stage = temp.path().join(format!("stage_{game_index}"));
        fs::create_dir_all(&stage)?;
        let mut paths = Vec::<(String, PathBuf)>::new();
        let mut package_keys = repair_keys.clone();

        // Materialize the package's own tickets first. Only those tickets,
        // not an unrelated local title.keys database, authorize restoring a
        // Rights ID to a previously ticketless NCZ header.
        let tid_prefix = info.title_id[..16.min(info.title_id.len())].to_ascii_lowercase();
        let mut extras = Vec::<(String, PathBuf)>::new();
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
            if entry.name.to_ascii_lowercase().ends_with(".tik") && entry.size <= 1024 * 1024 {
                let ticket = fs::read(&path)?;
                package_keys.add_ticket_data(&entry.name, &ticket);
            }
            extras.push((entry.name.clone(), path));
        }

        let meta_entry = entries
            .iter()
            .find(|e| e.name.eq_ignore_ascii_case(&info.cnmt_nca_name))
            .with_context(|| format!("CNMT NCA 누락: {}", info.cnmt_nca_name))?;
        let meta_path = stage.join("meta.nca");
        materialize_entry(input, meta_entry, &meta_path, cancel)?;
        paths.push((info.cnmt_nca_name.clone(), meta_path));

        let mut preserved_ticketless_ncz = 0usize;
        for (content_index, content) in info.contents.iter().enumerate() {
            let wanted = format!("{}.nca", content.nca_id);
            let entry = resolve_content_entry(&entries, &wanted)
                .with_context(|| format!("필수 콘텐츠 누락: {wanted}"))?;
            let path = stage.join(format!("content_{content_index}.nca"));
            materialize_entry(input, entry, &path, cancel)?;
            if entry.name.to_ascii_lowercase().ends_with(".ncz") && package_keys.title.is_empty() {
                preserved_ticketless_ncz += 1;
            }
            if entry.name.to_ascii_lowercase().ends_with(".ncz")
                && !package_keys.title.is_empty()
                && crate::formats::nca::restore_legacy_rights_header_region_if_key_available(
                    &path,
                    0,
                    fs::metadata(&path)?.len(),
                    &info.title_id,
                    &content.hash,
                    &package_keys,
                )?
            {
                log(format!("레거시 NCZ rights 헤더 복원: {wanted}"));
            }
            paths.push((wanted, path));
        }

        if preserved_ticketless_ncz > 0 {
            log(format!(
                "원본 티켓 없음: {} - NCZ {}개의 기존 무티켓 헤더 유지 (에뮬레이터 호환)",
                info.title_id, preserved_ticketless_ncz
            ));
        }
        paths.extend(extras);

        let output_name = format!(
            "{} [{}][v{}][{}].nsp",
            display_name,
            info.title_id,
            info.version,
            info.meta_type.label()
        );
        let output = staged_output.path().join(&output_name);
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
        output_names.push(output_name);
        progress(0.25 + 0.70 * (game_index + 1) as f32 / cnmts.len() as f32);
    }
    if cancel.load(Ordering::Relaxed) {
        bail!("작업이 중단되었습니다");
    }
    let target_output_dir = available_split_output_dir(output_dir, original_stem)?;
    fs::rename(staged_output.path(), &target_output_dir).with_context(|| {
        format!(
            "분할 결과 폴더를 안전하게 확정하지 못했습니다: {}",
            target_output_dir.display()
        )
    })?;
    let outputs = output_names
        .into_iter()
        .map(|name| target_output_dir.join(name))
        .collect();
    progress(1.0);
    Ok(outputs)
}

fn available_split_output_dir(output_dir: &Path, original_stem: &str) -> Result<PathBuf> {
    let clean_stem = sanitize_filename(original_stem);
    let stem = if clean_stem.is_empty() {
        "Split"
    } else {
        clean_stem.as_str()
    };
    for index in 1..=9999 {
        let folder = if index == 1 {
            format!("{stem} [Split]")
        } else {
            format!("{stem} [Split {index}]")
        };
        let candidate = output_dir.join(folder);
        // symlink_metadata catches dangling links too. A prior user file or
        // directory at the desired name is never replaced.
        match fs::symlink_metadata(&candidate) {
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(candidate),
            Ok(_) => {}
            Err(err) => return Err(err.into()),
        }
    }
    bail!("분할 결과 폴더 이름을 더 이상 생성할 수 없습니다");
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

#[cfg(test)]
mod stage70_split_tests {
    use super::*;
    use crate::{formats::nca, ops::container};

    #[test]
    fn stage73_invalid_split_input_never_deletes_existing_user_split_folder() -> Result<()> {
        let root = tempfile::tempdir()?;
        let input = root.path().join("unsafe.nsz");
        fs::write(&input, b"not a valid Switch container")?;
        let output_dir = root.path().join("output");
        let existing = output_dir.join("unsafe [Split]");
        fs::create_dir_all(&existing)?;
        let protected = existing.join("my-save-and-custom-name.txt");
        fs::write(&protected, b"must survive invalid file parse")?;

        assert!(
            split_package(
                &input,
                &output_dir,
                &root.path().join("unused-hactool"),
                &root.path().join("unused.keys"),
                false,
                &AtomicBool::new(false),
                &mut |_| {},
                &mut |_| {},
            )
            .is_err()
        );
        assert_eq!(
            fs::read(&protected)?,
            b"must survive invalid file parse",
            "A failing split must not erase a previous split or a user's files"
        );
        Ok(())
    }

    #[test]
    fn stage73_split_collision_keeps_every_existing_folder() -> Result<()> {
        let root = tempfile::tempdir()?;
        let first = root.path().join("Game [Split]");
        let second = root.path().join("Game [Split 2]");
        fs::create_dir_all(&first)?;
        fs::write(first.join("original-save.txt"), b"protected first")?;
        assert_eq!(available_split_output_dir(root.path(), "Game")?, second);
        fs::create_dir_all(&second)?;
        fs::write(second.join("note.txt"), b"protected second")?;
        assert_eq!(
            available_split_output_dir(root.path(), "Game")?,
            root.path().join("Game [Split 3]")
        );
        assert_eq!(
            fs::read(first.join("original-save.txt"))?,
            b"protected first"
        );
        assert_eq!(fs::read(second.join("note.txt"))?, b"protected second");
        Ok(())
    }

    #[test]
    #[ignore = "Requires locally authorized NSZ and a nonexistent private QA output root"]
    fn stage73_real_repeat_split_keeps_prior_output_and_generates_new_folder() -> Result<()> {
        let input = PathBuf::from(
            std::env::var_os("NSRP_SPLIT_QA_INPUT").context("Missing NSZ QA fixture")?,
        );
        let output_root = PathBuf::from(
            std::env::var_os("NSRP_SPLIT_QA_OUTPUT").context("Missing QA output root")?,
        );
        let hactool =
            PathBuf::from(std::env::var_os("NSRP_SPLIT_QA_HACTOOL").context("Missing hactool")?);
        let prod_keys =
            PathBuf::from(std::env::var_os("NSRP_SPLIT_QA_KEYS").context("Missing prod.keys")?);
        anyhow::ensure!(
            !output_root.exists(),
            "Only a fresh disposable QA folder may be used"
        );
        let source_len = fs::metadata(&input)?.len();
        let name = sanitize_filename(
            input
                .file_stem()
                .and_then(|s| s.to_str())
                .unwrap_or("Split"),
        );
        let existing = output_root.join(format!("{name} [Split]"));
        fs::create_dir_all(&existing)?;
        let sentinel = existing.join("user_custom_note.txt");
        fs::write(&sentinel, b"keep existing data")?;
        let outputs = split_package(
            &input,
            &output_root,
            &hactool,
            &prod_keys,
            false,
            &AtomicBool::new(false),
            &mut |_| {},
            &mut |line| println!("{line}"),
        )?;
        anyhow::ensure!(outputs.len() == 4, "Expected Base+Update+2 DLC NSPs");
        for path in &outputs {
            anyhow::ensure!(
                path.parent() == Some(output_root.join(format!("{name} [Split 2]")).as_path()),
                "Expected safe alternative Split 2 path"
            );
            let index = Pfs0Index::parse(path)?;
            anyhow::ensure!(!index.entries.is_empty(), "Empty split package");
        }
        anyhow::ensure!(
            fs::read(&sentinel)? == b"keep existing data",
            "Existing user split directory was modified"
        );
        anyhow::ensure!(
            fs::metadata(&input)?.len() == source_len,
            "User source file length changed"
        );
        println!("STAGE73_REAL_SPLIT_REPEATED_WITHOUT_DELETION packages=4");
        Ok(())
    }

    // Run against a locally supplied, authorized fixture; neither game files
    // nor keys nor user-specific paths are committed to the repository.
    #[test]
    #[ignore = "Requires a local NSZ fixture and fresh QA output directory"]
    fn ticketless_nsz_split_retains_its_original_ncz_headers() -> Result<()> {
        let input = PathBuf::from(
            std::env::var_os("NSRP_SPLIT_QA_INPUT").context("NSRP_SPLIT_QA_INPUT unset")?,
        );
        let output_root = PathBuf::from(
            std::env::var_os("NSRP_SPLIT_QA_OUTPUT").context("NSRP_SPLIT_QA_OUTPUT unset")?,
        );
        let hactool = PathBuf::from(
            std::env::var_os("NSRP_SPLIT_QA_HACTOOL").context("NSRP_SPLIT_QA_HACTOOL unset")?,
        );
        let prod_keys = PathBuf::from(
            std::env::var_os("NSRP_SPLIT_QA_KEYS").context("NSRP_SPLIT_QA_KEYS unset")?,
        );
        let source_len = fs::metadata(&input)?.len();
        let source_stem = input
            .file_stem()
            .and_then(|stem| stem.to_str())
            .context("Input file stem is not UTF-8")?;
        let expected_dir = output_root.join(format!("{} [Split]", sanitize_filename(source_stem)));
        anyhow::ensure!(
            !expected_dir.exists(),
            "Refusing to overwrite an existing QA split output directory"
        );
        let outputs = split_package(
            &input,
            &output_root,
            &hactool,
            &prod_keys,
            false,
            &AtomicBool::new(false),
            &mut |_| {},
            &mut |message| println!("{message}"),
        )?;
        anyhow::ensure!(outputs.len() == 4, "Expected a 4-package test fixture");
        let source_entries = container::list_entries(&input, true)?;
        let header_keys = KeySet::load(&prod_keys, None)?;
        let mut compared = 0;
        for output in &outputs {
            let split_entries = container::list_entries(output, true)?;
            anyhow::ensure!(
                split_entries
                    .iter()
                    .all(|entry| !entry.name.ends_with(".tik")),
                "Ticketless input unexpectedly produced a ticket"
            );
            for entry in &split_entries {
                if !entry.name.ends_with(".nca") || entry.name.ends_with(".cnmt.nca") {
                    continue;
                }
                let compressed_name = format!("{}.ncz", entry.name.trim_end_matches(".nca"));
                let Some(source_entry) = source_entries
                    .iter()
                    .find(|source| source.name.eq_ignore_ascii_case(&compressed_name))
                else {
                    continue;
                };
                let mut source = File::open(&input)?;
                source.seek(SeekFrom::Start(source_entry.offset))?;
                let mut original_header = vec![0u8; nca::NCA_XTS_HEADER_SIZE];
                source.read_exact(&mut original_header)?;
                let mut rebuilt = File::open(output)?;
                rebuilt.seek(SeekFrom::Start(entry.offset))?;
                let mut rebuilt_header = vec![0u8; nca::NCA_XTS_HEADER_SIZE];
                rebuilt.read_exact(&mut rebuilt_header)?;
                anyhow::ensure!(
                    rebuilt_header == original_header,
                    "Split changed a ticketless NCA header: {}",
                    entry.name
                );
                let info = nca::decrypt_header(&rebuilt_header, &header_keys)?;
                anyhow::ensure!(
                    info.rights_id.iter().all(|byte| *byte == 0),
                    "Split introduced an unsupported Rights ID: {}",
                    entry.name
                );
                compared += 1;
            }
        }
        anyhow::ensure!(
            compared == 4,
            "Expected four NCZ-backed NCA comparisons, got {compared}"
        );
        anyhow::ensure!(
            fs::metadata(input)?.len() == source_len,
            "Original NSZ length changed"
        );
        println!("STAGE70_TICKETLESS_SPLIT_HEADERS_PRESERVED=4 PACKAGES=4");
        Ok(())
    }
}
