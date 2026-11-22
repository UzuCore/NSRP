use crate::{
    formats::ncz_stream::decompress_ncz_region_to_nca,
    keys::{KeySet, parse_key_file, sanitize_title_keys_file},
    ops::{
        cnmt::{discover_game_metadata, extract_and_parse_cnmts},
        container::{ContainerEntry, list_entries},
        native_fs,
    },
    process::run_tool,
};
use anyhow::{Context, Result, bail};
use std::{
    collections::{BTreeMap, HashMap},
    ffi::OsString,
    fs::{self, File},
    io::{BufReader, BufWriter, Read, Seek, SeekFrom, Write},
    path::{Path, PathBuf},
    sync::atomic::{AtomicBool, Ordering},
};

#[derive(Debug, Clone)]
pub struct ExtractOptions {
    pub selected_names: Vec<String>,
    pub unpack_nca: bool,
}

impl Default for ExtractOptions {
    fn default() -> Self {
        Self {
            selected_names: Vec::new(),
            unpack_nca: true,
        }
    }
}

/// 분해 탭에 표시할 엔트리 목록을 Python판의 정규화 결과와 동일하게 만든다.
/// XCI/XCZ는 secure 계열만 노출하고, 압축 NCA(.ncz)는 사용자가 실제로 받게 될
/// .nca 이름으로 표시한다. `list_entries`가 반환하는 offset은 항상 절대 오프셋이다.
pub fn list_display_entries(
    input: &Path,
    workspace: &Path,
    hactool: &Path,
    prod_keys: &Path,
) -> Result<Vec<ContainerEntry>> {
    fs::create_dir_all(workspace)?;
    let ext = input
        .extension()
        .and_then(|value| value.to_str())
        .unwrap_or("")
        .to_ascii_lowercase();
    let skip_system_partitions = matches!(ext.as_str(), "xci" | "xcz");
    let temp = tempfile::Builder::new()
        .prefix("nsrp_extract_list_")
        .tempdir_in(workspace)?;
    let entries = match discover_game_metadata(
        input,
        temp.path(),
        hactool,
        prod_keys,
        &AtomicBool::new(false),
    ) {
        Ok((entries, _, _)) => entries,
        Err(_) => list_entries(input, skip_system_partitions)?,
    };
    Ok(entries
        .into_iter()
        .map(|mut entry| {
            if entry.name.to_ascii_lowercase().ends_with(".ncz") {
                entry.name = replace_extension(&entry.name, "nca");
            }
            entry
        })
        .collect())
}

pub fn extract(
    input: &Path,
    output_dir: &Path,
    workspace: &Path,
    hactool: &Path,
    prod_keys: &Path,
    options: &ExtractOptions,
    cancel: &AtomicBool,
    progress: &mut dyn FnMut(f32),
    log: &mut dyn FnMut(String),
) -> Result<Vec<PathBuf>> {
    fs::create_dir_all(workspace)?;
    let ext = input
        .extension()
        .and_then(|value| value.to_str())
        .unwrap_or("")
        .to_ascii_lowercase();
    let skip_system_partitions = matches!(ext.as_str(), "xci" | "xcz");
    let metadata_temp = tempfile::Builder::new()
        .prefix("nsrp_extract_metadata_")
        .tempdir_in(workspace)?;
    let (entries, discovered_cnmts) =
        match discover_game_metadata(input, metadata_temp.path(), hactool, prod_keys, cancel) {
            Ok((entries, cnmts, legacy_partition_fallback)) => {
                if legacy_partition_fallback {
                    log(
                        "구형 XCI 파티션 배치 감지: Update/DLC 콘텐츠를 분해 대상에 포함합니다"
                            .to_owned(),
                    );
                }
                (entries, Some(cnmts))
            }
            Err(err) => {
                log(format!(
                    "메타데이터 호환 탐색 경고: {err:#} — 기존 컨테이너 목록으로 분해를 계속합니다"
                ));
                (list_entries(input, skip_system_partitions)?, None)
            }
        };
    if options.unpack_nca {
        let title_keys = prod_keys
            .parent()
            .unwrap_or_else(|| Path::new("."))
            .join("title.keys");
        match merge_ticket_title_keys(input, &entries, &title_keys, cancel) {
            Ok(count) if count > 0 => log(format!("키 데이터베이스 갱신: {count}개 추가")),
            Ok(_) => {}
            Err(err) => log(format!("키 데이터베이스 갱신 경고: {err:#}")),
        }
    }
    let selected: Vec<&ContainerEntry> = if options.selected_names.is_empty() {
        entries.iter().collect()
    } else {
        entries
            .iter()
            .filter(|e| {
                let display_name = if e.name.to_ascii_lowercase().ends_with(".ncz") {
                    replace_extension(&e.name, "nca")
                } else {
                    e.name.clone()
                };
                options
                    .selected_names
                    .iter()
                    .any(|n| n.eq_ignore_ascii_case(&display_name))
            })
            .collect()
    };
    if selected.is_empty() {
        bail!("추출 대상 파일이 없습니다");
    }
    fs::create_dir_all(output_dir)?;

    let has_selected_ncz = selected
        .iter()
        .any(|entry| entry.name.to_ascii_lowercase().ends_with(".ncz"));
    let mut legacy_repair = HashMap::<String, (String, [u8; 32])>::new();
    let repair_keys = if has_selected_ncz {
        let cnmt_temp = tempfile::Builder::new()
            .prefix("nsrp_extract_cnmt_")
            .tempdir_in(workspace)?;
        let repair_cnmts = if let Some(cnmts) = discovered_cnmts.clone() {
            Some(cnmts)
        } else {
            extract_and_parse_cnmts(
                input,
                &entries,
                cnmt_temp.path(),
                hactool,
                prod_keys,
                cancel,
            )
            .ok()
        };
        if let Some(cnmts) = repair_cnmts {
            for cnmt in cnmts {
                for content in cnmt.contents {
                    legacy_repair.insert(
                        content.nca_id.to_ascii_lowercase(),
                        (cnmt.title_id.clone(), content.hash),
                    );
                }
            }
        }
        let title_keys = prod_keys
            .parent()
            .unwrap_or_else(|| Path::new("."))
            .join("title.keys");
        Some(KeySet::load(
            prod_keys,
            title_keys.is_file().then_some(title_keys.as_path()),
        )?)
    } else {
        None
    };

    // Load keys from their configured paths, without Public or .switch copies.
    let native_keys = if options.unpack_nca {
        KeySet::load_with_local_title_keys(prod_keys).ok()
    } else {
        None
    };
    let total = selected.iter().map(|e| e.size).sum::<u64>().max(1);
    let mut done = 0u64;
    let mut outputs = Vec::new();
    let mut input_file = BufReader::with_capacity(8 * 1024 * 1024, File::open(input)?);

    for (index, entry) in selected.iter().enumerate() {
        if cancel.load(Ordering::Relaxed) {
            bail!("작업이 중단되었습니다");
        }
        let lower = entry.name.to_ascii_lowercase();
        let output_name = if lower.ends_with(".ncz") {
            replace_extension(&entry.name, "nca")
        } else {
            entry.name.clone()
        };
        let output_path = output_dir.join(&output_name);
        if lower.ends_with(".ncz") {
            // A corrupted/truncated NCZ must never leave a partially
            // reconstructed NCA at the user-visible destination. Keep the
            // streamed output in the same-volume temporary file and publish
            // it only after the decoder and the buffered writer succeed.
            let mut staged = tempfile::Builder::new()
                .prefix("nsrp_ncz_extract_")
                .tempfile_in(output_dir)?;
            let base = done;
            {
                let mut out = BufWriter::with_capacity(8 * 1024 * 1024, staged.as_file_mut());
                decompress_ncz_region_to_nca(
                    &mut input_file,
                    entry.offset,
                    entry.size,
                    &mut out,
                    cancel,
                    |cur, inner_total| {
                        let frac = if inner_total == 0 {
                            1.0
                        } else {
                            cur as f32 / inner_total as f32
                        };
                        progress(
                            ((base as f32 + entry.size as f32 * frac.min(1.0)) / total as f32)
                                * 0.75,
                        );
                    },
                )?;
                out.flush()?;
            }
            staged.persist(&output_path)?;
        } else {
            copy_region(
                &mut input_file,
                entry.offset,
                entry.size,
                &output_path,
                cancel,
            )?;
        }
        log(format!("추출: {output_name}"));
        outputs.push(output_path.clone());

        let legacy_target = lower
            .ends_with(".ncz")
            .then(|| {
                let content_id = output_name
                    .strip_suffix(".nca")
                    .unwrap_or(&output_name)
                    .to_ascii_lowercase();
                legacy_repair.get(&content_id).cloned()
            })
            .flatten();

        if !options.unpack_nca
            && let (Some((title_id, expected_hash)), Some(keys)) =
                (legacy_target.as_ref(), repair_keys.as_ref())
            && crate::formats::nca::restore_legacy_rights_header_for_hash(
                &output_path,
                title_id,
                expected_hash,
                keys,
            )?
        {
            log(format!("레거시 NCZ rights 헤더 복원: {output_name}"));
        }

        if options.unpack_nca && output_name.to_ascii_lowercase().ends_with(".nca") {
            let unpack_temp = tempfile::Builder::new()
                .prefix("nsrp_hactool_nca_")
                .tempdir_in(workspace)?;
            let unpack_dir = unpack_temp.path().join("unpacked");
            fs::create_dir_all(&unpack_dir)?;
            let mut manual_base = None;
            let native_result = native_keys.as_ref().and_then(|keys| {
                match native_fs::unpack_nca(&output_path, &unpack_dir, keys, cancel) {
                    Ok(stats) if stats.total() > 0 && unpack_has_output(&unpack_dir) => Some(stats),
                    _ => {
                        // An incomplete native attempt must never mingle
                        // with another native strategy or the tool fallback.
                        let _ = fs::remove_dir_all(&unpack_dir);
                        fs::create_dir_all(&unpack_dir).ok()?;
                        native_fs::unpack_patched_manual_from_package(
                            &output_path,
                            input,
                            &entries,
                            unpack_temp.path(),
                            &unpack_dir,
                            keys,
                            cancel,
                        )
                        .ok()
                        .map(|(stats, matched_base)| {
                            manual_base = Some(matched_base);
                            stats
                        })
                    }
                }
            });
            if let Some(stats) = native_result
                && stats.total() > 0
                && unpack_has_output(&unpack_dir)
            {
                fs::remove_file(&output_path)?;
                move_dir(&unpack_dir, &output_path)?;
                outputs.pop();
                outputs.push(output_path.clone());
                if let Some(base) = manual_base {
                    log(format!(
                        "BKTR 매뉴얼 네이티브 추출 완료: {output_name} (검증된 원본 {base}, RomFS {}개)",
                        stats.romfs_files,
                    ));
                } else {
                    log(format!(
                        "NCA 네이티브 내부 추출 완료: {output_name} (RomFS {}개 / PartitionFS {}개)",
                        stats.romfs_files, stats.pfs0_files
                    ));
                }
                done += entry.size;
                progress(0.75 + 0.25 * ((index + 1) as f32 / selected.len() as f32));
                continue;
            }
            // Never combine partial native output with a fallback result.
            if cancel.load(Ordering::Relaxed) {
                bail!("작업이 중단되었습니다");
            }
            let _ = fs::remove_dir_all(&unpack_dir);
            fs::create_dir_all(&unpack_dir)?;
            let args = vec![
                OsString::from("-k"),
                prod_keys.as_os_str().to_owned(),
                OsString::from("-t"),
                OsString::from("nca"),
                OsString::from("--disablekeywarns"),
                OsString::from(format!("--romfsdir={}", unpack_dir.join("romfs").display())),
                OsString::from(format!("--exefsdir={}", unpack_dir.join("exefs").display())),
                OsString::from(format!(
                    "--section0dir={}",
                    unpack_dir.join("section0").display()
                )),
                output_path.as_os_str().to_owned(),
            ];
            let tool = run_tool(hactool, args, Some(workspace), cancel)?;
            let mut has_output = unpack_has_output(&unpack_dir);
            let mut detail = tool.combined();

            if (!tool.success() || !has_output)
                && let Some(parent) = hactool.parent()
                && parent.join("hactoolnet.exe").is_file()
            {
                let _ = fs::remove_dir_all(&unpack_dir);
                fs::create_dir_all(&unpack_dir)?;
                let hactoolnet = parent.join("hactoolnet.exe");
                let mut net_args = vec![
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
                if title_keys.is_file() {
                    net_args.extend([
                        OsString::from("--titlekeys"),
                        title_keys.as_os_str().to_owned(),
                    ]);
                }
                net_args.extend([
                    OsString::from("--romfsdir"),
                    unpack_dir.join("romfs").as_os_str().to_owned(),
                    OsString::from("--exefsdir"),
                    unpack_dir.join("exefs").as_os_str().to_owned(),
                    OsString::from("--section0dir"),
                    unpack_dir.join("section0").as_os_str().to_owned(),
                    output_path.as_os_str().to_owned(),
                ]);
                let net_tool = run_tool(&hactoolnet, net_args, Some(workspace), cancel)?;
                has_output = net_tool.success() && unpack_has_output(&unpack_dir);
                if !has_output {
                    detail = net_tool.combined();
                }
            }

            if has_output {
                fs::remove_file(&output_path)?;
                move_dir(&unpack_dir, &output_path)?;
                outputs.pop();
                outputs.push(output_path.clone());
                log(format!("NCA 내부 추출 완료: {output_name}"));
            } else {
                let _ = fs::remove_dir_all(&unpack_dir);
                if let (Some((title_id, expected_hash)), Some(keys)) =
                    (legacy_target.as_ref(), repair_keys.as_ref())
                    && crate::formats::nca::restore_legacy_rights_header_for_hash(
                        &output_path,
                        title_id,
                        expected_hash,
                        keys,
                    )?
                {
                    log(format!("레거시 NCZ rights 헤더 복원: {output_name}"));
                }
                log(format!(
                    "NCA 내부 추출 경고: {output_name} — {}",
                    detail.lines().next().unwrap_or("분해 결과 없음")
                ));
            }
        }
        done += entry.size;
        progress(0.75 + 0.25 * ((index + 1) as f32 / selected.len() as f32));
    }
    progress(1.0);
    Ok(outputs)
}

fn unpack_has_output(unpack_dir: &Path) -> bool {
    ["romfs", "exefs", "section0"]
        .iter()
        .map(|name| unpack_dir.join(name))
        .any(|path| {
            path.is_dir()
                && fs::read_dir(&path)
                    .ok()
                    .is_some_and(|mut entries| entries.next().is_some())
        })
}

fn merge_ticket_title_keys(
    input: &Path,
    entries: &[ContainerEntry],
    title_keys_path: &Path,
    cancel: &AtomicBool,
) -> Result<usize> {
    let _ = sanitize_title_keys_file(title_keys_path)?;
    let mut keys = if title_keys_path.is_file() {
        parse_key_file(title_keys_path, true).unwrap_or_default()
    } else {
        std::collections::HashMap::new()
    };
    let mut reader = BufReader::with_capacity(1024 * 1024, File::open(input)?);
    let mut added = 0usize;
    for entry in entries.iter().filter(|entry| {
        entry.name.to_ascii_lowercase().ends_with(".tik") && entry.size <= 1024 * 1024
    }) {
        if cancel.load(Ordering::Relaxed) {
            bail!("작업이 중단되었습니다");
        }
        let rights_id = entry
            .name
            .rsplit_once('.')
            .map(|(stem, _)| stem)
            .unwrap_or(&entry.name);
        if rights_id.len() != 32 || !rights_id.bytes().all(|byte| byte.is_ascii_hexdigit()) {
            continue;
        }
        if entry.size < 0x190 {
            continue;
        }
        reader.seek(SeekFrom::Start(entry.offset + 0x180))?;
        let mut title_key = [0u8; 16];
        reader.read_exact(&mut title_key)?;
        if title_key.iter().all(|&byte| byte == 0) {
            continue;
        }
        let id = rights_id.to_ascii_uppercase();
        if let std::collections::hash_map::Entry::Vacant(slot) = keys.entry(id) {
            slot.insert(title_key.to_vec());
            added += 1;
        }
    }
    if added == 0 {
        return Ok(0);
    }
    if let Some(parent) = title_keys_path.parent() {
        fs::create_dir_all(parent)?;
    }
    let sorted = keys.into_iter().collect::<BTreeMap<_, _>>();
    let mut text = String::new();
    for (rights_id, key) in sorted {
        if rights_id.len() == 32 && key.len() == 16 {
            text.push_str(&format!("{rights_id} = {}\n", hex::encode_upper(key)));
        }
    }
    fs::write(title_keys_path, text)
        .with_context(|| format!("title.keys 저장 실패: {}", title_keys_path.display()))?;
    Ok(added)
}

fn copy_region<R: Read + Seek>(
    reader: &mut R,
    offset: u64,
    size: u64,
    output: &Path,
    cancel: &AtomicBool,
) -> Result<()> {
    reader.seek(SeekFrom::Start(offset))?;
    let mut out = BufWriter::with_capacity(8 * 1024 * 1024, File::create(output)?);
    let mut left = size;
    let mut buf = vec![0u8; 8 * 1024 * 1024];
    while left > 0 {
        if cancel.load(Ordering::Relaxed) {
            bail!("작업이 중단되었습니다");
        }
        let take = left.min(buf.len() as u64) as usize;
        reader.read_exact(&mut buf[..take])?;
        out.write_all(&buf[..take])?;
        left -= take as u64;
    }
    out.flush()?;
    Ok(())
}

fn move_dir(src: &Path, dst: &Path) -> Result<()> {
    match fs::rename(src, dst) {
        Ok(()) => Ok(()),
        Err(_) => {
            fs::create_dir_all(dst)?;
            for entry in walkdir::WalkDir::new(src) {
                let entry = entry?;
                let rel = entry.path().strip_prefix(src)?;
                if rel.as_os_str().is_empty() {
                    continue;
                }
                let target = dst.join(rel);
                if entry.file_type().is_dir() {
                    fs::create_dir_all(&target)?;
                } else if entry.file_type().is_file() {
                    if let Some(parent) = target.parent() {
                        fs::create_dir_all(parent)?;
                    }
                    fs::copy(entry.path(), &target)?;
                }
            }
            fs::remove_dir_all(src)?;
            Ok(())
        }
    }
}

fn stem(name: &str) -> &str {
    name.rsplit_once('.').map(|p| p.0).unwrap_or(name)
}
fn replace_extension(name: &str, ext: &str) -> String {
    format!("{}.{}", stem(name), ext)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::formats::pfs0::build_from_paths;

    #[test]
    fn display_entries_use_absolute_offsets_and_normalized_nca_names() -> Result<()> {
        let temp = tempfile::tempdir()?;
        let payload = temp.path().join("payload.bin");
        fs::write(&payload, b"compressed-placeholder")?;
        let package = temp.path().join("sample.nsz");
        build_from_paths(&[("0123456789abcdef.ncz".to_owned(), payload)], &package)?;

        let entries = list_display_entries(
            &package,
            temp.path(),
            &temp.path().join("hactool.exe"),
            &temp.path().join("prod.keys"),
        )?;
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].name, "0123456789abcdef.nca");
        let index = crate::formats::pfs0::Pfs0Index::parse(&package)?;
        assert_eq!(
            entries[0].offset,
            index.data_start + index.entries[0].offset
        );
        Ok(())
    }

    #[test]
    fn tickets_are_merged_into_title_keys_for_internal_extract() -> Result<()> {
        let temp = tempfile::tempdir()?;
        let rights_id = "01001234567890000000000000000001";
        let ticket = temp.path().join("ticket.bin");
        let mut ticket_data = vec![0u8; 0x200];
        ticket_data[0x180..0x190].copy_from_slice(&[0x5A; 16]);
        fs::write(&ticket, ticket_data)?;
        let package = temp.path().join("sample.nsp");
        build_from_paths(&[(format!("{rights_id}.tik"), ticket)], &package)?;
        let entries = list_entries(&package, false)?;
        let title_keys = temp.path().join("title.keys");
        let cancel = AtomicBool::new(false);
        assert_eq!(
            merge_ticket_title_keys(&package, &entries, &title_keys, &cancel)?,
            1
        );
        let text = fs::read_to_string(&title_keys)?;
        assert!(text.contains(rights_id));
        assert!(text.contains("5A5A5A5A5A5A5A5A5A5A5A5A5A5A5A5A"));
        assert_eq!(
            merge_ticket_title_keys(&package, &entries, &title_keys, &cancel)?,
            0
        );
        Ok(())
    }
}
