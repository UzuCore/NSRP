use crate::{
    formats::ncz_stream::{decompress_ncz_region_to_nca, reconstructed_nca_size},
    keys::{KeySet, sanitize_title_keys_file},
    ops::{
        container::{ContainerEntry, extract_entry, list_entries},
        native_fs,
        native_meta::{read_cnmt_from_nca_bytes, read_cnmt_from_nca_region},
        title_support::nacp_language_records,
    },
    process::run_tool,
};
use anyhow::{Context, Result, bail, ensure};
use std::{
    collections::HashSet,
    ffi::OsString,
    fs::{self, File},
    io::{BufReader, BufWriter, Write},
    path::{Path, PathBuf},
    sync::atomic::{AtomicBool, Ordering},
};

/// Only a small metadata NCA may be decoded in memory. This limit is
/// enforced using the validated NCZ section table *before* allocating.
const MAX_IN_MEMORY_CNMT_NCA: u64 = 64 * 1024 * 1024;

#[cfg(test)]
#[path = "cnmt_compressed_tests.rs"]
pub(crate) mod compressed_tests;

pub(crate) fn is_cnmt_container_entry(name: &str) -> bool {
    let name = name.to_ascii_lowercase();
    name.ends_with(".cnmt.nca") || name.ends_with(".cnmt.ncz")
}

/// The exposed CNMT NCA name is always the decompressed .nca name, even
/// when the archive contains a compressed ".cnmt.ncz" entry.
fn canonical_cnmt_nca_name(name: &str) -> Result<String> {
    ensure!(is_cnmt_container_entry(name), "Not a CNMT NCA/NCZ: {name}");
    if name.to_ascii_lowercase().ends_with(".ncz") {
        Ok(format!("{}.nca", &name[..name.len() - 4]))
    } else {
        Ok(name.to_owned())
    }
}

/// Native, allocation-bounded CNMT discovery from an NSP/NSZ/XCI/XCZ
/// container region. Compressed metadata is reconstructed in memory only;
/// neither the complete container nor a separate CNMT NCA is written.
pub(crate) fn read_cnmt_from_container_entry(
    container: &Path,
    entry: &ContainerEntry,
    keys: &KeySet,
    cancel: &AtomicBool,
) -> Result<CnmtInfo> {
    ensure!(!cancel.load(Ordering::Relaxed), "작업이 중단되었습니다");
    let name = canonical_cnmt_nca_name(&entry.name)?;
    let original_size = fs::metadata(container)?.len();
    ensure!(
        entry
            .offset
            .checked_add(entry.size)
            .is_some_and(|end| end <= original_size),
        "CNMT entry is outside the package bounds: {}",
        entry.name
    );
    let raw = if entry.name.to_ascii_lowercase().ends_with(".ncz") {
        let mut file = BufReader::with_capacity(1024 * 1024, File::open(container)?);
        let decoded_size = reconstructed_nca_size(&mut file, entry.offset, entry.size)?;
        ensure!(
            decoded_size <= MAX_IN_MEMORY_CNMT_NCA,
            "Compressed CNMT exceeds the 64 MiB in-memory limit: {}",
            entry.name
        );
        let mut decoded = Vec::with_capacity(usize::try_from(decoded_size)?);
        let written = decompress_ncz_region_to_nca(
            &mut file,
            entry.offset,
            entry.size,
            &mut decoded,
            cancel,
            |_, _| {},
        )?;
        ensure!(
            written == decoded_size && decoded.len() as u64 == decoded_size,
            "Compressed CNMT reconstruction length mismatch: {}",
            entry.name
        );
        read_cnmt_from_nca_bytes(&decoded, keys)?
    } else {
        read_cnmt_from_nca_region(container, entry.offset, entry.size, keys)?
    };
    ensure!(!cancel.load(Ordering::Relaxed), "작업이 중단되었습니다");
    parse_cnmt(&raw, name)
}

/// XCI/XCZ에서 secure 파티션을 우선 사용하되, 구형 병합 도구가 Update/DLC의
/// CNMT를 update/normal 파티션에 둔 경우에는 실제 게임 메타데이터만 추가로
/// 찾아낸다. 시스템 업데이트용 CNMT(ContentMetaType::Other)는 fallback에서
/// 제외하므로 일반 게임카드의 system/update 파티션이 섞이지 않는다.
pub fn discover_game_metadata(
    container: &Path,
    temp_dir: &Path,
    hactool: &Path,
    prod_keys: &Path,
    cancel: &AtomicBool,
) -> Result<(Vec<ContainerEntry>, Vec<CnmtInfo>, bool)> {
    let primary_entries = list_entries(container, true)?;
    let primary = extract_and_parse_cnmts(
        container,
        &primary_entries,
        &temp_dir.join("primary"),
        hactool,
        prod_keys,
        cancel,
    );

    let ext = container
        .extension()
        .and_then(|value| value.to_str())
        .unwrap_or("")
        .to_ascii_lowercase();
    if !matches!(ext.as_str(), "xci" | "xcz") {
        return Ok((primary_entries, primary?, false));
    }

    let primary_cnmts = primary.unwrap_or_default();
    let all_entries = list_entries(container, false)?;
    let primary_meta_names = primary_entries
        .iter()
        .filter(|entry| is_cnmt_container_entry(&entry.name))
        .filter_map(|entry| canonical_cnmt_nca_name(&entry.name).ok())
        .map(|name| name.to_ascii_lowercase())
        .collect::<HashSet<_>>();
    let has_extra_meta = all_entries.iter().any(|entry| {
        is_cnmt_container_entry(&entry.name)
            && canonical_cnmt_nca_name(&entry.name)
                .ok()
                .is_some_and(|name| !primary_meta_names.contains(&name.to_ascii_lowercase()))
    });
    if !has_extra_meta {
        if primary_cnmts.is_empty() {
            bail!("cnmt.nca를 찾거나 해석하지 못했습니다");
        }
        return Ok((primary_entries, primary_cnmts, false));
    }

    let all_cnmts = extract_and_parse_cnmts_best_effort(
        container,
        &all_entries,
        &temp_dir.join("all_partitions"),
        hactool,
        prod_keys,
        cancel,
    )?;
    let primary_game_bases = primary_cnmts
        .iter()
        .filter(|cnmt| {
            matches!(
                cnmt.meta_type,
                ContentMetaType::Base | ContentMetaType::Update | ContentMetaType::Dlc
            )
        })
        .filter_map(|cnmt| base_title_id(&cnmt.title_id).ok())
        .collect::<HashSet<_>>();
    let mut game_cnmts = all_cnmts
        .into_iter()
        .filter(|cnmt| {
            matches!(
                cnmt.meta_type,
                ContentMetaType::Base | ContentMetaType::Update | ContentMetaType::Dlc
            )
        })
        .filter(|cnmt| {
            primary_game_bases.is_empty()
                || base_title_id(&cnmt.title_id)
                    .ok()
                    .is_some_and(|base| primary_game_bases.contains(&base))
        })
        .collect::<Vec<_>>();
    game_cnmts = select_latest_by_title(&game_cnmts);

    let primary_game_count = primary_cnmts
        .iter()
        .filter(|cnmt| {
            matches!(
                cnmt.meta_type,
                ContentMetaType::Base | ContentMetaType::Update | ContentMetaType::Dlc
            )
        })
        .count();
    if game_cnmts.len() <= primary_game_count {
        if primary_cnmts.is_empty() {
            bail!("유효한 게임 콘텐츠 메타데이터를 찾지 못했습니다");
        }
        return Ok((primary_entries, primary_cnmts, false));
    }

    let selected_entries = select_entries_for_cnmts(&all_entries, &game_cnmts);
    Ok((selected_entries, game_cnmts, true))
}

pub fn select_entries_for_cnmts(
    entries: &[ContainerEntry],
    cnmts: &[CnmtInfo],
) -> Vec<ContainerEntry> {
    let mut names = HashSet::new();
    let mut title_prefixes = HashSet::new();
    for cnmt in cnmts {
        names.insert(cnmt.cnmt_nca_name.to_ascii_lowercase());
        if let Some(stem) = cnmt.cnmt_nca_name.to_ascii_lowercase().strip_suffix(".nca") {
            names.insert(format!("{stem}.ncz"));
        }
        title_prefixes.insert(cnmt.title_id.to_ascii_lowercase());
        for content in &cnmt.contents {
            let stem = content.nca_id.to_ascii_lowercase();
            names.insert(format!("{stem}.nca"));
            names.insert(format!("{stem}.ncz"));
        }
    }
    entries
        .iter()
        .filter(|entry| {
            let lower = entry.name.to_ascii_lowercase();
            names.contains(&lower)
                || ((lower.ends_with(".tik") || lower.ends_with(".cert"))
                    && title_prefixes
                        .iter()
                        .any(|prefix| lower.starts_with(prefix)))
        })
        .cloned()
        .collect()
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum ContentMetaType {
    Base,
    Update,
    Dlc,
    Other(u8),
}

impl ContentMetaType {
    pub fn from_byte(value: u8) -> Self {
        match value {
            0x80 => Self::Base,
            0x81 => Self::Update,
            0x82 => Self::Dlc,
            other => Self::Other(other),
        }
    }

    pub fn label(&self) -> &'static str {
        match self {
            Self::Base => "Base",
            Self::Update => "Update",
            Self::Dlc => "DLC",
            Self::Other(_) => "Unknown",
        }
    }
}

#[derive(Debug, Clone)]
pub struct CnmtContent {
    pub hash: [u8; 32],
    pub nca_id: String,
    pub size: u64,
    pub content_type: u8,
}

#[derive(Debug, Clone)]
pub struct CnmtInfo {
    pub cnmt_nca_name: String,
    pub title_id: String,
    pub version: u32,
    pub meta_type: ContentMetaType,
    pub required_system_version: u64,
    pub contents: Vec<CnmtContent>,
    pub raw: Vec<u8>,
}

#[derive(Debug, Clone, Default)]
pub struct NacpSummary {
    pub primary_title: String,
    pub primary_publisher: String,
    pub display_version: String,
    pub age_rating: String,
    pub build_kind: String,
    pub languages: Vec<String>,
    pub language_titles: Vec<String>,
    pub language_publishers: Vec<String>,
    pub icon_path: Option<PathBuf>,
}

impl CnmtInfo {
    pub fn required_nca_names(&self) -> Vec<String> {
        let mut out = Vec::with_capacity(self.contents.len() + 1);
        out.push(self.cnmt_nca_name.clone());
        out.extend(self.contents.iter().map(|c| format!("{}.nca", c.nca_id)));
        out
    }

    pub fn control_nca_name(&self) -> Option<String> {
        self.contents
            .iter()
            .find(|c| c.content_type == 3)
            .map(|c| format!("{}.nca", c.nca_id))
    }
}

pub fn base_title_id(title_id: &str) -> Result<String> {
    let value = u64::from_str_radix(title_id.trim(), 16).context("Title ID 형식 오류")?;
    Ok(format!("{:016X}", value & 0xffff_ffff_ffff_e000))
}

pub fn parse_cnmt(data: &[u8], cnmt_nca_name: impl Into<String>) -> Result<CnmtInfo> {
    if data.len() < 0x20 {
        bail!("CNMT가 너무 짧습니다");
    }
    let mut tid_bytes = [0u8; 8];
    tid_bytes.copy_from_slice(&data[0..8]);
    tid_bytes.reverse();
    let title_id = hex::encode_upper(tid_bytes);
    let version = u32::from_le_bytes(data[8..12].try_into().unwrap());
    let meta_type = ContentMetaType::from_byte(data[0x0c]);
    let required_system_version = if data.len() >= 0x30 {
        u64::from_le_bytes(data[0x28..0x30].try_into().unwrap())
    } else {
        0
    };
    let extended_header_size = u16::from_le_bytes(data[0x0e..0x10].try_into().unwrap()) as usize;
    let content_count = u16::from_le_bytes(data[0x10..0x12].try_into().unwrap()) as usize;
    let table = 0x20usize
        .checked_add(extended_header_size)
        .context("CNMT table 오버플로")?;
    let table_end = table
        .checked_add(
            content_count
                .checked_mul(0x38)
                .context("CNMT content 수 오버플로")?,
        )
        .context("CNMT content table 오버플로")?;
    if table_end > data.len() {
        bail!("CNMT content table이 잘렸습니다");
    }

    let mut contents = Vec::with_capacity(content_count);
    for i in 0..content_count {
        let row = table + i * 0x38;
        let mut hash = [0u8; 32];
        hash.copy_from_slice(&data[row..row + 0x20]);
        let nca_id = hex::encode(&data[row + 0x20..row + 0x30]);
        let mut size_bytes = [0u8; 8];
        size_bytes[..6].copy_from_slice(&data[row + 0x30..row + 0x36]);
        let size = u64::from_le_bytes(size_bytes);
        let content_type = data[row + 0x36];
        contents.push(CnmtContent {
            hash,
            nca_id,
            size,
            content_type,
        });
    }
    Ok(CnmtInfo {
        cnmt_nca_name: cnmt_nca_name.into(),
        title_id,
        version,
        meta_type,
        required_system_version,
        contents,
        raw: data.to_vec(),
    })
}

pub fn extract_and_parse_cnmts(
    container: &Path,
    entries: &[ContainerEntry],
    temp_dir: &Path,
    hactool: &Path,
    prod_keys: &Path,
    cancel: &AtomicBool,
) -> Result<Vec<CnmtInfo>> {
    fs::create_dir_all(temp_dir)?;
    let mut result = Vec::new();
    // Read metadata directly from the encrypted container whenever possible.
    // Unsupported layouts still use the proven hactool/LibHac fallback.
    let native_keys = KeySet::load_with_local_title_keys(prod_keys).ok();
    for entry in entries.iter().filter(|e| is_cnmt_container_entry(&e.name)) {
        if cancel.load(Ordering::Relaxed) {
            bail!("작업이 중단되었습니다");
        }
        if let Some(info) = native_keys
            .as_ref()
            .and_then(|keys| read_cnmt_from_container_entry(container, entry, keys, cancel).ok())
        {
            result.push(info);
            continue;
        }
        ensure!(!cancel.load(Ordering::Relaxed), "작업이 중단되었습니다");
        let nca_name = canonical_cnmt_nca_name(&entry.name)?;
        let nca_path = temp_dir.join(&nca_name);
        extract_metadata_nca(container, entry, &nca_path, cancel)?;
        let out_dir = temp_dir.join(format!("cnmt_{}", sanitize(&entry.name)));
        let _ = fs::remove_dir_all(&out_dir);
        fs::create_dir_all(&out_dir)?;
        let cnmt_path =
            extract_cnmt_payload(&nca_path, &nca_name, &out_dir, hactool, prod_keys, cancel)?;
        let raw = fs::read(&cnmt_path)?;
        result.push(parse_cnmt(&raw, nca_name)?);
    }
    if result.is_empty() {
        bail!("cnmt.nca를 찾거나 해석하지 못했습니다");
    }
    Ok(result)
}

fn extract_and_parse_cnmts_best_effort(
    container: &Path,
    entries: &[ContainerEntry],
    temp_dir: &Path,
    hactool: &Path,
    prod_keys: &Path,
    cancel: &AtomicBool,
) -> Result<Vec<CnmtInfo>> {
    fs::create_dir_all(temp_dir)?;
    let mut result = Vec::new();
    let native_keys = KeySet::load_with_local_title_keys(prod_keys).ok();
    for entry in entries
        .iter()
        .filter(|entry| is_cnmt_container_entry(&entry.name))
    {
        if cancel.load(Ordering::Relaxed) {
            bail!("작업이 중단되었습니다");
        }
        if let Some(info) = native_keys
            .as_ref()
            .and_then(|keys| read_cnmt_from_container_entry(container, entry, keys, cancel).ok())
        {
            result.push(info);
            continue;
        }
        ensure!(!cancel.load(Ordering::Relaxed), "작업이 중단되었습니다");
        let nca_path = temp_dir.join(format!("meta_{}", sanitize(&entry.name)));
        if extract_metadata_nca(container, entry, &nca_path, cancel).is_err() {
            continue;
        }
        let out_dir = temp_dir.join(format!("parsed_{}", sanitize(&entry.name)));
        let nca_name = canonical_cnmt_nca_name(&entry.name)?;
        if let Ok(info) =
            parse_cnmt_nca_file(&nca_path, &nca_name, &out_dir, hactool, prod_keys, cancel)
        {
            result.push(info);
        }
    }
    Ok(result)
}

/// External metadata-only fallback for unsupported encrypted sections.
/// The native compressed route above normally avoids scratch NCA entirely.
fn extract_metadata_nca(
    container: &Path,
    entry: &ContainerEntry,
    output: &Path,
    cancel: &AtomicBool,
) -> Result<()> {
    if entry.name.to_ascii_lowercase().ends_with(".ncz") {
        let mut reader = BufReader::with_capacity(1024 * 1024, File::open(container)?);
        let mut writer = BufWriter::with_capacity(1024 * 1024, File::create(output)?);
        decompress_ncz_region_to_nca(
            &mut reader,
            entry.offset,
            entry.size,
            &mut writer,
            cancel,
            |_, _| {},
        )?;
        writer.flush()?;
        Ok(())
    } else {
        extract_entry(container, entry, output, cancel)
    }
}

pub fn parse_cnmt_nca_file(
    nca_path: &Path,
    nca_name: &str,
    out_dir: &Path,
    hactool: &Path,
    prod_keys: &Path,
    cancel: &AtomicBool,
) -> Result<CnmtInfo> {
    // No temporary plaintext or external process for supported CNMT NCAs.
    if let Ok(keys) = KeySet::load_with_local_title_keys(prod_keys)
        && let Ok(raw) =
            read_cnmt_from_nca_region(nca_path, 0, fs::metadata(nca_path)?.len(), &keys)
        && let Ok(info) = parse_cnmt(&raw, nca_name.to_owned())
    {
        return Ok(info);
    }
    let _ = fs::remove_dir_all(out_dir);
    fs::create_dir_all(out_dir)?;
    let cnmt_path = extract_cnmt_payload(nca_path, nca_name, out_dir, hactool, prod_keys, cancel)?;
    let raw = fs::read(cnmt_path)?;
    parse_cnmt(&raw, nca_name.to_owned())
}

fn extract_cnmt_payload(
    nca_path: &Path,
    nca_name: &str,
    out_dir: &Path,
    hactool: &Path,
    prod_keys: &Path,
    cancel: &AtomicBool,
) -> Result<PathBuf> {
    let _ = fs::remove_dir_all(out_dir);
    fs::create_dir_all(out_dir)?;
    let args = vec![
        OsString::from("-k"),
        prod_keys.as_os_str().to_owned(),
        OsString::from("--disablekeywarns"),
        OsString::from(format!("--section0dir={}", out_dir.display())),
        nca_path.as_os_str().to_owned(),
    ];
    let tool = run_tool(hactool, args, out_dir.parent(), cancel)?;
    if tool.success()
        && let Some(path) = find_cnmt_payload(out_dir)
    {
        return Ok(path);
    }
    let mut detail = tool.combined();

    if let Some(parent) = hactool.parent() {
        let hactoolnet = parent.join("hactoolnet.exe");
        if hactoolnet.is_file() {
            let _ = fs::remove_dir_all(out_dir);
            fs::create_dir_all(out_dir)?;
            let args = vec![
                OsString::from("-k"),
                prod_keys.as_os_str().to_owned(),
                OsString::from("--disablekeywarns"),
                OsString::from("--section0dir"),
                out_dir.as_os_str().to_owned(),
                nca_path.as_os_str().to_owned(),
            ];
            let net = run_tool(&hactoolnet, args, out_dir.parent(), cancel)?;
            if net.success()
                && let Some(path) = find_cnmt_payload(out_dir)
            {
                return Ok(path);
            }
            detail = net.combined();
        }
    }

    bail!("CNMT NCA 복호화 실패({nca_name}): {}", first_line(&detail))
}

fn find_cnmt_payload(out_dir: &Path) -> Option<PathBuf> {
    walkdir::WalkDir::new(out_dir)
        .into_iter()
        .filter_map(|entry| entry.ok())
        .find(|entry| {
            entry.file_type().is_file()
                && entry
                    .path()
                    .extension()
                    .and_then(|value| value.to_str())
                    .is_some_and(|value| value.eq_ignore_ascii_case("cnmt"))
        })
        .map(|entry| entry.path().to_path_buf())
}

pub fn get_nacp_summary_from_control_nca(
    control_nca: &Path,
    hactool: &Path,
    prod_keys: &Path,
    temp_dir: &Path,
    cancel: &AtomicBool,
) -> Result<Option<NacpSummary>> {
    let romfs = temp_dir.join("control_romfs");
    if extract_control_romfs(control_nca, &romfs, hactool, prod_keys, cancel).is_err() {
        return Ok(None);
    }
    let nacp = walkdir::WalkDir::new(&romfs)
        .into_iter()
        .filter_map(|e| e.ok())
        .find(|e| {
            e.file_type().is_file()
                && e.path()
                    .file_name()
                    .and_then(|s| s.to_str())
                    .map(|s| s.eq_ignore_ascii_case("control.nacp"))
                    .unwrap_or(false)
        })
        .map(|e| e.path().to_path_buf());
    let Some(nacp) = nacp else {
        return Ok(None);
    };
    let data = fs::read(nacp)?;
    Ok(Some(parse_nacp_summary(&data, &romfs, temp_dir)))
}

pub fn extract_control_romfs(
    control_nca: &Path,
    romfs: &Path,
    hactool: &Path,
    prod_keys: &Path,
    cancel: &AtomicBool,
) -> Result<()> {
    let _ = fs::remove_dir_all(romfs);
    fs::create_dir_all(romfs)?;
    if let Ok(keys) = KeySet::load_with_local_title_keys(prod_keys) {
        let parent = romfs.parent().unwrap_or_else(|| Path::new("."));
        let stage = tempfile::Builder::new()
            .prefix("nsrp_native_control_")
            .tempdir_in(parent)?;
        let staged_romfs = stage.path().join("romfs");
        if native_fs::unpack_nca(control_nca, stage.path(), &keys, cancel).is_ok()
            && contains_control_nacp(&staged_romfs)
        {
            fs::remove_dir_all(romfs)?;
            fs::rename(staged_romfs, romfs)?;
            return Ok(());
        }
    }
    // BKTR and unsupported layouts continue through hactool/LibHac.
    let args = vec![
        OsString::from("-k"),
        prod_keys.as_os_str().to_owned(),
        OsString::from("-t"),
        OsString::from("nca"),
        OsString::from("--disablekeywarns"),
        OsString::from(format!("--romfsdir={}", romfs.display())),
        control_nca.as_os_str().to_owned(),
    ];
    let tool = run_tool(hactool, args, control_nca.parent(), cancel)?;
    if tool.success() && contains_control_nacp(romfs) {
        return Ok(());
    }
    let mut detail = tool.combined();

    if let Some(parent) = hactool.parent() {
        let hactoolnet = parent.join("hactoolnet.exe");
        if hactoolnet.is_file() {
            let _ = fs::remove_dir_all(romfs);
            fs::create_dir_all(romfs)?;
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
            // External helpers require normalized title-key syntax. Never
            // rewrite the user's database just to read a Control NCA.
            let key_stage = tempfile::Builder::new()
                .prefix("nsrp_external_title_keys_")
                .tempdir_in(romfs.parent().unwrap_or_else(|| Path::new(".")))?;
            if title_keys.is_file() {
                let staged = key_stage.path().join("title.keys");
                fs::copy(&title_keys, &staged)?;
                sanitize_title_keys_file(&staged)?;
                args.extend([OsString::from("--titlekeys"), staged.as_os_str().to_owned()]);
            }
            args.extend([
                OsString::from("--romfsdir"),
                romfs.as_os_str().to_owned(),
                control_nca.as_os_str().to_owned(),
            ]);
            let net = run_tool(&hactoolnet, args, control_nca.parent(), cancel)?;
            if net.success() && contains_control_nacp(romfs) {
                return Ok(());
            }
            detail = net.combined();
        }
    }
    bail!("Control RomFS 추출 실패: {}", first_line(&detail))
}

fn contains_control_nacp(romfs: &Path) -> bool {
    walkdir::WalkDir::new(romfs)
        .into_iter()
        .filter_map(|entry| entry.ok())
        .any(|entry| {
            entry.file_type().is_file()
                && entry
                    .file_name()
                    .to_str()
                    .is_some_and(|name| name.eq_ignore_ascii_case("control.nacp"))
        })
}

pub fn get_title_from_control_nca(
    control_nca: &Path,
    hactool: &Path,
    prod_keys: &Path,
    temp_dir: &Path,
    cancel: &AtomicBool,
) -> Result<Option<String>> {
    Ok(
        get_nacp_summary_from_control_nca(control_nca, hactool, prod_keys, temp_dir, cancel)?
            .map(|summary| summary.primary_title)
            .filter(|title| !title.is_empty()),
    )
}

pub fn parse_nacp_title(data: &[u8]) -> Option<String> {
    // Priority: Korean -> American/British English -> Japanese -> first valid.
    let records = nacp_language_records(data).ok()?;
    nacp_priority_indices(records.len())
        .into_iter()
        .filter_map(|index| records.get(index))
        .map(|record| record.0.clone())
        .find(|value| is_reasonable_title(value))
}

fn parse_nacp_summary(data: &[u8], romfs: &Path, temp_dir: &Path) -> NacpSummary {
    const LANGUAGES: [&str; 18] = [
        "미국 영어",
        "영국 영어",
        "일본어",
        "프랑스어",
        "독일어",
        "라틴 아메리카 스페인어",
        "스페인어",
        "이탈리아어",
        "네덜란드어",
        "캐나다 프랑스어",
        "포르투갈어",
        "러시아어",
        "한국어",
        "중국어 (번체)",
        "중국어 (간체)",
        "브라질 포르투갈어",
        "폴란드어",
        "태국어",
    ];
    let records = nacp_language_records(data).unwrap_or_default();
    let titles = records
        .iter()
        .map(|record| record.0.clone())
        .collect::<Vec<_>>();
    let publishers = records
        .iter()
        .map(|record| record.1.clone())
        .collect::<Vec<_>>();
    let priorities = nacp_priority_indices(records.len());
    let selected = priorities
        .iter()
        .copied()
        .find(|&index| is_reasonable_title(&titles[index]));
    let primary_title = selected
        .map(|index| titles[index].clone())
        .unwrap_or_default();
    let primary_publisher = selected
        .map(|index| publishers[index].clone())
        .unwrap_or_default();
    let language_indices = priorities
        .iter()
        .copied()
        .filter(|&index| is_reasonable_title(&titles[index]))
        .collect::<Vec<_>>();
    let languages = language_indices
        .iter()
        .copied()
        .map(|index| {
            LANGUAGES
                .get(index)
                .map(|value| (*value).to_owned())
                .unwrap_or_else(|| format!("언어 슬롯 {index}"))
        })
        .collect::<Vec<_>>();
    let language_titles = language_indices
        .iter()
        .copied()
        .map(|index| titles[index].clone())
        .collect::<Vec<_>>();
    let language_publishers = language_indices
        .iter()
        .copied()
        .map(|index| publishers[index].clone())
        .collect::<Vec<_>>();
    let display_version = if data.len() >= 0x3070 {
        nacp_string(&data[0x3060..0x3070])
    } else {
        String::new()
    };

    let mut ratings = Vec::new();
    if data.len() >= 0x3060 {
        let cero = data[0x3040];
        if cero < 0x80 {
            let label = match cero {
                0 => "A".to_owned(),
                12 => "B".to_owned(),
                15 => "C".to_owned(),
                17 => "D".to_owned(),
                18 => "Z".to_owned(),
                _ => cero.to_string(),
            };
            ratings.push(format!("CERO {label}"));
        }
        let esrb = data[0x3043];
        if esrb < 0x80 {
            let label = match esrb {
                0 => "EC".to_owned(),
                3 => "E".to_owned(),
                6 => "E10+".to_owned(),
                10 | 13 => "T".to_owned(),
                17 => "M".to_owned(),
                18 => "AO".to_owned(),
                _ => esrb.to_string(),
            };
            ratings.push(format!("ESRB {label}"));
        }
        let pegi = data[0x3046];
        if pegi < 0x80 {
            ratings.push(format!("PEGI {pegi}"));
        }
        let grac = data[0x304d];
        if grac < 0x80 {
            ratings.insert(0, format!("GRAC {grac}"));
        }
    }
    let age_rating = ratings.join(" · ");

    let attribute_flag = if data.len() >= 0x302c {
        u32::from_le_bytes(data[0x3028..0x302c].try_into().unwrap())
    } else {
        0
    };
    let mut kinds = Vec::new();
    if attribute_flag & 0x1 != 0 {
        kinds.push("체험판");
    }
    if attribute_flag & 0x2 != 0 {
        kinds.push("키오스크 빌드");
    }
    let build_kind = if kinds.is_empty() {
        "정식판".to_owned()
    } else {
        kinds.join(" / ")
    };

    let icon_path = walkdir::WalkDir::new(romfs)
        .max_depth(2)
        .into_iter()
        .filter_map(|entry| entry.ok())
        .find(|entry| {
            let name = entry.file_name().to_string_lossy().to_ascii_lowercase();
            entry.file_type().is_file() && name.starts_with("icon_") && name.ends_with(".dat")
        })
        .and_then(|entry| {
            let target = temp_dir.join("analyze_icon.jpg");
            fs::copy(entry.path(), &target).ok().map(|_| target)
        });

    NacpSummary {
        primary_title,
        primary_publisher,
        display_version,
        age_rating,
        build_kind,
        languages,
        language_titles,
        language_publishers,
        icon_path,
    }
}

fn nacp_priority_indices(count: usize) -> Vec<usize> {
    let mut priorities = Vec::with_capacity(count);
    for index in [12usize, 0, 1, 2] {
        if index < count && !priorities.contains(&index) {
            priorities.push(index);
        }
    }
    for index in 0..count {
        if !priorities.contains(&index) {
            priorities.push(index);
        }
    }
    priorities
}

fn nacp_string(raw: &[u8]) -> String {
    let end = raw.iter().position(|&byte| byte == 0).unwrap_or(raw.len());
    String::from_utf8_lossy(&raw[..end]).trim().to_owned()
}

fn is_reasonable_title(value: &str) -> bool {
    let value = value.trim();
    if value.is_empty() || value.len() > 180 {
        return false;
    }
    !value.chars().any(|c| c.is_control() && c != '\t')
}

fn sanitize(value: &str) -> String {
    value
        .chars()
        .map(|c| if c.is_ascii_alphanumeric() { c } else { '_' })
        .collect()
}

fn first_line(value: &str) -> &str {
    value
        .lines()
        .find(|s| !s.trim().is_empty())
        .unwrap_or("알 수 없는 오류")
}

pub fn resolve_content_entry<'a>(
    entries: &'a [ContainerEntry],
    nca_name: &str,
) -> Option<&'a ContainerEntry> {
    let stem = nca_name.strip_suffix(".nca").unwrap_or(nca_name);
    let ncz = format!("{stem}.ncz");
    entries
        .iter()
        .find(|e| e.name.eq_ignore_ascii_case(nca_name) || e.name.eq_ignore_ascii_case(&ncz))
}

pub fn select_latest_by_title(cnmts: &[CnmtInfo]) -> Vec<CnmtInfo> {
    let mut map = std::collections::BTreeMap::<String, CnmtInfo>::new();
    for info in cnmts {
        match map.get(&info.title_id) {
            Some(old) if old.version >= info.version => {}
            _ => {
                map.insert(info.title_id.clone(), info.clone());
            }
        }
    }
    map.into_values().collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_cnmt_content_table() -> Result<()> {
        let mut data = vec![0u8; 0x20 + 0x38 * 2];
        data[0..8].copy_from_slice(&0x0100_1234_5678_0000u64.to_le_bytes());
        data[8..12].copy_from_slice(&65536u32.to_le_bytes());
        data[0x0c] = 0x80;
        data[0x10..0x12].copy_from_slice(&2u16.to_le_bytes());
        data[0x20 + 0x20..0x20 + 0x30].copy_from_slice(&[0x11; 16]);
        data[0x20 + 0x30..0x20 + 0x36].copy_from_slice(&12345u64.to_le_bytes()[..6]);
        data[0x20 + 0x36] = 3;
        let info = parse_cnmt(&data, "meta.cnmt.nca")?;
        assert_eq!(info.title_id, "0100123456780000");
        assert_eq!(info.version, 65536);
        assert_eq!(info.meta_type, ContentMetaType::Base);
        assert_eq!(info.contents.len(), 2);
        assert_eq!(info.contents[0].content_type, 3);
        Ok(())
    }

    #[test]
    fn legacy_partition_selection_keeps_only_game_content() {
        let base = CnmtInfo {
            cnmt_nca_name: "base.cnmt.nca".to_owned(),
            title_id: "0100123456780000".to_owned(),
            version: 0,
            meta_type: ContentMetaType::Base,
            required_system_version: 0,
            contents: vec![CnmtContent {
                hash: [0x11; 32],
                nca_id: "11111111111111111111111111111111".to_owned(),
                size: 10,
                content_type: 1,
            }],
            raw: Vec::new(),
        };
        let update = CnmtInfo {
            cnmt_nca_name: "update.cnmt.nca".to_owned(),
            title_id: "0100123456780800".to_owned(),
            version: 65536,
            meta_type: ContentMetaType::Update,
            required_system_version: 0,
            contents: vec![CnmtContent {
                hash: [0x22; 32],
                nca_id: "22222222222222222222222222222222".to_owned(),
                size: 20,
                content_type: 1,
            }],
            raw: Vec::new(),
        };
        let entries = vec![
            ContainerEntry {
                name: "base.cnmt.nca".to_owned(),
                offset: 0,
                size: 1,
            },
            ContainerEntry {
                name: "11111111111111111111111111111111.nca".to_owned(),
                offset: 1,
                size: 10,
            },
            ContainerEntry {
                name: "update.cnmt.nca".to_owned(),
                offset: 11,
                size: 1,
            },
            ContainerEntry {
                name: "22222222222222222222222222222222.ncz".to_owned(),
                offset: 12,
                size: 20,
            },
            ContainerEntry {
                name: "01001234567808000000000000000001.tik".to_owned(),
                offset: 32,
                size: 0x200,
            },
            ContainerEntry {
                name: "system.cnmt.nca".to_owned(),
                offset: 0x300,
                size: 1,
            },
            ContainerEntry {
                name: "deadbeefdeadbeefdeadbeefdeadbeef.nca".to_owned(),
                offset: 0x301,
                size: 1,
            },
        ];
        let selected = select_entries_for_cnmts(&entries, &[base, update]);
        let names = selected
            .iter()
            .map(|entry| entry.name.as_str())
            .collect::<Vec<_>>();
        assert!(names.contains(&"base.cnmt.nca"));
        assert!(names.contains(&"update.cnmt.nca"));
        assert!(names.contains(&"11111111111111111111111111111111.nca"));
        assert!(names.contains(&"22222222222222222222222222222222.ncz"));
        assert!(names.contains(&"01001234567808000000000000000001.tik"));
        assert!(!names.contains(&"system.cnmt.nca"));
        assert!(!names.contains(&"deadbeefdeadbeefdeadbeefdeadbeef.nca"));
    }

    #[test]
    fn nacp_prefers_korean() -> Result<()> {
        let mut data = vec![0u8; 0x300 * 16];
        data[..7].copy_from_slice(b"English");
        data[0x200..0x209].copy_from_slice(b"Publisher");
        let ko = "한국어 게임".as_bytes();
        let ko_publisher = "한국 제작사".as_bytes();
        let off = 12 * 0x300;
        data[off..off + ko.len()].copy_from_slice(ko);
        data[off + 0x200..off + 0x200 + ko_publisher.len()].copy_from_slice(ko_publisher);
        assert_eq!(parse_nacp_title(&data).as_deref(), Some("한국어 게임"));
        let temp = tempfile::tempdir()?;
        let summary = parse_nacp_summary(&data, temp.path(), temp.path());
        assert_eq!(
            summary.languages.first().map(String::as_str),
            Some("한국어")
        );
        assert_eq!(
            summary.language_titles.first().map(String::as_str),
            Some("한국어 게임")
        );
        assert_eq!(
            summary.language_publishers.first().map(String::as_str),
            Some("한국 제작사")
        );
        assert_eq!(
            summary.languages.get(1).map(String::as_str),
            Some("미국 영어")
        );
        assert_eq!(
            summary.language_titles.get(1).map(String::as_str),
            Some("English")
        );
        Ok(())
    }
}
