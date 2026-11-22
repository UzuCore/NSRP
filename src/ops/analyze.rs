use crate::{
    formats::ncz_stream::decompress_ncz_region_to_nca,
    ops::{
        cnmt::{
            CnmtInfo, ContentMetaType, NacpSummary, discover_game_metadata,
            get_nacp_summary_from_control_nca, resolve_content_entry,
        },
        container::{ContainerEntry, list_entries},
    },
};
use anyhow::{Result, bail};
use sha2::{Digest, Sha256};
use std::{
    fs::{self, File},
    io::{BufReader, BufWriter, Read, Seek, SeekFrom, Write},
    path::Path,
    sync::atomic::{AtomicBool, Ordering},
};

#[derive(Debug, Clone)]
pub struct ContentVerification {
    pub name: String,
    pub present: bool,
    pub size_ok: Option<bool>,
    pub hash_ok: Option<bool>,
}

#[derive(Debug, Clone)]
pub struct AnalysisReport {
    pub package_type: String,
    pub ncz_mode: String,
    pub input_size: u64,
    pub file_count: usize,
    pub nca_count: usize,
    pub ncz_count: usize,
    pub ticket_count: usize,
    pub title: Option<String>,
    pub nacp: Option<NacpSummary>,
    pub entries: Vec<ContainerEntry>,
    pub cnmts: Vec<CnmtInfo>,
    pub verification: Vec<ContentVerification>,
}

impl AnalysisReport {
    pub fn to_text(&self) -> String {
        let mut lines = vec![
            format!("형식: {}", self.package_type),
            format!("크기: {} bytes", self.input_size),
            format!(
                "엔트리: {} (NCA {}, NCZ {}, ticket {})",
                self.file_count, self.nca_count, self.ncz_count, self.ticket_count
            ),
        ];
        if let Some(title) = &self.title {
            lines.push(format!("게임명: {title}"));
        }
        lines.push(format!("CNMT: {}개", self.cnmts.len()));
        for info in &self.cnmts {
            lines.push(format!(
                "  {} v{} {} ({})",
                info.title_id,
                info.version,
                info.meta_type.label(),
                info.cnmt_nca_name
            ));
        }
        let missing = self.verification.iter().filter(|v| !v.present).count();
        let bad_size = self
            .verification
            .iter()
            .filter(|v| v.size_ok == Some(false))
            .count();
        let bad_hash = self
            .verification
            .iter()
            .filter(|v| v.hash_ok == Some(false))
            .count();
        lines.push(format!(
            "검증: 누락 {missing}, 크기 불일치 {bad_size}, 해시 불일치 {bad_hash}"
        ));
        lines.join("\n")
    }
}

pub fn analyze(
    input: &Path,
    temp_dir: &Path,
    hactool: &Path,
    prod_keys: &Path,
    cancel: &AtomicBool,
    progress: &mut dyn FnMut(f32),
) -> Result<AnalysisReport> {
    let (entries, cnmts, _) = discover_game_metadata(
        input,
        &temp_dir.join("metadata"),
        hactool,
        prod_keys,
        cancel,
    )?;
    if entries.is_empty() {
        bail!("컨테이너 엔트리가 없습니다");
    }
    let package_type = input
        .extension()
        .and_then(|s| s.to_str())
        .unwrap_or("")
        .to_ascii_uppercase();
    let input_size = fs::metadata(input)?.len();
    let nca_count = entries
        .iter()
        .filter(|e| e.name.to_ascii_lowercase().ends_with(".nca"))
        .count();
    let ncz_count = entries
        .iter()
        .filter(|e| e.name.to_ascii_lowercase().ends_with(".ncz"))
        .count();
    let ticket_count = entries
        .iter()
        .filter(|e| e.name.to_ascii_lowercase().ends_with(".tik"))
        .count();
    let ncz_mode = detect_ncz_mode(input, &entries)?;
    progress(0.15);
    progress(0.45);

    let mut title = None;
    let mut nacp = None;
    if let Some(base) = cnmts
        .iter()
        .filter(|c| c.meta_type == ContentMetaType::Base)
        .max_by_key(|c| c.version)
        && let Some(control_name) = base.control_nca_name()
        && let Some(entry) = resolve_content_entry(&entries, &control_name)
    {
        let control_path = temp_dir.join("control.nca");
        materialize_nca(input, entry, &control_path, cancel)?;
        nacp = get_nacp_summary_from_control_nca(
            &control_path,
            hactool,
            prod_keys,
            &temp_dir.join("nacp"),
            cancel,
        )
        .unwrap_or(None);
        title = nacp
            .as_ref()
            .map(|summary| summary.primary_title.clone())
            .filter(|value| !value.is_empty());
    }
    progress(0.60);

    let total_checks = cnmts.iter().map(|c| c.contents.len()).sum::<usize>().max(1);
    let mut checked = 0usize;
    let mut verification = Vec::new();
    let mut reader = BufReader::with_capacity(8 * 1024 * 1024, File::open(input)?);
    for info in &cnmts {
        for content in &info.contents {
            if cancel.load(Ordering::Relaxed) {
                bail!("작업이 중단되었습니다");
            }
            let expected_name = format!("{}.nca", content.nca_id);
            let entry = resolve_content_entry(&entries, &expected_name);
            let mut item = ContentVerification {
                name: expected_name,
                present: entry.is_some(),
                size_ok: None,
                hash_ok: None,
            };
            if let Some(entry) = entry
                && entry.name.to_ascii_lowercase().ends_with(".nca")
            {
                item.size_ok = Some(entry.size == content.size);
                if entry.size == content.size {
                    item.hash_ok = Some(
                        hash_region(&mut reader, entry.offset, entry.size, cancel)? == content.hash,
                    );
                }
            }
            verification.push(item);
            checked += 1;
            progress(0.60 + 0.40 * checked as f32 / total_checks as f32);
        }
    }
    progress(1.0);
    Ok(AnalysisReport {
        package_type,
        ncz_mode,
        input_size,
        file_count: entries.len(),
        nca_count,
        ncz_count,
        ticket_count,
        title,
        nacp,
        entries,
        cnmts,
        verification,
    })
}

pub fn analyze_metadata(
    input: &Path,
    temp_dir: &Path,
    hactool: &Path,
    prod_keys: &Path,
    cancel: &AtomicBool,
    progress: &mut dyn FnMut(f32),
) -> Result<AnalysisReport> {
    let (entries, cnmts, _) = discover_game_metadata(
        input,
        &temp_dir.join("metadata"),
        hactool,
        prod_keys,
        cancel,
    )?;
    if entries.is_empty() {
        bail!("컨테이너 엔트리가 없습니다");
    }
    let package_type = input
        .extension()
        .and_then(|s| s.to_str())
        .unwrap_or("")
        .to_ascii_uppercase();
    let input_size = fs::metadata(input)?.len();
    let nca_count = entries
        .iter()
        .filter(|entry| entry.name.to_ascii_lowercase().ends_with(".nca"))
        .count();
    let ncz_count = entries
        .iter()
        .filter(|entry| entry.name.to_ascii_lowercase().ends_with(".ncz"))
        .count();
    let ticket_count = entries
        .iter()
        .filter(|entry| entry.name.to_ascii_lowercase().ends_with(".tik"))
        .count();
    let ncz_mode = detect_ncz_mode(input, &entries)?;
    progress(0.15);
    progress(0.55);

    let mut title = None;
    let mut nacp = None;
    if let Some(base) = cnmts
        .iter()
        .filter(|cnmt| cnmt.meta_type == ContentMetaType::Base)
        .max_by_key(|cnmt| cnmt.version)
        && let Some(control_name) = base.control_nca_name()
        && let Some(entry) = resolve_content_entry(&entries, &control_name)
    {
        let control_path = temp_dir.join("control.nca");
        materialize_nca(input, entry, &control_path, cancel)?;
        nacp = get_nacp_summary_from_control_nca(
            &control_path,
            hactool,
            prod_keys,
            &temp_dir.join("nacp"),
            cancel,
        )
        .unwrap_or(None);
        title = nacp
            .as_ref()
            .map(|summary| summary.primary_title.clone())
            .filter(|value| !value.is_empty());
    }
    progress(1.0);
    Ok(AnalysisReport {
        package_type,
        ncz_mode,
        input_size,
        file_count: entries.len(),
        nca_count,
        ncz_count,
        ticket_count,
        title,
        nacp,
        entries,
        cnmts,
        verification: Vec::new(),
    })
}

pub fn verify_headers(
    input: &Path,
    base_count: usize,
    cancel: &AtomicBool,
    log: &mut dyn FnMut(String),
) -> Result<()> {
    if !input.is_file() {
        bail!("원본 파일이 사라졌습니다");
    }
    let file_size = fs::metadata(input)?.len();
    // 헤더 검사는 컨테이너 자체의 무결성을 보는 기능이므로 XCI/XCZ의
    // system/update/normal 파티션까지 포함해 전체 엔트리를 검사한다.
    let entries = list_entries(input, false)?;
    log(format!(
        "  파일 크기: {} ({} bytes)",
        human_size(file_size),
        grouped_number(file_size)
    ));

    if entries.is_empty() {
        log("  [경고] 분석 결과에 파일 목록이 없습니다".to_owned());
    }
    let max_end = entries
        .iter()
        .map(|entry| entry.offset.saturating_add(entry.size))
        .max()
        .unwrap_or(0);
    if max_end > file_size {
        log(format!(
            "  [오류] 잘림 감지: 헤더가 가리키는 끝({}) > 실제 파일 크기",
            grouped_number(max_end)
        ));
    } else {
        log(format!(
            "  ✓ 컨테이너 구조: 정상 (내부 파일 {}개)",
            entries.len()
        ));
    }

    let has_tik = entries
        .iter()
        .any(|entry| entry.name.to_ascii_lowercase().ends_with(".tik"));
    let has_cert = entries
        .iter()
        .any(|entry| entry.name.to_ascii_lowercase().ends_with(".cert"));
    let nca_entries = entries
        .iter()
        .filter(|entry| entry.name.to_ascii_lowercase().ends_with(".nca"))
        .collect::<Vec<_>>();
    let ncz_count = entries
        .iter()
        .filter(|entry| entry.name.to_ascii_lowercase().ends_with(".ncz"))
        .count();

    if nca_entries.is_empty() && ncz_count == 0 {
        log("  [경고] NCA/NCZ 파일이 하나도 없습니다".to_owned());
    }
    if has_tik {
        log(format!(
            "  · 티켓: 있음{}",
            if has_cert { "" } else { " (cert 없음)" }
        ));
    } else {
        log("  · 티켓 없음 (티켓리스 빌드 가능성)".to_owned());
    }
    if ncz_count > 0 {
        log(format!(
            "  · 압축 NCA(.ncz): {ncz_count}개 — 해시 검증은 풀 디컴프레션 필요(생략)"
        ));
    }

    let mut bad_count = 0usize;
    let mut decrypted_count = 0usize;
    let mut reader = BufReader::with_capacity(1024 * 1024, File::open(input)?);
    let mut header = [0u8; 0x400];
    for entry in &nca_entries {
        if cancel.load(Ordering::Relaxed) {
            bail!("작업이 중단되었습니다");
        }
        if entry.size < 0x400 {
            log(format!(
                "  [오류] {}: 크기가 너무 작음 ({} bytes)",
                entry.name, entry.size
            ));
            bad_count += 1;
            continue;
        }
        reader.seek(SeekFrom::Start(entry.offset))?;
        reader.read_exact(&mut header)?;
        if matches!(&header[0x200..0x204], b"NCA0" | b"NCA1" | b"NCA2" | b"NCA3") {
            decrypted_count += 1;
        }
    }

    if !nca_entries.is_empty() {
        if bad_count == 0 {
            log(format!(
                "  ✓ NCA 헤더 {}개: 정상 크기/오프셋",
                nca_entries.len()
            ));
        } else {
            log(format!(
                "  [오류] NCA 헤더 {}개 중 {bad_count}개 손상",
                nca_entries.len()
            ));
        }
        if decrypted_count > 0 {
            log(format!(
                "  [경고] 복호화된 NCA {decrypted_count}개 감지 (원본 해시 검증 불가)"
            ));
        }
    }

    log("─── 헤더 검사 결과 ───".to_owned());
    if base_count >= 2 {
        log(format!("  · 멀티 패키지 (본편 {base_count}개)"));
    }
    if bad_count > 0 {
        log("  [오류] 결과: 손상 (NCA 헤더 이상)".to_owned());
    } else if max_end > file_size {
        log("  [오류] 결과: 구조 손상 (파일 잘림)".to_owned());
    } else if decrypted_count > 0 && !has_tik {
        log("  [경고] 결과: 변형됨 (복호화 + 티켓리스), 구조는 정상".to_owned());
    } else if decrypted_count > 0 {
        log("  [경고] 결과: 변형됨 (복호화), 구조는 정상".to_owned());
    } else if !has_tik && !nca_entries.is_empty() {
        log("  ✓ 결과: 정상 (티켓리스 빌드)".to_owned());
    } else {
        log("  ✓ 결과: 정상".to_owned());
    }
    Ok(())
}

fn detect_ncz_mode(input: &Path, entries: &[ContainerEntry]) -> Result<String> {
    let compressed_family = input
        .extension()
        .and_then(|value| value.to_str())
        .is_some_and(|value| matches!(value.to_ascii_lowercase().as_str(), "nsz" | "xcz"));
    if !compressed_family {
        return Ok(String::new());
    }

    const MAGIC_OFFSET: u64 = 0x4000;
    const SCAN_LIMIT: u64 = 0x10000;
    let candidates = entries
        .iter()
        .filter(|entry| {
            entry.name.to_ascii_lowercase().ends_with(".ncz") && entry.size > MAGIC_OFFSET + 8
        })
        .take(3)
        .collect::<Vec<_>>();
    if candidates.is_empty() {
        return Ok("알 수 없음".to_owned());
    }

    let mut reader = BufReader::with_capacity(128 * 1024, File::open(input)?);
    let mut block_votes = 0usize;
    let mut stream_votes = 0usize;
    for entry in candidates {
        reader.seek(SeekFrom::Start(entry.offset + MAGIC_OFFSET))?;
        let scan_size = (entry.size - MAGIC_OFFSET).min(SCAN_LIMIT) as usize;
        let mut data = vec![0u8; scan_size];
        reader.read_exact(&mut data)?;
        if data.get(..8) != Some(b"NCZSECTN") {
            continue;
        }
        if data.windows(8).any(|window| window == b"NCZBLOCK") {
            block_votes += 1;
        } else {
            stream_votes += 1;
        }
    }

    Ok(match (block_votes, stream_votes) {
        (0, 0) => "알 수 없음",
        (_, 0) => "블록",
        (0, _) => "스트리밍",
        _ => "혼합 (블록+스트리밍)",
    }
    .to_owned())
}

fn human_size(size: u64) -> String {
    if size >= 1024 * 1024 * 1024 {
        format!("{:.2} GB", size as f64 / (1024.0 * 1024.0 * 1024.0))
    } else if size >= 1024 * 1024 {
        format!("{:.2} MB", size as f64 / (1024.0 * 1024.0))
    } else if size >= 1024 {
        format!("{:.2} KB", size as f64 / 1024.0)
    } else {
        format!("{size} B")
    }
}

fn grouped_number(value: u64) -> String {
    let raw = value.to_string();
    let mut output = String::with_capacity(raw.len() + raw.len() / 3);
    let first = raw.len() % 3;
    if first > 0 {
        output.push_str(&raw[..first]);
    }
    for chunk in raw.as_bytes()[first..].chunks(3) {
        if !output.is_empty() {
            output.push(',');
        }
        output.push_str(std::str::from_utf8(chunk).unwrap_or_default());
    }
    output
}

fn materialize_nca(
    input: &Path,
    entry: &ContainerEntry,
    output: &Path,
    cancel: &AtomicBool,
) -> Result<()> {
    let mut reader = BufReader::with_capacity(8 * 1024 * 1024, File::open(input)?);
    if entry.name.to_ascii_lowercase().ends_with(".ncz") {
        let mut out = BufWriter::with_capacity(8 * 1024 * 1024, File::create(output)?);
        decompress_ncz_region_to_nca(
            &mut reader,
            entry.offset,
            entry.size,
            &mut out,
            cancel,
            |_, _| {},
        )?;
        out.flush()?;
    } else {
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
    }
    Ok(())
}

fn hash_region<R: Read + Seek>(
    reader: &mut R,
    offset: u64,
    size: u64,
    cancel: &AtomicBool,
) -> Result<[u8; 32]> {
    reader.seek(SeekFrom::Start(offset))?;
    let mut hash = Sha256::new();
    let mut remaining = size;
    let mut buf = vec![0u8; 4 * 1024 * 1024];
    while remaining > 0 {
        if cancel.load(Ordering::Relaxed) {
            bail!("작업이 중단되었습니다");
        }
        let take = remaining.min(buf.len() as u64) as usize;
        reader.read_exact(&mut buf[..take])?;
        hash.update(&buf[..take]);
        remaining -= take as u64;
    }
    let digest = hash.finalize().into();
    Ok(digest)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ncz_entry(name: &str, offset: u64, size: u64) -> ContainerEntry {
        ContainerEntry {
            name: name.to_owned(),
            offset,
            size,
        }
    }

    #[test]
    fn detects_stream_block_and_mixed_ncz_modes() -> Result<()> {
        let temp = tempfile::tempdir()?;
        let path = temp.path().join("sample.nsz");
        let entry_size = 0x5000u64;
        let second_offset = 0x6000u64;
        let mut data = vec![0u8; (second_offset + entry_size) as usize];

        data[0x4000..0x4008].copy_from_slice(b"NCZSECTN");
        fs::write(&path, &data)?;
        assert_eq!(
            detect_ncz_mode(&path, &[ncz_entry("a.ncz", 0, entry_size)])?,
            "스트리밍"
        );

        data[0x4080..0x4088].copy_from_slice(b"NCZBLOCK");
        fs::write(&path, &data)?;
        assert_eq!(
            detect_ncz_mode(&path, &[ncz_entry("a.ncz", 0, entry_size)])?,
            "블록"
        );

        let second_magic = (second_offset + 0x4000) as usize;
        data[second_magic..second_magic + 8].copy_from_slice(b"NCZSECTN");
        fs::write(&path, &data)?;
        assert_eq!(
            detect_ncz_mode(
                &path,
                &[
                    ncz_entry("a.ncz", 0, entry_size),
                    ncz_entry("b.ncz", second_offset, entry_size),
                ],
            )?,
            "혼합 (블록+스트리밍)"
        );
        Ok(())
    }
}
