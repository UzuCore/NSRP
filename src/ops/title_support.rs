use crate::{
    formats::ncz_stream::decompress_ncz_region_to_nca, ops::container::ContainerEntry,
    process::run_tool,
};
use anyhow::{Context, Result, bail};
use flate2::{Compression, read::DeflateDecoder, write::DeflateEncoder};
use image::{codecs::jpeg::JpegEncoder, imageops::FilterType};
use sha2::{Digest, Sha256};
use std::{
    ffi::OsString,
    fs::{self, File},
    io::{BufReader, BufWriter, Read, Seek, SeekFrom, Write},
    path::{Path, PathBuf},
    sync::atomic::{AtomicBool, Ordering},
};

const NACP_TITLE_AREA_SIZE: usize = 0x3000;
const NACP_TITLE_SLOT_SIZE: usize = 0x300;
const NACP_NAME_SIZE: usize = 0x200;
const NACP_PUBLISHER_SIZE: usize = 0x100;
const NACP_TITLES_DATA_FORMAT_OFFSET: usize = 0x3215;

fn nacp_titles_data_format(data: &[u8]) -> Result<u8> {
    let format = data
        .get(NACP_TITLES_DATA_FORMAT_OFFSET)
        .copied()
        .unwrap_or(0);
    match format {
        0 | 1 => Ok(format),
        other => bail!("지원하지 않는 NACP TitlesDataFormat: {other}"),
    }
}

fn decode_nacp_title_table(data: &[u8]) -> Result<(Vec<u8>, usize, u8)> {
    if data.len() < NACP_TITLE_AREA_SIZE {
        bail!("NACP title 영역이 잘렸습니다");
    }
    let format = nacp_titles_data_format(data)?;
    if format == 0 {
        return Ok((data[..NACP_TITLE_AREA_SIZE].to_vec(), 16, 0));
    }

    let compressed_size = u16::from_le_bytes([data[0], data[1]]) as usize;
    if compressed_size == 0 || compressed_size > NACP_TITLE_AREA_SIZE - 2 {
        bail!("NACP 압축 title 크기가 잘못되었습니다: {compressed_size}");
    }
    let mut decoder = DeflateDecoder::new(&data[2..2 + compressed_size]);
    let mut decoded = Vec::with_capacity(0x6000);
    decoder
        .read_to_end(&mut decoded)
        .context("NACP 압축 title DEFLATE 해제 실패")?;
    if decoded.len() != 0x6000 {
        bail!(
            "NACP 압축 title 해제 크기 오류: {} (예상 24576)",
            decoded.len()
        );
    }
    Ok((decoded, 32, 1))
}

fn encode_nacp_title_table(data: &mut [u8], table: &[u8], format: u8) -> Result<()> {
    if data.len() < NACP_TITLE_AREA_SIZE {
        bail!("NACP title 영역이 잘렸습니다");
    }
    match format {
        0 => {
            if table.len() != NACP_TITLE_AREA_SIZE {
                bail!("NACP Format0 title table 크기 오류");
            }
            data[..NACP_TITLE_AREA_SIZE].copy_from_slice(table);
        }
        1 => {
            if table.len() != 0x6000 {
                bail!("NACP Format1 title table 크기 오류");
            }
            let mut encoder = DeflateEncoder::new(Vec::new(), Compression::best());
            encoder.write_all(table)?;
            let compressed = encoder.finish()?;
            if compressed.len() > NACP_TITLE_AREA_SIZE - 2 || compressed.len() > u16::MAX as usize {
                bail!("수정된 NACP title 데이터가 압축 영역에 들어가지 않습니다");
            }
            data[..NACP_TITLE_AREA_SIZE].fill(0);
            data[..2].copy_from_slice(&(compressed.len() as u16).to_le_bytes());
            data[2..2 + compressed.len()].copy_from_slice(&compressed);
        }
        other => bail!("지원하지 않는 NACP TitlesDataFormat: {other}"),
    }
    Ok(())
}

fn nacp_field(raw: &[u8]) -> String {
    let end = raw.iter().position(|&byte| byte == 0).unwrap_or(raw.len());
    String::from_utf8_lossy(&raw[..end]).trim().to_owned()
}

pub(crate) fn nacp_language_records(data: &[u8]) -> Result<Vec<(String, String)>> {
    let (table, count, _) = decode_nacp_title_table(data)?;
    let mut out = Vec::with_capacity(count);
    for index in 0..count {
        let off = index * NACP_TITLE_SLOT_SIZE;
        out.push((
            nacp_field(&table[off..off + NACP_NAME_SIZE]),
            nacp_field(&table[off + NACP_NAME_SIZE..off + NACP_NAME_SIZE + NACP_PUBLISHER_SIZE]),
        ));
    }
    Ok(out)
}

pub(crate) fn nacp_title(data: &[u8], index: usize) -> String {
    nacp_language_records(data)
        .ok()
        .and_then(|records| records.get(index).map(|record| record.0.clone()))
        .unwrap_or_default()
}

fn validate_nacp_title(title: &str) -> Result<()> {
    if title.len() > NACP_NAME_SIZE - 1 {
        bail!(
            "타이틀이 너무 깁니다: UTF-8 {} bytes (최대 511 bytes)",
            title.len()
        );
    }
    if title.chars().any(char::is_control) {
        bail!("타이틀에는 NUL/개행 등의 제어문자를 사용할 수 없습니다");
    }
    Ok(())
}

/// NACP의 EN/JA/KO 제목을 한 번에 수정한다. Format0(16개 고정 슬롯)과
/// Format1(32개 raw-DEFLATE 압축 슬롯)을 모두 보존하며 처리한다.
pub(crate) fn patch_nacp_titles(
    data: &mut [u8],
    english: Option<&str>,
    japanese: Option<&str>,
    korean: Option<&str>,
) -> Result<u8> {
    let (mut table, count, format) = decode_nacp_title_table(data)?;
    let patches = [(0usize, english), (2usize, japanese), (12usize, korean)];
    let mut patched_indices = Vec::new();
    for (index, title) in patches {
        let Some(title) = title.filter(|value| !value.is_empty()) else {
            continue;
        };
        validate_nacp_title(title)?;
        if index >= count {
            bail!("NACP language slot out of range: {index}");
        }
        let off = index * NACP_TITLE_SLOT_SIZE;
        table[off..off + NACP_NAME_SIZE].fill(0);
        table[off..off + title.len()].copy_from_slice(title.as_bytes());
        patched_indices.push(index);
    }

    // 비어 있는 publisher에 제목 자체를 복사하던 구 로직은 제거한다.
    // 새 언어 슬롯에 publisher가 없을 때만 기존 유효 publisher를 재사용한다.
    let fallback_publisher = [0usize, 2, 12]
        .into_iter()
        .chain(0..count)
        .find_map(|index| {
            if index >= count {
                return None;
            }
            let off = index * NACP_TITLE_SLOT_SIZE + NACP_NAME_SIZE;
            let raw = &table[off..off + NACP_PUBLISHER_SIZE];
            raw.iter().any(|&byte| byte != 0).then(|| raw.to_vec())
        });
    if let Some(publisher) = fallback_publisher {
        for index in patched_indices {
            let off = index * NACP_TITLE_SLOT_SIZE + NACP_NAME_SIZE;
            if table[off..off + NACP_PUBLISHER_SIZE]
                .iter()
                .all(|&byte| byte == 0)
            {
                table[off..off + NACP_PUBLISHER_SIZE].copy_from_slice(&publisher);
            }
        }
    }

    encode_nacp_title_table(data, &table, format)?;
    Ok(format)
}

pub(crate) fn replace_icons(romfs: &Path, source_image: &Path) -> Result<()> {
    let image = image::open(source_image)
        .with_context(|| format!("failed to read icon image: {}", source_image.display()))?
        .resize_exact(256, 256, FilterType::Lanczos3)
        .to_rgb8();
    let mut jpeg = Vec::new();
    JpegEncoder::new_with_quality(&mut jpeg, 100).encode_image(&image)?;
    let mut replaced = 0usize;
    for entry in walkdir::WalkDir::new(romfs)
        .max_depth(2)
        .into_iter()
        .filter_map(|e| e.ok())
    {
        let name = entry.file_name().to_string_lossy().to_ascii_lowercase();
        if entry.file_type().is_file() && name.starts_with("icon_") && name.ends_with(".dat") {
            fs::write(entry.path(), &jpeg)?;
            replaced += 1;
        }
    }
    if replaced == 0 {
        bail!("no icon_*.dat file was found");
    }
    Ok(())
}

pub(crate) fn find_cnmt_content_row(data: &[u8], nca_id: &str) -> Option<usize> {
    if data.len() < 0x20 {
        return None;
    }
    let ext = u16::from_le_bytes(data[0x0e..0x10].try_into().ok()?) as usize;
    let count = u16::from_le_bytes(data[0x10..0x12].try_into().ok()?) as usize;
    let base = 0x20 + ext;
    let expected = hex::decode(nca_id).ok()?;
    for i in 0..count {
        let row = base + i * 0x38;
        if row + 0x38 <= data.len() && data[row + 0x20..row + 0x30] == expected {
            return Some(row);
        }
    }
    None
}

pub(crate) fn patch_cnmt_nca(
    encrypted_path: &Path,
    old_cnmt: &[u8],
    new_cnmt: &[u8],
    hactool: &Path,
    prod_keys: &Path,
    title_key: Option<&[u8]>,
    temp_dir: &Path,
    cancel: &AtomicBool,
) -> Result<PathBuf> {
    if old_cnmt.len() != new_cnmt.len() {
        bail!("CNMT length changed");
    }
    let plain_path = temp_dir.join("cnmt_plain.nca");
    let mut args = vec![
        OsString::from("-k"),
        prod_keys.as_os_str().to_owned(),
        OsString::from("--disablekeywarns"),
        OsString::from(format!("--plaintext={}", plain_path.display())),
    ];
    if let Some(key) = title_key {
        args.push(OsString::from(format!("--titlekey={}", hex::encode(key))));
    }
    args.push(encrypted_path.as_os_str().to_owned());
    let tool = run_tool(hactool, args, Some(temp_dir), cancel)?;
    if !tool.success() || !plain_path.is_file() {
        let mut detail = tool.combined();
        if let Some(parent) = hactool.parent() {
            let hactoolnet = parent.join("hactoolnet.exe");
            if hactoolnet.is_file() {
                let _ = fs::remove_file(&plain_path);
                let mut args = vec![
                    OsString::from("-k"),
                    prod_keys.as_os_str().to_owned(),
                    OsString::from("--disablekeywarns"),
                    OsString::from("--plaintext"),
                    plain_path.as_os_str().to_owned(),
                ];
                if let Some(key) = title_key {
                    args.extend([
                        OsString::from("--titlekey"),
                        OsString::from(hex::encode(key)),
                    ]);
                }
                args.push(encrypted_path.as_os_str().to_owned());
                let net = run_tool(&hactoolnet, args, Some(temp_dir), cancel)?;
                if net.success() && plain_path.is_file() {
                    detail.clear();
                } else {
                    detail = net.combined();
                }
            }
        }
        if !plain_path.is_file() {
            bail!("failed to extract CNMT plaintext: {detail}");
        }
    }
    let plain = fs::read(&plain_path)?;
    let abs = find_cnmt_payload_offset(&plain).context("CNMT payload not found")?;
    if abs + old_cnmt.len() > plain.len() {
        bail!("CNMT payload out of range");
    }
    let mut encrypted = fs::read(encrypted_path)?;
    if abs + old_cnmt.len() > encrypted.len() {
        bail!("encrypted CNMT NCA out of range");
    }
    for i in 0..old_cnmt.len() {
        encrypted[abs + i] ^= old_cnmt[i] ^ new_cnmt[i];
    }
    let output = temp_dir.join("new_meta.cnmt.nca");
    fs::write(&output, encrypted)?;
    Ok(output)
}

pub(crate) fn find_cnmt_payload_offset(data: &[u8]) -> Option<usize> {
    let pfs0 = data.windows(4).position(|w| w == b"PFS0")?;
    if pfs0 + 16 > data.len() {
        return None;
    }
    let count = u32::from_le_bytes(data[pfs0 + 4..pfs0 + 8].try_into().ok()?) as usize;
    let string_size = u32::from_le_bytes(data[pfs0 + 8..pfs0 + 12].try_into().ok()?) as usize;
    let entries = pfs0 + 16;
    let strings = entries.checked_add(count.checked_mul(24)?)?;
    let data_start = strings.checked_add(string_size)?;
    if data_start > data.len() {
        return None;
    }
    for i in 0..count {
        let row = entries + i * 24;
        if row + 24 > data.len() {
            return None;
        }
        let offset = u64::from_le_bytes(data[row..row + 8].try_into().ok()?) as usize;
        let name_off = u32::from_le_bytes(data[row + 16..row + 20].try_into().ok()?) as usize;
        let name_start = strings.checked_add(name_off)?;
        if name_start >= data_start {
            return None;
        }
        let end = data[name_start..data_start].iter().position(|&b| b == 0)? + name_start;
        let name = std::str::from_utf8(&data[name_start..end]).ok()?;
        if name.ends_with(".cnmt") {
            return data_start.checked_add(offset);
        }
    }
    None
}

pub(crate) fn materialize_entry(
    input: &Path,
    entry: &ContainerEntry,
    output: &Path,
    cancel: &AtomicBool,
) -> Result<()> {
    if entry.name.to_ascii_lowercase().ends_with(".ncz") {
        let mut reader = BufReader::with_capacity(8 * 1024 * 1024, File::open(input)?);
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
        Ok(())
    } else {
        let mut reader = BufReader::with_capacity(8 * 1024 * 1024, File::open(input)?);
        copy_region(&mut reader, entry.offset, entry.size, output, cancel)
    }
}

pub(crate) fn copy_region<R: Read + Seek>(
    reader: &mut R,
    offset: u64,
    size: u64,
    output: &Path,
    cancel: &AtomicBool,
) -> Result<()> {
    reader.seek(SeekFrom::Start(offset))?;
    let mut out = BufWriter::with_capacity(8 * 1024 * 1024, File::create(output)?);
    let mut remaining = size;
    let mut buf = vec![0u8; 8 * 1024 * 1024];
    while remaining > 0 {
        if cancel.load(Ordering::Relaxed) {
            bail!("operation cancelled");
        }
        let take = remaining.min(buf.len() as u64) as usize;
        reader.read_exact(&mut buf[..take])?;
        out.write_all(&buf[..take])?;
        remaining -= take as u64;
    }
    out.flush()?;
    Ok(())
}

pub(crate) fn sha256_file(path: &Path) -> Result<[u8; 32]> {
    let mut file = BufReader::new(File::open(path)?);
    let mut hash = Sha256::new();
    let mut buf = vec![0u8; 4 * 1024 * 1024];
    loop {
        let n = file.read(&mut buf)?;
        if n == 0 {
            break;
        }
        hash.update(&buf[..n]);
    }
    Ok(hash.finalize().into())
}

pub(crate) fn move_file(src: &Path, dst: &Path) -> Result<()> {
    if dst.exists() {
        fs::remove_file(dst)?;
    }
    match fs::rename(src, dst) {
        Ok(()) => Ok(()),
        Err(_) => {
            fs::copy(src, dst)?;
            fs::remove_file(src)?;
            Ok(())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn patches_format1_titles_and_preserves_publisher_fallback() -> Result<()> {
        let mut nacp = vec![0u8; 0x4000];
        nacp[NACP_TITLES_DATA_FORMAT_OFFSET] = 1;
        let mut table = vec![0u8; 0x6000];
        table[..7].copy_from_slice(b"Example");
        table[NACP_NAME_SIZE..NACP_NAME_SIZE + 9].copy_from_slice(b"Publisher");
        encode_nacp_title_table(&mut nacp, &table, 1)?;

        assert_eq!(
            patch_nacp_titles(&mut nacp, None, None, Some("한국어 게임"))?,
            1
        );
        assert_eq!(nacp_title(&nacp, 12), "한국어 게임");
        let records = nacp_language_records(&nacp)?;
        assert_eq!(records[12].1, "Publisher");
        assert_eq!(nacp[NACP_TITLES_DATA_FORMAT_OFFSET], 1);
        Ok(())
    }

    #[test]
    fn refuses_unknown_title_format_and_oversized_title() {
        let mut unknown = vec![0u8; 0x4000];
        unknown[NACP_TITLES_DATA_FORMAT_OFFSET] = 2;
        assert!(patch_nacp_titles(&mut unknown, None, None, Some("테스트")).is_err());

        let mut normal = vec![0u8; 0x4000];
        let oversized = "가".repeat(171);
        assert!(patch_nacp_titles(&mut normal, None, None, Some(&oversized)).is_err());
    }
}
