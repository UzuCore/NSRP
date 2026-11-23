use anyhow::{Context, Result, bail};
use byteorder::{LittleEndian, ReadBytesExt, WriteBytesExt};
use sha2::{Digest, Sha256};
use std::{
    collections::HashSet,
    fs::{self, File},
    io::{self, BufReader, BufWriter, Read, Seek, SeekFrom, Write},
    path::{Path, PathBuf},
    sync::atomic::{AtomicBool, Ordering},
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Hfs0Entry {
    pub name: String,
    pub offset: u64,
    pub size: u64,
    pub hash_target_size: u32,
    pub hash: [u8; 32],
}

#[derive(Debug, Clone)]
pub struct Hfs0Index {
    pub base: u64,
    pub data_start: u64,
    pub entries: Vec<Hfs0Entry>,
}

impl Hfs0Index {
    pub fn parse_at<R: Read + Seek>(reader: &mut R, base: u64, file_size: u64) -> Result<Self> {
        reader.seek(SeekFrom::Start(base))?;
        let mut magic = [0u8; 4];
        reader.read_exact(&mut magic)?;
        if &magic != b"HFS0" {
            bail!("HFS0 magic 불일치");
        }
        let count = reader.read_u32::<LittleEndian>()?;
        let string_size = reader.read_u32::<LittleEndian>()?;
        let _reserved = reader.read_u32::<LittleEndian>()?;
        if count == 0 || count > 16_384 || string_size > 64 * 1024 * 1024 {
            bail!("비정상 HFS0 헤더");
        }
        let mut raw = vec![0u8; count as usize * 64];
        reader.read_exact(&mut raw)?;
        let mut strings = vec![0u8; string_size as usize];
        reader.read_exact(&mut strings)?;
        let data_start = reader.stream_position()?;
        let mut entries = Vec::with_capacity(count as usize);
        let mut seen = HashSet::new();
        for i in 0..count as usize {
            let p = &raw[i * 64..(i + 1) * 64];
            let mut c = io::Cursor::new(p);
            let offset = c.read_u64::<LittleEndian>()?;
            let mut size = c.read_u64::<LittleEndian>()?;
            let string_offset = c.read_u32::<LittleEndian>()? as usize;
            let hash_target_size = c.read_u32::<LittleEndian>()?;
            // HFS0 reserves bytes 0x18..0x1f in each entry. The digest is
            // stored at 0x20..0x3f (not immediately after the size field).
            // Do not read the reserved bytes as part of the SHA-256.
            let _reserved = c.read_u64::<LittleEndian>()?;
            let mut hash = [0u8; 32];
            c.read_exact(&mut hash)?;
            if string_offset >= strings.len() {
                bail!("HFS0 문자열 오프셋 오류");
            }
            let end = strings[string_offset..]
                .iter()
                .position(|&b| b == 0)
                .map(|n| string_offset + n)
                .context("HFS0 파일명 종료 문자 없음")?;
            let name = std::str::from_utf8(&strings[string_offset..end])?.to_owned();
            validate_name(&name)?;
            if !seen.insert(name.to_lowercase()) {
                bail!("중복 HFS0 파일명: {name}");
            }
            let abs_start = data_start
                .checked_add(offset)
                .context("HFS0 오프셋 오버플로")?;
            let abs_end = abs_start.checked_add(size).context("HFS0 크기 오버플로")?;
            if abs_end > file_size {
                let overrun = abs_end - file_size;
                let trimmed_padding = matches!(
                    name.to_ascii_lowercase().as_str(),
                    "secure" | "normal" | "update" | "logo"
                ) && overrun <= 0x200
                    && abs_start < file_size;
                if trimmed_padding {
                    size -= overrun;
                } else {
                    bail!("HFS0 엔트리 범위 초과: {name}");
                }
            }
            entries.push(Hfs0Entry {
                name,
                offset,
                size,
                hash_target_size,
                hash,
            });
        }
        Ok(Self {
            base,
            data_start,
            entries,
        })
    }

    pub fn entry(&self, name: &str) -> Option<&Hfs0Entry> {
        self.entries
            .iter()
            .find(|e| e.name.eq_ignore_ascii_case(name))
    }
}

pub fn find_xci_root(path: &Path) -> Result<Hfs0Index> {
    Ok(find_xci_root_with_header_base(path)?.0)
}

pub fn find_xci_root_with_header_base(path: &Path) -> Result<(Hfs0Index, Option<u64>)> {
    let mut file = BufReader::new(File::open(path)?);
    let size = file.get_ref().metadata()?.len();
    let mut candidates: Vec<(u64, Option<u64>)> = Vec::new();
    for base in [0u64, 0x1000, 0x200] {
        if base + 0x140 > size {
            continue;
        }
        file.seek(SeekFrom::Start(base + 0x100))?;
        let mut magic = [0u8; 4];
        file.read_exact(&mut magic)?;
        if &magic != b"HEAD" {
            continue;
        }
        file.seek(SeekFrom::Start(base + 0x130))?;
        let addr = file.read_u64::<LittleEndian>()?;
        for candidate in [addr, addr.saturating_mul(0x200)] {
            if candidate > 0
                && candidate < size
                && !candidates.iter().any(|(off, _)| *off == candidate)
            {
                candidates.push((candidate, Some(base)));
            }
        }
    }
    candidates.extend(
        [
            0x200u64, 0x400, 0x1000, 0x2000, 0x4000, 0x8000, 0xf000, 0x10000, 0x20000,
        ]
        .into_iter()
        .map(|off| (off, None)),
    );
    for (off, header_base) in candidates {
        if off + 16 > size {
            continue;
        }
        if let Ok(index) = Hfs0Index::parse_at(&mut file, off, size) {
            return Ok((index, header_base));
        }
    }
    // Last-resort 0x200-aligned scan through the conventional header area.
    for off in (0x200u64..size.min(0x20000)).step_by(0x200) {
        if let Ok(index) = Hfs0Index::parse_at(&mut file, off, size) {
            return Ok((index, None));
        }
    }
    bail!("XCI 루트 HFS0를 찾지 못했습니다")
}

pub fn collect_leaf_entries(
    path: &Path,
    skip_system_partitions: bool,
) -> Result<Vec<(String, u64, u64)>> {
    let mut file = BufReader::new(File::open(path)?);
    let size = file.get_ref().metadata()?.len();
    let root = find_xci_root(path)?;
    let mut out = Vec::new();
    let mut visited = HashSet::new();
    fn walk<R: Read + Seek>(
        reader: &mut R,
        file_size: u64,
        index: Hfs0Index,
        skip_system: bool,
        visited: &mut HashSet<u64>,
        out: &mut Vec<(String, u64, u64)>,
    ) -> Result<()> {
        if !visited.insert(index.base) {
            return Ok(());
        }
        for entry in index.entries {
            let abs = index.data_start + entry.offset;
            let lower = entry.name.to_ascii_lowercase();
            if skip_system && matches!(lower.as_str(), "update" | "logo" | "normal") {
                continue;
            }
            if lower.ends_with(".nca")
                || lower.ends_with(".ncz")
                || lower.ends_with(".tik")
                || lower.ends_with(".cert")
            {
                out.push((entry.name, abs, entry.size));
                continue;
            }
            if abs + 16 <= file_size
                && let Ok(sub) = Hfs0Index::parse_at(reader, abs, file_size)
            {
                walk(reader, file_size, sub, skip_system, visited, out)?;
            }
        }
        Ok(())
    }
    walk(
        &mut file,
        size,
        root,
        skip_system_partitions,
        &mut visited,
        &mut out,
    )?;
    Ok(out)
}

pub fn build_from_paths(entries: &[(String, PathBuf)], out_path: &Path, align: u64) -> Result<()> {
    build_from_paths_layout(entries, out_path, align, align)
}

/// Rebuild an HFS0 hierarchy in a single seekable output without staging each
/// transformed NCA/NCZ or sub-partition. Offsets, payload lengths and SHA-256
/// hashes of the first 0x200 bytes are backfilled after each entry completes.
/// Callers own the output transaction and must discard it on failure.
pub fn build_to_stream<W, F>(
    names: &[String],
    out: &mut W,
    header_align: u64,
    data_align: u64,
    cancel: &AtomicBool,
    mut write_entry: F,
) -> Result<u64>
where
    W: Read + Write + Seek,
    F: FnMut(usize, &mut W) -> Result<()>,
{
    if names.is_empty() || names.len() > 16_384 {
        bail!("HFS0 파일 개수가 비정상입니다");
    }
    let header_align = header_align.max(1);
    let data_align = data_align.max(1);
    let mut strings = Vec::new();
    let mut string_offsets = Vec::with_capacity(names.len());
    let mut seen = HashSet::new();
    for name in names {
        validate_name(name)?;
        if !seen.insert(name.to_lowercase()) {
            bail!("중복 HFS0 파일명: {name}");
        }
        string_offsets.push(u32::try_from(strings.len()).context("HFS0 문자열 테이블 초과")?);
        strings.extend_from_slice(name.as_bytes());
        strings.push(0);
        if strings.len() > 64 * 1024 * 1024 {
            bail!("HFS0 문자열 테이블이 너무 큽니다");
        }
    }
    let raw_header = 16u64
        .checked_add((names.len() as u64) * 64)
        .and_then(|v| v.checked_add(strings.len() as u64))
        .context("HFS0 헤더 크기 오버플로")?;
    let header_size = raw_header
        .checked_add(header_align - 1)
        .map(|v| (v / header_align) * header_align)
        .context("HFS0 헤더 정렬 오버플로")?;
    let padding = usize::try_from(header_size - raw_header)?;
    if padding > 16 * 1024 * 1024 {
        bail!("HFS0 헤더 정렬이 비정상적으로 큽니다");
    }
    strings.resize(strings.len() + padding, 0);

    let header_begin = out.stream_position()?;
    out.write_all(b"HFS0")?;
    out.write_u32::<LittleEndian>(names.len() as u32)?;
    out.write_u32::<LittleEndian>(
        u32::try_from(strings.len()).context("HFS0 문자열 테이블 초과")?,
    )?;
    out.write_u32::<LittleEndian>(0)?;
    out.write_all(&vec![0u8; names.len() * 64])?;
    out.write_all(&strings)?;
    let data_begin = out.stream_position()?;
    let mut written_data = 0u64;
    let mut lengths = Vec::with_capacity(names.len());
    let mut offsets = Vec::with_capacity(names.len());
    let mut hashes = Vec::with_capacity(names.len());
    let mut hash_lengths = Vec::with_capacity(names.len());
    let zero_pad = [0u8; 4096];
    for index in 0..names.len() {
        if cancel.load(Ordering::Relaxed) {
            bail!("작업이 중단되었습니다");
        }
        let aligned = written_data
            .checked_add(data_align - 1)
            .map(|v| (v / data_align) * data_align)
            .context("HFS0 데이터 정렬 오버플로")?;
        let mut pad = aligned - written_data;
        while pad > 0 {
            let take = pad.min(zero_pad.len() as u64) as usize;
            out.write_all(&zero_pad[..take])?;
            pad -= take as u64;
        }
        let start = out.stream_position()?;
        if start
            != data_begin
                .checked_add(aligned)
                .context("HFS0 오프셋 오버플로")?
        {
            bail!("HFS0 출력 위치가 예상과 다릅니다");
        }
        write_entry(index, out)?;
        let end = out.stream_position()?;
        let size = end.checked_sub(start).context("HFS0 기록 위치 역행")?;
        let hash_size = size.min(0x200) as usize;
        let mut head = [0u8; 0x200];
        out.seek(SeekFrom::Start(start))?;
        out.read_exact(&mut head[..hash_size])?;
        hashes.push(Sha256::digest(&head[..hash_size]));
        out.seek(SeekFrom::Start(end))?;
        offsets.push(aligned);
        lengths.push(size);
        hash_lengths.push(hash_size as u32);
        written_data = aligned
            .checked_add(size)
            .context("HFS0 데이터 크기 오버플로")?;
    }
    if cancel.load(Ordering::Relaxed) {
        bail!("작업이 중단되었습니다");
    }
    let end = out.stream_position()?;
    out.seek(SeekFrom::Start(header_begin + 16))?;
    for index in 0..names.len() {
        out.write_u64::<LittleEndian>(offsets[index])?;
        out.write_u64::<LittleEndian>(lengths[index])?;
        out.write_u32::<LittleEndian>(string_offsets[index])?;
        out.write_u32::<LittleEndian>(hash_lengths[index])?;
        out.write_u64::<LittleEndian>(0)?;
        out.write_all(&hashes[index])?;
    }
    out.seek(SeekFrom::Start(end))?;
    Ok(end - header_begin)
}

pub fn build_from_paths_layout(
    entries: &[(String, PathBuf)],
    out_path: &Path,
    header_align: u64,
    data_align: u64,
) -> Result<()> {
    if entries.is_empty() {
        bail!("HFS0 빌드 대상이 비어 있습니다");
    }
    let header_align = header_align.max(1);
    let data_align = data_align.max(1);
    let mut strings = Vec::new();
    let mut string_offsets = Vec::new();
    let mut sizes = Vec::new();
    let mut hashes = Vec::new();
    for (name, path) in entries {
        validate_name(name)?;
        string_offsets.push(strings.len() as u32);
        strings.extend_from_slice(name.as_bytes());
        strings.push(0);
        let size = fs::metadata(path)?.len();
        sizes.push(size);
        let target = size.min(0x200) as usize;
        let mut f = File::open(path)?;
        let mut data = vec![0u8; target];
        f.read_exact(&mut data)?;
        hashes.push(Sha256::digest(&data));
    }
    let raw_header = 16u64 + entries.len() as u64 * 64 + strings.len() as u64;
    let header_size = align_up(raw_header, header_align);
    strings.resize(strings.len() + (header_size - raw_header) as usize, 0);
    if let Some(parent) = out_path.parent() {
        fs::create_dir_all(parent)?;
    }
    let mut out = BufWriter::new(File::create(out_path)?);
    out.write_all(b"HFS0")?;
    out.write_u32::<LittleEndian>(entries.len() as u32)?;
    out.write_u32::<LittleEndian>(strings.len() as u32)?;
    out.write_u32::<LittleEndian>(0)?;
    let mut rel = 0u64;
    for i in 0..entries.len() {
        out.write_u64::<LittleEndian>(rel)?;
        out.write_u64::<LittleEndian>(sizes[i])?;
        out.write_u32::<LittleEndian>(string_offsets[i])?;
        out.write_u32::<LittleEndian>(sizes[i].min(0x200) as u32)?;
        out.write_u64::<LittleEndian>(0)?;
        out.write_all(&hashes[i])?;
        rel = align_up(rel + sizes[i], data_align);
    }
    out.write_all(&strings)?;
    let mut buf = vec![0u8; 4 * 1024 * 1024];
    let mut written_data = 0u64;
    for (_, path) in entries {
        if !written_data.is_multiple_of(data_align) {
            let pad = data_align - written_data % data_align;
            out.write_all(&vec![0u8; pad as usize])?;
            written_data += pad;
        }
        let mut src = BufReader::new(File::open(path)?);
        loop {
            let n = src.read(&mut buf)?;
            if n == 0 {
                break;
            }
            out.write_all(&buf[..n])?;
            written_data += n as u64;
        }
    }
    out.flush()?;
    Ok(())
}

fn align_up(v: u64, a: u64) -> u64 {
    v.div_ceil(a) * a
}

fn validate_name(name: &str) -> Result<()> {
    super::name::validate_container_filename(name)
}

#[cfg(test)]
mod streaming_tests {
    use super::*;
    use anyhow::ensure;
    use std::fs::OpenOptions;

    /// The external Stage57 QA fixture is a *real* NTFS sparse file,
    /// logically 36 GiB but physically <1 MiB. The test reads bounded
    /// regions only and never rewrites the fixture or scans all 36 GiB.
    #[cfg(windows)]
    #[test]
    #[ignore = "requires explicitly created Stage57 NTFS sparse file in isolated QA root"]
    fn stage57_real_sparse_36gib_xci_seek_and_bounds() -> Result<()> {
        use std::os::windows::fs::MetadataExt;

        let path = PathBuf::from(
            std::env::var_os("NSRP_STAGE57_SPARSE_XCI")
                .context("missing NSRP_STAGE57_SPARSE_XCI QA fixture path")?,
        );
        ensure!(
            path.to_string_lossy()
                .starts_with(r"D:\NSW.dev\NSRP_STAGE57_SAFETY_20261122\qa\sparse_36gib\"),
            "refusing non-QA sparse input path"
        );
        let meta = fs::symlink_metadata(&path)?;
        ensure!(
            meta.is_file() && !meta.file_type().is_symlink(),
            "not a regular QA file"
        );
        ensure!(
            meta.file_attributes() & 0x200 != 0,
            "expected NTFS sparse-file flag"
        );
        ensure!(meta.len() == (36u64 << 30), "wrong logical QA file length");
        let index = find_xci_root(&path)?;
        assert_eq!(index.base, 512);
        assert_eq!(index.data_start, 600);
        let entry = index
            .entry("big.nca")
            .context("missing sparse HFS0 entry")?;
        assert_eq!(entry.offset, 34u64 << 30);
        assert_eq!(entry.size, 1u64 << 20);
        let absolute = index.data_start + entry.offset;
        assert!(absolute > (u32::MAX as u64));
        let files = collect_leaf_entries(&path, false)?;
        assert_eq!(files, vec![("big.nca".to_string(), absolute, 1u64 << 20)]);

        let mut src = File::open(&path)?;
        src.seek(SeekFrom::Start(absolute))?;
        let mut marker = [0u8; 15];
        src.read_exact(&mut marker)?;
        assert_eq!(&marker, b"STAGE57_SPARSE!");
        src.seek(SeekFrom::Start(absolute + (1 << 20) - 4))?;
        let mut tail = [0u8; 4];
        src.read_exact(&mut tail)?;
        assert_eq!(&tail, b"TAIL");

        // Fail closed at an artificial logical EOF, with no mutation.
        assert!(
            Hfs0Index::parse_at(&mut src, 512, absolute + (1 << 20) - 1).is_err(),
            "out-of-bounds sparse HFS0 payload must not be accepted"
        );
        Ok(())
    }

    #[test]
    fn stage55_virtual_36gib_hfs0_offsets_are_64bit_and_checked() -> Result<()> {
        // A small header with a virtual 36 GiB logical file size. No
        // multi-gigabyte file is created, mapped, read, or allocated.
        let huge_offset = 34u64 << 30;
        let payload_len = 24u64 << 20;
        let logical_len = 36u64 << 30;
        let mut header = Vec::with_capacity(16 + 64 + 10);
        header.extend_from_slice(b"HFS0");
        header.extend_from_slice(&1u32.to_le_bytes());
        header.extend_from_slice(&10u32.to_le_bytes());
        header.extend_from_slice(&0u32.to_le_bytes());
        let mut entry = [0u8; 64];
        entry[..8].copy_from_slice(&huge_offset.to_le_bytes());
        entry[8..16].copy_from_slice(&payload_len.to_le_bytes());
        header.extend_from_slice(&entry);
        header.extend_from_slice(b"large.nca\0");
        let data_start = header.len() as u64;

        let parsed = Hfs0Index::parse_at(&mut io::Cursor::new(&header), 0, logical_len)?;
        assert_eq!(parsed.data_start, data_start);
        assert_eq!(parsed.entries[0].name, "large.nca");
        assert_eq!(parsed.entries[0].offset, huge_offset);
        assert_eq!(parsed.entries[0].size, payload_len);

        let truncated = data_start + huge_offset + payload_len - 1;
        assert!(
            Hfs0Index::parse_at(&mut io::Cursor::new(&header), 0, truncated).is_err(),
            "A virtual large-file entry beyond EOF must fail closed"
        );

        // The parser must reject u64 wraparound even when a malicious
        // caller advertises the maximum possible file length.
        header[16..24].copy_from_slice(&u64::MAX.to_le_bytes());
        assert!(
            Hfs0Index::parse_at(&mut io::Cursor::new(&header), 0, u64::MAX).is_err(),
            "A virtual large-file offset overflow must fail closed"
        );
        Ok(())
    }

    fn readwrite(path: &Path) -> Result<File> {
        Ok(OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .open(path)?)
    }

    #[test]
    fn streamed_hfs0_matches_previous_staged_builder() -> Result<()> {
        let temp = tempfile::tempdir()?;
        let a = temp.path().join("a.bin");
        let b = temp.path().join("b.bin");
        fs::write(
            &a,
            (0..1234u32).map(|i| (i % 251) as u8).collect::<Vec<_>>(),
        )?;
        fs::write(&b, vec![0x5au8; 37])?;
        let names = vec!["some_game.nca".to_string(), "control.tik".to_string()];
        let paths = vec![(names[0].clone(), a.clone()), (names[1].clone(), b.clone())];
        let staged = temp.path().join("staged.hfs0");
        let streamed = temp.path().join("streamed.hfs0");
        build_from_paths_layout(&paths, &staged, 0x200, 1)?;
        let mut output = readwrite(&streamed)?;
        build_to_stream(
            &names,
            &mut output,
            0x200,
            1,
            &AtomicBool::new(false),
            |i, dst| {
                let mut src = File::open(&paths[i].1)?;
                io::copy(&mut src, dst)?;
                Ok(())
            },
        )?;
        drop(output);
        assert_eq!(fs::read(&staged)?, fs::read(&streamed)?);
        Ok(())
    }

    #[test]
    fn nested_hfs0_stream_is_byte_identical_to_two_stage_build() -> Result<()> {
        let temp = tempfile::tempdir()?;
        let payload = temp.path().join("content.nca");
        fs::write(&payload, vec![0x42u8; 8193])?;
        let partition = temp.path().join("old_partition.hfs0");
        build_from_paths_layout(
            &[("content.nca".into(), payload.clone())],
            &partition,
            0x200,
            1,
        )?;
        let root = temp.path().join("old_root.hfs0");
        build_from_paths_layout(&[("secure".into(), partition)], &root, 0x200, 1)?;
        let nested = temp.path().join("nested.hfs0");
        let mut output = readwrite(&nested)?;
        let cancel = AtomicBool::new(false);
        build_to_stream(
            &["secure".into()],
            &mut output,
            0x200,
            1,
            &cancel,
            |_, out| {
                build_to_stream(&["content.nca".into()], out, 0x200, 1, &cancel, |_, sub| {
                    io::copy(&mut File::open(&payload)?, sub)?;
                    Ok(())
                })?;
                Ok(())
            },
        )?;
        drop(output);
        assert_eq!(fs::read(&root)?, fs::read(&nested)?);
        Ok(())
    }

    #[test]
    fn streamed_hfs0_cancellation_rejects_payload_without_finishing_index() -> Result<()> {
        let temp = tempfile::tempdir()?;
        let mut output = readwrite(&temp.path().join("cancelled.hfs0"))?;
        let cancel = AtomicBool::new(false);
        let result = build_to_stream(
            &["first.nca".into(), "second.nca".into()],
            &mut output,
            0x200,
            1,
            &cancel,
            |index, out| {
                out.write_all(b"first entry")?;
                if index == 0 {
                    cancel.store(true, Ordering::Relaxed);
                }
                Ok(())
            },
        );
        assert!(result.is_err());
        assert!(cancel.load(Ordering::Relaxed));
        Ok(())
    }

    #[test]
    #[ignore = "sparse 4 GiB+ output test on a filesystem supporting large files"]
    fn streamed_hfs0_handles_sparse_file_larger_than_four_gib() -> Result<()> {
        let temp = tempfile::tempdir()?;
        let path = temp.path().join("large_sparse.hfs0");
        let mut output = readwrite(&path)?;
        let file_size = (4u64 << 30) + 97;
        build_to_stream(
            &["large.nca".into()],
            &mut output,
            0x200,
            1,
            &AtomicBool::new(false),
            |_, out| {
                let start = out.stream_position()?;
                out.write_all(&[0x41; 0x200])?;
                out.seek(SeekFrom::Start(start + file_size - 1))?;
                out.write_all(&[0x5a])?;
                Ok(())
            },
        )?;
        assert_eq!(output.metadata()?.len(), 0x200 + file_size);
        let len = output.metadata()?.len();
        let index = Hfs0Index::parse_at(&mut output, 0, len)?;
        assert_eq!(index.entries[0].size, file_size);
        Ok(())
    }
}
