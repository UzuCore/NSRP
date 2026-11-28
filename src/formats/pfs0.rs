use crate::disk_space::ensure_disk_space;
use anyhow::{Context, Result, bail, ensure};
use byteorder::{LittleEndian, ReadBytesExt, WriteBytesExt};
use std::{
    collections::HashSet,
    fs::{self, File},
    io::{self, BufReader, BufWriter, Read, Seek, SeekFrom, Write},
    path::{Path, PathBuf},
    sync::atomic::{AtomicBool, Ordering},
};

const MAX_FILES: u32 = 16_384;
const MAX_STRING_TABLE: u32 = 64 * 1024 * 1024;

/// A transformed NCA is stored in a temporary file, while an unchanged
/// container entry can be read directly from its original package. Avoid
/// writing unchanged entries to temporary files only to read them again.
#[derive(Debug, Clone)]
pub enum Pfs0Source {
    File(PathBuf),
    Region {
        container: PathBuf,
        offset: u64,
        size: u64,
    },
}

impl Pfs0Source {
    fn size(&self) -> Result<u64> {
        match self {
            Self::File(path) => Ok(fs::metadata(path)
                .with_context(|| format!("입력 파일 없음: {}", path.display()))?
                .len()),
            Self::Region {
                container,
                offset,
                size,
            } => {
                let len = fs::metadata(container)
                    .with_context(|| format!("입력 컨테이너 없음: {}", container.display()))?
                    .len();
                let end = offset
                    .checked_add(*size)
                    .context("PFS0 입력 범위 오버플로")?;
                if end > len {
                    bail!("PFS0 원본 영역이 컨테이너 범위를 벗어납니다");
                }
                Ok(*size)
            }
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Pfs0Entry {
    pub name: String,
    pub offset: u64,
    pub size: u64,
}

#[derive(Debug, Clone)]
pub struct Pfs0Index {
    pub data_start: u64,
    pub entries: Vec<Pfs0Entry>,
}

impl Pfs0Index {
    pub fn parse(path: &Path) -> Result<Self> {
        let mut file = BufReader::new(File::open(path)?);
        let file_size = file.get_ref().metadata()?.len();
        Self::parse_reader(&mut file, 0, file_size)
    }

    pub fn parse_reader<R: Read + Seek>(
        reader: &mut R,
        base: u64,
        container_size: u64,
    ) -> Result<Self> {
        let limit = base
            .checked_add(container_size)
            .context("PFS0 size overflow")?;
        if container_size < 16 {
            bail!("PFS0 header exceeds its bounded region");
        }
        reader.seek(SeekFrom::Start(base))?;
        let mut magic = [0u8; 4];
        reader.read_exact(&mut magic)?;
        if &magic != b"PFS0" {
            bail!("PFS0 magic 불일치");
        }
        let count = reader.read_u32::<LittleEndian>()?;
        let string_size = reader.read_u32::<LittleEndian>()?;
        let _reserved = reader.read_u32::<LittleEndian>()?;
        if count == 0 || count > MAX_FILES {
            bail!("비정상 PFS0 파일 수: {count}");
        }
        if string_size > MAX_STRING_TABLE {
            bail!("PFS0 문자열 테이블이 너무 큽니다");
        }

        let table_size = 16u64 + u64::from(count) * 24 + u64::from(string_size);
        if table_size > container_size {
            bail!("PFS0 index exceeds its bounded region");
        }

        let mut raw = vec![0u8; count as usize * 24];
        reader.read_exact(&mut raw)?;
        let mut strings = vec![0u8; string_size as usize];
        reader.read_exact(&mut strings)?;
        let data_start = reader.stream_position()?;
        let mut entries = Vec::with_capacity(count as usize);
        let mut seen = HashSet::new();
        for i in 0..count as usize {
            let p = &raw[i * 24..(i + 1) * 24];
            let mut c = io::Cursor::new(p);
            let offset = c.read_u64::<LittleEndian>()?;
            let size = c.read_u64::<LittleEndian>()?;
            let string_offset = c.read_u32::<LittleEndian>()? as usize;
            let _reserved = c.read_u32::<LittleEndian>()?;
            if string_offset >= strings.len() {
                bail!("PFS0 문자열 오프셋 오류");
            }
            let end = strings[string_offset..]
                .iter()
                .position(|&b| b == 0)
                .map(|n| string_offset + n)
                .context("PFS0 파일명 종료 문자가 없습니다")?;
            let name = std::str::from_utf8(&strings[string_offset..end])
                .context("PFS0 파일명이 UTF-8이 아닙니다")?
                .to_owned();
            validate_name(&name)?;
            let folded = name.to_lowercase();
            if !seen.insert(folded) {
                bail!("중복 PFS0 파일명: {name}");
            }
            let abs_end = data_start
                .checked_add(offset)
                .and_then(|v| v.checked_add(size))
                .context("PFS0 엔트리 크기 오버플로")?;
            if abs_end > limit {
                bail!("PFS0 엔트리가 컨테이너 범위를 벗어납니다: {name}");
            }
            entries.push(Pfs0Entry { name, offset, size });
        }
        Ok(Self {
            data_start,
            entries,
        })
    }

    pub fn entry(&self, name: &str) -> Option<&Pfs0Entry> {
        self.entries
            .iter()
            .find(|e| e.name.eq_ignore_ascii_case(name))
    }

    pub fn read_entry(&self, container: &Path, entry: &Pfs0Entry) -> Result<Vec<u8>> {
        let size: usize = entry
            .size
            .try_into()
            .context("엔트리가 메모리 한도를 넘습니다")?;
        let mut file = BufReader::new(File::open(container)?);
        file.seek(SeekFrom::Start(self.data_start + entry.offset))?;
        let mut data = vec![0u8; size];
        file.read_exact(&mut data)?;
        Ok(data)
    }

    pub fn extract_all(&self, container: &Path, out_dir: &Path) -> Result<Vec<PathBuf>> {
        fs::create_dir_all(out_dir)?;
        let mut source = BufReader::new(File::open(container)?);
        let mut output = Vec::with_capacity(self.entries.len());
        for entry in &self.entries {
            let dst = out_dir.join(&entry.name);
            source.seek(SeekFrom::Start(self.data_start + entry.offset))?;
            let mut out = BufWriter::new(File::create(&dst)?);
            copy_n(&mut source, &mut out, entry.size)?;
            out.flush()?;
            output.push(dst);
        }
        Ok(output)
    }
}

pub fn build_from_dir(dir: &Path, out_path: &Path) -> Result<()> {
    let mut paths: Vec<(String, PathBuf)> = fs::read_dir(dir)?
        .filter_map(|e| e.ok())
        .filter(|e| e.file_type().map(|t| t.is_file()).unwrap_or(false))
        .map(|e| (e.file_name().to_string_lossy().into_owned(), e.path()))
        .collect();
    paths.sort_by(|a, b| a.0.cmp(&b.0));
    build_from_paths(&paths, out_path)
}

pub fn build_from_paths(entries: &[(String, PathBuf)], out_path: &Path) -> Result<()> {
    let sources = entries
        .iter()
        .map(|(name, path)| (name.clone(), Pfs0Source::File(path.clone())))
        .collect::<Vec<_>>();
    build_from_sources(&sources, out_path, &AtomicBool::new(false))
}

/// Stream transformed entries directly into a PFS0 package. This avoids
/// writing compressed NCZ files to disk merely to copy them into the package.
/// The entry table is backfilled when the final entry sizes are known.
pub fn build_from_streams<F>(
    names: &[String],
    out_path: &Path,
    cancel: &AtomicBool,
    mut write_entry: F,
) -> Result<()>
where
    F: FnMut(usize, &mut BufWriter<File>) -> Result<()>,
{
    if names.is_empty() || names.len() > MAX_FILES as usize {
        bail!("PFS0 빌드 대상 파일 수가 유효하지 않습니다");
    }
    let mut strings = Vec::new();
    let mut string_offsets = Vec::with_capacity(names.len());
    let mut seen = HashSet::new();
    for name in names {
        validate_name(name)?;
        if !seen.insert(name.to_lowercase()) {
            bail!("중복 PFS0 파일명: {name}");
        }
        string_offsets.push(u32::try_from(strings.len()).context("PFS0 문자열 테이블 크기 초과")?);
        strings.extend_from_slice(name.as_bytes());
        strings.push(0);
        if strings.len() > MAX_STRING_TABLE as usize {
            bail!("PFS0 문자열 테이블이 너무 큽니다");
        }
    }
    let header_size = 16usize + names.len() * 24 + strings.len();
    let aligned_header = (header_size + 1 + 0x1f) & !0x1f;
    strings.resize(strings.len() + aligned_header - header_size, 0);

    let parent = out_path.parent().context("PFS0 출력 디렉터리가 없습니다")?;
    fs::create_dir_all(parent)?;
    // An output name may be submitted twice. Never share a deterministic
    // .partial pathname between concurrent writes and never remove a
    // previously completed output before the new file has been validated.
    let staged = tempfile::Builder::new()
        .prefix("nsrp_pfs0_")
        .suffix(".partial")
        .tempfile_in(parent)?;
    let result = (|| -> Result<()> {
        let mut out = BufWriter::with_capacity(4 * 1024 * 1024, staged.reopen()?);
        out.write_all(b"PFS0")?;
        out.write_u32::<LittleEndian>(names.len() as u32)?;
        out.write_u32::<LittleEndian>(strings.len() as u32)?;
        out.write_u32::<LittleEndian>(0)?;
        out.write_all(&vec![0u8; names.len() * 24])?;
        out.write_all(&strings)?;

        let mut lengths = Vec::with_capacity(names.len());
        let mut total_data = 0u64;
        for index in 0..names.len() {
            if cancel.load(Ordering::Relaxed) {
                bail!("작업이 중단되었습니다");
            }
            let before = out.stream_position()?;
            write_entry(index, &mut out)?;
            let after = out.stream_position()?;
            let len = after
                .checked_sub(before)
                .context("PFS0 출력 위치가 역행했습니다")?;
            total_data = total_data
                .checked_add(len)
                .context("PFS0 데이터 크기 오버플로")?;
            lengths.push(len);
        }
        if cancel.load(Ordering::Relaxed) {
            bail!("작업이 중단되었습니다");
        }
        let end = out.stream_position()?;
        out.seek(SeekFrom::Start(16))?;
        let mut rel = 0u64;
        for (index, len) in lengths.iter().enumerate() {
            out.write_u64::<LittleEndian>(rel)?;
            out.write_u64::<LittleEndian>(*len)?;
            out.write_u32::<LittleEndian>(string_offsets[index])?;
            out.write_u32::<LittleEndian>(0)?;
            rel += len;
        }
        out.flush()?;
        drop(out);
        let actual = staged.as_file().metadata()?.len();
        if actual != end || actual != aligned_header as u64 + total_data {
            bail!("PFS0 패키지 길이 검증 실패");
        }
        Ok(())
    })();
    result?;
    ensure!(!cancel.load(Ordering::Relaxed), "작업이 중단되었습니다");
    // NamedTempFile::persist atomically replaces the destination on the
    // same volume. Failure drops the private temp but keeps the old file.
    staged
        .persist(out_path)
        .map_err(|e| e.error)
        .with_context(|| format!("PFS0 결과 원자적 반영 실패: {}", out_path.display()))?;
    Ok(())
}

/// Mixed direct-region and generated-file PFS0 assembly. All source ranges
/// are checked before creating the destination, and cancellation works during
/// the potentially multi-gigabyte final copy.
pub fn build_from_sources(
    entries: &[(String, Pfs0Source)],
    out_path: &Path,
    cancel: &AtomicBool,
) -> Result<()> {
    if entries.is_empty() {
        bail!("PFS0 빌드 대상이 비어 있습니다");
    }
    if entries.len() > MAX_FILES as usize {
        bail!("PFS0 파일 수가 한도를 넘습니다");
    }
    let mut string_offsets = Vec::with_capacity(entries.len());
    let mut strings = Vec::new();
    let mut sizes = Vec::with_capacity(entries.len());
    let mut seen = HashSet::new();
    for (name, source) in entries {
        validate_name(name)?;
        if !seen.insert(name.to_lowercase()) {
            bail!("중복 PFS0 파일명: {name}");
        }
        string_offsets.push(strings.len() as u32);
        strings.extend_from_slice(name.as_bytes());
        strings.push(0);
        sizes.push(source.size()?);
    }
    let full_header = 16usize + entries.len() * 24 + strings.len();
    let aligned_header = (full_header + 1 + 0x1f) & !0x1f;
    strings.resize(strings.len() + (aligned_header - full_header), 0);
    let output_data_bytes = sizes
        .iter()
        .try_fold(0u64, |total, bytes| total.checked_add(*bytes))
        .context("PFS0 전체 출력 크기 오버플로")?;
    let expected_bytes = (aligned_header as u64)
        .checked_add(output_data_bytes)
        .context("PFS0 헤더 및 데이터 크기 오버플로")?;

    let parent = out_path.parent().context("PFS0 출력 디렉터리가 없습니다")?;
    fs::create_dir_all(parent)?;
    ensure!(!cancel.load(Ordering::Relaxed), "작업이 중단되었습니다");
    // The old output remains allocated until the new PFS0 is complete.
    // Do not begin a multi-gigabyte staging copy when there is no room for
    // the *whole* replacement and filesystem headroom on this volume.
    ensure_disk_space(parent, expected_bytes)?;
    let staged = tempfile::Builder::new()
        .prefix("nsrp_pfs0_")
        .suffix(".partial")
        .tempfile_in(parent)?;
    let result = (|| -> Result<()> {
        let mut out = BufWriter::with_capacity(4 * 1024 * 1024, staged.reopen()?);
        out.write_all(b"PFS0")?;
        out.write_u32::<LittleEndian>(entries.len() as u32)?;
        out.write_u32::<LittleEndian>(strings.len() as u32)?;
        out.write_u32::<LittleEndian>(0)?;
        let mut rel = 0u64;
        for (i, size) in sizes.iter().enumerate() {
            out.write_u64::<LittleEndian>(rel)?;
            out.write_u64::<LittleEndian>(*size)?;
            out.write_u32::<LittleEndian>(string_offsets[i])?;
            out.write_u32::<LittleEndian>(0)?;
            rel = rel
                .checked_add(*size)
                .context("PFS0 데이터 크기 오버플로")?;
        }
        out.write_all(&strings)?;
        let mut buf = vec![0u8; 2 * 1024 * 1024];
        let mut current_region: Option<(PathBuf, BufReader<File>)> = None;
        for ((_, source), &size) in entries.iter().zip(&sizes) {
            match source {
                Pfs0Source::File(path) => {
                    let mut src = BufReader::with_capacity(buf.len(), File::open(path)?);
                    copy_bounded(&mut src, &mut out, size, &mut buf, cancel)?;
                }
                Pfs0Source::Region {
                    container, offset, ..
                } => {
                    if current_region
                        .as_ref()
                        .is_none_or(|(path, _)| path != container)
                    {
                        current_region = Some((
                            container.clone(),
                            BufReader::with_capacity(buf.len(), File::open(container)?),
                        ));
                    }
                    let (_, reader) = current_region.as_mut().expect("region file available");
                    reader.seek(SeekFrom::Start(*offset))?;
                    copy_bounded(reader, &mut out, size, &mut buf, cancel)?;
                }
            }
        }
        out.flush()?;
        drop(out);
        let actual = staged.as_file().metadata()?.len();
        if actual != expected_bytes {
            bail!("PFS0 결과 크기 검증 실패: {actual} != {expected_bytes}");
        }
        Ok(())
    })();
    result?;
    ensure!(!cancel.load(Ordering::Relaxed), "작업이 중단되었습니다");
    staged
        .persist(out_path)
        .map_err(|e| e.error)
        .with_context(|| format!("PFS0 결과 원자적 반영 실패: {}", out_path.display()))?;
    Ok(())
}

fn validate_name(name: &str) -> Result<()> {
    super::name::validate_container_filename(name)
}

fn copy_bounded<R: Read, W: Write>(
    source: &mut R,
    output: &mut W,
    mut remaining: u64,
    scratch: &mut [u8],
    cancel: &AtomicBool,
) -> Result<()> {
    while remaining > 0 {
        if cancel.load(Ordering::Relaxed) {
            bail!("작업이 중단되었습니다");
        }
        let take = remaining.min(scratch.len() as u64) as usize;
        source.read_exact(&mut scratch[..take])?;
        output.write_all(&scratch[..take])?;
        remaining -= take as u64;
    }
    Ok(())
}

pub fn copy_n<R: Read, W: Write>(src: &mut R, dst: &mut W, mut remaining: u64) -> Result<()> {
    let mut buf = vec![0u8; 4 * 1024 * 1024];
    while remaining > 0 {
        let take = usize::try_from(remaining.min(buf.len() as u64)).unwrap();
        let n = src.read(&mut buf[..take])?;
        if n == 0 {
            bail!("컨테이너 입력이 예상보다 일찍 끝났습니다");
        }
        dst.write_all(&buf[..n])?;
        remaining -= n as u64;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bounded_copy_cancellation_after_two_megabytes_is_observed() -> Result<()> {
        struct CancelAfterFirstChunk<'a> {
            cancel: &'a AtomicBool,
            bytes: usize,
        }
        impl Write for CancelAfterFirstChunk<'_> {
            fn write(&mut self, block: &[u8]) -> io::Result<usize> {
                self.bytes += block.len();
                if self.bytes >= 2 * 1024 * 1024 {
                    self.cancel.store(true, Ordering::Relaxed);
                }
                Ok(block.len())
            }
            fn flush(&mut self) -> io::Result<()> {
                Ok(())
            }
        }
        let cancel = AtomicBool::new(false);
        let mut source = io::Cursor::new(vec![0x73u8; 8 * 1024 * 1024]);
        let mut output = CancelAfterFirstChunk {
            cancel: &cancel,
            bytes: 0,
        };
        let mut scratch = vec![0u8; 2 * 1024 * 1024];
        let result = copy_bounded(
            &mut source,
            &mut output,
            8 * 1024 * 1024,
            &mut scratch,
            &cancel,
        );
        assert!(result.is_err(), "cancellation during copy was ignored");
        assert_eq!(output.bytes, 2 * 1024 * 1024);
        assert_eq!(source.position(), 2 * 1024 * 1024);
        Ok(())
    }

    #[test]
    fn streamed_entries_match_file_packaging_byte_for_byte() -> Result<()> {
        let dir = tempfile::tempdir()?;
        let paths = [
            ("first.nca".to_string(), dir.path().join("first.bin")),
            ("second.tik".to_string(), dir.path().join("second.bin")),
        ];
        fs::write(&paths[0].1, vec![0x61u8; 4 * 1024 * 1024 + 37])?;
        fs::write(&paths[1].1, b"abcdefg")?;
        let staged = dir.path().join("staged.nsp");
        let streamed = dir.path().join("streamed.nsp");
        build_from_paths(&paths, &staged)?;
        let names = paths
            .iter()
            .map(|(name, _)| name.clone())
            .collect::<Vec<_>>();
        build_from_streams(&names, &streamed, &AtomicBool::new(false), |i, out| {
            let mut file = File::open(&paths[i].1)?;
            io::copy(&mut file, out)?;
            Ok(())
        })?;
        assert_eq!(fs::read(staged)?, fs::read(streamed)?);
        Ok(())
    }

    #[test]
    fn streamed_failure_cleans_partial_without_replacing_existing_output() -> Result<()> {
        let dir = tempfile::tempdir()?;
        let dest = dir.path().join("existing.nsz");
        fs::write(&dest, b"previous valid package")?;
        let names = vec!["entry.ncz".to_string()];
        let err = build_from_streams(&names, &dest, &AtomicBool::new(false), |_, out| {
            out.write_all(b"half written")?;
            bail!("simulated encoder failure");
        });
        assert!(err.is_err());
        assert_eq!(fs::read(&dest)?, b"previous valid package");
        assert!(!dest.with_extension("nsz.partial").exists());
        let canceled = AtomicBool::new(true);
        assert!(build_from_streams(&names, &dest, &canceled, |_, _| Ok(())).is_err());
        assert_eq!(fs::read(dest)?, b"previous valid package");
        Ok(())
    }

    #[cfg(windows)]
    #[test]
    fn disk_full_error_in_middle_of_output_preserves_completed_destination() -> Result<()> {
        let dir = tempfile::tempdir()?;
        let dest = dir.path().join("existing_output.nsz");
        let original = b"fully completed previous game package".to_vec();
        fs::write(&dest, &original)?;
        let observed_flushed_partial = AtomicBool::new(false);
        let failed = build_from_streams(
            &["program.ncz".to_owned()],
            &dest,
            &AtomicBool::new(false),
            |_, out| {
                out.write_all(&vec![0x5a; 8 * 1024 * 1024])?;
                out.flush()?;
                ensure!(
                    out.get_ref().metadata()?.len() >= 8 * 1024 * 1024,
                    "a real temporary file must contain more than 1 MiB before failure"
                );
                observed_flushed_partial.store(true, Ordering::Relaxed);
                // Controlled I/O error emulates ERROR_DISK_FULL without
                // exhausting the user's actual system volume.
                Err(io::Error::from_raw_os_error(112).into())
            },
        );
        assert!(observed_flushed_partial.load(Ordering::Relaxed));
        assert!(failed.is_err(), "injected storage-full failure was ignored");
        assert_eq!(fs::read(&dest)?, original);
        assert!(
            fs::read_dir(dir.path())?
                .filter_map(Result::ok)
                .all(|file| !file.file_name().to_string_lossy().ends_with(".partial"))
        );
        Ok(())
    }

    #[test]
    fn cancellation_after_writing_payload_keeps_previous_complete_file() -> Result<()> {
        let dir = tempfile::tempdir()?;
        let dest = dir.path().join("existing_output.nsp");
        let original = b"old finished archive".to_vec();
        fs::write(&dest, &original)?;
        let cancel = AtomicBool::new(false);
        let failed = build_from_streams(&["program.nca".to_owned()], &dest, &cancel, |_, out| {
            out.write_all(&vec![0x11; 1024 * 1024])?;
            cancel.store(true, Ordering::Relaxed);
            Ok(())
        });
        assert!(failed.is_err(), "late cancellation was ignored");
        assert_eq!(fs::read(&dest)?, original);
        assert!(
            fs::read_dir(dir.path())?
                .filter_map(Result::ok)
                .all(|file| !file.file_name().to_string_lossy().ends_with(".partial"))
        );
        Ok(())
    }

    #[cfg(windows)]
    #[test]
    fn locked_source_in_direct_region_package_preserves_previous_output() -> Result<()> {
        use std::os::windows::fs::OpenOptionsExt;
        let dir = tempfile::tempdir()?;
        let source = dir.path().join("locked_source.nca");
        let dest = dir.path().join("old_valid_result.nsp");
        fs::write(&source, vec![0x37; 5 * 1024 * 1024])?;
        fs::write(&dest, b"completed PFS0 that must be retained")?;
        let hold = fs::OpenOptions::new()
            .read(true)
            .share_mode(0)
            .open(&source)?;
        let failed = build_from_sources(
            &[("program.nca".to_owned(), Pfs0Source::File(source.clone()))],
            &dest,
            &AtomicBool::new(false),
        );
        assert!(failed.is_err(), "locked source was unexpectedly readable");
        drop(hold);
        assert_eq!(fs::read(&dest)?, b"completed PFS0 that must be retained");
        assert!(
            fs::read_dir(dir.path())?
                .filter_map(Result::ok)
                .all(|file| !file.file_name().to_string_lossy().ends_with(".partial"))
        );
        Ok(())
    }

    #[test]
    fn direct_regions_match_staged_package_byte_for_byte() -> Result<()> {
        let tmp = tempfile::tempdir()?;
        let paths = [
            ("가.nca".into(), tmp.path().join("a.nca")),
            ("b.tik".into(), tmp.path().join("b.tik")),
        ];
        fs::write(&paths[0].1, vec![7u8; 4 * 1024 * 1024 + 37])?;
        fs::write(&paths[1].1, b"small ticket")?;
        let original = tmp.path().join("input.nsp");
        build_from_paths(&paths, &original)?;
        let index = Pfs0Index::parse(&original)?;
        let regions = index
            .entries
            .iter()
            .map(|entry| {
                (
                    entry.name.clone(),
                    Pfs0Source::Region {
                        container: original.clone(),
                        offset: index.data_start + entry.offset,
                        size: entry.size,
                    },
                )
            })
            .collect::<Vec<_>>();
        let direct = tmp.path().join("direct.nsp");
        build_from_sources(&regions, &direct, &AtomicBool::new(false))?;
        assert_eq!(fs::read(&original)?, fs::read(&direct)?);
        let mixed = tmp.path().join("mixed.nsp");
        let mixed_sources = vec![
            regions[0].clone(),
            (
                index.entries[1].name.clone(),
                Pfs0Source::File(paths[1].1.clone()),
            ),
        ];
        build_from_sources(&mixed_sources, &mixed, &AtomicBool::new(false))?;
        assert_eq!(fs::read(&original)?, fs::read(&mixed)?);
        Ok(())
    }

    #[test]
    fn invalid_region_and_cancel_leave_no_output() -> Result<()> {
        let tmp = tempfile::tempdir()?;
        let src = tmp.path().join("source.nca");
        fs::write(&src, vec![0x55u8; 4 * 1024 * 1024])?;
        let invalid = tmp.path().join("invalid.nsp");
        let range = vec![(
            "invalid.nca".to_owned(),
            Pfs0Source::Region {
                container: src.clone(),
                offset: 4 * 1024 * 1024 - 1,
                size: 2,
            },
        )];
        assert!(build_from_sources(&range, &invalid, &AtomicBool::new(false)).is_err());
        assert!(!invalid.exists());
        let canceled = tmp.path().join("cancel.nsp");
        assert!(
            build_from_sources(
                &[("cancel.nca".to_owned(), Pfs0Source::File(src))],
                &canceled,
                &AtomicBool::new(true)
            )
            .is_err()
        );
        assert!(!canceled.exists());
        assert!(!canceled.with_extension("nsp.partial").exists());
        Ok(())
    }

    #[test]
    fn completed_output_is_replaced_only_by_valid_complete_pfs0() -> Result<()> {
        let dir = tempfile::tempdir()?;
        let dest = dir.path().join("existing.nsp");
        let input = dir.path().join("source.bin");
        fs::write(&dest, b"original completed output")?;
        fs::write(&input, b"replacement payload")?;
        let names = vec!["first.nca".to_owned()];
        build_from_streams(&names, &dest, &AtomicBool::new(false), |_, writer| {
            writer.write_all(b"replacement payload")?;
            Ok(())
        })?;
        let first = Pfs0Index::parse(&dest)?;
        assert_eq!(
            first.read_entry(&dest, first.entry("first.nca").unwrap())?,
            b"replacement payload"
        );
        let sources = vec![("second.nca".to_owned(), Pfs0Source::File(input))];
        build_from_sources(&sources, &dest, &AtomicBool::new(false))?;
        let second = Pfs0Index::parse(&dest)?;
        assert_eq!(
            second.read_entry(&dest, second.entry("second.nca").unwrap())?,
            b"replacement payload"
        );
        assert!(
            fs::read_dir(dir.path())?
                .filter_map(Result::ok)
                .all(|f| !f.file_name().to_string_lossy().ends_with(".partial"))
        );
        Ok(())
    }

    #[test]
    fn same_destination_concurrent_streams_never_share_a_partial_file() -> Result<()> {
        use std::sync::{Arc, Barrier};
        let dir = tempfile::tempdir()?;
        let dest = dir.path().join("simultaneous.nsp");
        fs::write(&dest, b"preexisting complete output")?;
        let start = Arc::new(Barrier::new(3));
        let handles = (0..2)
            .map(|i| {
                let start = Arc::clone(&start);
                let dest = dest.clone();
                std::thread::spawn(move || {
                    let entry = format!("writer_{i}.nca");
                    start.wait();
                    build_from_streams(&[entry], &dest, &AtomicBool::new(false), |_, out| {
                        out.write_all(&vec![i as u8 + 1; 1024 * 1024])?;
                        Ok(())
                    })
                })
            })
            .collect::<Vec<_>>();
        start.wait();
        let outcomes = handles
            .into_iter()
            .map(|thread| thread.join().expect("worker panicked"))
            .collect::<Vec<_>>();
        assert!(
            outcomes.iter().any(Result::is_ok),
            "at least one isolated writer should publish"
        );
        let index = Pfs0Index::parse(&dest)?;
        assert_eq!(index.entries.len(), 1);
        assert!(matches!(
            index.entries[0].name.as_str(),
            "writer_0.nca" | "writer_1.nca"
        ));
        assert_eq!(index.entries[0].size, 1024 * 1024);
        assert!(
            fs::read_dir(dir.path())?
                .filter_map(Result::ok)
                .all(|file| !file.file_name().to_string_lossy().ends_with(".partial"))
        );
        Ok(())
    }

    #[cfg(windows)]
    #[test]
    fn blocked_atomic_replace_preserves_previous_file_and_cleans_temp() -> Result<()> {
        use std::os::windows::fs::OpenOptionsExt;
        let dir = tempfile::tempdir()?;
        let dest = dir.path().join("locked.nsz");
        fs::write(&dest, b"completed bytes must survive")?;
        // No sharing, including delete; Windows must deny atomic rename.
        let hold = std::fs::OpenOptions::new()
            .read(true)
            .share_mode(0)
            .open(&dest)?;
        let failed = build_from_streams(
            &["entry.nca".to_owned()],
            &dest,
            &AtomicBool::new(false),
            |_, writer| {
                writer.write_all(b"a complete replacement that must not publish")?;
                Ok(())
            },
        );
        assert!(failed.is_err(), "locked old output unexpectedly replaced");
        drop(hold);
        assert_eq!(fs::read(&dest)?, b"completed bytes must survive");
        assert!(
            fs::read_dir(dir.path())?
                .filter_map(Result::ok)
                .all(|file| !file.file_name().to_string_lossy().ends_with(".partial"))
        );
        Ok(())
    }

    #[cfg(windows)]
    #[test]
    #[ignore = "requires NTFS sparse-file support in a disposable QA directory"]
    fn stage89_sparse_36gib_pfs0_4_8_16gib_offsets() -> Result<()> {
        use std::os::windows::fs::MetadataExt;
        let owner = tempfile::tempdir()?;
        let path = owner.path().join("sparse.nsp");
        File::create(&path)?;
        let status = std::process::Command::new("fsutil.exe")
            .arg("sparse")
            .arg("setflag")
            .arg(&path)
            .status()?;
        ensure!(
            status.success() && fs::metadata(&path)?.file_attributes() & 0x200 != 0,
            "Sparse flag unavailable; refusing large file allocation"
        );
        let offsets = [4u64 << 30, 8u64 << 30, 16u64 << 30, 34u64 << 30];
        let mut header = b"PFS0".to_vec();
        header.write_u32::<LittleEndian>(4)?;
        let names = b"a.nca\0b.nca\0c.nca\0d.nca\0";
        header.write_u32::<LittleEndian>(names.len() as u32)?;
        header.write_u32::<LittleEndian>(0)?;
        for (i, offset) in offsets.into_iter().enumerate() {
            header.write_u64::<LittleEndian>(offset)?;
            header.write_u64::<LittleEndian>(16)?;
            header.write_u32::<LittleEndian>((i * 6) as u32)?;
            header.write_u32::<LittleEndian>(0)?;
        }
        header.extend_from_slice(names);
        let mut file = fs::OpenOptions::new().write(true).read(true).open(&path)?;
        file.set_len(36u64 << 30)?;
        file.write_all(&header)?;
        for (i, offset) in offsets.into_iter().enumerate() {
            file.seek(SeekFrom::Start(header.len() as u64 + offset))?;
            file.write_all(&[i as u8 + 1; 16])?;
        }
        file.sync_all()?;
        let index = Pfs0Index::parse(&path)?;
        for (i, entry) in index.entries.iter().enumerate() {
            assert_eq!(entry.offset, offsets[i]);
            assert_eq!(index.read_entry(&path, entry)?, vec![i as u8 + 1; 16]);
        }
        assert!(
            Pfs0Index::parse_reader(&mut file, 0, header.len() as u64 + offsets[3] + 15).is_err()
        );
        println!("STAGE89_SPARSE_REAL_36GIB_OFFSET_PASS");
        Ok(())
    }

    #[test]
    fn stage87_pfs0_rejects_oversized_index_before_allocating_or_reading_it() -> Result<()> {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(b"PFS0");
        bytes.extend_from_slice(&1u32.to_le_bytes());
        bytes.extend_from_slice(&MAX_STRING_TABLE.to_le_bytes());
        bytes.extend_from_slice(&0u32.to_le_bytes());
        let mut reader = std::io::Cursor::new(bytes);
        let error = Pfs0Index::parse_reader(&mut reader, 0, 16).unwrap_err();
        assert!(error.to_string().contains("bounded region"));
        assert_eq!(reader.position(), 16);
        assert!(Pfs0Index::parse_reader(&mut reader, u64::MAX - 1, 16).is_err());
        Ok(())
    }

    #[test]
    fn pfs0_roundtrip() -> Result<()> {
        let temp = tempfile::tempdir()?;
        fs::write(temp.path().join("a.nca"), b"abc")?;
        fs::write(temp.path().join("b.cnmt.nca"), vec![7u8; 10_003])?;
        let out = temp.path().join("sample.nsp");
        build_from_dir(temp.path(), &out)?;
        let idx = Pfs0Index::parse(&out)?;
        assert_eq!(idx.entries.len(), 2);
        assert_eq!(idx.read_entry(&out, idx.entry("a.nca").unwrap())?, b"abc");
        Ok(())
    }
}
