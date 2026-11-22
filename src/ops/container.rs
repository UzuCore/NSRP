use crate::formats::{hfs0, pfs0::Pfs0Index};
use anyhow::{Result, bail};
use std::{
    fs::File,
    io::{BufReader, BufWriter, Read, Seek, SeekFrom, Write},
    path::Path,
    sync::atomic::{AtomicBool, Ordering},
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ContainerEntry {
    pub name: String,
    pub offset: u64,
    pub size: u64,
}

pub fn list_entries(path: &Path, skip_system_partitions: bool) -> Result<Vec<ContainerEntry>> {
    let ext = path
        .extension()
        .and_then(|s| s.to_str())
        .unwrap_or("")
        .to_ascii_lowercase();
    match ext.as_str() {
        "nsp" | "nsz" => {
            let index = Pfs0Index::parse(path)?;
            Ok(index
                .entries
                .into_iter()
                .map(|e| ContainerEntry {
                    name: e.name,
                    offset: index.data_start + e.offset,
                    size: e.size,
                })
                .collect())
        }
        "xci" | "xcz" => Ok(hfs0::collect_leaf_entries(path, skip_system_partitions)?
            .into_iter()
            .map(|(name, offset, size)| ContainerEntry { name, offset, size })
            .collect()),
        _ => bail!("지원하지 않는 컨테이너 형식: {}", path.display()),
    }
}

/// 일반 XCI/XCZ에서는 system/update/normal 파티션을 건너뛰되, 구형 병합 도구가
/// 게임 CNMT 자체를 해당 파티션에 넣어 둔 컨테이너는 전체 파티션으로 한 번 재시도한다.
/// 반환 bool은 legacy partition fallback 사용 여부다.
pub fn list_entries_with_metadata_fallback(path: &Path) -> Result<(Vec<ContainerEntry>, bool)> {
    let entries = list_entries(path, true)?;
    let ext = path
        .extension()
        .and_then(|value| value.to_str())
        .unwrap_or("")
        .to_ascii_lowercase();
    if !matches!(ext.as_str(), "xci" | "xcz")
        || entries
            .iter()
            .any(|entry| crate::ops::cnmt::is_cnmt_container_entry(&entry.name))
    {
        return Ok((entries, false));
    }

    let all_entries = list_entries(path, false)?;
    if all_entries
        .iter()
        .any(|entry| crate::ops::cnmt::is_cnmt_container_entry(&entry.name))
    {
        return Ok((all_entries, true));
    }
    Ok((entries, false))
}

pub fn extract_entry(
    container: &Path,
    entry: &ContainerEntry,
    out_path: &Path,
    cancel: &AtomicBool,
) -> Result<()> {
    if let Some(parent) = out_path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let mut input = BufReader::with_capacity(8 * 1024 * 1024, File::open(container)?);
    input.seek(SeekFrom::Start(entry.offset))?;
    let mut output = BufWriter::with_capacity(8 * 1024 * 1024, File::create(out_path)?);
    let mut remaining = entry.size;
    let mut buffer = vec![0u8; 8 * 1024 * 1024];
    while remaining > 0 {
        if cancel.load(Ordering::Relaxed) {
            bail!("작업이 중단되었습니다");
        }
        let take = remaining.min(buffer.len() as u64) as usize;
        input.read_exact(&mut buffer[..take])?;
        output.write_all(&buffer[..take])?;
        remaining -= take as u64;
    }
    output.flush()?;
    Ok(())
}

pub fn extract_entries(
    container: &Path,
    entries: &[ContainerEntry],
    out_dir: &Path,
    cancel: &AtomicBool,
    progress: &mut dyn FnMut(f32),
) -> Result<()> {
    std::fs::create_dir_all(out_dir)?;
    let total = entries.iter().map(|e| e.size).sum::<u64>().max(1);
    let mut done = 0u64;
    // Reuse one package handle and one 2 MiB buffer instead of reopening
    // every entry and allocating three 8 MiB buffers for each extraction.
    let mut source = BufReader::with_capacity(2 * 1024 * 1024, File::open(container)?);
    let mut scratch = vec![0u8; 2 * 1024 * 1024];
    for entry in entries {
        if cancel.load(Ordering::Relaxed) {
            bail!("작업이 중단되었습니다");
        }
        source.seek(SeekFrom::Start(entry.offset))?;
        let mut output =
            BufWriter::with_capacity(2 * 1024 * 1024, File::create(out_dir.join(&entry.name))?);
        let mut left = entry.size;
        while left > 0 {
            if cancel.load(Ordering::Relaxed) {
                bail!("작업이 중단되었습니다");
            }
            let take = left.min(scratch.len() as u64) as usize;
            source.read_exact(&mut scratch[..take])?;
            output.write_all(&scratch[..take])?;
            left -= take as u64;
        }
        output.flush()?;
        done += entry.size;
        progress(done as f32 / total as f32);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::formats::pfs0::build_from_paths;

    #[test]
    fn batched_extraction_matches_package_and_handles_cancellation() -> Result<()> {
        let tmp = tempfile::tempdir()?;
        let first = tmp.path().join("a.nca");
        let second = tmp.path().join("b.tik");
        let large = (0..(4 * 1024 * 1024 + 17))
            .map(|i| (i % 251) as u8)
            .collect::<Vec<_>>();
        std::fs::write(&first, &large)?;
        std::fs::write(&second, b"ticket")?;
        let container = tmp.path().join("game.nsp");
        build_from_paths(
            &[("a.nca".into(), first), ("b.tik".into(), second)],
            &container,
        )?;
        let entries = list_entries(&container, false)?;
        let mut progress = Vec::new();
        let output = tmp.path().join("output");
        extract_entries(
            &container,
            &entries,
            &output,
            &AtomicBool::new(false),
            &mut |value| progress.push(value),
        )?;
        assert_eq!(std::fs::read(output.join("a.nca"))?, large);
        assert_eq!(std::fs::read(output.join("b.tik"))?, b"ticket");
        assert_eq!(progress.len(), 2);
        assert!((progress[1] - 1.0).abs() < f32::EPSILON);
        let aborted = tmp.path().join("aborted");
        assert!(
            extract_entries(
                &container,
                &entries,
                &aborted,
                &AtomicBool::new(true),
                &mut |_| {}
            )
            .is_err()
        );
        assert!(!aborted.join("a.nca").exists());
        Ok(())
    }
}
