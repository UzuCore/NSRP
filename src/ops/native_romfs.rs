//! Deterministic, streaming Nintendo Switch RomFS image writer.
//!
//! Rebuilds both directory and file trees, hash buckets and collision chains.
//! The input directory is never modified; partial output stays in a temporary
//! file and only a validated image is published at a new path.

use anyhow::{Context, Result, ensure};
use std::{
    collections::HashSet,
    fs::{self, File},
    io::{Read, Seek, SeekFrom, Write},
    path::{Path, PathBuf},
    sync::atomic::{AtomicBool, Ordering},
};

const EMPTY: u32 = u32::MAX;
const HEADER_SIZE: u64 = 0x50;
const MAX_ENTRIES: usize = 200_000;
const MAX_METADATA: usize = 256 * 1024 * 1024;

#[derive(Debug, Clone, Copy)]
pub struct RomfsBuildStats {
    pub files: usize,
    pub directories: usize,
    pub bytes: u64,
}

struct Directory {
    name: String,
    path: PathBuf,
    parent: Option<usize>,
    children: Vec<usize>,
    files: Vec<usize>,
    record: u32,
}

struct Entry {
    name: String,
    path: PathBuf,
    parent: usize,
    length: u64,
    data_offset: u64,
    record: u32,
}

fn put32(bytes: &mut [u8], at: usize, value: u32) {
    bytes[at..at + 4].copy_from_slice(&value.to_le_bytes());
}

fn put64(bytes: &mut [u8], at: usize, value: u64) {
    bytes[at..at + 8].copy_from_slice(&value.to_le_bytes());
}

fn align(value: u64, by: u64) -> Result<u64> {
    value
        .checked_add(by - 1)
        .map(|v| v / by * by)
        .context("RomFS alignment overflow")
}

fn check_name(name: &str) -> Result<()> {
    ensure!(
        !name.is_empty()
            && !matches!(name, "." | "..")
            && !name.ends_with([' ', '.'])
            && name.len() <= 1024
            && !name.chars().any(|ch| {
                ch.is_control()
                    || matches!(ch, '/' | '\\' | '<' | '>' | ':' | '"' | '|' | '?' | '*')
            }),
        "unsafe RomFS entry name"
    );
    let stem = name.split('.').next().unwrap_or("").to_ascii_uppercase();
    ensure!(
        !matches!(stem.as_str(), "CON" | "PRN" | "AUX" | "NUL")
            && !(stem.len() == 4
                && (stem.starts_with("COM") || stem.starts_with("LPT"))
                && stem.as_bytes()[3].is_ascii_digit()
                && stem.as_bytes()[3] != b'0'),
        "Windows reserved RomFS name"
    );
    Ok(())
}

fn ensure_regular(metadata: &fs::Metadata) -> Result<()> {
    ensure!(
        !metadata.file_type().is_symlink(),
        "RomFS symlink is unsupported"
    );
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt;
        ensure!(
            metadata.file_attributes() & 0x400 == 0,
            "RomFS reparse-point input is unsupported"
        );
    }
    Ok(())
}

fn scan(root: &Path, cancel: &AtomicBool) -> Result<(Vec<Directory>, Vec<Entry>)> {
    let meta = fs::symlink_metadata(root)?;
    ensure_regular(&meta)?;
    ensure!(meta.is_dir(), "RomFS input is not a directory");
    let mut directories = vec![Directory {
        name: String::new(),
        path: root.to_owned(),
        parent: None,
        children: Vec::new(),
        files: Vec::new(),
        record: 0,
    }];
    let mut files = Vec::new();
    let mut seen = HashSet::new();
    let mut index = 0;
    while index < directories.len() {
        ensure!(!cancel.load(Ordering::Relaxed), "작업이 중단되었습니다");
        let mut children =
            fs::read_dir(&directories[index].path)?.collect::<std::io::Result<Vec<_>>>()?;
        children.sort_by_key(|entry| entry.file_name().to_string_lossy().into_owned());
        for child in children {
            let name = child
                .file_name()
                .into_string()
                .map_err(|_| anyhow::anyhow!("RomFS filename is not UTF-8"))?;
            check_name(&name)?;
            let path = child.path();
            let relative = path.strip_prefix(root)?;
            ensure!(
                seen.insert(relative.to_string_lossy().to_lowercase()),
                "case-colliding RomFS paths"
            );
            let metadata = fs::symlink_metadata(&path)?;
            ensure_regular(&metadata)?;
            if metadata.is_dir() {
                let child_index = directories.len();
                directories.push(Directory {
                    name,
                    path,
                    parent: Some(index),
                    children: Vec::new(),
                    files: Vec::new(),
                    record: 0,
                });
                directories[index].children.push(child_index);
            } else {
                ensure!(metadata.is_file(), "RomFS special file is unsupported");
                files.push(Entry {
                    name,
                    path,
                    parent: index,
                    length: metadata.len(),
                    data_offset: 0,
                    record: 0,
                });
                directories[index].files.push(files.len() - 1);
            }
            ensure!(
                files.len() + directories.len() <= MAX_ENTRIES,
                "RomFS has too many entries"
            );
        }
        index += 1;
    }
    Ok((directories, files))
}

fn bucket_count(count: usize) -> usize {
    if count < 3 {
        return 3;
    }
    if count < 19 {
        return count | 1;
    }
    let mut value = count;
    while [2, 3, 5, 7, 11, 13, 17]
        .iter()
        .any(|prime| value.is_multiple_of(*prime))
    {
        value += 1;
    }
    value
}

fn name_hash(parent_record: u32, name: &[u8]) -> u32 {
    name.iter().fold(parent_record ^ 123_456_789, |acc, byte| {
        acc.rotate_right(5) ^ u32::from(*byte)
    })
}

fn alloc_record(table: &mut Vec<u8>, record_len: usize, name: &str) -> Result<u32> {
    let at = table.len();
    let size = record_len
        .checked_add(name.len())
        .context("RomFS metadata overflow")?;
    let new_len = usize::try_from(align((at + size) as u64, 4)?)?;
    ensure!(new_len <= MAX_METADATA, "RomFS metadata too large");
    table.resize(new_len, 0);
    table[at + record_len..at + record_len + name.len()].copy_from_slice(name.as_bytes());
    Ok(u32::try_from(at)?)
}

fn make_tables(dirs: &mut [Directory], files: &mut [Entry]) -> Result<[Vec<u8>; 4]> {
    let mut dir_records = Vec::new();
    let mut file_records = Vec::new();
    for dir in dirs.iter_mut() {
        dir.record = alloc_record(&mut dir_records, 0x18, &dir.name)?;
    }
    for file in files.iter_mut() {
        file.record = alloc_record(&mut file_records, 0x20, &file.name)?;
    }
    // Precompute sibling record offsets once: no quadratic searches through
    // directories containing thousands of game assets.
    let mut next_directory = vec![EMPTY; dirs.len()];
    let mut next_file = vec![EMPTY; files.len()];
    for dir in dirs.iter() {
        for siblings in dir.children.windows(2) {
            next_directory[siblings[0]] = dirs[siblings[1]].record;
        }
        for siblings in dir.files.windows(2) {
            next_file[siblings[0]] = files[siblings[1]].record;
        }
    }
    let mut dir_hash = vec![EMPTY; bucket_count(dirs.len())];
    let mut file_hash = vec![EMPTY; bucket_count(files.len())];
    for (i, dir) in dirs.iter().enumerate() {
        let at = dir.record as usize;
        // The RomFS root is its own parent (record offset 0), not a sentinel.
        let parent = dir.parent.map_or(0, |id| dirs[id].record);
        put32(&mut dir_records, at, parent);
        put32(&mut dir_records, at + 4, next_directory[i]);
        put32(
            &mut dir_records,
            at + 8,
            dir.children.first().map_or(EMPTY, |id| dirs[*id].record),
        );
        put32(
            &mut dir_records,
            at + 12,
            dir.files.first().map_or(EMPTY, |id| files[*id].record),
        );
        put32(&mut dir_records, at + 20, u32::try_from(dir.name.len())?);
        let bucket = name_hash(parent, dir.name.as_bytes()) as usize % dir_hash.len();
        put32(&mut dir_records, at + 16, dir_hash[bucket]);
        dir_hash[bucket] = dir.record;
    }
    for (i, file) in files.iter().enumerate() {
        let at = file.record as usize;
        let parent = dirs[file.parent].record;
        put32(&mut file_records, at, parent);
        put32(&mut file_records, at + 4, next_file[i]);
        put64(&mut file_records, at + 8, file.data_offset);
        put64(&mut file_records, at + 16, file.length);
        put32(&mut file_records, at + 28, u32::try_from(file.name.len())?);
        let bucket = name_hash(parent, file.name.as_bytes()) as usize % file_hash.len();
        put32(&mut file_records, at + 24, file_hash[bucket]);
        file_hash[bucket] = file.record;
    }
    let to_bytes = |buckets: Vec<u32>| {
        buckets
            .into_iter()
            .flat_map(u32::to_le_bytes)
            .collect::<Vec<_>>()
    };
    Ok([
        to_bytes(dir_hash),
        dir_records,
        to_bytes(file_hash),
        file_records,
    ])
}

/// Construct a complete new RomFS image, including empty folders and renamed,
/// added or deleted entries. The caller must supply an unused output path.
pub fn build_romfs(root: &Path, output: &Path, cancel: &AtomicBool) -> Result<RomfsBuildStats> {
    ensure!(!output.exists(), "RomFS writer refuses to overwrite output");
    let dest_parent = output.parent().context("RomFS output parent missing")?;
    fs::create_dir_all(dest_parent)?;
    ensure!(
        !dest_parent
            .canonicalize()?
            .starts_with(root.canonicalize()?),
        "RomFS output must be outside input tree"
    );
    let (mut dirs, mut files) = scan(root, cancel)?;
    let mut data_size = 0u64;
    for entry in &mut files {
        data_size = align(data_size, 16)?;
        entry.data_offset = data_size;
        data_size = data_size
            .checked_add(entry.length)
            .context("RomFS file region overflow")?;
    }
    // The canonical RomFS layout puts both hash and metadata tables before
    // the file data. In particular, LibHac validates this table ordering.
    let tables = make_tables(&mut dirs, &mut files)?;
    let mut staged = tempfile::NamedTempFile::new_in(dest_parent)?;
    let output_file = staged.as_file_mut();
    output_file.write_all(&[0u8; HEADER_SIZE as usize])?;
    let mut position = HEADER_SIZE;
    let mut header = [0u8; HEADER_SIZE as usize];
    put64(&mut header, 0, HEADER_SIZE);
    for (index, table) in tables.iter().enumerate() {
        let aligned = align(position, 16)?;
        output_file.write_all(&vec![0u8; usize::try_from(aligned - position)?])?;
        position = aligned;
        let field = 0x08 + index * 0x10;
        put64(&mut header, field, position);
        put64(&mut header, field + 8, table.len() as u64);
        output_file.write_all(table)?;
        position = position
            .checked_add(table.len() as u64)
            .context("RomFS metadata position overflow")?;
    }
    let start_data = align(position, 16)?;
    output_file.write_all(&vec![0u8; usize::try_from(start_data - position)?])?;
    position = start_data;
    put64(&mut header, 0x48, start_data);
    let mut buffer = vec![0u8; 256 * 1024];
    for entry in &files {
        ensure!(!cancel.load(Ordering::Relaxed), "작업이 중단되었습니다");
        let desired = start_data
            .checked_add(entry.data_offset)
            .context("RomFS entry offset overflow")?;
        ensure!(desired >= position, "RomFS data offsets are not ordered");
        output_file.write_all(&vec![0u8; usize::try_from(desired - position)?])?;
        position = desired;
        let mut source = File::open(&entry.path)?;
        ensure!(
            source.metadata()?.len() == entry.length,
            "RomFS input changed during build"
        );
        let mut remaining = entry.length;
        while remaining > 0 {
            ensure!(!cancel.load(Ordering::Relaxed), "작업이 중단되었습니다");
            let take = usize::try_from(remaining.min(buffer.len() as u64))?;
            source.read_exact(&mut buffer[..take])?;
            output_file.write_all(&buffer[..take])?;
            remaining -= take as u64;
        }
        ensure!(
            source.read(&mut buffer[..1])? == 0,
            "RomFS input grew during build"
        );
        position = position
            .checked_add(entry.length)
            .context("RomFS size overflow")?;
    }
    ensure!(
        position == start_data + data_size,
        "RomFS data layout mismatch"
    );
    output_file.seek(SeekFrom::Start(0))?;
    output_file.write_all(&header)?;
    output_file.flush()?;
    ensure!(
        output_file.metadata()?.len() == position,
        "RomFS image size mismatch"
    );
    staged.persist_noclobber(output)?;
    Ok(RomfsBuildStats {
        files: files.len(),
        directories: dirs.len() - 1,
        bytes: position,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ops::native_fs::romfs_file_index;

    #[test]
    fn builds_nested_unicode_empty_directories_and_mutations() -> Result<()> {
        let temp = tempfile::tempdir()?;
        let root = temp.path().join("input");
        fs::create_dir_all(root.join("한글/空目录"))?;
        fs::create_dir_all(root.join("empty"))?;
        fs::write(root.join("한글/a.txt"), b"new data")?;
        fs::write(root.join("zero.bin"), b"")?;
        let first = temp.path().join("first.romfs");
        let stats = build_romfs(&root, &first, &AtomicBool::new(false))?;
        assert_eq!(stats.files, 2);
        assert_eq!(stats.directories, 3);
        let input = fs::read(&first)?;
        let index = romfs_file_index(&input, 0, input.len() as u64)?;
        assert_eq!(index.len(), 2);
        assert!(
            index
                .iter()
                .any(|(p, _, len, _)| p == Path::new("한글/a.txt") && *len == 8)
        );
        fs::rename(root.join("한글/a.txt"), root.join("한글/renamed.txt"))?;
        fs::remove_file(root.join("zero.bin"))?;
        fs::write(root.join("한글/added.bin"), vec![5u8; 513])?;
        let second = temp.path().join("second.romfs");
        build_romfs(&root, &second, &AtomicBool::new(false))?;
        let output = fs::read(&second)?;
        let updated = romfs_file_index(&output, 0, output.len() as u64)?;
        assert_eq!(updated.len(), 2);
        assert!(
            updated
                .iter()
                .any(|(p, _, len, _)| p == Path::new("한글/added.bin") && *len == 513)
        );
        assert!(
            !updated
                .iter()
                .any(|(p, _, _, _)| p == Path::new("zero.bin"))
        );
        Ok(())
    }

    #[test]
    fn rejects_unsafe_inputs_and_existing_output() -> Result<()> {
        let temp = tempfile::tempdir()?;
        let root = temp.path().join("in");
        fs::create_dir_all(&root)?;
        fs::write(root.join("ok"), b"okay")?;
        let output = temp.path().join("test.romfs");
        build_romfs(&root, &output, &AtomicBool::new(false))?;
        assert!(build_romfs(&root, &output, &AtomicBool::new(false)).is_err());
        assert!(build_romfs(&root, &root.join("unsafe.romfs"), &AtomicBool::new(false)).is_err());
        Ok(())
    }
}
