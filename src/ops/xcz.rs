use crate::{
    formats::{
        hfs0::{self, Hfs0Index},
        nca::{NCA_NCZ_HEADER_SIZE, make_ncz_plan_from_reader},
        ncz_stream::{decompress_ncz_region_to_nca, write_nca_region_to_ncz},
    },
    keys::KeySet,
};
use anyhow::{Context, Result, bail};
use byteorder::{LittleEndian, WriteBytesExt};
use sha2::{Digest, Sha256};
use std::{
    fs::{self, File},
    io::{BufReader, BufWriter, Read, Seek, SeekFrom, Write},
    path::{Path, PathBuf},
    sync::atomic::{AtomicBool, Ordering},
};

#[derive(Debug, Clone)]
pub struct XczOptions {
    pub level: i32,
    pub threads: usize,
    pub block_mode: bool,
    pub long_mode: bool,
}

impl Default for XczOptions {
    fn default() -> Self {
        Self {
            level: 18,
            threads: num_cpus::get().max(1),
            block_mode: true,
            long_mode: false,
        }
    }
}

#[derive(Debug, Clone, Default)]
pub struct XczStats {
    pub nca_count: usize,
    pub ncz_count: usize,
    pub input_size: u64,
    pub output_size: u64,
}

pub fn compress_xci(
    input: &Path,
    output: &Path,
    keys: &mut KeySet,
    options: &XczOptions,
    cancel: &AtomicBool,
    progress: &mut dyn FnMut(f32),
    log: &mut dyn FnMut(String),
) -> Result<XczStats> {
    transform_xci(input, output, Some((keys, options)), cancel, progress, log)
}

pub fn decompress_xcz(
    input: &Path,
    output: &Path,
    cancel: &AtomicBool,
    progress: &mut dyn FnMut(f32),
    log: &mut dyn FnMut(String),
) -> Result<XczStats> {
    transform_xci(input, output, None, cancel, progress, log)
}

pub fn decompress_xcz_repaired(
    input: &Path,
    output: &Path,
    hactool: &Path,
    prod_keys: &Path,
    cancel: &AtomicBool,
    progress: &mut dyn FnMut(f32),
    log: &mut dyn FnMut(String),
) -> Result<XczStats> {
    let stats = transform_xci(
        input,
        output,
        None,
        cancel,
        &mut |p| progress(p * 0.92),
        log,
    )?;
    crate::ops::compress::repair_legacy_container_headers(
        output,
        true,
        hactool,
        prod_keys,
        cancel,
        &mut |p| progress(0.92 + p * 0.08),
        log,
    )?;
    progress(1.0);
    Ok(stats)
}

fn transform_xci(
    input: &Path,
    output: &Path,
    compress: Option<(&mut KeySet, &XczOptions)>,
    cancel: &AtomicBool,
    progress: &mut dyn FnMut(f32),
    log: &mut dyn FnMut(String),
) -> Result<XczStats> {
    // Preserve the previous staging implementation for isolated A/B
    // benchmarking and compatibility diagnosis. Normal jobs never create
    // intermediate HFS0 partitions or per-entry NCA/NCZ copies.
    if std::env::var_os("NSRP_XCZ_COMPAT_STAGING").is_some() {
        return transform_xci_staged(input, output, compress, cancel, progress, log);
    }
    streaming::transform_xci_streamed(input, output, compress, cancel, progress, log)
}

#[path = "xcz_streaming.rs"]
mod streaming;

fn transform_xci_staged(
    input: &Path,
    output: &Path,
    mut compress: Option<(&mut KeySet, &XczOptions)>,
    cancel: &AtomicBool,
    progress: &mut dyn FnMut(f32),
    log: &mut dyn FnMut(String),
) -> Result<XczStats> {
    let input_size = fs::metadata(input)?.len();
    let (root, header_base) = hfs0::find_xci_root_with_header_base(input)?;
    let out_parent = output.parent().unwrap_or_else(|| Path::new("."));
    fs::create_dir_all(out_parent)?;
    let temp = tempfile::Builder::new()
        .prefix("nsrp_xcz_")
        .tempdir_in(out_parent)?;
    let mut source = BufReader::with_capacity(8 * 1024 * 1024, File::open(input)?);

    if let Some((keys, _)) = compress.as_mut() {
        collect_xci_ticket_keys(&mut source, input_size, &root, keys)?;
    }

    let total_payload = root.entries.iter().map(|e| e.size).sum::<u64>().max(1);
    let mut root_done = 0u64;
    let mut root_paths = Vec::<(String, PathBuf)>::new();
    let mut stats = XczStats {
        input_size,
        ..Default::default()
    };

    for (partition_index, entry) in root.entries.iter().enumerate() {
        if cancel.load(Ordering::Relaxed) {
            bail!("작업이 중단되었습니다");
        }
        let abs = root.data_start + entry.offset;
        let partition_path = temp
            .path()
            .join(format!("partition_{partition_index}.hfs0"));
        match Hfs0Index::parse_at(&mut source, abs, input_size) {
            Ok(sub) => {
                let subdir = temp.path().join(format!("partition_{partition_index}"));
                fs::create_dir_all(&subdir)?;
                let mut sub_paths = Vec::<(String, PathBuf)>::new();
                let sub_total = sub.entries.iter().map(|e| e.size).sum::<u64>().max(1);
                let mut sub_done = 0u64;
                for (file_index, file_entry) in sub.entries.iter().enumerate() {
                    if cancel.load(Ordering::Relaxed) {
                        bail!("작업이 중단되었습니다");
                    }
                    let file_abs = sub.data_start + file_entry.offset;
                    let lower = file_entry.name.to_ascii_lowercase();
                    if let Some((keys, options)) = compress.as_mut() {
                        let keys: &mut KeySet = keys;
                        let options: &XczOptions = options;
                        if lower.ends_with(".nca") {
                            stats.nca_count += 1;
                            let mut head =
                                vec![0u8; file_entry.size.min(NCA_NCZ_HEADER_SIZE as u64) as usize];
                            source.seek(SeekFrom::Start(file_abs))?;
                            source.read_exact(&mut head)?;
                            if head.len() >= NCA_NCZ_HEADER_SIZE
                                && let Ok(plan) = make_ncz_plan_from_reader(
                                    &mut source,
                                    file_abs,
                                    file_entry.size,
                                    &head,
                                    keys,
                                )
                            {
                                let name = replace_extension(&file_entry.name, "ncz");
                                let path = subdir.join(format!("{file_index}.ncz"));
                                let mut out =
                                    BufWriter::with_capacity(8 * 1024 * 1024, File::create(&path)?);
                                let base_root = root_done;
                                let base_sub = sub_done;
                                write_nca_region_to_ncz(
                                    &mut source,
                                    file_abs,
                                    file_entry.size,
                                    &plan,
                                    &mut out,
                                    options.level.clamp(1, 22),
                                    options.threads.max(1),
                                    options.block_mode,
                                    options.long_mode,
                                    cancel,
                                    |cur, total| {
                                        let frac = if total == 0 {
                                            1.0
                                        } else {
                                            cur as f32 / total as f32
                                        };
                                        let current_partition =
                                            base_sub as f32 + file_entry.size as f32 * frac;
                                        let overall = base_root as f32
                                            + entry.size as f32
                                                * (current_partition / sub_total as f32).min(1.0);
                                        progress((overall / total_payload as f32) * 0.95);
                                    },
                                )?;
                                out.flush()?;
                                stats.ncz_count += 1;
                                log(format!("NCZ 압축: {}", file_entry.name));
                                sub_paths.push((name, path));
                                sub_done += file_entry.size;
                                continue;
                            }
                            let path = subdir.join(format!("{file_index}.nca"));
                            copy_region(&mut source, file_abs, file_entry.size, &path, cancel)?;
                            sub_paths.push((file_entry.name.clone(), path));
                        } else {
                            let path = subdir.join(format!("{file_index}.bin"));
                            copy_region(&mut source, file_abs, file_entry.size, &path, cancel)?;
                            sub_paths.push((file_entry.name.clone(), path));
                        }
                    } else if lower.ends_with(".ncz") {
                        let name = replace_extension(&file_entry.name, "nca");
                        let path = subdir.join(format!("{file_index}.nca"));
                        let mut out =
                            BufWriter::with_capacity(8 * 1024 * 1024, File::create(&path)?);
                        let base_root = root_done;
                        let base_sub = sub_done;
                        decompress_ncz_region_to_nca(
                            &mut source,
                            file_abs,
                            file_entry.size,
                            &mut out,
                            cancel,
                            |cur, total| {
                                let frac = if total == 0 {
                                    1.0
                                } else {
                                    cur as f32 / total as f32
                                };
                                let current_partition =
                                    base_sub as f32 + file_entry.size as f32 * frac.min(1.0);
                                let overall = base_root as f32
                                    + entry.size as f32
                                        * (current_partition / sub_total as f32).min(1.0);
                                progress((overall / total_payload as f32) * 0.95);
                            },
                        )?;
                        out.flush()?;
                        stats.ncz_count += 1;
                        log(format!("NCZ 해제: {}", file_entry.name));
                        sub_paths.push((name, path));
                    } else {
                        let path = subdir.join(format!("{file_index}.bin"));
                        copy_region(&mut source, file_abs, file_entry.size, &path, cancel)?;
                        sub_paths.push((file_entry.name.clone(), path));
                    }
                    sub_done += file_entry.size;
                }
                if sub_paths.is_empty() {
                    bail!("HFS0 파티션이 변환 후 비었습니다: {}", entry.name);
                }
                hfs0::build_from_paths_layout(&sub_paths, &partition_path, 0x200, 1)?;
            }
            Err(_) => {
                copy_region(&mut source, abs, entry.size, &partition_path, cancel)?;
            }
        }
        root_paths.push((entry.name.clone(), partition_path));
        root_done += entry.size;
        progress((root_done as f32 / total_payload as f32) * 0.95);
    }

    let new_root = temp.path().join("root.hfs0");
    hfs0::build_from_paths_layout(&root_paths, &new_root, 0x200, 1)?;
    let new_root_size = fs::metadata(&new_root)?.len();
    let root_hash = sha256_file(&new_root)?;
    let partial = output.with_extension(format!(
        "{}.partial",
        output.extension().and_then(|s| s.to_str()).unwrap_or("xci")
    ));
    {
        let mut out = BufWriter::with_capacity(8 * 1024 * 1024, File::create(&partial)?);
        source.seek(SeekFrom::Start(0))?;
        copy_exact(&mut source, &mut out, root.base, cancel)?;
        let mut root_file = BufReader::with_capacity(8 * 1024 * 1024, File::open(&new_root)?);
        std::io::copy(&mut root_file, &mut out)?;
        out.flush()?;
    }
    if let Some(base) = header_base {
        let mut out = fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(&partial)?;
        out.seek(SeekFrom::Start(base + 0x138))?;
        out.write_u64::<LittleEndian>(new_root_size)?;
        out.seek(SeekFrom::Start(base + 0x118))?;
        let pages = (root.base + new_root_size) / 0x200;
        out.write_u32::<LittleEndian>(pages.min(u32::MAX as u64) as u32)?;
        out.seek(SeekFrom::Start(base + 0x140))?;
        out.write_all(&root_hash)?;
        out.flush()?;
    }
    if output.exists() {
        fs::remove_file(output)?;
    }
    fs::rename(&partial, output)?;
    stats.output_size = fs::metadata(output)?.len();
    progress(1.0);
    Ok(stats)
}

fn collect_xci_ticket_keys<R: Read + Seek>(
    source: &mut R,
    file_size: u64,
    root: &Hfs0Index,
    keys: &mut KeySet,
) -> Result<()> {
    for partition in &root.entries {
        let abs = root.data_start + partition.offset;
        let Ok(sub) = Hfs0Index::parse_at(source, abs, file_size) else {
            continue;
        };
        for entry in sub
            .entries
            .iter()
            .filter(|e| e.name.to_ascii_lowercase().ends_with(".tik") && e.size <= 1024 * 1024)
        {
            let size = usize::try_from(entry.size).context("ticket 크기 오류")?;
            let mut data = vec![0u8; size];
            source.seek(SeekFrom::Start(sub.data_start + entry.offset))?;
            source.read_exact(&mut data)?;
            keys.add_ticket_data(&entry.name, &data);
        }
    }
    Ok(())
}

fn copy_region<R: Read + Seek>(
    source: &mut R,
    offset: u64,
    size: u64,
    output: &Path,
    cancel: &AtomicBool,
) -> Result<()> {
    source.seek(SeekFrom::Start(offset))?;
    let mut out = BufWriter::with_capacity(8 * 1024 * 1024, File::create(output)?);
    copy_exact(source, &mut out, size, cancel)?;
    out.flush()?;
    Ok(())
}

fn copy_exact<R: Read, W: Write>(
    source: &mut R,
    output: &mut W,
    mut remaining: u64,
    cancel: &AtomicBool,
) -> Result<()> {
    let mut buffer = vec![0u8; 8 * 1024 * 1024];
    while remaining > 0 {
        if cancel.load(Ordering::Relaxed) {
            bail!("작업이 중단되었습니다");
        }
        let take = remaining.min(buffer.len() as u64) as usize;
        source.read_exact(&mut buffer[..take])?;
        output.write_all(&buffer[..take])?;
        remaining -= take as u64;
    }
    Ok(())
}

fn sha256_file(path: &Path) -> Result<[u8; 32]> {
    let mut file = BufReader::new(File::open(path)?);
    let mut hash = Sha256::new();
    let mut buffer = vec![0u8; 4 * 1024 * 1024];
    loop {
        let n = file.read(&mut buffer)?;
        if n == 0 {
            break;
        }
        hash.update(&buffer[..n]);
    }
    Ok(hash.finalize().into())
}

fn replace_extension(name: &str, extension: &str) -> String {
    match name.rsplit_once('.') {
        Some((stem, _)) => format!("{stem}.{extension}"),
        None => format!("{name}.{extension}"),
    }
}

#[cfg(test)]
#[path = "xcz_bktr_tests.rs"]
mod bktr_tests;
