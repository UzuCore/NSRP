use crate::{
    atomic_file::publish_generated_file,
    formats::{ncz_stream::decompress_ncz_region_to_nca, pfs0::build_from_streams},
    keys::KeySet,
    ops::{
        cnmt::discover_game_metadata,
        compress::{CompressOptions, compress_nsp, decompress_nsz_repaired},
        container::list_entries,
        native_xci::XciSource,
        nsz_xci::try_native_nsz_to_xci,
        nsz_xci_stream::try_streamed_nsz_to_xci,
        xci_output::{
            XciBuilder, build_xci_auto_verified, build_xci_native_sources_verified,
            publish_decoded_xci, publish_verified_xci,
        },
        xcz::{XczOptions, compress_xci, decompress_xcz_repaired},
    },
};
use anyhow::{Context, Result, bail};
use std::{
    fs::{self, File},
    io::{BufReader, BufWriter, Read, Seek, SeekFrom, Write},
    path::{Path, PathBuf},
    sync::atomic::{AtomicBool, Ordering},
};

const DEFAULT_GAME_INFO_INI: &str = "[XCI_Header]\r\n\
PackageID=10492310773436918493\r\n\
GamecardIV=6A-6C-CA-77-93-17-52-50-4F-F2-A7-48-3C-FF-81-8A\r\n\
KEKIndex=0\r\n\
InitialDataHash=09-47-C7-9D-01-C1-93-B3-C9-A7-70-F6-E6-23-73-4B-C6-19-18-4A-C4-CE-48-8D-6F-07-AB-BB-AE-53-B9-59\r\n\
[GameCard_Info]\r\n\
Version=4778801821143285351\r\n\
AccessControlFlags=1872686116\r\n\
ReadWaitTime=172636576\r\n\
ReadWaitTime2=3760023131\r\n\
WriteWriteTime=1709233185\r\n\
WriteWriteTime2=4151208775\r\n\
FirmwareMode=4207214535\r\n\
CUPVersion=2920828692\r\n\
CUPID=8650043608759144999\r\n";

pub(crate) fn game_info_preset_data(resource_dir: &Path) -> Result<Vec<u8>> {
    let preset = resource_dir.join("bin").join("game_info_preset.ini");
    if preset.is_file() {
        return fs::read(&preset)
            .with_context(|| format!("game_info_preset.ini 읽기 실패: {}", preset.display()));
    }
    Ok(DEFAULT_GAME_INFO_INI.as_bytes().to_vec())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TargetFormat {
    Nsp,
    Xci,
}

#[derive(Debug, Clone)]
pub struct ConvertOptions {
    pub target: TargetFormat,
    pub compress_after: bool,
    pub compression: CompressOptions,
}

pub fn convert(
    input: &Path,
    output_dir: &Path,
    resource_dir: &Path,
    prod_keys: &Path,
    keys: &mut KeySet,
    options: &ConvertOptions,
    cancel: &AtomicBool,
    progress: &mut dyn FnMut(f32),
    log: &mut dyn FnMut(String),
) -> Result<PathBuf> {
    fs::create_dir_all(output_dir)?;
    let stem = input
        .file_stem()
        .and_then(|s| s.to_str())
        .unwrap_or("output");
    let ext = input
        .extension()
        .and_then(|s| s.to_str())
        .unwrap_or("")
        .to_ascii_lowercase();

    let already_target = matches!(options.target, TargetFormat::Nsp) && ext == "nsp"
        || matches!(options.target, TargetFormat::Xci) && ext == "xci";
    if already_target {
        if !options.compress_after {
            log(format!(
                "이미 {} 형식입니다",
                match options.target {
                    TargetFormat::Nsp => "NSP",
                    TargetFormat::Xci => "XCI",
                }
            ));
            progress(1.0);
            return Ok(input.to_path_buf());
        }
        // The input is already the right container. Compress it directly
        // instead of copying an entire multi-gigabyte NSP/XCI to a temporary
        // file and immediately reading it back.
        let final_path = output_dir.join(format!(
            "{stem}.{}",
            if options.target == TargetFormat::Nsp {
                "nsz"
            } else {
                "xcz"
            }
        ));
        match options.target {
            TargetFormat::Nsp => {
                compress_nsp(
                    input,
                    &final_path,
                    keys,
                    &options.compression,
                    cancel,
                    progress,
                    log,
                )?;
            }
            TargetFormat::Xci => {
                let xcz_options = XczOptions {
                    level: options.compression.level,
                    threads: options.compression.threads,
                    block_mode: options.compression.block_mode,
                    long_mode: options.compression.long_mode,
                };
                compress_xci(
                    input,
                    &final_path,
                    keys,
                    &xcz_options,
                    cancel,
                    progress,
                    log,
                )?;
            }
        }
        return Ok(final_path);
    }
    let temp = tempfile::Builder::new()
        .prefix("nsrp_convert_")
        .tempdir_in(output_dir)?;
    let intermediate = match options.target {
        TargetFormat::Nsp => temp.path().join(format!("{stem}.nsp")),
        TargetFormat::Xci => temp.path().join(format!("{stem}.xci")),
    };

    match options.target {
        TargetFormat::Nsp => {
            if ext == "nsp" {
                fs::copy(input, &intermediate)?;
            } else if ext == "nsz" {
                decompress_nsz_repaired(
                    input,
                    &intermediate,
                    &resource_dir.join("bin").join("hactool.exe"),
                    prod_keys,
                    cancel,
                    &mut |p| progress(p * 0.75),
                    log,
                )?;
            } else if matches!(ext.as_str(), "xci" | "xcz") {
                container_to_nsp(
                    input,
                    &intermediate,
                    &resource_dir.join("bin").join("hactool.exe"),
                    prod_keys,
                    cancel,
                    &mut |p| progress(p * 0.75),
                    log,
                )?;
            } else {
                bail!("지원하지 않는 입력 형식: {ext}");
            }
        }
        TargetFormat::Xci => {
            if ext == "xci" {
                fs::copy(input, &intermediate)?;
                progress(0.75);
            } else if ext == "xcz" {
                decompress_xcz_repaired(
                    input,
                    &intermediate,
                    &resource_dir.join("bin").join("hactool.exe"),
                    prod_keys,
                    cancel,
                    &mut |p| progress(p * 0.75),
                    log,
                )?;
            } else {
                let temp_nsp = temp.path().join("source.nsp");
                let fast_nsz_work = temp.path().join("nsz_direct_attempt");
                let used_direct = if ext == "nsz" {
                    if try_streamed_nsz_to_xci(
                        input,
                        &intermediate,
                        resource_dir,
                        keys,
                        cancel,
                        progress,
                        log,
                    )? {
                        true
                    } else {
                        // The Stage34 byte-verified NCZ-only materialization
                        // remains available for non-native CNMT layouts.
                        try_native_nsz_to_xci(
                            input,
                            &intermediate,
                            resource_dir,
                            prod_keys,
                            keys,
                            &fast_nsz_work,
                            cancel,
                            progress,
                            log,
                        )?
                    }
                } else {
                    false
                };
                if !used_direct {
                    // If metadata or capacity checks reject this fast path
                    // after individual NCZ files were decoded, release that
                    // scratch allocation *before* expanding the full fallback
                    // NSP. Never make both copies coexist unnecessarily.
                    if fast_nsz_work.exists() {
                        fs::remove_dir_all(&fast_nsz_work)?;
                    }
                    let source_nsp = if ext == "nsp" {
                        input
                    } else if ext == "nsz" {
                        decompress_nsz_repaired(
                            input,
                            &temp_nsp,
                            &resource_dir.join("bin").join("hactool.exe"),
                            prod_keys,
                            cancel,
                            &mut |p| progress(p * 0.35),
                            log,
                        )?;
                        temp_nsp.as_path()
                    } else {
                        bail!("지원하지 않는 입력 형식: {ext}");
                    };
                    build_xci_from_nsp(
                        source_nsp,
                        &intermediate,
                        resource_dir,
                        prod_keys,
                        cancel,
                        log,
                    )?;
                }
                progress(0.75);
            }
        }
    }

    if options.compress_after {
        match options.target {
            TargetFormat::Nsp => {
                let final_path = output_dir.join(format!("{stem}.nsz"));
                compress_nsp(
                    &intermediate,
                    &final_path,
                    keys,
                    &options.compression,
                    cancel,
                    &mut |p| progress(0.75 + p * 0.25),
                    log,
                )?;
                Ok(final_path)
            }
            TargetFormat::Xci => {
                let final_path = output_dir.join(format!("{stem}.xcz"));
                let xcz_options = XczOptions {
                    level: options.compression.level,
                    threads: options.compression.threads,
                    block_mode: options.compression.block_mode,
                    long_mode: options.compression.long_mode,
                };
                compress_xci(
                    &intermediate,
                    &final_path,
                    keys,
                    &xcz_options,
                    cancel,
                    &mut |p| progress(0.75 + p * 0.25),
                    log,
                )?;
                Ok(final_path)
            }
        }
    } else {
        let final_path = output_dir.join(intermediate.file_name().unwrap());
        if matches!(options.target, TargetFormat::Xci) {
            if ext == "xcz" {
                publish_decoded_xci(&intermediate, &final_path, cancel)?;
            } else {
                publish_verified_xci(&intermediate, &final_path, cancel)?;
            }
        } else {
            publish_generated_file(&intermediate, &final_path, cancel)?;
        }
        progress(1.0);
        Ok(final_path)
    }
}

/// XCI/XCZ의 secure 계열 콘텐츠만 PFS0 NSP로 평탄화한다.
pub fn container_to_nsp(
    input: &Path,
    output: &Path,
    hactool: &Path,
    prod_keys: &Path,
    cancel: &AtomicBool,
    progress: &mut dyn FnMut(f32),
    log: &mut dyn FnMut(String),
) -> Result<()> {
    let parent = output.parent().unwrap_or_else(|| Path::new("."));
    fs::create_dir_all(parent)?;
    let temp = tempfile::Builder::new()
        .prefix("nsrp_xci_nsp_")
        .tempdir_in(parent)?;
    let entries = match discover_game_metadata(
        input,
        &temp.path().join("metadata"),
        hactool,
        prod_keys,
        cancel,
    ) {
        Ok((entries, _, legacy_partition_fallback)) => {
            if legacy_partition_fallback {
                log("구형 XCI 파티션 배치 감지: Update/DLC를 포함해 NSP로 변환합니다".to_owned());
            }
            entries
        }
        Err(err) => {
            log(format!(
                "메타데이터 호환 탐색 경고: {err:#} — secure 파티션 기준으로 변환을 계속합니다"
            ));
            list_entries(input, true)?
        }
    };
    let selected: Vec<_> = entries
        .into_iter()
        .filter(|e| {
            let n = e.name.to_ascii_lowercase();
            n.ends_with(".nca")
                || n.ends_with(".ncz")
                || n.ends_with(".tik")
                || n.ends_with(".cert")
        })
        .collect();
    if selected.is_empty() {
        bail!("NSP로 변환할 콘텐츠가 없습니다");
    }
    let total = selected.iter().map(|e| e.size).sum::<u64>().max(1);
    let mut done = 0u64;
    // Plan the same ordered/deduplicated PFS0 entries as before, then stream
    // them from the XCI/XCZ directly. Neither uncompressed NCAs nor decoded
    // NCZs need a second on-disk copy in the conversion workspace.
    let mut ordered = selected
        .iter()
        .enumerate()
        .map(|(i, entry)| {
            (
                if entry.name.to_ascii_lowercase().ends_with(".ncz") {
                    replace_extension(&entry.name, "nca")
                } else {
                    entry.name.clone()
                },
                i,
            )
        })
        .collect::<Vec<_>>();
    ordered.sort_by(|a, b| a.0.cmp(&b.0));
    ordered.dedup_by(|a, b| a.0.eq_ignore_ascii_case(&b.0));
    let names = ordered
        .iter()
        .map(|(name, _)| name.clone())
        .collect::<Vec<_>>();
    let mut source = BufReader::with_capacity(2 * 1024 * 1024, File::open(input)?);
    let mut scratch = vec![0u8; 2 * 1024 * 1024];
    build_from_streams(&names, output, cancel, |i, out| {
        let entry = &selected[ordered[i].1];
        if entry.name.to_ascii_lowercase().ends_with(".ncz") {
            let base = done;
            decompress_ncz_region_to_nca(
                &mut source,
                entry.offset,
                entry.size,
                out,
                cancel,
                |cur, inner| {
                    let frac = if inner == 0 {
                        1.0
                    } else {
                        cur as f32 / inner as f32
                    };
                    progress(
                        (base as f32 + entry.size as f32 * frac.min(1.0)) / total as f32 * 0.90,
                    );
                },
            )?;
        } else {
            source.seek(SeekFrom::Start(entry.offset))?;
            let mut remaining = entry.size;
            while remaining > 0 {
                if cancel.load(Ordering::Relaxed) {
                    bail!("작업이 중단되었습니다");
                }
                let count = remaining.min(scratch.len() as u64) as usize;
                source.read_exact(&mut scratch[..count])?;
                out.write_all(&scratch[..count])?;
                remaining -= count as u64;
            }
        }
        done += entry.size;
        progress(done as f32 / total as f32 * 0.90);
        Ok(())
    })?;
    log(format!("NSP 생성: {}개 엔트리", names.len()));
    progress(1.0);
    Ok(())
}

pub fn build_xci_from_nsp(
    nsp: &Path,
    output: &Path,
    resource_dir: &Path,
    prod_keys: &Path,
    cancel: &AtomicBool,
    log: &mut dyn FnMut(String),
) -> Result<()> {
    let index = crate::formats::pfs0::Pfs0Index::parse(nsp)?;
    let ncas: Vec<_> = index
        .entries
        .iter()
        .filter(|e| e.name.to_ascii_lowercase().ends_with(".nca"))
        .collect();
    if ncas.len() < 4 {
        bail!(
            "XCI 변환에는 최소 4개의 NCA가 필요합니다 (현재 {})",
            ncas.len()
        );
    }
    let expected_ncas = ncas
        .iter()
        .map(|entry| (entry.name.clone(), entry.size))
        .collect::<Vec<_>>();
    let preset_data = game_info_preset_data(resource_dir)?;
    let direct_sources = ncas
        .iter()
        .map(|entry| {
            Ok(XciSource {
                name: entry.name.clone(),
                path: nsp.to_path_buf(),
                offset: index
                    .data_start
                    .checked_add(entry.offset)
                    .context("NSP->XCI 원본 영역 오프셋 오버플로")?,
                length: entry.size,
            })
        })
        .collect::<Result<Vec<_>>>()?;

    if build_xci_native_sources_verified(
        output,
        &expected_ncas,
        &direct_sources,
        &preset_data,
        cancel,
    )? {
        log("XCI: Rust 네이티브 빌더 (NSP 직접 스트리밍, 중간 NCA 사본 없음)".to_owned());
        log(format!("XCI 생성 완료: {}", output.display()));
        return Ok(());
    }
    // Unsupported card layouts retain Stage32's byte-verified hacbuild
    // fallback and are materialized only after the native gate rejects them.
    let temp = crate::workspace::temp_workspace("nsrp_hacbuild_")?;
    let work_root = temp.path().join("work");
    let secure = work_root.join("secure");
    fs::create_dir_all(&secure)?;
    fs::create_dir_all(work_root.join("normal"))?;
    fs::create_dir_all(work_root.join("update"))?;
    let mut source = BufReader::with_capacity(8 * 1024 * 1024, File::open(nsp)?);
    for entry in ncas {
        copy_region(
            &mut source,
            index.data_start + entry.offset,
            entry.size,
            &secure.join(&entry.name),
            cancel,
        )?;
    }

    let engine = build_xci_auto_verified(
        output,
        &expected_ncas,
        &work_root,
        temp.path(),
        resource_dir,
        prod_keys,
        &preset_data,
        cancel,
    )?;
    log(match engine {
        XciBuilder::NativeRust => "XCI: Rust 네이티브 빌더 사용".to_owned(),
        XciBuilder::HacbuildFallback => "XCI: 미검증 레이아웃, hacbuild 폴백".to_owned(),
    });
    log(format!("XCI 생성 완료: {}", output.display()));
    Ok(())
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

fn replace_extension(name: &str, ext: &str) -> String {
    match name.rsplit_once('.') {
        Some((stem, _)) => format!("{stem}.{ext}"),
        None => format!("{name}.{ext}"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        formats::hfs0::{self, Hfs0Index},
        keys::KeySet,
    };

    #[test]
    #[ignore = "Requires local authorized ticketless NSZ and dedicated empty QA output folder"]
    fn stage71_real_nsz_conversion_preserves_legacy_bootable_headers() -> Result<()> {
        use anyhow::{Context, ensure};
        let input = PathBuf::from(
            std::env::var_os("NSRP_CONVERT_QA_INPUT").context("No NSZ fixture path")?,
        );
        let target = PathBuf::from(
            std::env::var_os("NSRP_CONVERT_QA_OUTPUT").context("No QA output directory")?,
        );
        let resource_dir = PathBuf::from(
            std::env::var_os("NSRP_MERGE_QA_RESOURCES").context("No resources directory")?,
        );
        let prod_keys =
            PathBuf::from(std::env::var_os("NSRP_MERGE_QA_KEYS").context("No key file")?);
        let format = std::env::var("NSRP_CONVERT_QA_FORMAT")
            .context("Set NSRP_CONVERT_QA_FORMAT to nsp or xci")?;
        ensure!(
            matches!(format.as_str(), "nsp" | "xci"),
            "Unexpected target format"
        );
        ensure!(
            !target.exists(),
            "Refusing to overwrite an existing output folder"
        );
        let old_len = fs::metadata(&input)?.len();
        let mut keys = KeySet::load_with_local_title_keys(&prod_keys)?;
        let output = convert(
            &input,
            &target,
            &resource_dir,
            &prod_keys,
            &mut keys,
            &ConvertOptions {
                target: if format == "nsp" {
                    TargetFormat::Nsp
                } else {
                    TargetFormat::Xci
                },
                compress_after: false,
                compression: CompressOptions::default(),
            },
            &AtomicBool::new(false),
            &mut |_| {},
            &mut |message| println!("{message}"),
        )?;
        ensure!(output.extension().is_some_and(|ext| ext == format.as_str()));
        ensure!(output.is_file() && fs::metadata(&output)?.len() > 100_000);
        let entries = crate::ops::container::list_entries(&output, true)?;
        let cnmt_count = entries
            .iter()
            .filter(|entry| crate::ops::cnmt::is_cnmt_container_entry(&entry.name))
            .count();
        ensure!(cnmt_count == 4, "All 4 CNMT titles must survive conversion");
        let original_entries = crate::ops::container::list_entries(&input, true)?;
        let mut verified_headers = 0usize;
        for entry in entries.iter().filter(|entry| {
            entry.name.to_ascii_lowercase().ends_with(".nca")
                && !crate::ops::cnmt::is_cnmt_container_entry(&entry.name)
        }) {
            let original_name = format!(
                "{}.ncz",
                entry.name.strip_suffix(".nca").unwrap_or(&entry.name)
            );
            let Some(original) = original_entries
                .iter()
                .find(|source| source.name.eq_ignore_ascii_case(&original_name))
            else {
                continue;
            };
            let mut source = File::open(&input)?;
            source.seek(SeekFrom::Start(original.offset))?;
            let mut original_head = vec![0u8; crate::formats::nca::NCA_XTS_HEADER_SIZE];
            source.read_exact(&mut original_head)?;
            let mut converted = File::open(&output)?;
            converted.seek(SeekFrom::Start(entry.offset))?;
            let mut converted_head = vec![0u8; crate::formats::nca::NCA_XTS_HEADER_SIZE];
            converted.read_exact(&mut converted_head)?;
            ensure!(
                converted_head == original_head,
                "Conversion rewrote a ticketless header: {}",
                entry.name
            );
            verified_headers += 1;
        }
        ensure!(
            verified_headers == 4,
            "Expected 4 byte-identical NCZ-backed NCA headers, found {verified_headers}"
        );
        ensure!(fs::metadata(&input)?.len() == old_len, "Input size changed");
        println!(
            "STAGE71_NSZ_CONVERT_PASS format={format} cnmts={cnmt_count} headers={verified_headers} bytes={} output={}",
            fs::metadata(&output)?.len(),
            output.display()
        );
        Ok(())
    }

    #[test]
    fn game_info_preset_has_builtin_fallback() -> Result<()> {
        let temp = tempfile::tempdir()?;
        let data = game_info_preset_data(temp.path())?;
        let text = String::from_utf8(data)?;
        assert!(text.contains("[XCI_Header]"));
        assert!(text.contains("PackageID=10492310773436918493"));
        assert!(text.contains("[GameCard_Info]"));
        Ok(())
    }

    #[test]
    fn xcz_to_xci_is_direct_decompression() -> Result<()> {
        let temp = tempfile::tempdir()?;
        let payload = temp.path().join("payload.bin");
        fs::write(&payload, b"partition-preservation-test")?;

        let secure = temp.path().join("secure.hfs0");
        hfs0::build_from_paths_layout(&[("payload.bin".to_owned(), payload)], &secure, 0x200, 1)?;
        let root = temp.path().join("root.hfs0");
        hfs0::build_from_paths_layout(&[("secure".to_owned(), secure)], &root, 0x200, 1)?;
        let input_xci = temp.path().join("input.xci");
        let mut image = vec![0u8; 0x200];
        image.extend_from_slice(&fs::read(&root)?);
        fs::write(&input_xci, image)?;

        let input_xcz = temp.path().join("input.xcz");
        let cancel = AtomicBool::new(false);
        let mut keys = KeySet::default();
        compress_xci(
            &input_xci,
            &input_xcz,
            &mut keys,
            &XczOptions {
                level: 3,
                threads: 1,
                block_mode: false,
                long_mode: false,
            },
            &cancel,
            &mut |_| {},
            &mut |_| {},
        )?;

        let output_dir = temp.path().join("out");
        let restored = convert(
            &input_xcz,
            &output_dir,
            temp.path(),
            &temp.path().join("unused.keys"),
            &mut keys,
            &ConvertOptions {
                target: TargetFormat::Xci,
                compress_after: false,
                compression: CompressOptions::default(),
            },
            &cancel,
            &mut |_| {},
            &mut |_| {},
        )?;

        let mut file = File::open(&restored)?;
        let file_size = file.metadata()?.len();
        let root = hfs0::find_xci_root(&restored)?;
        let secure = root.entry("secure").context("secure partition missing")?;
        let secure_index =
            Hfs0Index::parse_at(&mut file, root.data_start + secure.offset, file_size)?;
        let payload_preserved = secure_index.entry("payload.bin").is_some();
        assert!(payload_preserved);
        Ok(())
    }

    #[test]
    fn same_format_without_compression_is_a_noop() -> Result<()> {
        let temp = tempfile::tempdir()?;
        let input = temp.path().join("original.nsp");
        fs::write(&input, b"do-not-rewrite")?;
        let output_dir = temp.path().join("different-output");
        let cancel = AtomicBool::new(false);
        let mut keys = KeySet::default();
        let result = convert(
            &input,
            &output_dir,
            temp.path(),
            &temp.path().join("unused.keys"),
            &mut keys,
            &ConvertOptions {
                target: TargetFormat::Nsp,
                compress_after: false,
                compression: CompressOptions::default(),
            },
            &cancel,
            &mut |_| {},
            &mut |_| {},
        )?;
        assert_eq!(result, input);
        assert_eq!(fs::read(&result)?, b"do-not-rewrite");
        assert!(!output_dir.join("original.nsp").exists());
        Ok(())
    }
}
