use crate::formats::{
    nca::{NczPlan, decrypt_chunk_in_place},
    ncz::{
        BLOCK_MAGIC, ENC_AES_CTR, ENC_AES_CTR_SKIP_LAYER_HASH, ENC_NONE, ENC_XTS, NCZ_HEADER_SIZE,
        NczBlockHeader, NczSection, STREAM_MAGIC, validated_ncz_body_size, write_section_table,
    },
};
use anyhow::{Context, Result, bail, ensure};
use byteorder::{LittleEndian, ReadBytesExt, WriteBytesExt};
use rayon::prelude::*;
use sha2::{Digest, Sha256};
use std::{
    io::{Read, Seek, SeekFrom, Write},
    sync::atomic::{AtomicBool, Ordering},
    time::{Duration, Instant},
};

/// NCA 구간을 통째로 메모리에 올리지 않고 NCZ로 기록한다.
/// `reader`는 부모 NSP/XCI 또는 독립 NCA이고 `nca_base`는 NCA의 절대 시작점이다.
pub fn write_nca_region_to_ncz<R, W, F>(
    reader: &mut R,
    nca_base: u64,
    nca_size: u64,
    plan: &NczPlan,
    out: &mut W,
    level: i32,
    threads: usize,
    block_mode: bool,
    long_mode: bool,
    cancel: &AtomicBool,
    mut progress: F,
) -> Result<[u8; 32]>
where
    R: Read + Seek,
    W: Write + Seek,
    F: FnMut(u64, u64),
{
    if nca_size < NCZ_HEADER_SIZE as u64 {
        bail!("NCA가 NCZ 최소 헤더보다 짧습니다");
    }
    out.write_all(&plan.original_bytes)?;
    write_section_table(&mut *out, &plan.sections)?;
    let body_total = nca_size - NCZ_HEADER_SIZE as u64;
    if block_mode {
        write_block_body(
            reader,
            nca_base,
            body_total,
            plan,
            out,
            level,
            threads,
            long_mode,
            cancel,
            &mut progress,
        )
    } else {
        write_stream_body(
            reader,
            nca_base,
            body_total,
            plan,
            out,
            level,
            threads,
            long_mode,
            cancel,
            &mut progress,
        )
    }
}

#[derive(Debug, Clone)]
struct RegionHeader {
    original: Vec<u8>,
    sections: Vec<NczSection>,
    block: Option<NczBlockHeader>,
    compressed_offset: u64,
}

/// Read only bounded NCZ metadata to predict the reconstructed NCA size.
/// This does not allocate/decode the NCA body and can reject unsupported
/// XCI capacity tiers before creating multi-gigabyte temporary files.
pub(crate) fn reconstructed_nca_size<R: Read + Seek>(
    reader: &mut R,
    ncz_base: u64,
    ncz_size: u64,
) -> Result<u64> {
    let header = parse_region_header(reader, ncz_base, ncz_size)?;
    let body = validated_ncz_body_size(&header.sections)?;
    if let Some(block) = header.block {
        ensure!(
            block.decompressed_size == body,
            "NCZBLOCK size disagrees with reconstructed NCA sections"
        );
    }
    (NCZ_HEADER_SIZE as u64)
        .checked_add(body)
        .context("NCZ reconstructed NCA size overflow")
}

/// NCZ가 NSP/NSZ 내부에 있어도 전체 엔트리를 메모리에 올리지 않고 NCA로 복원한다.
pub fn decompress_ncz_region_to_nca<R, W, F>(
    reader: &mut R,
    ncz_base: u64,
    ncz_size: u64,
    out: &mut W,
    cancel: &AtomicBool,
    mut progress: F,
) -> Result<u64>
where
    R: Read + Seek,
    W: Write,
    F: FnMut(u64, u64),
{
    ensure!(!cancel.load(Ordering::Relaxed), "작업이 중단되었습니다");
    let header = parse_region_header(reader, ncz_base, ncz_size)?;
    let body_expected = validated_ncz_body_size(&header.sections)?;
    if let Some(block) = &header.block {
        ensure!(
            block.decompressed_size == body_expected,
            "NCZBLOCK decompressed size disagrees with the NCA section table"
        );
    }
    // Reject malformed metadata and cancellation before publishing any
    // reconstructed NCA header to the caller.
    out.write_all(&header.original)?;

    let mut processed = 0u64;
    if let Some(block) = &header.block {
        reader.seek(SeekFrom::Start(ncz_base + header.compressed_offset))?;
        ensure!(
            (14..=24).contains(&block.block_size_exponent),
            "NCZBLOCK 블록 지수가 안전 범위를 벗어났습니다"
        );
        let block_size = 1usize
            .checked_shl(block.block_size_exponent as u32)
            .context("NCZBLOCK 크기 오류")?;
        let count = block.compressed_sizes.len();
        let full_blocks = (count - 1) as u64 * block_size as u64;
        ensure!(
            block.decompressed_size > full_blocks
                && block.decompressed_size <= full_blocks + block_size as u64,
            "NCZBLOCK 블록 수와 원본 크기가 일치하지 않습니다"
        );
        let max_encoded = zstd::zstd_safe::compress_bound(block_size);
        let mut encoded_bytes = 0u64;
        for &size in &block.compressed_sizes {
            ensure!(
                size > 0 && size as usize <= max_encoded,
                "NCZBLOCK 블록의 압축 크기가 비정상입니다"
            );
            encoded_bytes = encoded_bytes
                .checked_add(u64::from(size))
                .context("NCZBLOCK 압축 크기 오버플로")?;
        }
        ensure!(
            header
                .compressed_offset
                .checked_add(encoded_bytes)
                .is_some_and(|end| end <= ncz_size),
            "NCZBLOCK 데이터가 원본 엔트리를 벗어납니다"
        );

        // Independent blocks can be decoded and encrypted concurrently,
        // while the shared input and output remain strictly ordered.
        // Reuse the bounded set of buffers and zstd contexts for all blocks.
        struct DecodeSlot {
            encoded: Vec<u8>,
            plain: Vec<u8>,
            decoder: zstd::bulk::Decompressor<'static>,
            expected: usize,
            absolute: u64,
            raw: bool,
        }
        let workers = std::env::var("NSRP_NCZ_DECODE_WORKERS")
            .ok()
            .and_then(|value| value.parse::<usize>().ok())
            .filter(|n| (1..=8).contains(n))
            .unwrap_or_else(|| num_cpus::get().clamp(1, 4))
            .min(count);
        let pool = rayon::ThreadPoolBuilder::new()
            .num_threads(workers)
            .build()
            .context("NCZBLOCK 복원 작업자 생성 실패")?;
        let mut slots: Vec<DecodeSlot> = (0..workers)
            .map(|_| {
                Ok(DecodeSlot {
                    encoded: Vec::new(),
                    plain: vec![0; block_size],
                    decoder: zstd::bulk::Decompressor::new()?,
                    expected: 0,
                    absolute: 0,
                    raw: false,
                })
            })
            .collect::<Result<_>>()?;
        let trace = std::env::var_os("NSRP_STAGE14_PROFILE").is_some();
        let total_start = Instant::now();
        let (mut read_time, mut decode_time, mut write_time) =
            (Duration::ZERO, Duration::ZERO, Duration::ZERO);
        let mut index = 0usize;
        while index < count {
            if cancel.load(Ordering::Relaxed) {
                bail!("작업이 중단되었습니다");
            }
            let batch = workers.min(count - index);
            let started = Instant::now();
            for (local, slot) in slots.iter_mut().take(batch).enumerate() {
                let block_index = index + local;
                let expected = if block_index + 1 == count {
                    (block.decompressed_size - full_blocks) as usize
                } else {
                    block_size
                };
                slot.encoded
                    .resize(block.compressed_sizes[block_index] as usize, 0);
                reader.read_exact(&mut slot.encoded)?;
                slot.expected = expected;
                slot.absolute = NCZ_HEADER_SIZE as u64 + (block_index as u64) * block_size as u64;
                slot.raw = slot.encoded.len() == expected;
            }
            read_time += started.elapsed();
            let started = Instant::now();
            pool.install(|| {
                slots[..batch]
                    .par_iter_mut()
                    .try_for_each(|slot| -> Result<()> {
                        let decoded = if slot.raw {
                            &mut slot.encoded[..]
                        } else {
                            let written = slot
                                .decoder
                                .decompress_to_buffer(
                                    &slot.encoded,
                                    &mut slot.plain[..slot.expected],
                                )
                                .context("NCZBLOCK zstd 해제 실패")?;
                            ensure!(written == slot.expected, "NCZBLOCK 해제 크기 불일치");
                            &mut slot.plain[..slot.expected]
                        };
                        crypt_sections_in_place(decoded, slot.absolute, &header.sections)?;
                        Ok(())
                    })
            })?;
            decode_time += started.elapsed();
            let started = Instant::now();
            for slot in slots.iter().take(batch) {
                if slot.raw {
                    out.write_all(&slot.encoded)?;
                } else {
                    out.write_all(&slot.plain[..slot.expected])?;
                }
                processed += slot.expected as u64;
                progress(processed, block.decompressed_size);
            }
            write_time += started.elapsed();
            index += batch;
        }
        if trace {
            eprintln!(
                "STAGE14_NCZ_RESTORE_PROFILE blocks={count} workers={workers} total_ms={} read_ms={} zstd_crypt_ms={} write_ms={}",
                total_start.elapsed().as_millis(),
                read_time.as_millis(),
                decode_time.as_millis(),
                write_time.as_millis()
            );
        }
        if processed != block.decompressed_size {
            bail!("NCZBLOCK 전체 해제 크기 불일치");
        }
    } else {
        if header.compressed_offset >= ncz_size {
            bail!("NCZ zstd 스트림이 없습니다");
        }
        reader.seek(SeekFrom::Start(ncz_base + header.compressed_offset))?;
        let limited = reader.take(ncz_size - header.compressed_offset);
        let mut decoder = zstd::stream::read::Decoder::new(limited)?;
        let mut buffer = vec![0u8; 8 * 1024 * 1024];
        loop {
            if cancel.load(Ordering::Relaxed) {
                bail!("작업이 중단되었습니다");
            }
            let n = decoder.read(&mut buffer)?;
            if n == 0 {
                break;
            }
            let next = processed
                .checked_add(n as u64)
                .context("NCZ zstd stream decompression size overflow")?;
            ensure!(
                next <= body_expected,
                "NCZ zstd stream expands beyond its declared NCA section range"
            );
            let absolute = NCZ_HEADER_SIZE as u64 + processed;
            crypt_sections_in_place(&mut buffer[..n], absolute, &header.sections)?;
            out.write_all(&buffer[..n])?;
            processed = next;
            progress(processed, body_expected);
        }
    }

    ensure!(
        processed == body_expected,
        "NCZ decompressed body size does not match the NCA section table"
    );
    Ok(NCZ_HEADER_SIZE as u64 + processed)
}

fn parse_region_header<R: Read + Seek>(
    reader: &mut R,
    base: u64,
    size: u64,
) -> Result<RegionHeader> {
    base.checked_add(size)
        .context("NCZ archive entry range overflow")?;
    if size < (NCZ_HEADER_SIZE + 16) as u64 {
        bail!("NCZ가 너무 짧습니다");
    }
    reader.seek(SeekFrom::Start(base))?;
    let mut original = vec![0u8; NCZ_HEADER_SIZE];
    reader.read_exact(&mut original)?;
    let mut magic = [0u8; 8];
    reader.read_exact(&mut magic)?;
    if &magic != STREAM_MAGIC {
        bail!("NCZSECTN magic 불일치");
    }
    let count = reader.read_i64::<LittleEndian>()?;
    if count <= 0 || count > 4096 {
        bail!("비정상 NCZ section 수: {count}");
    }
    let section_table_end = (NCZ_HEADER_SIZE as u64 + 16)
        .checked_add((count as u64) * 64)
        .context("NCZ section table size overflow")?;
    ensure!(
        section_table_end
            .checked_add(8)
            .is_some_and(|end| end <= size),
        "NCZ section table exceeds the current archive entry"
    );
    let mut sections = Vec::with_capacity(count as usize);
    for _ in 0..count {
        let offset = reader.read_i64::<LittleEndian>()?;
        let section_size = reader.read_i64::<LittleEndian>()?;
        let crypto_type = reader.read_i64::<LittleEndian>()?;
        let _padding = reader.read_i64::<LittleEndian>()?;
        if offset < 0 || section_size <= 0 {
            bail!("비정상 NCZ section 범위");
        }
        let mut key = [0u8; 16];
        let mut counter = [0u8; 16];
        reader.read_exact(&mut key)?;
        reader.read_exact(&mut counter)?;
        sections.push(NczSection {
            offset: offset as u64,
            size: section_size as u64,
            crypto_type,
            crypto_key: key,
            crypto_counter: counter,
        });
    }

    validated_ncz_body_size(&sections)?;
    let after_sections = reader.stream_position()?;
    if after_sections < base || after_sections - base + 8 > size {
        bail!("NCZ section table이 엔트리 범위를 벗어납니다");
    }
    let mut next = [0u8; 8];
    reader.read_exact(&mut next)?;
    if &next == BLOCK_MAGIC {
        ensure!(
            section_table_end
                .checked_add(24)
                .is_some_and(|end| end <= size),
            "NCZBLOCK fixed header exceeds the current archive entry"
        );
        let version = reader.read_u8()?;
        let _kind = reader.read_u8()?;
        let _unused = reader.read_u8()?;
        let exponent = reader.read_u8()?;
        let block_count = reader.read_i32::<LittleEndian>()?;
        let decompressed_size = reader.read_i64::<LittleEndian>()?;
        if !matches!(version, 1 | 2)
            || block_count <= 0
            || block_count > 4_000_000
            || decompressed_size < 0
        {
            bail!("비정상 NCZBLOCK 헤더");
        }
        ensure!(
            section_table_end
                .checked_add(24 + (block_count as u64) * 4)
                .is_some_and(|end| end < size),
            "NCZBLOCK size table exceeds the current archive entry"
        );
        let mut compressed_sizes = Vec::with_capacity(block_count as usize);
        for _ in 0..block_count {
            compressed_sizes.push(reader.read_u32::<LittleEndian>()?);
        }
        let compressed_offset = reader.stream_position()? - base;
        if compressed_offset >= size {
            bail!("NCZBLOCK 데이터가 없습니다");
        }
        Ok(RegionHeader {
            original,
            sections,
            block: Some(NczBlockHeader {
                block_size_exponent: exponent,
                decompressed_size: decompressed_size as u64,
                compressed_sizes,
            }),
            compressed_offset,
        })
    } else {
        reader.seek(SeekFrom::Start(after_sections))?;
        Ok(RegionHeader {
            original,
            sections,
            block: None,
            compressed_offset: after_sections - base,
        })
    }
}

fn crypt_sections_in_place(
    chunk: &mut [u8],
    absolute_offset: u64,
    sections: &[NczSection],
) -> Result<()> {
    let chunk_end = absolute_offset + chunk.len() as u64;
    for section in sections {
        let section_end = section.offset + section.size;
        let start = absolute_offset.max(section.offset);
        let end = chunk_end.min(section_end);
        if start >= end {
            continue;
        }
        match section.crypto_type {
            ENC_NONE => {}
            ENC_AES_CTR | ENC_AES_CTR_SKIP_LAYER_HASH => {
                let local_start = (start - absolute_offset) as usize;
                let local_end = (end - absolute_offset) as usize;
                crate::crypto::nca_ctr_xcrypt_range(
                    &mut chunk[local_start..local_end],
                    &section.crypto_key,
                    &section.crypto_counter,
                    start,
                )?;
            }
            ENC_XTS => bail!("NCZ XTS section은 지원하지 않습니다"),
            other => bail!("알 수 없는 NCZ crypto type: {other}"),
        }
    }
    Ok(())
}

fn write_stream_body<R, W, F>(
    reader: &mut R,
    nca_base: u64,
    body_total: u64,
    plan: &NczPlan,
    out: &mut W,
    level: i32,
    threads: usize,
    long_mode: bool,
    cancel: &AtomicBool,
    progress: &mut F,
) -> Result<[u8; 32]>
where
    R: Read + Seek,
    W: Write,
    F: FnMut(u64, u64),
{
    reader.seek(SeekFrom::Start(nca_base + NCZ_HEADER_SIZE as u64))?;
    let mut encoder = zstd::stream::write::Encoder::new(out, level)?;
    if long_mode {
        encoder.long_distance_matching(true)?;
        encoder.window_log(27)?;
    } else {
        encoder.window_log(25)?;
    }
    if threads > 1 {
        encoder.multithread(threads.min(u32::MAX as usize) as u32)?;
    }
    let mut hasher = Sha256::new();
    let mut processed = 0u64;
    let mut buffer = vec![0u8; 8 * 1024 * 1024];
    while processed < body_total {
        if cancel.load(Ordering::Relaxed) {
            bail!("작업이 중단되었습니다");
        }
        let take = (body_total - processed).min(buffer.len() as u64) as usize;
        reader.read_exact(&mut buffer[..take])?;
        let absolute = NCZ_HEADER_SIZE as u64 + processed;
        decrypt_chunk_in_place(&mut buffer[..take], absolute, &plan.crypto_spans)?;
        hasher.update(&buffer[..take]);
        encoder.write_all(&buffer[..take])?;
        processed += take as u64;
        progress(processed, body_total);
    }
    encoder.finish()?;
    Ok(hasher.finalize().into())
}

fn write_block_body<R, W, F>(
    reader: &mut R,
    nca_base: u64,
    body_total: u64,
    plan: &NczPlan,
    out: &mut W,
    level: i32,
    threads: usize,
    long_mode: bool,
    cancel: &AtomicBool,
    progress: &mut F,
) -> Result<[u8; 32]>
where
    R: Read + Seek,
    W: Write + Seek,
    F: FnMut(u64, u64),
{
    const EXP: u8 = 20;
    const BLOCK: usize = 1 << EXP;
    let block_count = body_total.div_ceil(BLOCK as u64) as usize;
    if block_count > i32::MAX as usize {
        bail!("NCZBLOCK 블록 수가 너무 많습니다");
    }
    out.write_all(BLOCK_MAGIC)?;
    let header_pos = out.stream_position()?;
    out.write_all(&vec![0u8; 16 + block_count * 4])?;

    reader.seek(SeekFrom::Start(nca_base + NCZ_HEADER_SIZE as u64))?;
    // Two batches are in flight, so cap their aggregate buffers and zstd
    // contexts even when the caller requests dozens of threads. Long-distance
    // matching uses much larger dictionaries, so bound it more conservatively.
    let max_workers = if long_mode { 2 } else { 16 };
    let worker_count = threads.clamp(1, max_workers).min(block_count.max(1));
    let pool = rayon::ThreadPoolBuilder::new()
        .num_threads(worker_count)
        .build()
        .context("NCZBLOCK 작업자 생성 실패")?;

    // Persist zstd contexts and buffers across every block. Two bounded
    // batches let the main thread read, decrypt and hash the next 4 MiB while
    // the worker pool compresses the preceding batch, without staging files
    // or changing the NCZBLOCK layout.
    struct CompressSlot {
        plain: Vec<u8>,
        encoded: Vec<u8>,
        compressor: zstd::bulk::Compressor<'static>,
        length: usize,
    }
    struct CompressBatch {
        slots: Vec<CompressSlot>,
        count: usize,
        zstd_elapsed: Duration,
    }
    let create_batch = || -> Result<CompressBatch> {
        let slots: Result<Vec<CompressSlot>> = (0..worker_count)
            .map(|_| {
                let mut compressor = zstd::bulk::Compressor::new(level)?;
                if long_mode {
                    compressor.long_distance_matching(true)?;
                    compressor.window_log(27)?;
                }
                Ok(CompressSlot {
                    plain: vec![0; BLOCK],
                    encoded: Vec::with_capacity(zstd::zstd_safe::compress_bound(BLOCK)),
                    compressor,
                    length: 0,
                })
            })
            .collect();
        Ok(CompressBatch {
            slots: slots?,
            count: 0,
            zstd_elapsed: Duration::ZERO,
        })
    };
    let first_batch = create_batch()?;
    let spare_batch = create_batch()?;

    let mut compressed_sizes = Vec::with_capacity(block_count);
    let mut hasher = Sha256::new();
    let mut processed = 0u64;
    let mut block_index = 0usize;
    let trace = std::env::var_os("NSRP_STAGE14_PROFILE").is_some();
    let total_start = Instant::now();
    let (mut prepare_time, mut zstd_time, mut write_time) =
        (Duration::ZERO, Duration::ZERO, Duration::ZERO);

    let (send_task, recv_task) = std::sync::mpsc::sync_channel::<CompressBatch>(1);
    let (send_done, recv_done) = std::sync::mpsc::channel::<Result<CompressBatch>>();
    std::thread::scope(|scope| -> Result<()> {
        let compressor_thread = scope.spawn(move || {
            while let Ok(mut batch) = recv_task.recv() {
                let start = Instant::now();
                let result = pool.install(|| {
                    batch.slots[..batch.count]
                        .par_iter_mut()
                        .try_for_each(|slot| -> Result<()> {
                            slot.encoded.clear();
                            slot.compressor.compress_to_buffer(
                                &slot.plain[..slot.length],
                                &mut slot.encoded,
                            )?;
                            Ok(())
                        })
                });
                if let Err(error) = result {
                    let _ = send_done.send(Err(error));
                    break;
                }
                batch.zstd_elapsed = start.elapsed();
                if send_done.send(Ok(batch)).is_err() {
                    break;
                }
            }
        });

        let mut flush_batch = |batch: &CompressBatch| -> Result<()> {
            let started = Instant::now();
            for slot in batch.slots.iter().take(batch.count) {
                let data = if slot.encoded.len() < slot.length {
                    &slot.encoded[..]
                } else {
                    &slot.plain[..slot.length]
                };
                compressed_sizes.push(u32::try_from(data.len())?);
                out.write_all(data)?;
                processed += slot.length as u64;
                progress(processed, body_total);
            }
            write_time += started.elapsed();
            Ok(())
        };

        let pipeline_result = (|| -> Result<()> {
            let mut available = first_batch;
            let mut spare = Some(spare_batch);
            let mut pending = false;
            while block_index < block_count {
                if cancel.load(Ordering::Relaxed) {
                    bail!("작업이 중단되었습니다");
                }
                let batch_count = worker_count.min(block_count - block_index);
                let started = Instant::now();
                for (local, slot) in available.slots.iter_mut().take(batch_count).enumerate() {
                    let index = block_index + local;
                    let absolute = NCZ_HEADER_SIZE as u64 + index as u64 * BLOCK as u64;
                    let remaining = body_total.saturating_sub(index as u64 * BLOCK as u64);
                    let take = remaining.min(BLOCK as u64) as usize;
                    reader.read_exact(&mut slot.plain[..take])?;
                    decrypt_chunk_in_place(&mut slot.plain[..take], absolute, &plan.crypto_spans)?;
                    hasher.update(&slot.plain[..take]);
                    slot.length = take;
                }
                available.count = batch_count;
                prepare_time += started.elapsed();

                if pending {
                    let finished = recv_done
                        .recv()
                        .context("NCZBLOCK 압축 작업자가 종료되었습니다")??;
                    zstd_time += finished.zstd_elapsed;
                    flush_batch(&finished)?;
                    spare = Some(finished);
                }
                send_task
                    .send(available)
                    .map_err(|_| anyhow::anyhow!("NCZBLOCK 작업 전송 실패"))?;
                pending = true;
                available = spare.take().context("NCZBLOCK 예비 버퍼 없음")?;
                block_index += batch_count;
            }
            if pending {
                let finished = recv_done
                    .recv()
                    .context("NCZBLOCK 마지막 압축 결과 없음")??;
                zstd_time += finished.zstd_elapsed;
                flush_batch(&finished)?;
            }
            Ok(())
        })();
        drop(send_task);
        drop(recv_done);
        compressor_thread
            .join()
            .map_err(|_| anyhow::anyhow!("NCZBLOCK 작업자 스레드 패닉"))?;
        pipeline_result
    })?;

    if trace {
        eprintln!(
            "STAGE14_NCZ_COMPRESS_PROFILE blocks={block_count} workers={worker_count} total_ms={} read_decrypt_hash_ms={} zstd_ms={} write_ms={}",
            total_start.elapsed().as_millis(),
            prepare_time.as_millis(),
            zstd_time.as_millis(),
            write_time.as_millis()
        );
    }

    let eof = out.stream_position()?;
    out.seek(SeekFrom::Start(header_pos))?;
    out.write_all(&[2, 2, 0, EXP])?;
    out.write_i32::<LittleEndian>(block_count as i32)?;
    out.write_i64::<LittleEndian>(body_total as i64)?;
    for size in compressed_sizes {
        out.write_u32::<LittleEndian>(size)?;
    }
    out.seek(SeekFrom::Start(eof))?;
    Ok(hasher.finalize().into())
}

#[cfg(test)]
mod stage14_tests {
    use super::*;
    use crate::formats::nca::NczPlan;
    use anyhow::ensure;
    use std::io::Cursor;

    fn fixture() -> Result<(Vec<u8>, Vec<u8>)> {
        const BLOCK: usize = 1 << 20;
        let mut nca = vec![0x5a; NCZ_HEADER_SIZE];
        let mut body = vec![0u8; 4 * BLOCK + 2_533];
        for (i, b) in body.iter_mut().enumerate() {
            *b = match i / BLOCK {
                0 => (i % 31) as u8,
                1 => ((i.wrapping_mul(131).wrapping_add(i / 253)) % 251) as u8,
                2 => 0,
                3 => ((i >> 4) % 256) as u8,
                _ => 0xbe,
            };
        }
        nca.extend_from_slice(&body);
        let plan = NczPlan {
            original_bytes: nca[..NCZ_HEADER_SIZE].to_vec(),
            decrypted_recrypted_header: Vec::new(),
            section_key: [0; 16],
            sections: vec![NczSection {
                offset: NCZ_HEADER_SIZE as u64,
                size: body.len() as u64,
                crypto_type: ENC_NONE,
                crypto_key: [0; 16],
                crypto_counter: [0; 16],
            }],
            crypto_spans: Vec::new(),
            content_type: 0,
        };
        let mut source = Cursor::new(&nca);
        let mut compressed = Cursor::new(Vec::new());
        let digest = write_nca_region_to_ncz(
            &mut source,
            0,
            nca.len() as u64,
            &plan,
            &mut compressed,
            3,
            4,
            true,
            false,
            &AtomicBool::new(false),
            |_, _| {},
        )?;
        let expected: [u8; 32] = Sha256::digest(&body).into();
        ensure!(digest == expected);
        Ok((nca, compressed.into_inner()))
    }

    #[test]
    fn block_multithread_roundtrip_matches_every_byte() -> Result<()> {
        let (nca, ncz) = fixture()?;
        let mut restored = Vec::new();
        let count = decompress_ncz_region_to_nca(
            &mut Cursor::new(&ncz),
            0,
            ncz.len() as u64,
            &mut restored,
            &AtomicBool::new(false),
            |_, _| {},
        )?;
        ensure!(count as usize == nca.len());
        ensure!(restored == nca, "parallel NCZ roundtrip differs");
        Ok(())
    }

    #[test]
    fn oversized_or_truncated_block_is_rejected_before_allocation() -> Result<()> {
        let (_, compressed) = fixture()?;
        let exponent_at = NCZ_HEADER_SIZE + 16 + 64 + 8 + 3;
        let mut oversized = compressed.clone();
        oversized[exponent_at] = 31;
        ensure!(
            decompress_ncz_region_to_nca(
                &mut Cursor::new(&oversized),
                0,
                oversized.len() as u64,
                &mut Vec::new(),
                &AtomicBool::new(false),
                |_, _| {},
            )
            .is_err(),
            "unsafe NCZ exponent accepted"
        );
        let mut truncated = compressed;
        truncated.truncate(truncated.len() - 128);
        ensure!(
            decompress_ncz_region_to_nca(
                &mut Cursor::new(&truncated),
                0,
                truncated.len() as u64,
                &mut Vec::new(),
                &AtomicBool::new(false),
                |_, _| {},
            )
            .is_err(),
            "truncated NCZBLOCK accepted"
        );
        Ok(())
    }

    #[test]
    fn malformed_ncz_metadata_is_rejected_before_any_output() -> Result<()> {
        let (_, compressed) = fixture()?;
        let count_at = NCZ_HEADER_SIZE + 8;
        let section_offset_at = NCZ_HEADER_SIZE + 16;
        let section_size_at = section_offset_at + 8;
        let crypto_at = section_offset_at + 16;
        let block_at = section_offset_at + 64;
        let decompressed_size_at = block_at + 16;
        let mut cases: Vec<(&str, Vec<u8>)> = Vec::new();

        let mut forged_count = compressed.clone();
        forged_count[count_at..count_at + 8].copy_from_slice(&4096_i64.to_le_bytes());
        cases.push(("section count exceeds entry", forged_count));

        let mut header_overlap = compressed.clone();
        header_overlap[section_offset_at..section_offset_at + 8]
            .copy_from_slice(&0x2000_i64.to_le_bytes());
        cases.push(("section begins inside NCZ header", header_overlap));

        let mut huge_section = compressed.clone();
        huge_section[section_size_at..section_size_at + 8].copy_from_slice(&i64::MAX.to_le_bytes());
        cases.push(("declared 8 EiB NCA cannot allocate", huge_section));

        let mut unsupported_crypto = compressed.clone();
        unsupported_crypto[crypto_at..crypto_at + 8].copy_from_slice(&ENC_XTS.to_le_bytes());
        cases.push(("unsupported XTS crypto", unsupported_crypto));

        let mut wrong_block_length = compressed.clone();
        wrong_block_length[decompressed_size_at..decompressed_size_at + 8]
            .copy_from_slice(&1_i64.to_le_bytes());
        cases.push(("block size disagrees with sections", wrong_block_length));

        let mut forged_block_count = compressed.clone();
        forged_block_count[block_at + 12..block_at + 16]
            .copy_from_slice(&1_000_000_i32.to_le_bytes());
        cases.push(("block table extends beyond entry", forged_block_count));

        for (case, bytes) in cases {
            let mut restored = Vec::new();
            ensure!(
                decompress_ncz_region_to_nca(
                    &mut Cursor::new(&bytes),
                    0,
                    bytes.len() as u64,
                    &mut restored,
                    &AtomicBool::new(false),
                    |_, _| {},
                )
                .is_err(),
                "Malformed NCZ was accepted: {case}"
            );
            ensure!(
                restored.is_empty(),
                "Malformed NCZ produced output before validation: {case}"
            );
        }
        Ok(())
    }

    #[test]
    fn stream_body_cannot_expand_beyond_section_table_size() -> Result<()> {
        let original = vec![0xa5; NCZ_HEADER_SIZE];
        let body = vec![0x33u8; 2 * 1024 * 1024];
        let sections = vec![NczSection {
            offset: NCZ_HEADER_SIZE as u64,
            size: (body.len() / 2) as u64,
            crypto_type: ENC_NONE,
            crypto_key: [0; 16],
            crypto_counter: [0; 16],
        }];
        let ncz = crate::formats::ncz::build_streaming(&original, &body, &sections, 3)?;
        let mut restored = Vec::new();
        ensure!(
            decompress_ncz_region_to_nca(
                &mut Cursor::new(&ncz),
                0,
                ncz.len() as u64,
                &mut restored,
                &AtomicBool::new(false),
                |_, _| {},
            )
            .is_err(),
            "An oversized zstd stream must not be accepted"
        );
        ensure!(
            restored.len() == NCZ_HEADER_SIZE,
            "Oversized stream must not write any of its invalid body"
        );
        Ok(())
    }

    #[test]
    fn cancellation_after_first_batch_drains_worker_without_deadlock() -> Result<()> {
        const BLOCK: usize = 1 << 20;
        let nca = vec![0x5a; NCZ_HEADER_SIZE + 12 * BLOCK];
        let plan = NczPlan {
            original_bytes: nca[..NCZ_HEADER_SIZE].to_vec(),
            decrypted_recrypted_header: Vec::new(),
            section_key: [0; 16],
            sections: vec![NczSection {
                offset: NCZ_HEADER_SIZE as u64,
                size: (12 * BLOCK) as u64,
                crypto_type: ENC_NONE,
                crypto_key: [0; 16],
                crypto_counter: [0; 16],
            }],
            crypto_spans: Vec::new(),
            content_type: 0,
        };
        let cancelled = AtomicBool::new(false);
        let result = write_nca_region_to_ncz(
            &mut Cursor::new(&nca),
            0,
            nca.len() as u64,
            &plan,
            &mut Cursor::new(Vec::new()),
            3,
            4,
            true,
            false,
            &cancelled,
            |processed, _| {
                if processed > 0 {
                    cancelled.store(true, Ordering::Relaxed);
                }
            },
        );
        ensure!(
            result.is_err(),
            "cancelled NCZ encoder completed as success"
        );
        Ok(())
    }
}
