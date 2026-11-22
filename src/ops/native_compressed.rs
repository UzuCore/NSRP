//! Independent, bounded-memory reader for NCA compressed RomFS storage.
//!
//! The on-disk BucketTree resides after the compressed data and contains
//! mappings from decompressed RomFS positions to physical data offsets.
//! Supports one BucketTree index root and bounded multiple entry leaves.
//! This covers the previously verified single-leaf layout and the common
//! multi-leaf compressed-storage index without inventing multi-level roots.
//! Unknown types/levels/regions are rejected for the existing LibHac fallback.
//!
//! Entries of type 0 copy bytes directly; type 1 represents zeros; type 3
//! holds a raw LZ4 block. No GPL-licensed implementation is copied here.

use anyhow::{Context, Result, ensure};
use std::{
    io::{self, Read, Seek, SeekFrom},
    sync::Arc,
    time::{Duration, Instant},
};

const NODE_SIZE: usize = 0x4000;
const RECORD_SIZE: usize = 0x18;
const MAX_BLOCK: usize = 0x10000;
const MAX_IMAGE: u64 = 16 * 1024 * 1024 * 1024;
const MAX_INDEX_ENTRIES: usize = 1_000_000;
const MAX_INDEX_BYTES: usize = 32 * 1024 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Compression {
    Plain,
    Zeros,
    Lz4,
}

#[derive(Debug, Clone, Copy)]
struct Entry {
    virtual_offset: u64,
    physical_offset: u64,
    compression: Compression,
    physical_size: i32,
}

pub(crate) struct CompressedBktrReader<R> {
    source: R,
    data_offset: u64,
    logical_size: u64,
    entries: Arc<[Entry]>,
    position: u64,
    cached: Option<(usize, Vec<u8>)>,
    compressed_scratch: Vec<u8>,
    profile: Option<CompressedReaderProfile>,
}

/// The physical index is already validated by the primary reader. Sharing
/// the immutable map avoids re-reading the same 32 KiB BucketTree from each
/// worker's encrypted BKTR virtual section, while keeping independent source
/// handles and decompression buffers.
#[derive(Clone)]
pub(crate) struct CompressedBktrIndex {
    data_offset: u64,
    logical_size: u64,
    physical_virtual_size: u64,
    entries: Arc<[Entry]>,
}

#[derive(Default)]
struct CompressedReaderProfile {
    index_open: Duration,
    encoded_io: Duration,
    plain_io: Duration,
    lz4: Duration,
    blocks: u64,
    bytes: u64,
}

impl<R> Drop for CompressedBktrReader<R> {
    fn drop(&mut self) {
        if let Some(p) = &self.profile {
            eprintln!(
                "STAGE14_BKTR_COMPRESSED_PROFILE open_ms={} encoded_io_ms={} plain_io_ms={} lz4_ms={} blocks={} bytes={}",
                p.index_open.as_millis(),
                p.encoded_io.as_millis(),
                p.plain_io.as_millis(),
                p.lz4.as_millis(),
                p.blocks,
                p.bytes
            );
        }
    }
}

fn read_u32(bytes: &[u8], offset: usize) -> Result<u32> {
    Ok(u32::from_le_bytes(bytes[offset..offset + 4].try_into()?))
}

fn read_i32(bytes: &[u8], offset: usize) -> Result<i32> {
    Ok(i32::from_le_bytes(bytes[offset..offset + 4].try_into()?))
}

fn read_u64(bytes: &[u8], offset: usize) -> Result<u64> {
    Ok(u64::from_le_bytes(bytes[offset..offset + 8].try_into()?))
}

fn read_i64(bytes: &[u8], offset: usize) -> Result<i64> {
    Ok(i64::from_le_bytes(bytes[offset..offset + 8].try_into()?))
}

/// Shared, header-only geometry validation for BKTR compressed-storage
/// extraction and standalone NCA flatten/repack. A layout must be supported
/// by the reader before the builder is allowed to remove its index.
#[derive(Debug, Clone, Copy)]
pub(crate) struct CompressedBktrLayout {
    data_offset: u64,
    index_offset: u64,
    index_bytes: usize,
    entry_count: usize,
    bucket_count: usize,
}

pub(crate) fn validate_compressed_bktr_layout(
    fs: &[u8],
    physical_virtual_size: u64,
) -> Result<CompressedBktrLayout> {
    validate_compressed_bktr_layout_inner(fs, physical_virtual_size, false)
}

/// Called only after the patch's metadata SHA and every lookup-table IVFC
/// block have been authenticated by verify_patch_metadata_integrity. The
/// compressed index still undergoes all usual independent bounds checks.
pub(crate) fn validate_compressed_bktr_layout_after_verified_patch(
    fs: &[u8],
    physical_virtual_size: u64,
) -> Result<CompressedBktrLayout> {
    validate_compressed_bktr_layout_inner(fs, physical_virtual_size, true)
}

fn validate_compressed_bktr_layout_inner(
    fs: &[u8],
    physical_virtual_size: u64,
    verified_patch_metadata: bool,
) -> Result<CompressedBktrLayout> {
    ensure!(
        fs.len() == 0x200,
        "compressed BKTR filesystem header truncated"
    );
    let metadata_storage_supported = match fs[5] {
        0 => fs[0x1a0..0x200].iter().all(|&b| b == 0),
        1 if verified_patch_metadata => {
            u64::from_le_bytes(fs[0x1a8..0x1b0].try_into()?) == 0xe8
                && fs[0x1b0..0x1d0].iter().any(|&b| b != 0)
                && fs[0x1d0..0x200].iter().all(|&b| b == 0)
        }
        _ => false,
    };
    ensure!(
        (fs[2], fs[3], fs[4]) == (0, 3, 4)
            && metadata_storage_supported
            && &fs[8..12] == b"IVFC"
            && fs[0x148..0x178].iter().all(|&b| b == 0)
            && fs[0x194..0x1a0].iter().all(|&b| b == 0),
        "unsupported compressed BKTR filesystem"
    );
    let levels = read_u32(fs, 0x14)?;
    ensure!((2..=7).contains(&levels), "invalid compressed IVFC levels");
    let level_at = 0x18 + (levels as usize - 2) * 0x18;
    let data_offset = read_u64(fs, level_at)?;
    let physical_data_size = read_u64(fs, level_at + 8)?;
    ensure!(
        data_offset.checked_add(physical_data_size) == Some(physical_virtual_size),
        "compressed data-level range mismatch"
    );
    let index_offset = read_u64(fs, 0x178)?;
    let index_size = read_u64(fs, 0x180)?;
    let entry_count = read_u32(fs, 0x190)? as usize;
    let per_leaf = (NODE_SIZE - 0x10) / RECORD_SIZE;
    let bucket_count = entry_count.div_ceil(per_leaf);
    let max_root_buckets = (NODE_SIZE - 0x10) / 8;
    let index_bytes = (1usize)
        .checked_add(bucket_count)
        .and_then(|n| n.checked_mul(NODE_SIZE))
        .context("compressed BKTR index byte count overflow")?;
    ensure!(
        &fs[0x188..0x18c] == b"BKTR"
            && read_u32(fs, 0x18c)? == 1
            && (1..=MAX_INDEX_ENTRIES).contains(&entry_count)
            && (1..=max_root_buckets).contains(&bucket_count)
            && fs[0x194..0x1a0].iter().all(|&b| b == 0)
            && index_offset > 0
            && index_bytes <= MAX_INDEX_BYTES
            && index_size == index_bytes as u64
            && index_offset.checked_add(index_size) == Some(physical_data_size),
        "unsupported compressed BKTR metadata index"
    );
    Ok(CompressedBktrLayout {
        data_offset,
        index_offset,
        index_bytes,
        entry_count,
        bucket_count,
    })
}

impl<R: Read + Seek> CompressedBktrReader<R> {
    /// Same bounded-memory cursor and LZ4 cache for both the initial
    /// validated index and worker handles created from that shared index.
    fn from_index(source: R, index: &CompressedBktrIndex, index_open: Duration) -> Self {
        Self {
            source,
            data_offset: index.data_offset,
            logical_size: index.logical_size,
            entries: Arc::clone(&index.entries),
            position: 0,
            cached: None,
            compressed_scratch: Vec::new(),
            profile: std::env::var_os("NSRP_STAGE14_PROFILE").map(|_| CompressedReaderProfile {
                index_open,
                ..Default::default()
            }),
        }
    }

    #[cfg(test)]
    pub(crate) fn open(source: R, fs: &[u8], physical_virtual_size: u64) -> Result<Self> {
        Self::open_with_verified_patch(source, fs, physical_virtual_size, false)
    }

    fn open_with_verified_patch(
        mut source: R,
        fs: &[u8],
        physical_virtual_size: u64,
        verified_patch_metadata: bool,
    ) -> Result<Self> {
        let started = Instant::now();
        let layout = if verified_patch_metadata {
            validate_compressed_bktr_layout_after_verified_patch(fs, physical_virtual_size)?
        } else {
            validate_compressed_bktr_layout(fs, physical_virtual_size)?
        };
        let data_offset = layout.data_offset;
        let index_offset = layout.index_offset;
        let count = layout.entry_count;
        let per_leaf = (NODE_SIZE - 0x10) / RECORD_SIZE;
        let bucket_count = layout.bucket_count;
        source.seek(SeekFrom::Start(
            data_offset
                .checked_add(index_offset)
                .context("compression index position overflow")?,
        ))?;
        let mut index = vec![0u8; layout.index_bytes];
        source.read_exact(&mut index)?;
        let logical_size = read_u64(&index, 8)?;
        ensure!(
            read_u32(&index, 0)? == 0
                && read_u32(&index, 4)? as usize == bucket_count
                && (1..=MAX_IMAGE).contains(&logical_size),
            "compressed BKTR BucketTree root invalid"
        );
        let mut entries = Vec::with_capacity(count);
        let mut previous_bucket_end = 0u64;
        for bucket in 0..bucket_count {
            let start = (bucket + 1) * NODE_SIZE;
            let leaf = &index[start..start + NODE_SIZE];
            let local_count = (count - bucket * per_leaf).min(per_leaf);
            let leaf_end = read_u64(leaf, 8)?;
            ensure!(
                read_u32(leaf, 0)? as usize == bucket
                    && read_u32(leaf, 4)? as usize == local_count
                    && leaf_end > previous_bucket_end
                    && leaf_end <= logical_size,
                "compressed BKTR BucketTree leaf invalid"
            );
            for i in 0..local_count {
                let at = 0x10 + i * RECORD_SIZE;
                let virtual_offset = read_i64(leaf, at)?;
                let physical_offset = read_i64(leaf, at + 8)?;
                let physical_size = read_i32(leaf, at + 0x14)?;
                let compression = match leaf[at + 0x10] {
                    0 => Compression::Plain,
                    1 => Compression::Zeros,
                    3 => Compression::Lz4,
                    _ => anyhow::bail!("unsupported compressed BKTR compression type"),
                };
                ensure!(
                    virtual_offset >= 0 && physical_offset >= 0,
                    "compressed BKTR mapping has invalid signed offset"
                );
                // The three bytes after the one-byte CompressionType are
                // structure alignment padding, not flags. Real compressed
                // NCA entries can contain nonzero padding. All meaningful
                // fields still receive strict range, ordering, size,
                // compression-type and authenticated-section validation.
                if bucket > 0 && i == 0 {
                    ensure!(
                        virtual_offset as u64 == previous_bucket_end,
                        "compressed BKTR leaves have a discontinuous logical boundary"
                    );
                }
                entries.push(Entry {
                    virtual_offset: virtual_offset as u64,
                    physical_offset: physical_offset as u64,
                    compression,
                    physical_size,
                });
            }
            ensure!(
                entries
                    .last()
                    .is_some_and(|last| last.virtual_offset < leaf_end),
                "compressed BKTR leaf end does not cover its final entry"
            );
            previous_bucket_end = leaf_end;
        }
        ensure!(
            previous_bucket_end == logical_size,
            "compressed BKTR leaves do not cover the declared RomFS length"
        );
        ensure!(
            entries[0].virtual_offset == 0
                && entries
                    .last()
                    .is_some_and(|entry| entry.virtual_offset < logical_size)
                && entries
                    .windows(2)
                    .all(|w| w[0].virtual_offset < w[1].virtual_offset),
            "compressed BKTR mappings are not strictly ordered"
        );
        for (i, entry) in entries.iter().enumerate() {
            let end = entries
                .get(i + 1)
                .map_or(logical_size, |next| next.virtual_offset);
            let span = end - entry.virtual_offset;
            match entry.compression {
                Compression::Plain => {
                    ensure!(
                        (entry.physical_size == -1
                            || u64::try_from(entry.physical_size).ok() == Some(span))
                            && entry
                                .physical_offset
                                .checked_add(span)
                                .is_some_and(|n| n <= index_offset),
                        "compressed BKTR uncompressed span exceeds physical data"
                    );
                }
                Compression::Zeros => {
                    ensure!(
                        entry.physical_size == 0 && entry.physical_offset <= index_offset,
                        "compressed BKTR zero span has invalid physical metadata"
                    );
                }
                Compression::Lz4 => {
                    ensure!(
                        span <= MAX_BLOCK as u64
                            && entry.physical_size > 0
                            && entry.physical_size as usize <= MAX_BLOCK
                            && entry.physical_offset.is_multiple_of(16)
                            && entry
                                .physical_offset
                                .checked_add(entry.physical_size as u64)
                                .is_some_and(|n| n <= index_offset),
                        "compressed BKTR LZ4 block is too large or out of bounds"
                    );
                }
            }
        }
        let index = CompressedBktrIndex {
            data_offset,
            logical_size,
            physical_virtual_size,
            entries: Arc::from(entries),
        };
        Ok(Self::from_index(source, &index, started.elapsed()))
    }

    pub(crate) fn logical_size(&self) -> u64 {
        self.logical_size
    }

    pub(crate) fn shared_index(&self, physical_virtual_size: u64) -> CompressedBktrIndex {
        CompressedBktrIndex {
            data_offset: self.data_offset,
            logical_size: self.logical_size,
            physical_virtual_size,
            entries: Arc::clone(&self.entries),
        }
    }

    pub(crate) fn open_shared(
        source: R,
        shared: &CompressedBktrIndex,
        physical_virtual_size: u64,
    ) -> Result<Self> {
        ensure!(
            physical_virtual_size == shared.physical_virtual_size,
            "compressed BKTR source virtual size changed after index validation"
        );
        Ok(Self::from_index(source, shared, Duration::ZERO))
    }
}

impl CompressedBktrReader<super::native_bktr::BktrVirtualReader> {
    /// A BktrVirtualReader can only be created after verification of the
    /// authenticated metadata IVFC chain (when present). Ordinary Read+Seek
    /// handles cannot bypass this proof by setting a boolean.
    pub(crate) fn open_from_verified_bktr(
        source: super::native_bktr::BktrVirtualReader,
        fs: &[u8],
        physical_virtual_size: u64,
    ) -> Result<Self> {
        Self::open_with_verified_patch(source, fs, physical_virtual_size, true)
    }
}

/// Raw LZ4 block decoding with explicit bounds, overlapping matches and exact
/// output size checks. Reuse the caller's buffer across adjacent 64 KiB blocks.
fn expand_lz4_into(src: &[u8], expected: usize, out: &mut Vec<u8>) -> io::Result<()> {
    if expected == 0 || expected > MAX_BLOCK {
        return Err(io::Error::other("LZ4 output length invalid"));
    }
    out.clear();
    if out.capacity() < expected {
        out.reserve(expected);
    }
    let mut at = 0usize;
    while at < src.len() {
        let token = src[at];
        at += 1;
        let mut literal_length = usize::from(token >> 4);
        if literal_length == 15 {
            loop {
                let add = *src
                    .get(at)
                    .ok_or_else(|| io::Error::other("LZ4 literal length truncated"))?;
                at += 1;
                literal_length = literal_length
                    .checked_add(usize::from(add))
                    .ok_or_else(|| io::Error::other("LZ4 literal overflow"))?;
                if add != 255 {
                    break;
                }
            }
        }
        if at.checked_add(literal_length).is_none_or(|n| n > src.len())
            || out
                .len()
                .checked_add(literal_length)
                .is_none_or(|n| n > expected)
        {
            return Err(io::Error::other("LZ4 literal bytes out of bounds"));
        }
        out.extend_from_slice(&src[at..at + literal_length]);
        at += literal_length;
        if at == src.len() {
            break;
        }
        if at + 2 > src.len() {
            return Err(io::Error::other("LZ4 match offset truncated"));
        }
        let distance = usize::from(u16::from_le_bytes([src[at], src[at + 1]]));
        at += 2;
        if distance == 0 || distance > out.len() {
            return Err(io::Error::other("LZ4 invalid match distance"));
        }
        let mut match_length = usize::from(token & 0x0f) + 4;
        if token & 0x0f == 15 {
            loop {
                let add = *src
                    .get(at)
                    .ok_or_else(|| io::Error::other("LZ4 match length truncated"))?;
                at += 1;
                match_length = match_length
                    .checked_add(usize::from(add))
                    .ok_or_else(|| io::Error::other("LZ4 match length overflow"))?;
                if add != 255 {
                    break;
                }
            }
        }
        if out
            .len()
            .checked_add(match_length)
            .is_none_or(|n| n > expected)
        {
            return Err(io::Error::other("LZ4 match exceeds output block"));
        }
        // LZ4 matches can overlap their own output. Copy the first period,
        // then repeatedly double the known suffix. This replaces one Vec
        // growth/push per byte with a handful of bulk copies for long runs.
        let initial = match_length.min(distance);
        let from = out.len() - distance;
        out.extend_from_within(from..from + initial);
        let mut copied = initial;
        while copied < match_length {
            let next = copied.min(match_length - copied);
            let from = out.len() - copied;
            out.extend_from_within(from..from + next);
            copied += next;
        }
    }
    if out.len() != expected {
        return Err(io::Error::other(
            "LZ4 output length does not match BucketTree",
        ));
    }
    Ok(())
}

#[cfg(test)]
fn expand_lz4_block(src: &[u8], expected: usize) -> io::Result<Vec<u8>> {
    let mut out = Vec::new();
    expand_lz4_into(src, expected, &mut out)?;
    Ok(out)
}

impl<R: Read + Seek> Read for CompressedBktrReader<R> {
    fn read(&mut self, bytes: &mut [u8]) -> io::Result<usize> {
        if bytes.is_empty() || self.position >= self.logical_size {
            return Ok(0);
        }
        let index = self
            .entries
            .partition_point(|entry| entry.virtual_offset <= self.position)
            .checked_sub(1)
            .ok_or_else(|| io::Error::other("BKTR compressed position has no mapping"))?;
        let entry = self.entries[index];
        let end = self
            .entries
            .get(index + 1)
            .map_or(self.logical_size, |next| next.virtual_offset);
        let take = bytes
            .len()
            .min(usize::try_from(end - self.position).unwrap_or(usize::MAX));
        let relative = self.position - entry.virtual_offset;
        match entry.compression {
            Compression::Plain => {
                let started = self.profile.as_ref().map(|_| Instant::now());
                let physical = self.data_offset + entry.physical_offset + relative;
                self.source.seek(SeekFrom::Start(physical))?;
                self.source.read_exact(&mut bytes[..take])?;
                if let (Some(at), Some(p)) = (started, self.profile.as_mut()) {
                    p.plain_io += at.elapsed();
                }
            }
            Compression::Zeros => bytes[..take].fill(0),
            Compression::Lz4 => {
                if self
                    .cached
                    .as_ref()
                    .is_none_or(|(cached, _)| *cached != index)
                {
                    let started = self.profile.as_ref().map(|_| Instant::now());
                    let block = &mut self.compressed_scratch;
                    block.resize(entry.physical_size as usize, 0);
                    let physical = self.data_offset + entry.physical_offset;
                    self.source.seek(SeekFrom::Start(physical))?;
                    self.source.read_exact(block)?;
                    if let (Some(at), Some(p)) = (started, self.profile.as_mut()) {
                        p.encoded_io += at.elapsed();
                    }
                    let started = self.profile.as_ref().map(|_| Instant::now());
                    let mut decoded = self.cached.take().map_or_else(Vec::new, |(_, data)| data);
                    expand_lz4_into(block, (end - entry.virtual_offset) as usize, &mut decoded)?;
                    self.cached = Some((index, decoded));
                    if let (Some(at), Some(p)) = (started, self.profile.as_mut()) {
                        p.lz4 += at.elapsed();
                        p.blocks += 1;
                    }
                }
                let decoded = &self
                    .cached
                    .as_ref()
                    .ok_or_else(|| io::Error::other("decompression cache absent"))?
                    .1;
                let from = relative as usize;
                bytes[..take].copy_from_slice(&decoded[from..from + take]);
            }
        }
        if let Some(p) = &mut self.profile {
            p.bytes += take as u64;
        }
        self.position += take as u64;
        Ok(take)
    }
}

impl<R> Seek for CompressedBktrReader<R> {
    fn seek(&mut self, pos: SeekFrom) -> io::Result<u64> {
        let next = match pos {
            SeekFrom::Start(n) => i128::from(n),
            SeekFrom::End(n) => i128::from(self.logical_size) + i128::from(n),
            SeekFrom::Current(n) => i128::from(self.position) + i128::from(n),
        };
        if !(0..=i128::from(self.logical_size)).contains(&next) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "compressed BKTR seek exceeds virtual RomFS",
            ));
        }
        self.position = next as u64;
        Ok(self.position)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    #[test]
    fn stage41_authenticated_compressed_bktr_requires_verified_patch_path() -> Result<()> {
        let (plain, data) = synthetic();
        let mut authenticated = plain.clone();
        authenticated[5] = 1;
        authenticated[0x1a8..0x1b0].copy_from_slice(&0xe8u64.to_le_bytes());
        authenticated[0x1b0] = 0x42;
        assert!(validate_compressed_bktr_layout(&authenticated, 0xa000).is_err());
        assert!(
            CompressedBktrReader::open(Cursor::new(data.clone()), &authenticated, 0xa000).is_err(),
            "An arbitrary Read+Seek must not bypass IVFC authentication"
        );
        let valid = validate_compressed_bktr_layout_after_verified_patch(&authenticated, 0xa000)?;
        assert_eq!(valid.index_bytes, 0x8000);

        let mut bad = authenticated.clone();
        bad[0x1a8..0x1b0].copy_from_slice(&0xffffu64.to_le_bytes());
        assert!(validate_compressed_bktr_layout_after_verified_patch(&bad, 0xa000).is_err());
        bad = authenticated.clone();
        bad[0x1d0] = 1;
        assert!(validate_compressed_bktr_layout_after_verified_patch(&bad, 0xa000).is_err());
        bad = authenticated.clone();
        bad[0x194] = 1;
        assert!(validate_compressed_bktr_layout_after_verified_patch(&bad, 0xa000).is_err());
        bad = authenticated.clone();
        bad[5] = 2;
        assert!(validate_compressed_bktr_layout_after_verified_patch(&bad, 0xa000).is_err());
        // A normal type-0 input remains readable through the legacy path.
        assert!(validate_compressed_bktr_layout(&plain, 0xa000).is_ok());
        Ok(())
    }

    fn synthetic() -> (Vec<u8>, Vec<u8>) {
        let mut fs = vec![0u8; 0x200];
        fs[2..6].copy_from_slice(&[0, 3, 4, 0]);
        fs[8..12].copy_from_slice(b"IVFC");
        fs[0x14..0x18].copy_from_slice(&3u32.to_le_bytes());
        fs[0x30..0x38].copy_from_slice(&0x1000u64.to_le_bytes());
        fs[0x38..0x40].copy_from_slice(&0x9000u64.to_le_bytes());
        fs[0x178..0x180].copy_from_slice(&0x1000u64.to_le_bytes());
        fs[0x180..0x188].copy_from_slice(&0x8000u64.to_le_bytes());
        fs[0x188..0x18c].copy_from_slice(b"BKTR");
        fs[0x18c..0x190].copy_from_slice(&1u32.to_le_bytes());
        fs[0x190..0x194].copy_from_slice(&2u32.to_le_bytes());
        let mut bytes = vec![0u8; 0xa000];
        bytes[0x1000..0x1005].copy_from_slice(b"hello");
        bytes[0x1010..0x1015].copy_from_slice(&[0x40, b'A', b'B', b'C', b'D']);
        bytes[0x2004..0x2008].copy_from_slice(&1u32.to_le_bytes());
        bytes[0x2008..0x2010].copy_from_slice(&9u64.to_le_bytes());
        bytes[0x6004..0x6008].copy_from_slice(&2u32.to_le_bytes());
        bytes[0x6008..0x6010].copy_from_slice(&9u64.to_le_bytes());
        // BucketTree entry 0: passthrough with unknown physical span (-1).
        bytes[0x6020..0x6028].copy_from_slice(&0u64.to_le_bytes());
        bytes[0x6024..0x6028].copy_from_slice(&(-1i32).to_le_bytes());
        // BucketTree entry 1: compressed block with 16-byte alignment.
        bytes[0x6028..0x6030].copy_from_slice(&5u64.to_le_bytes());
        bytes[0x6030..0x6038].copy_from_slice(&0x10u64.to_le_bytes());
        bytes[0x6038] = 3;
        bytes[0x603c..0x6040].copy_from_slice(&5i32.to_le_bytes());
        (fs, bytes)
    }

    #[test]
    fn stage23_multiple_compressed_bktr_leaves_and_corrupt_boundary() -> Result<()> {
        let per = (NODE_SIZE - 0x10) / RECORD_SIZE;
        let count = per + 1;
        let logical_size = count as u64;
        let index_offset = 0x1000u64;
        let index_size = (3 * NODE_SIZE) as u64;
        let physical_size = index_offset + index_size;
        let mut fs = vec![0u8; 0x200];
        fs[2..6].copy_from_slice(&[0, 3, 4, 0]);
        fs[8..12].copy_from_slice(b"IVFC");
        fs[0x14..0x18].copy_from_slice(&3u32.to_le_bytes());
        fs[0x30..0x38].copy_from_slice(&0u64.to_le_bytes());
        fs[0x38..0x40].copy_from_slice(&physical_size.to_le_bytes());
        fs[0x178..0x180].copy_from_slice(&index_offset.to_le_bytes());
        fs[0x180..0x188].copy_from_slice(&index_size.to_le_bytes());
        fs[0x188..0x18c].copy_from_slice(b"BKTR");
        fs[0x18c..0x190].copy_from_slice(&1u32.to_le_bytes());
        fs[0x190..0x194].copy_from_slice(&(count as u32).to_le_bytes());
        let mut raw = vec![0u8; physical_size as usize];
        let root = index_offset as usize;
        raw[root + 4..root + 8].copy_from_slice(&2u32.to_le_bytes());
        raw[root + 8..root + 16].copy_from_slice(&logical_size.to_le_bytes());
        for i in 0..count {
            let leaf_number = i / per;
            let local = i % per;
            let leaf = root + (leaf_number + 1) * NODE_SIZE;
            raw[leaf..leaf + 4].copy_from_slice(&(leaf_number as u32).to_le_bytes());
            raw[leaf + 4..leaf + 8]
                .copy_from_slice(&((if leaf_number == 0 { per } else { 1 }) as u32).to_le_bytes());
            raw[leaf + 8..leaf + 16].copy_from_slice(
                &(if leaf_number == 0 {
                    per as u64
                } else {
                    logical_size
                })
                .to_le_bytes(),
            );
            let at = leaf + 0x10 + local * RECORD_SIZE;
            raw[at..at + 8].copy_from_slice(&(i as u64).to_le_bytes());
            raw[at + 0x10] = 1; // zero-filled span, no physical data
        }
        let mut reader = CompressedBktrReader::open(Cursor::new(raw.clone()), &fs, physical_size)?;
        assert_eq!(reader.logical_size(), logical_size);
        let mut decoded = vec![1u8; count];
        reader.read_exact(&mut decoded)?;
        assert!(decoded.iter().all(|&byte| byte == 0));
        reader.seek(SeekFrom::Start(per as u64 - 1))?;
        let mut crossing = [0xff; 2];
        reader.read_exact(&mut crossing)?;
        assert_eq!(crossing, [0, 0]);

        let second_leaf = root + 2 * NODE_SIZE;
        let mut wrong_leaf = raw.clone();
        wrong_leaf[second_leaf..second_leaf + 4].copy_from_slice(&0u32.to_le_bytes());
        assert!(
            CompressedBktrReader::open(Cursor::new(wrong_leaf), &fs, physical_size).is_err(),
            "repeated leaf indexes must fail closed"
        );
        let mut overlapping = raw.clone();
        overlapping[second_leaf + 0x10..second_leaf + 0x18].copy_from_slice(&0u64.to_le_bytes());
        assert!(
            CompressedBktrReader::open(Cursor::new(overlapping), &fs, physical_size).is_err(),
            "overlapping compressed leaf ranges must fail closed"
        );
        let mut broken_count = fs.clone();
        broken_count[0x190..0x194].copy_from_slice(&u32::MAX.to_le_bytes());
        assert!(
            CompressedBktrReader::open(Cursor::new(raw), &broken_count, physical_size).is_err(),
            "untrusted oversized compressed entry count must fail before allocation"
        );
        Ok(())
    }

    #[test]
    fn stage51_nonzero_alignment_padding_does_not_change_lz4_mapping() -> Result<()> {
        let (fs_header, mut data) = synthetic();
        // The second BucketTree entry begins at 0x6028. Its type is at
        // +0x10; the three following bytes are alignment padding and may
        // contain arbitrary values in legitimate images.
        data[0x6039..0x603c].copy_from_slice(&[0x10, 0xa5, 0x7e]);
        let mut reader =
            CompressedBktrReader::open(std::io::Cursor::new(data.clone()), &fs_header, 0xa000)?;
        let mut decoded = [0u8; 9];
        reader.read_exact(&mut decoded)?;
        assert_eq!(&decoded, b"helloABCD");
        // A signed negative physical offset remains rejected even when
        // nonzero alignment padding is allowed.
        data[0x6030..0x6038].copy_from_slice(&(-1i64).to_le_bytes());
        assert!(
            CompressedBktrReader::open(std::io::Cursor::new(data), &fs_header, 0xa000).is_err()
        );
        Ok(())
    }

    #[test]
    fn compressed_romfs_mixes_plain_and_raw_lz4() -> Result<()> {
        let (fs, data) = synthetic();
        let mut reader = CompressedBktrReader::open(Cursor::new(data), &fs, 0xa000)?;
        assert_eq!(reader.logical_size(), 9);
        let mut buf = [0u8; 9];
        reader.read_exact(&mut buf)?;
        assert_eq!(&buf, b"helloABCD");
        reader.seek(SeekFrom::Start(3))?;
        let mut overlapping = [0u8; 5];
        reader.read_exact(&mut overlapping)?;
        assert_eq!(&overlapping, b"loABC");
        assert!(reader.seek(SeekFrom::End(1)).is_err());
        Ok(())
    }

    #[test]
    fn shared_compressed_bktr_index_preserves_plain_lz4_and_random_access() -> Result<()> {
        let (fs, data) = synthetic();
        let original = CompressedBktrReader::open(Cursor::new(data.clone()), &fs, 0xa000)?;
        let index = original.shared_index(0xa000);
        let mut worker =
            CompressedBktrReader::open_shared(Cursor::new(data.clone()), &index, 0xa000)?;
        assert!(Arc::ptr_eq(&index.entries, &worker.entries));
        assert_eq!(worker.logical_size(), original.logical_size());
        let mut full = [0; 9];
        worker.read_exact(&mut full)?;
        assert_eq!(&full, b"helloABCD");
        worker.seek(SeekFrom::Start(4))?;
        let mut crossing = [0; 5];
        worker.read_exact(&mut crossing)?;
        assert_eq!(&crossing, b"oABCD");
        worker.seek(SeekFrom::End(-4))?;
        let mut compressed = [0; 4];
        worker.read_exact(&mut compressed)?;
        assert_eq!(&compressed, b"ABCD");
        assert!(
            CompressedBktrReader::open_shared(Cursor::new(data), &index, 0x9000).is_err(),
            "shared mapping must reject changed virtual size"
        );
        Ok(())
    }

    #[test]
    fn shared_compressed_index_does_not_read_source_on_open() -> Result<()> {
        struct NoRead;
        impl Read for NoRead {
            fn read(&mut self, _: &mut [u8]) -> io::Result<usize> {
                Err(io::Error::other(
                    "source unexpectedly read while sharing index",
                ))
            }
        }
        impl Seek for NoRead {
            fn seek(&mut self, _: SeekFrom) -> io::Result<u64> {
                Err(io::Error::other(
                    "source unexpectedly seeked while sharing index",
                ))
            }
        }
        let (fs, data) = synthetic();
        let primary = CompressedBktrReader::open(Cursor::new(data), &fs, 0xa000)?;
        let index = primary.shared_index(0xa000);
        let worker = CompressedBktrReader::open_shared(NoRead, &index, 0xa000)?;
        assert!(Arc::ptr_eq(&worker.entries, &index.entries));
        Ok(())
    }

    #[test]
    fn lz4_rejects_bad_offsets_and_output_limits() {
        assert_eq!(
            expand_lz4_block(&[0x40, b'A', b'B', b'C', b'D'], 4).unwrap(),
            b"ABCD"
        );
        assert!(expand_lz4_block(&[0x00, 0x00, 0x00], 4).is_err());
        assert!(expand_lz4_block(&[0x40, b'A'], 4).is_err());
        assert!(expand_lz4_block(&[0x00], 0).is_err());
        assert_eq!(
            expand_lz4_block(&[0x11, b'A', 0x01, 0x00], 6).unwrap(),
            b"AAAAAA"
        );
    }

    #[test]
    fn lz4_bulk_matches_reference_for_overlaps_and_boundary_sizes() -> Result<()> {
        fn extra(mut value: usize, encoded: &mut Vec<u8>) {
            while value >= 255 {
                encoded.push(255);
                value -= 255;
            }
            encoded.push(value as u8);
        }
        for distance in 1..=48usize {
            for length in [4, 5, 7, 18, 19, 20, 31, 63, 255, 1024, 4095, 65500] {
                if distance + length > MAX_BLOCK {
                    continue;
                }
                let literals = (0..distance)
                    .map(|i| ((i * 37 + distance) % 251) as u8)
                    .collect::<Vec<_>>();
                let mut encoded =
                    vec![((distance.min(15) as u8) << 4) | ((length - 4).min(15) as u8)];
                if distance >= 15 {
                    extra(distance - 15, &mut encoded);
                }
                encoded.extend_from_slice(&literals);
                encoded.extend_from_slice(&(distance as u16).to_le_bytes());
                if length - 4 >= 15 {
                    extra(length - 19, &mut encoded);
                }
                let mut expected = literals.clone();
                for _ in 0..length {
                    expected.push(expected[expected.len() - distance]);
                }
                let decoded = expand_lz4_block(&encoded, expected.len())?;
                assert_eq!(decoded, expected, "distance={distance} length={length}");
            }
        }
        Ok(())
    }

    #[test]
    fn lz4_output_allocation_is_reused_and_bad_stream_is_rejected() -> Result<()> {
        let mut decoded = Vec::with_capacity(MAX_BLOCK);
        let original = decoded.as_ptr();
        for _ in 0..100 {
            expand_lz4_into(&[0x11, b'Z', 1, 0], 6, &mut decoded)?;
            assert_eq!(&decoded, b"ZZZZZZ");
            assert_eq!(decoded.as_ptr(), original, "unexpected buffer reallocation");
            expand_lz4_into(&[0x40, b'A', b'B', b'C', b'D'], 4, &mut decoded)?;
            assert_eq!(&decoded, b"ABCD");
        }
        for bad in [&[0x11, b'X', 0, 0][..], &[0xff, 0xff][..]] {
            assert!(expand_lz4_into(bad, 20, &mut decoded).is_err());
        }
        Ok(())
    }

    #[test]
    fn compressed_bktr_plain_region_supports_offsets_above_four_gib() -> Result<()> {
        // A sparse synthetic source covers >4 GiB logical and physical
        // offsets, but allocates only the 32 KiB BucketTree metadata.
        struct SparseSource {
            pos: u64,
            length: u64,
            index_offset: u64,
            index: Vec<u8>,
        }
        impl Read for SparseSource {
            fn read(&mut self, output: &mut [u8]) -> io::Result<usize> {
                let take = output.len().min(
                    usize::try_from(self.length.saturating_sub(self.pos)).unwrap_or(usize::MAX),
                );
                output[..take].fill(0);
                let end = self.pos + take as u64;
                let index_end = self.index_offset + self.index.len() as u64;
                let start = self.pos.max(self.index_offset);
                let stop = end.min(index_end);
                if start < stop {
                    let dest = (start - self.pos) as usize;
                    let source = (start - self.index_offset) as usize;
                    let count = (stop - start) as usize;
                    output[dest..dest + count].copy_from_slice(&self.index[source..source + count]);
                }
                self.pos += take as u64;
                Ok(take)
            }
        }
        impl Seek for SparseSource {
            fn seek(&mut self, from: SeekFrom) -> io::Result<u64> {
                let next = match from {
                    SeekFrom::Start(n) => i128::from(n),
                    SeekFrom::End(n) => i128::from(self.length) + i128::from(n),
                    SeekFrom::Current(n) => i128::from(self.pos) + i128::from(n),
                };
                if !(0..=i128::from(self.length)).contains(&next) {
                    return Err(io::Error::other("sparse source seek outside file"));
                }
                self.pos = next as u64;
                Ok(self.pos)
            }
        }
        let size = (4u64 << 30) + 0x1001;
        let data_offset = 0x1000u64;
        let index_offset = size;
        let index_size = (2 * NODE_SIZE) as u64;
        let physical_size = data_offset + index_offset + index_size;
        let mut fs = vec![0u8; 0x200];
        fs[2..6].copy_from_slice(&[0, 3, 4, 0]);
        fs[8..12].copy_from_slice(b"IVFC");
        fs[0x14..0x18].copy_from_slice(&3u32.to_le_bytes());
        fs[0x30..0x38].copy_from_slice(&data_offset.to_le_bytes());
        fs[0x38..0x40].copy_from_slice(&(index_offset + index_size).to_le_bytes());
        fs[0x178..0x180].copy_from_slice(&index_offset.to_le_bytes());
        fs[0x180..0x188].copy_from_slice(&index_size.to_le_bytes());
        fs[0x188..0x18c].copy_from_slice(b"BKTR");
        fs[0x18c..0x190].copy_from_slice(&1u32.to_le_bytes());
        fs[0x190..0x194].copy_from_slice(&1u32.to_le_bytes());
        let mut index = vec![0u8; 2 * NODE_SIZE];
        index[4..8].copy_from_slice(&1u32.to_le_bytes());
        index[8..16].copy_from_slice(&size.to_le_bytes());
        index[NODE_SIZE + 4..NODE_SIZE + 8].copy_from_slice(&1u32.to_le_bytes());
        index[NODE_SIZE + 8..NODE_SIZE + 16].copy_from_slice(&size.to_le_bytes());
        index[NODE_SIZE + 0x24..NODE_SIZE + 0x28].copy_from_slice(&(-1i32).to_le_bytes());
        let sparse = SparseSource {
            pos: 0,
            length: physical_size,
            index_offset: data_offset + index_offset,
            index,
        };
        let mut reader = CompressedBktrReader::open(sparse, &fs, physical_size)?;
        assert_eq!(reader.logical_size(), size);
        let mut zeroes = [0x77u8; 128];
        reader.seek(SeekFrom::Start((4u64 << 30) - 32))?;
        reader.read_exact(&mut zeroes)?;
        assert!(zeroes.iter().all(|&value| value == 0));
        reader.seek(SeekFrom::End(-17))?;
        assert_eq!(reader.read(&mut zeroes)?, 17);
        assert!(reader.seek(SeekFrom::End(1)).is_err());
        Ok(())
    }

    #[test]
    fn compressed_index_corruption_is_rejected() {
        let (fs, data) = synthetic();
        let mut wrong_version = fs.clone();
        wrong_version[0x18c] = 2;
        assert!(
            CompressedBktrReader::open(Cursor::new(data.clone()), &wrong_version, 0xa000).is_err()
        );
        let mut bad_count = fs.clone();
        bad_count[0x190..0x194].copy_from_slice(&u32::MAX.to_le_bytes());
        assert!(CompressedBktrReader::open(Cursor::new(data.clone()), &bad_count, 0xa000).is_err());
        let mut bad = data.clone();
        bad[0x6038] = 9;
        assert!(CompressedBktrReader::open(Cursor::new(bad), &fs, 0xa000).is_err());
    }
}
