//! On-demand BKTR virtual section reader for base/update NCA pairs.
//!
//! The indirect tree maps each virtual byte either to a base-section offset
//! or to an encrypted patch-section offset. The patch encryption tree then
//! selects the appropriate AES-CTR-EX generation for physical update bytes.
//! Unsupported layouts are rejected so the LibHac fallback remains safe.

use crate::formats::{
    bktr::{
        BktrRelocationEntry, BktrRelocationTable, BktrSectionInfo, aes_ctr_ex_counter,
        collect_from_reader, collect_relocations_from_reader, verify_patch_metadata_integrity,
    },
    nca::NcaSection,
};
use aes::Aes128;
use anyhow::{Result, bail, ensure};
use cipher::{KeyIvInit, StreamCipher, StreamCipherSeek};
use ctr::Ctr128BE;
use std::{
    collections::HashMap,
    fs::File,
    io::{self, BufReader, Read, Seek, SeekFrom},
    path::{Path, PathBuf},
    sync::Arc,
    time::{Duration, Instant},
};

type CachedCtr = Ctr128BE<Aes128>;
// Measured with real compressed BKTR reads: 256 KiB avoids excessive
// read-ahead for short mapped spans, and 2 handles x 4 workers use ~2 MiB
// instead of the former ~8 MiB of physical reader buffers.
const READ_BUFFER: usize = 256 * 1024;

fn read_buffer_capacity() -> usize {
    // Benchmark-only override for independent source I/O A/B. Unknown
    // values always fall back to the verified production default.
    std::env::var("NSRP_BKTR_BENCH_READ_KIB")
        .ok()
        .and_then(|v| v.parse::<usize>().ok())
        .filter(|&size| matches!(size, 64 | 128 | 256 | 1024))
        .map_or(READ_BUFFER, |kib| kib * 1024)
}

pub(crate) struct BktrVirtualReader {
    base: BufReader<File>,
    patch: BufReader<File>,
    base_section: NcaSection,
    patch_section: NcaSection,
    patch_key: [u8; 16],
    relocation: Arc<BktrRelocationTable>,
    crypto: Arc<BktrSectionInfo>,
    position: u64,
    base_cipher: Option<CachedCtr>,
    base_cipher_at: Option<u64>,
    patch_ciphers: HashMap<u32, CachedCtr>,
    patch_cipher_at: HashMap<u32, u64>,
    base_reader_at: Option<u64>,
    patch_reader_at: Option<u64>,
    always_seek: bool,
    profile: Option<BktrReaderProfile>,
}

/// Validated BKTR mappings are immutable. Worker handles can share them
/// without re-reading, decrypting and parsing both BucketTree indexes.
pub(crate) struct BktrReaderTemplate {
    base_path: PathBuf,
    patch_path: PathBuf,
    base_size: u64,
    patch_size: u64,
    base_section: NcaSection,
    patch_section: NcaSection,
    base_key: Option<[u8; 16]>,
    patch_key: [u8; 16],
    relocation: Arc<BktrRelocationTable>,
    crypto: Arc<BktrSectionInfo>,
}

#[derive(Default)]
struct BktrReaderProfile {
    open: Duration,
    base_io: Duration,
    patch_io: Duration,
    aes: Duration,
    bytes: u64,
    reads: u64,
}

impl Drop for BktrVirtualReader {
    fn drop(&mut self) {
        if let Some(p) = &self.profile {
            eprintln!(
                "STAGE14_BKTR_AES_PROFILE open_ms={} base_io_ms={} patch_io_ms={} aes_ms={} bytes={} reads={}",
                p.open.as_millis(),
                p.base_io.as_millis(),
                p.patch_io.as_millis(),
                p.aes.as_millis(),
                p.bytes,
                p.reads
            );
        }
    }
}

impl BktrVirtualReader {
    /// Common initializer for the primary reader and every worker handle.
    /// Index parsing/validation happens only in open; all readers reuse
    /// the exact same mapping but own independent file cursors and CTR state.
    #[allow(clippy::too_many_arguments)]
    fn from_validated_parts(
        base: File,
        patch: File,
        base_section: NcaSection,
        patch_section: NcaSection,
        base_key: Option<[u8; 16]>,
        patch_key: [u8; 16],
        relocation: Arc<BktrRelocationTable>,
        crypto: Arc<BktrSectionInfo>,
        started: Instant,
    ) -> Result<Self> {
        let base_cipher = base_key
            .map(|key| make_ctr(&key, &base_section.counter))
            .transpose()?;
        Ok(Self {
            base: BufReader::with_capacity(read_buffer_capacity(), base),
            patch: BufReader::with_capacity(read_buffer_capacity(), patch),
            base_section,
            patch_section,
            patch_key,
            relocation,
            crypto,
            position: 0,
            base_cipher,
            base_cipher_at: None,
            patch_ciphers: HashMap::new(),
            patch_cipher_at: HashMap::new(),
            base_reader_at: None,
            patch_reader_at: None,
            always_seek: std::env::var("NSRP_BKTR_BENCH_IO_CURSOR").ok().as_deref()
                == Some("always"),
            profile: std::env::var_os("NSRP_STAGE14_PROFILE").map(|_| BktrReaderProfile {
                open: started.elapsed(),
                ..Default::default()
            }),
        })
    }

    #[allow(clippy::too_many_arguments)]
    pub(crate) fn open(
        base_path: &Path,
        patch_path: &Path,
        base_section: &NcaSection,
        patch_section: &NcaSection,
        patch_fs_header: &[u8],
        base_key: Option<[u8; 16]>,
        patch_key: [u8; 16],
    ) -> Result<Self> {
        let started = Instant::now();
        ensure!(
            matches!(base_section.encryption_type, 1 | 3)
                && matches!(patch_section.encryption_type, 4),
            "unsupported BKTR base/patch section crypto"
        );
        if base_section.encryption_type == 3 && base_key.is_none() {
            bail!("BKTR base crypto key unavailable");
        }
        let base = File::open(base_path)?;
        let mut patch = File::open(patch_path)?;
        let base_size = base.metadata()?.len();
        let patch_size = patch.metadata()?.len();
        ensure!(
            base_section
                .offset
                .checked_add(base_section.size)
                .is_some_and(|v| v <= base_size)
                && patch_section
                    .offset
                    .checked_add(patch_section.size)
                    .is_some_and(|v| v <= patch_size),
            "BKTR NCA section exceeds physical file"
        );
        // Newer BKTR lookup trees carry an independent authenticated
        // metadata IVFC. Verify every lookup block before trusting either
        // mapping table. Legacy sections without the layer remain supported.
        verify_patch_metadata_integrity(
            &mut patch,
            0,
            patch_size,
            patch_section.offset,
            patch_section.size,
            patch_fs_header,
            &patch_key,
        )?;
        let relocation = collect_relocations_from_reader(
            &mut patch,
            0,
            patch_size,
            patch_section.offset,
            patch_section.size,
            patch_fs_header,
            &patch_key,
        )?;
        let crypto = collect_from_reader(
            &mut patch,
            0,
            patch_size,
            patch_section.offset,
            patch_section.size,
            patch_fs_header,
            &patch_key,
        )?;
        ensure!(
            relocation.virtual_size > 0
                && !relocation.entries.is_empty()
                && !crypto.entries.is_empty(),
            "BKTR overlay has no mapping"
        );
        // Bounds-check every relocation span before exposing the reader.
        for (i, entry) in relocation.entries.iter().enumerate() {
            let end = relocation
                .entries
                .get(i + 1)
                .map_or(relocation.virtual_size, |next| next.virtual_offset);
            let length = end
                .checked_sub(entry.virtual_offset)
                .ok_or_else(|| anyhow::anyhow!("BKTR relocation entries not increasing"))?;
            let max = if entry.from_patch {
                crypto.bktr_offset
            } else {
                base_section.size
            };
            ensure!(
                entry
                    .source_offset
                    .checked_add(length)
                    .is_some_and(|v| v <= max),
                "BKTR relocation region exceeds its source"
            );
        }
        Self::from_validated_parts(
            base,
            patch,
            base_section.clone(),
            patch_section.clone(),
            base_key,
            patch_key,
            Arc::new(relocation),
            Arc::new(crypto),
            started,
        )
    }

    pub(crate) fn virtual_size(&self) -> u64 {
        self.relocation.virtual_size
    }

    pub(crate) fn shared_template(
        &self,
        base_path: &Path,
        patch_path: &Path,
        base_key: Option<[u8; 16]>,
    ) -> Result<BktrReaderTemplate> {
        Ok(BktrReaderTemplate {
            base_path: base_path.to_path_buf(),
            patch_path: patch_path.to_path_buf(),
            base_size: self.base.get_ref().metadata()?.len(),
            patch_size: self.patch.get_ref().metadata()?.len(),
            base_section: self.base_section.clone(),
            patch_section: self.patch_section.clone(),
            base_key,
            patch_key: self.patch_key,
            relocation: Arc::clone(&self.relocation),
            crypto: Arc::clone(&self.crypto),
        })
    }

    fn select(&self, position: u64) -> io::Result<(usize, &BktrRelocationEntry)> {
        let count = self
            .relocation
            .entries
            .partition_point(|entry| entry.virtual_offset <= position);
        let index = count
            .checked_sub(1)
            .ok_or_else(|| io::Error::other("BKTR read before first mapping"))?;
        Ok((index, &self.relocation.entries[index]))
    }
}

impl BktrReaderTemplate {
    pub(crate) fn open(&self) -> Result<BktrVirtualReader> {
        let started = Instant::now();
        let base = File::open(&self.base_path)?;
        let patch = File::open(&self.patch_path)?;
        // Newly opened handles must still satisfy the previously validated
        // section bounds. Never share file positions across worker handles.
        ensure!(
            base.metadata()?.len() == self.base_size && patch.metadata()?.len() == self.patch_size,
            "BKTR source length changed after index validation"
        );
        BktrVirtualReader::from_validated_parts(
            base,
            patch,
            self.base_section.clone(),
            self.patch_section.clone(),
            self.base_key,
            self.patch_key,
            Arc::clone(&self.relocation),
            Arc::clone(&self.crypto),
            started,
        )
    }
}

impl Read for BktrVirtualReader {
    fn read(&mut self, output: &mut [u8]) -> io::Result<usize> {
        if output.is_empty() || self.position >= self.relocation.virtual_size {
            return Ok(0);
        }
        let (entry_index, entry) = self.select(self.position)?;
        let span_end = self
            .relocation
            .entries
            .get(entry_index + 1)
            .map_or(self.relocation.virtual_size, |next| next.virtual_offset);
        let virtual_remaining = span_end - self.position;
        let count = output
            .len()
            .min(usize::try_from(virtual_remaining).unwrap_or(usize::MAX));
        let source = entry
            .source_offset
            .checked_add(self.position - entry.virtual_offset)
            .ok_or_else(|| io::Error::other("BKTR mapping overflow"))?;
        let actual = if entry.from_patch {
            let index = self
                .crypto
                .entries
                .partition_point(|crypt| crypt.offset <= source)
                .checked_sub(1)
                .ok_or_else(|| io::Error::other("BKTR encryption segment not mapped"))?;
            let crypt = &self.crypto.entries[index];
            let crypt_end = self
                .crypto
                .entries
                .get(index + 1)
                .map_or(self.crypto.bktr_offset, |next| next.offset)
                .min(self.crypto.bktr_offset);
            if source >= crypt_end {
                return Err(io::Error::other("BKTR encryption boundary exceeded"));
            }
            let take = count.min(usize::try_from(crypt_end - source).unwrap_or(usize::MAX));
            let absolute = self
                .patch_section
                .offset
                .checked_add(source)
                .ok_or_else(|| io::Error::other("BKTR patch physical offset overflow"))?;
            let started = self.profile.as_ref().map(|_| Instant::now());
            read_at(
                &mut self.patch,
                &mut self.patch_reader_at,
                absolute,
                &mut output[..take],
                self.always_seek,
            )?;
            if let (Some(at), Some(p)) = (started, self.profile.as_mut()) {
                p.patch_io += at.elapsed();
            }
            if crypt.encrypted {
                let started = self.profile.as_ref().map(|_| Instant::now());
                if !self.patch_ciphers.contains_key(&crypt.generation) {
                    // Malformed update files may supply arbitrarily many
                    // generation IDs. Avoid unbounded cached key schedules.
                    if self.patch_ciphers.len() >= 64 {
                        self.patch_ciphers.clear();
                        self.patch_cipher_at.clear();
                    }
                    let counter = aes_ctr_ex_counter(self.crypto.secure_value, crypt.generation);
                    let cipher = make_ctr(&self.patch_key, &counter)
                        .map_err(|error| io::Error::other(error.to_string()))?;
                    self.patch_ciphers.insert(crypt.generation, cipher);
                }
                let cipher = self
                    .patch_ciphers
                    .get_mut(&crypt.generation)
                    .ok_or_else(|| io::Error::other("BKTR cipher unavailable"))?;
                if self.patch_cipher_at.get(&crypt.generation).copied() != Some(absolute) {
                    cipher.seek(absolute);
                }
                cipher.apply_keystream(&mut output[..take]);
                self.patch_cipher_at
                    .insert(crypt.generation, absolute + take as u64);
                if let (Some(at), Some(p)) = (started, self.profile.as_mut()) {
                    p.aes += at.elapsed();
                }
            }
            take
        } else {
            let absolute = self
                .base_section
                .offset
                .checked_add(source)
                .ok_or_else(|| io::Error::other("BKTR base physical offset overflow"))?;
            let started = self.profile.as_ref().map(|_| Instant::now());
            read_at(
                &mut self.base,
                &mut self.base_reader_at,
                absolute,
                &mut output[..count],
                self.always_seek,
            )?;
            if let (Some(at), Some(p)) = (started, self.profile.as_mut()) {
                p.base_io += at.elapsed();
            }
            if let Some(cipher) = self.base_cipher.as_mut() {
                let started = self.profile.as_ref().map(|_| Instant::now());
                if self.base_cipher_at != Some(absolute) {
                    cipher.seek(absolute);
                }
                cipher.apply_keystream(&mut output[..count]);
                self.base_cipher_at = Some(absolute + count as u64);
                if let (Some(at), Some(p)) = (started, self.profile.as_mut()) {
                    p.aes += at.elapsed();
                }
            }
            count
        };
        if let Some(p) = &mut self.profile {
            p.bytes += actual as u64;
            p.reads += 1;
        }
        self.position += actual as u64;
        Ok(actual)
    }
}

/// BKTR work units normally read adjacent physical spans. Reusing each
/// reader's position avoids needless seeks without ever sharing file handles
/// or AES state between workers. On any read error the hint is invalidated.
fn read_at(
    reader: &mut BufReader<File>,
    next_at: &mut Option<u64>,
    absolute: u64,
    output: &mut [u8],
    always_seek: bool,
) -> io::Result<()> {
    let contiguous = !always_seek && *next_at == Some(absolute);
    *next_at = None;
    if !contiguous {
        reader.seek(SeekFrom::Start(absolute))?;
    }
    reader.read_exact(output)?;
    *next_at = Some(
        absolute
            .checked_add(output.len() as u64)
            .ok_or_else(|| io::Error::other("BKTR physical read overflow"))?,
    );
    Ok(())
}

fn make_ctr(key: &[u8; 16], counter: &[u8; 16]) -> Result<CachedCtr> {
    // NCA CTR counter high nibble is retained at byte 8. The low 60 bits
    // encode the absolute 16-byte block index. StreamCipherSeek then skips
    // to the corresponding byte offset without re-expanding the AES key.
    let mut iv = *counter;
    iv[8..16].fill(0);
    iv[8] = counter[7] & 0xf0;
    Ok(CachedCtr::new_from_slices(key, &iv)?)
}

impl Seek for BktrVirtualReader {
    fn seek(&mut self, pos: SeekFrom) -> io::Result<u64> {
        let current = i128::from(self.position);
        let size = i128::from(self.relocation.virtual_size);
        let target = match pos {
            SeekFrom::Start(value) => i128::from(value),
            SeekFrom::End(value) => size + i128::from(value),
            SeekFrom::Current(value) => current + i128::from(value),
        };
        if !(0..=size).contains(&target) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "BKTR seek outside virtual section",
            ));
        }
        self.position = target as u64;
        Ok(self.position)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::nca_ctr_xcrypt_range;
    use crate::formats::bktr::AesCtrExEntry;
    use crate::formats::nca::{NCA_XTS_HEADER_SIZE, decrypt_header, derive_section_key};
    use crate::formats::ncz_stream::decompress_ncz_region_to_nca;
    use crate::keys::KeySet;
    use crate::ops::container::list_entries;
    use crate::ops::native_compressed::{
        CompressedBktrReader, validate_compressed_bktr_layout_after_verified_patch,
    };
    use anyhow::Context;
    use sha2::Digest;
    use std::io::{BufWriter, Write};
    use std::sync::atomic::AtomicBool;
    use std::{collections::BTreeMap, fs, path::Path};

    fn hash_sandbox_files(root: &Path) -> Result<BTreeMap<std::path::PathBuf, (u64, String)>> {
        let mut result = BTreeMap::new();
        let mut pending = vec![root.to_path_buf()];
        let mut buffer = vec![0u8; 1024 * 1024];
        while let Some(dir) = pending.pop() {
            for entry in fs::read_dir(&dir)? {
                let path = entry?.path();
                let meta = fs::symlink_metadata(&path)?;
                ensure!(
                    !meta.file_type().is_symlink(),
                    "Unexpected symlink in sandbox RomFS"
                );
                if meta.is_dir() {
                    pending.push(path);
                    continue;
                }
                ensure!(meta.is_file(), "Unrecognized sandbox RomFS object");
                let mut hasher = sha2::Sha256::new();
                let mut reader = File::open(&path)?;
                loop {
                    let n = reader.read(&mut buffer)?;
                    if n == 0 {
                        break;
                    }
                    hasher.update(&buffer[..n]);
                }
                result.insert(
                    path.strip_prefix(root)?.to_path_buf(),
                    (meta.len(), hex::encode(hasher.finalize())),
                );
            }
        }
        Ok(result)
    }

    #[test]
    fn physical_cursor_reuses_contiguous_reads_and_recovers_after_error() -> Result<()> {
        let dir = tempfile::tempdir()?;
        let path = dir.path().join("physical.bin");
        fs::write(&path, (0u8..=255).collect::<Vec<_>>())?;
        let mut reader = BufReader::with_capacity(32, File::open(&path)?);
        let mut next = None;
        let mut bytes = [0u8; 8];
        read_at(&mut reader, &mut next, 8, &mut bytes, false)?;
        assert_eq!(&bytes, &[8, 9, 10, 11, 12, 13, 14, 15]);
        assert_eq!(next, Some(16));
        read_at(&mut reader, &mut next, 16, &mut bytes, false)?;
        assert_eq!(&bytes, &[16, 17, 18, 19, 20, 21, 22, 23]);
        assert_eq!(next, Some(24));
        read_at(&mut reader, &mut next, 3, &mut bytes, false)?;
        assert_eq!(&bytes, &[3, 4, 5, 6, 7, 8, 9, 10]);
        assert!(read_at(&mut reader, &mut next, 252, &mut bytes, false).is_err());
        assert_eq!(next, None, "failed reads must not retain cursor hints");
        read_at(&mut reader, &mut next, 0, &mut bytes, false)?;
        assert_eq!(&bytes, &[0, 1, 2, 3, 4, 5, 6, 7]);
        read_at(&mut reader, &mut next, 8, &mut bytes, true)?;
        assert_eq!(&bytes, &[8, 9, 10, 11, 12, 13, 14, 15]);
        assert_eq!(next, Some(16));
        Ok(())
    }

    #[test]
    #[ignore = "requires a real base/patch Program NCZ pair with compressed BKTR metadata in disposable NSRP_ROOT"]
    fn inspect_real_compressed_bktr_index() -> Result<()> {
        let root = std::path::PathBuf::from(
            std::env::var_os("NSRP_ROOT")
                .ok_or_else(|| anyhow::anyhow!("NSRP_ROOT (isolated QA directory) is required"))?,
        );
        ensure!(
            root.to_string_lossy().contains("SAFETY"),
            "Refusing to prepare test NCAs outside an isolated QA sandbox"
        );
        let sample = root.join("legacy_sample.nsz");
        let keys = KeySet::load(&root.join("prod.keys"), Some(&root.join("title.keys")))?;
        let items = list_entries(&sample, true)?;
        let mut source = File::open(&sample)?;
        let mut selected = Vec::new();
        for item in items {
            if !item.name.ends_with(".ncz") {
                continue;
            }
            let mut header = [0u8; NCA_XTS_HEADER_SIZE];
            source.seek(SeekFrom::Start(item.offset))?;
            source.read_exact(&mut header)?;
            if let Ok(info) = decrypt_header(&header, &keys)
                && info.content_type == 0
                && info.sections.iter().any(|sec| sec.encryption_type == 4)
            {
                selected.push((item, true));
                continue;
            }
            if let Ok(info) = decrypt_header(&header, &keys)
                && info.content_type == 0
                && info.sections.iter().any(|sec| {
                    let at = 0x400 + sec.index * 0x200;
                    info.decrypted_header[at + 2] == 0 && sec.encryption_type == 3
                })
            {
                selected.push((item, false));
            }
        }
        ensure!(selected.len() == 2, "Expected base+patch NCA Program pair");
        let scratch = tempfile::Builder::new()
            .prefix("stage8_real_bktr_index_")
            .tempdir_in(&root)?;
        let mut base = None;
        let mut update = None;
        for (item, patch) in &selected {
            let path = scratch
                .path()
                .join(if *patch { "update.nca" } else { "base.nca" });
            let mut output = BufWriter::new(File::create(&path)?);
            decompress_ncz_region_to_nca(
                &mut source,
                item.offset,
                item.size,
                &mut output,
                &AtomicBool::new(false),
                |_, _| {},
            )?;
            output.flush()?;
            if *patch {
                update = Some(path);
            } else {
                base = Some(path);
            }
        }
        let base = base.ok_or_else(|| anyhow::anyhow!("Base missing"))?;
        let update = update.ok_or_else(|| anyhow::anyhow!("Update missing"))?;
        let mut base_head = [0u8; NCA_XTS_HEADER_SIZE];
        let mut update_head = [0u8; NCA_XTS_HEADER_SIZE];
        File::open(&base)?.read_exact(&mut base_head)?;
        File::open(&update)?.read_exact(&mut update_head)?;
        let base_info = decrypt_header(&base_head, &keys)?;
        let update_info = decrypt_header(&update_head, &keys)?;
        let base_section = base_info
            .sections
            .iter()
            .find(|sec| {
                let at = 0x400 + sec.index * 0x200;
                base_info.decrypted_header[at + 2] == 0
            })
            .ok_or_else(|| anyhow::anyhow!("Base RomFS missing"))?;
        let patch_section = update_info
            .sections
            .iter()
            .find(|sec| sec.encryption_type == 4)
            .ok_or_else(|| anyhow::anyhow!("Patch RomFS missing"))?;
        let fs_start = 0x400 + patch_section.index * 0x200;
        let fs_header = &update_info.decrypted_header[fs_start..fs_start + 0x200];
        let mut reader = BktrVirtualReader::open(
            &base,
            &update,
            base_section,
            patch_section,
            fs_header,
            (base_section.encryption_type == 3)
                .then(|| derive_section_key(&base_info, &keys))
                .transpose()?,
            derive_section_key(&update_info, &keys)?,
        )?;
        let levels = u32::from_le_bytes(fs_header[0x14..0x18].try_into()?);
        ensure!(levels >= 2, "Invalid BKTR RomFS layer count: {levels}");
        let last = 0x18 + (levels as usize - 2) * 0x18;
        ensure!(
            last + 8 <= fs_header.len(),
            "BKTR RomFS layer table exceeds its NCA header"
        );
        let data_offset = u64::from_le_bytes(fs_header[last..last + 8].try_into()?);
        let table_offset = u64::from_le_bytes(fs_header[0x178..0x180].try_into()?);
        let table_size = u64::from_le_bytes(fs_header[0x180..0x188].try_into()?);
        ensure!(
            (0x8000..=32 * 1024 * 1024).contains(&table_size)
                && table_size % 0x4000 == 0
                && table_offset > 0,
            "This diagnostic requires bounded compressed BKTR metadata; input offset={table_offset:#x} size={table_size:#x}"
        );
        // The production decoder supports both single-leaf and multi-leaf
        // BucketTrees. Require its complete geometry check instead of
        // assuming the one 0x8000-byte fixture used in Stage 39.
        let virtual_size = reader.virtual_size();
        validate_compressed_bktr_layout_after_verified_patch(fs_header, virtual_size)?;
        let tree_start = data_offset
            .checked_add(table_offset)
            .context("BKTR compression tree offset overflow")?;
        ensure!(
            tree_start
                .checked_add(table_size)
                .is_some_and(|end| end <= reader.virtual_size()),
            "BKTR compression tree lies outside the virtual RomFS"
        );
        reader.seek(SeekFrom::Start(tree_start))?;
        let mut table = vec![0u8; table_size as usize];
        reader.read_exact(&mut table)?;
        eprintln!(
            "COMPRESSED_BKTR_INDEX virtual_size={:#x} data_offset={:#x} table_offset={:#x} table_bytes={:#x} root_header={} leaf_header={}",
            reader.virtual_size(),
            data_offset,
            table_offset,
            table_size,
            hex::encode(&table[..0x40]),
            hex::encode(&table[0x4000..0x4040])
        );
        for i in 0..2.min((table_size as usize - 0x4010) / 0x18) {
            let at = 0x4010 + i * 0x18;
            eprintln!(
                "COMPRESSED_BKTR_ENTRY index={} virtual={:#x} physical={:#x} type={} physical_size={:#x} reserved={}",
                i,
                u64::from_le_bytes(table[at..at + 8].try_into()?),
                u64::from_le_bytes(table[at + 8..at + 16].try_into()?),
                table[at + 16],
                u32::from_le_bytes(table[at + 20..at + 24].try_into()?),
                hex::encode(&table[at + 17..at + 20]),
            );
        }
        // Validate the complete compressed lookup and actual raw LZ4 data
        // from the independently decrypted BKTR overlay. Reading at three
        // widely separated locations exercises its seek/mapping logic while
        // avoiding a full game extraction or any writes outside scratch.
        let mut compressed =
            CompressedBktrReader::open_from_verified_bktr(reader, fs_header, virtual_size)?;
        let logical = compressed.logical_size();
        ensure!(logical > 0, "Real compressed BKTR reports an empty RomFS");
        for offset in [0, logical / 2, logical.saturating_sub(512)] {
            let take = (logical - offset).min(512) as usize;
            let mut probe = vec![0u8; take];
            compressed.seek(SeekFrom::Start(offset))?;
            compressed.read_exact(&mut probe)?;
            eprintln!(
                "STAGE40_COMPRESSED_BKTR_READ offset={offset:#x} bytes={take} sha256={}",
                hex::encode(sha2::Sha256::digest(&probe)),
            );
        }
        eprintln!(
            "STAGE40_COMPRESSED_BKTR_VARIANT_PASS tree_bytes={table_size} logical_bytes={logical}"
        );
        if fs_header[5] == 1 {
            ensure!(
                CompressedBktrReader::open(
                    std::io::Cursor::new(Vec::<u8>::new()),
                    fs_header,
                    virtual_size,
                )
                .is_err(),
                "Unauthenticated raw reader unexpectedly accepted metadata-hashed BKTR"
            );
            let mut modified = fs_header.to_vec();
            modified[0x1b0] ^= 1;
            ensure!(
                BktrVirtualReader::open(
                    &base,
                    &update,
                    base_section,
                    patch_section,
                    &modified,
                    (base_section.encryption_type == 3)
                        .then(|| derive_section_key(&base_info, &keys))
                        .transpose()?,
                    derive_section_key(&update_info, &keys)?,
                )
                .is_err(),
                "Forged authenticated metadata digest must fail"
            );
            modified = fs_header.to_vec();
            modified[0x190..0x194].copy_from_slice(&u32::MAX.to_le_bytes());
            ensure!(
                BktrVirtualReader::open(
                    &base,
                    &update,
                    base_section,
                    patch_section,
                    &modified,
                    (base_section.encryption_type == 3)
                        .then(|| derive_section_key(&base_info, &keys))
                        .transpose()?,
                    derive_section_key(&update_info, &keys)?,
                )
                .is_err(),
                "Invalid compressed BucketTree entry count must fail before access"
            );
            eprintln!(
                "STAGE41_HASHED_BKTR_TAMPER_REJECT_PASS sha256=1 invalid_index=1 unauthenticated_open=1"
            );
        }
        if std::env::var_os("NSRP_STAGE41_VERIFY_ROMS").is_some() {
            // The native extractor is never permitted to write outside the
            // uniquely owned sandbox. This exercises ALL compressed blocks,
            // not only the three probes in the earlier diagnostic.
            let reference_executable = std::env::var_os("NSRP_STAGE41_HACTOOLNET_REFERENCE");
            let reference_out = scratch.path().join("libhac");
            let reference_first = reference_executable.is_some()
                && std::env::var("NSRP_STAGE52_BKTR_ORDER").ok().as_deref() == Some("libhac_first");
            let run_reference = || -> Result<u128> {
                let executable = reference_executable
                    .as_ref()
                    .context("Independent LibHac executable missing")?;
                let started = std::time::Instant::now();
                let process = std::process::Command::new(executable)
                    .arg("--disablekeywarns")
                    .arg("--suppresskeys")
                    .arg("--enablehash")
                    .arg("--keyset")
                    .arg(root.join("prod.keys"))
                    .arg("--titlekeys")
                    .arg(root.join("title.keys"))
                    .arg("--basenca")
                    .arg(&base)
                    .arg("--romfsdir")
                    .arg(&reference_out)
                    .arg(&update)
                    .output()?;
                let elapsed_ms = started.elapsed().as_millis();
                ensure!(
                    process.status.success(),
                    "Independent LibHac extraction failed: {}",
                    String::from_utf8_lossy(&process.stderr)
                );
                Ok(elapsed_ms)
            };
            let reference_ms_before_native = if reference_first {
                Some(run_reference()?)
            } else {
                None
            };
            let native_out = scratch.path().join("native");
            let native_start = std::time::Instant::now();
            let stats = crate::ops::native_fs::unpack_patched_nca(
                &update,
                &base,
                &native_out,
                &keys,
                &AtomicBool::new(false),
                true,
                false,
            )?;
            let native_extract_ms = native_start.elapsed().as_millis();
            // NativeFsStats writes a named "romfs" child. LibHac's
            // --romfsdir writes its files directly at the requested path.
            // Compare relative game paths, not these wrapper directories.
            let native_files = hash_sandbox_files(&native_out.join("romfs"))?;
            ensure!(
                stats.romfs_files == native_files.len() && !native_files.is_empty(),
                "Native authenticated compressed BKTR extraction file count mismatch"
            );
            eprintln!(
                "STAGE41_NATIVE_HASHED_BKTR_FULL_EXTRACT_PASS files={} tree_bytes={table_size}",
                native_files.len()
            );
            if reference_executable.is_some() {
                let libhac_extract_ms = if let Some(time) = reference_ms_before_native {
                    time
                } else {
                    run_reference()?
                };
                let reference_files = hash_sandbox_files(&reference_out)?;
                eprintln!(
                    "STAGE41_BKTR_INDEPENDENT_FILE_COUNTS native={} libhac={}",
                    native_files.len(),
                    reference_files.len()
                );
                if native_files != reference_files {
                    for (name, value) in native_files
                        .iter()
                        .filter(|(name, value)| reference_files.get(*name) != Some(*value))
                        .take(5)
                    {
                        eprintln!(
                            "STAGE41_BKTR_DIFF native_path={} native={:?} reference={:?}",
                            name.display(),
                            value,
                            reference_files.get(name)
                        );
                    }
                    for (name, value) in reference_files
                        .iter()
                        .filter(|(name, _)| !native_files.contains_key(*name))
                        .take(5)
                    {
                        eprintln!(
                            "STAGE41_BKTR_EXTRA_REFERENCE path={} value={:?}",
                            name.display(),
                            value,
                        );
                    }
                }
                ensure!(
                    reference_files == native_files,
                    "Native BKTR files differ in names, sizes or SHA-256 from independent LibHac extraction"
                );
                eprintln!(
                    "STAGE41_NATIVE_BKTR_LIBHAC_EXACT_SHA_MATCH files={} tree_bytes={table_size}",
                    native_files.len()
                );
                let order = if reference_first {
                    "libhac_then_native"
                } else {
                    "native_then_libhac"
                };
                eprintln!(
                    "STAGE51_BKTR_EXTRACT_TIMING native_ms={native_extract_ms} libhac_ms={libhac_extract_ms} files={} tree_bytes={table_size} order={order} cache=uncontrolled hashes_outside_times",
                    native_files.len()
                );
                eprintln!(
                    "STAGE52_BKTR_BENCH_ORDER native_ms={native_extract_ms} libhac_ms={libhac_extract_ms} order={order} native_sort={} native_workers={} files={} tree_bytes={table_size}",
                    std::env::var("NSRP_BKTR_BENCH_IO_ORDER").unwrap_or_else(|_| "tree".to_owned()),
                    std::env::var("NSRP_BKTR_BENCH_WORKERS").unwrap_or_else(|_| "auto".to_owned()),
                    native_files.len()
                );
            }
        }
        Ok(())
    }

    #[test]
    fn virtual_reads_cross_base_patch_and_crypto_boundaries() -> Result<()> {
        let temp = tempfile::tempdir()?;
        let base_path = temp.path().join("base.bin");
        let patch_path = temp.path().join("patch.bin");
        fs::write(&base_path, b"ABCDEFGHIJKLMNOP")?;
        let patch_key = [0x42u8; 16];
        let secure = 0x11223344u32;
        let mut encrypted = *b"12345678";
        nca_ctr_xcrypt_range(
            &mut encrypted[..4],
            &patch_key,
            &aes_ctr_ex_counter(secure, 7),
            0,
        )?;
        nca_ctr_xcrypt_range(
            &mut encrypted[4..],
            &patch_key,
            &aes_ctr_ex_counter(secure, 9),
            4,
        )?;
        fs::write(&patch_path, encrypted)?;
        let mut virtual_reader = BktrVirtualReader {
            base: BufReader::new(File::open(&base_path)?),
            patch: BufReader::new(File::open(&patch_path)?),
            base_section: NcaSection {
                index: 0,
                offset: 0,
                size: 16,
                encryption_type: 1,
                counter: [0u8; 16],
            },
            patch_section: NcaSection {
                index: 0,
                offset: 0,
                size: 8,
                encryption_type: 4,
                counter: [0u8; 16],
            },
            patch_key,
            relocation: Arc::new(BktrRelocationTable {
                virtual_size: 24,
                entries: vec![
                    BktrRelocationEntry {
                        virtual_offset: 0,
                        source_offset: 0,
                        from_patch: false,
                    },
                    BktrRelocationEntry {
                        virtual_offset: 8,
                        source_offset: 0,
                        from_patch: true,
                    },
                    BktrRelocationEntry {
                        virtual_offset: 16,
                        source_offset: 8,
                        from_patch: false,
                    },
                ],
            }),
            crypto: Arc::new(BktrSectionInfo {
                section_offset: 0,
                section_size: 8,
                bktr_offset: 8,
                secure_value: secure,
                entries: vec![
                    AesCtrExEntry {
                        offset: 0,
                        encrypted: true,
                        generation: 7,
                    },
                    AesCtrExEntry {
                        offset: 4,
                        encrypted: true,
                        generation: 9,
                    },
                ],
            }),
            position: 0,
            base_cipher: None,
            base_cipher_at: None,
            patch_ciphers: HashMap::new(),
            patch_cipher_at: HashMap::new(),
            base_reader_at: None,
            patch_reader_at: None,
            always_seek: false,
            profile: None,
        };
        let mut full = Vec::new();
        virtual_reader.read_to_end(&mut full)?;
        assert_eq!(&full, b"ABCDEFGH12345678IJKLMNOP");
        assert_eq!(virtual_reader.seek(SeekFrom::Start(7))?, 7);
        let mut across = [0u8; 10];
        virtual_reader.read_exact(&mut across)?;
        assert_eq!(&across, b"H12345678I");
        assert!(virtual_reader.seek(SeekFrom::End(1)).is_err());
        let template = virtual_reader.shared_template(&base_path, &patch_path, None)?;
        let mut worker = template.open()?;
        let mut independent = Vec::new();
        worker.read_to_end(&mut independent)?;
        assert_eq!(independent, full, "shared BKTR index changed worker output");
        fs::write(&patch_path, b"short")?;
        assert!(
            template.open().is_err(),
            "changed BKTR source length was silently accepted"
        );
        Ok(())
    }
}
