use crate::crypto::nca_ctr_xcrypt_range;
use anyhow::{Context, Result, bail, ensure};
use byteorder::{ByteOrder, LittleEndian};
use sha2::{Digest, Sha256};
use std::io::{Read, Seek, SeekFrom};

const NODE_SIZE: usize = 0x4000;
const NODE_HEADER_SIZE: usize = 0x10;
const ENTRY_SIZE: usize = 0x10;
const PATCH_RELOC_OFFSET: usize = 0x100;
const PATCH_ENC_OFFSET: usize = 0x120;
const PATCH_ENC_SIZE: usize = 0x128;
const PATCH_ENC_HEADER: usize = 0x130;
const FS_COUNTER_OFFSET: usize = 0x140;
const PATCH_RELOC_SIZE: usize = 0x108;
const PATCH_RELOC_HEADER: usize = 0x110;
// The indirect record is packed: virtual u64 + physical u64 + storage u32.
const RELOC_ENTRY_SIZE: usize = 0x14;

/// Both BucketTree indexes occupy separate regions of the same BKTR NCA
/// section. Validate the shared layout before either parser reads metadata.
/// Gaps are permitted: some valid updates may not place the tables adjacent.
#[derive(Debug, Clone, Copy)]
struct BktrPatchTableRanges {
    relocation_offset: u64,
    relocation_size: u64,
    encryption_offset: u64,
    encryption_size: u64,
}

fn patch_table_ranges(fs: &[u8], section_size: u64) -> Result<BktrPatchTableRanges> {
    if fs.len() < 0x200 {
        bail!("BKTR filesystem header is truncated");
    }
    let reloc_offset = read_i64(fs, PATCH_RELOC_OFFSET, "relocation offset")?;
    let reloc_size = read_i64(fs, PATCH_RELOC_SIZE, "relocation size")?;
    let enc_offset = read_i64(fs, PATCH_ENC_OFFSET, "encryption offset")?;
    let enc_size = read_i64(fs, PATCH_ENC_SIZE, "encryption size")?;
    // Empty physical patches have no AES-CTR-EX payload. Older verified
    // Manual updates have two 2-node tables. Newer metadata-hashed updates
    // may omit the encryption tree entirely: exactly one 2-node relocation
    // tree, its authenticated 0x4000 hash layer and 0xe8-byte metadata
    // trailer. Only these two *observed* zero-offset geometries are allowed;
    // relocation entries are separately required to reference the base.
    let empty_hashed = reloc_offset == 0
        && fs[5] == 1
        && reloc_size == (2 * NODE_SIZE) as i64
        && enc_offset == reloc_size
        && enc_size == 0
        && section_size == (3 * NODE_SIZE + 0x200) as u64
        && LittleEndian::read_u64(&fs[0x1a0..0x1a8]) == (3 * NODE_SIZE) as u64
        && LittleEndian::read_u64(&fs[0x1a8..0x1b0]) == 0xe8;
    let empty_legacy = reloc_offset == 0
        && reloc_size == (2 * NODE_SIZE) as i64
        && enc_offset == reloc_size
        && enc_size == (2 * NODE_SIZE) as i64
        && section_size == (4 * NODE_SIZE) as u64;
    if reloc_offset == 0 && !(empty_hashed || empty_legacy) {
        bail!("BKTR zero-offset layout is not an empty base-only patch");
    }
    if reloc_offset < 0 || reloc_size < NODE_SIZE as i64 {
        bail!("BKTR relocation offset/size invalid");
    }
    if enc_offset < 0 || (enc_size < NODE_SIZE as i64 && !empty_hashed) {
        bail!("BKTR encryption offset/size invalid");
    }
    let relocation_offset = reloc_offset as u64;
    let relocation_size = reloc_size as u64;
    let encryption_offset = enc_offset as u64;
    let encryption_size = enc_size as u64;
    let relocation_end = relocation_offset
        .checked_add(relocation_size)
        .context("BKTR relocation tree end overflow")?;
    let encryption_end = encryption_offset
        .checked_add(encryption_size)
        .context("BKTR encryption tree end overflow")?;
    if relocation_end > encryption_offset || encryption_end > section_size {
        bail!("BKTR metadata tables overlap or exceed NCA section");
    }
    Ok(BktrPatchTableRanges {
        relocation_offset,
        relocation_size,
        encryption_offset,
        encryption_size,
    })
}

/// Authenticate the newer BKTR patch lookup tables through their AES-CTR
/// decrypted SHA256 metadata trailer and a complete 3-layer IVFC tree.
/// Missing metadata is supported for legacy BKTR; unrecognized metadata,
/// hash, compression and sparse variants fail closed. Metadata-hashed BKTR
/// may legitimately contain a separate compressed RomFS BucketTree index
/// (FS 0x178..0x1a0); that index does not replace or weaken the lookup-tree
/// IVFC chain checked below.
pub fn verify_patch_metadata_integrity<R: Read + Seek>(
    reader: &mut R,
    nca_base: u64,
    nca_size: u64,
    section_offset: u64,
    section_size: u64,
    fs: &[u8],
    key: &[u8; 16],
) -> Result<bool> {
    ensure!(fs.len() == 0x200, "BKTR metadata FS header truncated");
    let trailer = &fs[0x1a0..0x1d0];
    if fs[5] == 0 && trailer.iter().all(|&byte| byte == 0) {
        return Ok(false);
    }
    let compressed = &fs[0x178..0x1a0];
    let has_compression = compressed.iter().any(|&byte| byte != 0);
    // The 0x18-byte BucketTree entries pack [virtual, physical, type+size].
    // The metadata descriptor is authenticated as part of the NCA FS header;
    // its full index is validated separately against the reconstructed
    // virtual RomFS geometry by CompressedBktrReader.
    let compression_supported = !has_compression
        || (LittleEndian::read_u64(&fs[0x178..0x180]) > 0
            && (0x8000..=32 * 1024 * 1024).contains(&LittleEndian::read_u64(&fs[0x180..0x188]))
            && &fs[0x188..0x18c] == b"BKTR"
            && LittleEndian::read_u32(&fs[0x18c..0x190]) == 1
            && (1..=1_000_000).contains(&LittleEndian::read_u32(&fs[0x190..0x194]))
            && fs[0x194..0x1a0].iter().all(|&byte| byte == 0)
            && {
                let count = LittleEndian::read_u32(&fs[0x190..0x194]) as usize;
                let leaves = count.div_ceil((NODE_SIZE - 0x10) / 0x18);
                (1 + leaves).checked_mul(NODE_SIZE)
                    == usize::try_from(LittleEndian::read_u64(&fs[0x180..0x188])).ok()
            });
    ensure!(
        (fs[2], fs[3], fs[4], fs[5]) == (0, 3, 4, 1)
            && fs[0x148..0x178].iter().all(|&byte| byte == 0)
            && compression_supported
            && fs[0x1d0..0x200].iter().all(|&byte| byte == 0),
        "BKTR metadata hash type or other storage extension is unsupported"
    );
    let range = patch_table_ranges(fs, section_size)?;
    let relocation_end = range
        .relocation_offset
        .checked_add(range.relocation_size)
        .context("BKTR relocation tree end overflow")?;
    let crypto_end = range
        .encryption_offset
        .checked_add(range.encryption_size)
        .context("BKTR encryption tree end overflow")?;
    let info_offset = LittleEndian::read_u64(&trailer[..8]);
    let info_size = LittleEndian::read_u64(&trailer[8..16]);
    ensure!(
        relocation_end == range.encryption_offset
            && info_size == 0xe8
            && info_offset.is_multiple_of(16)
            && info_offset.checked_add(0x200) == Some(section_size)
            && section_offset
                .checked_add(section_size)
                .is_some_and(|end| end <= nca_size),
        "unsupported BKTR metadata hash trailer or physical table bounds"
    );
    let counter = normal_section_counter(fs);
    let mut read_decrypted = |relative: u64, target: &mut [u8]| -> Result<()> {
        let section_position = section_offset
            .checked_add(relative)
            .context("BKTR metadata section offset overflow")?;
        let absolute = nca_base
            .checked_add(section_position)
            .context("BKTR metadata source offset overflow")?;
        reader.seek(SeekFrom::Start(absolute))?;
        reader.read_exact(target)?;
        nca_ctr_xcrypt_range(target, key, &counter, section_position)
    };
    let mut metadata = [0u8; 0xe8];
    read_decrypted(info_offset, &mut metadata)?;
    ensure!(
        Sha256::digest(metadata)[..] == trailer[0x10..0x30],
        "BKTR metadata SHA256 differs from NCA FS header"
    );
    // The authenticated NcaMetaDataHashData prefixes an IVFC metadata
    // structure with its physical hash-layer offset.
    let layer_offset = LittleEndian::read_u64(&metadata[0..8]);
    ensure!(
        &metadata[8..12] == b"IVFC"
            && LittleEndian::read_u32(&metadata[0x14..0x18]) == 3
            && LittleEndian::read_u64(&metadata[0x18..0x20]) == 0
            && LittleEndian::read_u64(&metadata[0x20..0x28]) == NODE_SIZE as u64
            && LittleEndian::read_u32(&metadata[0x28..0x2c]) == 14
            && LittleEndian::read_u64(&metadata[0x30..0x38]) == NODE_SIZE as u64
            && LittleEndian::read_u32(&metadata[0x40..0x44]) == 14
            && layer_offset == crypto_end
            && layer_offset.checked_add(NODE_SIZE as u64) == Some(info_offset),
        "unsupported BKTR metadata IVFC layout"
    );
    let data_size = LittleEndian::read_u64(&metadata[0x38..0x40]);
    ensure!(
        data_size == crypto_end - range.relocation_offset
            && data_size > 0
            && data_size.is_multiple_of(NODE_SIZE as u64)
            && data_size.div_ceil(NODE_SIZE as u64) * 32 <= NODE_SIZE as u64,
        "BKTR metadata IVFC data range does not cover both lookup tables"
    );
    let mut hash_layer = [0u8; NODE_SIZE];
    read_decrypted(layer_offset, &mut hash_layer)?;
    ensure!(
        Sha256::digest(hash_layer)[..] == metadata[0xc8..0xe8],
        "BKTR metadata IVFC root hash mismatch"
    );
    let mut block = [0u8; NODE_SIZE];
    for index in 0..data_size / NODE_SIZE as u64 {
        read_decrypted(
            range.relocation_offset + index * NODE_SIZE as u64,
            &mut block,
        )?;
        let start = index as usize * 32;
        ensure!(
            Sha256::digest(block)[..] == hash_layer[start..start + 32],
            "BKTR metadata IVFC lookup-table block hash mismatch"
        );
    }
    Ok(true)
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BktrRelocationEntry {
    /// Offset into the virtual IVFC filesystem section after applying the update.
    pub virtual_offset: u64,
    /// Offset into the original section (base) or update section (patch).
    pub source_offset: u64,
    pub from_patch: bool,
}

#[derive(Debug, Clone)]
pub struct BktrRelocationTable {
    pub virtual_size: u64,
    pub entries: Vec<BktrRelocationEntry>,
}

/// Decode the on-disk BKTR indirect (relocation) table. The table itself is
/// encrypted with the regular NCA AES-CTR counter, not the per-subsection
/// AES-CTR-EX counter used by the patched data region.
pub fn collect_relocations_from_reader<R: Read + Seek>(
    reader: &mut R,
    nca_base: u64,
    nca_size: u64,
    section_offset: u64,
    section_size: u64,
    fs_header: &[u8],
    section_key: &[u8; 16],
) -> Result<BktrRelocationTable> {
    if fs_header.len() < 0x200 {
        bail!("BKTR relocation FS header is truncated");
    }
    let section_end = section_offset
        .checked_add(section_size)
        .context("BKTR section size overflow")?;
    if section_end > nca_size {
        bail!("BKTR relocation section exceeds NCA");
    }
    let layout = patch_table_ranges(fs_header, section_size)?;
    let tree_offset = layout.relocation_offset;
    let tree_size = layout.relocation_size;
    let header = fs_header
        .get(PATCH_RELOC_HEADER..PATCH_RELOC_HEADER + 0x10)
        .context("BKTR relocation header absent")?;
    if &header[..4] != b"BKTR" {
        bail!("BKTR relocation magic mismatch");
    }
    let total_count = LittleEndian::read_i32(&header[8..12]);
    if !(1..=1_000_000).contains(&total_count) {
        bail!("BKTR relocation count invalid: {total_count}");
    }
    let total_count = total_count as usize;
    let per_node = (NODE_SIZE - NODE_HEADER_SIZE) / RELOC_ENTRY_SIZE;
    let bucket_count = total_count.div_ceil(per_node);
    let root_nodes = 1 + usize::from(bucket_count > (NODE_SIZE - NODE_HEADER_SIZE) / 8);
    // For huge tables (>two tree levels), fall back rather than relying on a
    // partial interpretation of the bucket-tree indexing geometry.
    if bucket_count > (NODE_SIZE - NODE_HEADER_SIZE) / 8 {
        bail!("BKTR relocation table requires unsupported multi-level index");
    }
    let node_bytes = root_nodes * NODE_SIZE;
    let leaf_bytes = bucket_count
        .checked_mul(NODE_SIZE)
        .context("BKTR relocation leaf length overflow")?;
    let full_size = node_bytes
        .checked_add(leaf_bytes)
        .context("BKTR relocation total length overflow")?;
    if full_size as u64 > tree_size || full_size > 64 * 1024 * 1024 {
        bail!("BKTR relocation table is truncated or too large");
    }

    let mut tree = vec![0u8; full_size];
    let absolute = nca_base
        .checked_add(section_offset)
        .and_then(|x| x.checked_add(tree_offset))
        .context("BKTR relocation physical offset overflow")?;
    reader.seek(SeekFrom::Start(absolute))?;
    reader.read_exact(&mut tree)?;
    let ctr = normal_section_counter(fs_header);
    nca_ctr_xcrypt_range(&mut tree, section_key, &ctr, section_offset + tree_offset)?;

    let actual_buckets = LittleEndian::read_u32(&tree[4..8]) as usize;
    let virtual_size = LittleEndian::read_u64(&tree[8..16]);
    if actual_buckets != bucket_count || virtual_size == 0 {
        bail!(
            "BKTR relocation root invalid: buckets={actual_buckets}/{bucket_count}, virtual_size={virtual_size}"
        );
    }
    let mut entries = Vec::with_capacity(total_count);
    for bucket in 0..bucket_count {
        let start = node_bytes + bucket * NODE_SIZE;
        let leaf = &tree[start..start + NODE_SIZE];
        let leaf_index = LittleEndian::read_i32(&leaf[0..4]);
        let count = LittleEndian::read_i32(&leaf[4..8]);
        let bucket_end = LittleEndian::read_i64(&leaf[8..16]);
        if leaf_index != bucket as i32
            || count <= 0
            || count as usize > per_node
            || bucket_end < 0
            || bucket_end as u64 > virtual_size
        {
            bail!("BKTR relocation leaf is invalid: bucket={bucket}");
        }
        for i in 0..count as usize {
            let at = NODE_HEADER_SIZE + i * RELOC_ENTRY_SIZE;
            let v = LittleEndian::read_i64(&leaf[at..at + 8]);
            let source = LittleEndian::read_i64(&leaf[at + 8..at + 16]);
            let source_index = LittleEndian::read_u32(&leaf[at + 16..at + 20]);
            if v < 0 || source < 0 || source_index > 1 {
                bail!("BKTR relocation entry invalid bucket={bucket} entry={i}");
            }
            entries.push(BktrRelocationEntry {
                virtual_offset: v as u64,
                source_offset: source as u64,
                from_patch: source_index == 1,
            });
        }
    }
    if entries.len() != total_count
        || entries.first().map(|entry| entry.virtual_offset) != Some(0)
        || entries
            .last()
            .is_none_or(|entry| entry.virtual_offset >= virtual_size)
        || entries
            .windows(2)
            .any(|pair| pair[0].virtual_offset >= pair[1].virtual_offset)
    {
        bail!("BKTR relocation entries are missing or out of order");
    }
    if tree_offset == 0 && entries.iter().any(|entry| entry.from_patch) {
        bail!("BKTR zero-offset relocation references absent patch data");
    }
    Ok(BktrRelocationTable {
        virtual_size,
        entries,
    })
}

fn normal_section_counter(fs_header: &[u8]) -> [u8; 16] {
    let mut counter = [0u8; 16];
    for i in 0..8 {
        counter[i] = fs_header[FS_COUNTER_OFFSET + 7 - i];
    }
    counter
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AesCtrExEntry {
    pub offset: u64,
    pub encrypted: bool,
    pub generation: u32,
}

#[derive(Debug, Clone)]
pub struct BktrSectionInfo {
    pub section_offset: u64,
    pub section_size: u64,
    pub bktr_offset: u64,
    pub secure_value: u32,
    pub entries: Vec<AesCtrExEntry>,
}

pub fn collect_from_reader<R: Read + Seek>(
    reader: &mut R,
    nca_base: u64,
    nca_size: u64,
    section_offset: u64,
    section_size: u64,
    fs_header: &[u8],
    section_key: &[u8; 16],
) -> Result<BktrSectionInfo> {
    if fs_header.len() < 0x200 {
        bail!("BKTR FS header가 0x200보다 짧습니다");
    }

    let layout = patch_table_ranges(fs_header, section_size)?;
    let bktr_offset = layout.relocation_offset;
    let enc_tree_offset = layout.encryption_offset;
    let enc_tree_size = layout.encryption_size;

    // The authenticated metadata-hash variant with no physical patch data
    // genuinely has no encryption index to read. Authenticate its complete
    // lookup tree first, then provide the caller with an inert marker: it
    // will never decrypt a patch span because all relocations must be base.
    if enc_tree_size == 0 {
        ensure!(
            bktr_offset == 0
                && fs_header[5] == 1
                && verify_patch_metadata_integrity(
                    reader,
                    nca_base,
                    nca_size,
                    section_offset,
                    section_size,
                    fs_header,
                    section_key
                )?,
            "empty physical patch lacks authenticated metadata lookup"
        );
        return Ok(BktrSectionInfo {
            section_offset,
            section_size,
            bktr_offset: 0,
            secure_value: LittleEndian::read_u32(
                &fs_header[FS_COUNTER_OFFSET + 4..FS_COUNTER_OFFSET + 8],
            ),
            entries: vec![AesCtrExEntry {
                offset: 0,
                encrypted: false,
                generation: 0,
            }],
        });
    }

    let enc_header = fs_header
        .get(PATCH_ENC_HEADER..PATCH_ENC_HEADER + 0x10)
        .context("BKTR encryption tree header 누락")?;
    let signature = LittleEndian::read_u32(&enc_header[0..4]);
    if signature != u32::from_le_bytes(*b"BKTR") {
        bail!("BKTR signature 불일치: {signature:#010x}");
    }
    let entry_count = LittleEndian::read_i32(&enc_header[8..12]);
    if entry_count <= 0 || entry_count > 1_000_000 {
        bail!("BKTR entry count 범위 오류: {entry_count}");
    }
    let entry_count = entry_count as usize;
    let node_storage_size = query_node_storage_size(entry_count)?;
    let entry_storage_size = query_entry_storage_size(entry_count)?;
    let expected_size = node_storage_size
        .checked_add(entry_storage_size)
        .context("BKTR storage size 오버플로")?;
    if usize::try_from(enc_tree_size)
        .ok()
        .is_none_or(|n| n < expected_size)
    {
        bail!(
            "BKTR encryption tree가 너무 짧습니다: {:#x} < {expected_size:#x}",
            enc_tree_size
        );
    }

    let section_end = section_offset
        .checked_add(section_size)
        .context("BKTR section 범위 오버플로")?;
    if section_end > nca_size {
        bail!("BKTR section이 NCA 범위를 벗어납니다");
    }

    let entry_rel = enc_tree_offset
        .checked_add(node_storage_size as u64)
        .context("BKTR entry storage offset 오버플로")?;
    let entry_abs_in_nca = section_offset
        .checked_add(entry_rel)
        .context("BKTR entry absolute offset 오버플로")?;
    let mut entry_storage = vec![0u8; entry_storage_size];
    reader.seek(SeekFrom::Start(
        nca_base
            .checked_add(entry_abs_in_nca)
            .context("BKTR source offset 오버플로")?,
    ))?;
    reader.read_exact(&mut entry_storage)?;

    let mut normal_counter = [0u8; 16];
    for i in 0..8 {
        normal_counter[i] = fs_header[FS_COUNTER_OFFSET + 7 - i];
    }
    nca_ctr_xcrypt_range(
        &mut entry_storage,
        section_key,
        &normal_counter,
        entry_abs_in_nca,
    )?;

    // BucketTree stores its entries in physical, ascending order. Sorting
    // untrusted records can hide swapped or damaged encryption leaves and
    // select the wrong CTR-EX generation for a patched physical span.
    let entries = parse_entry_storage(&entry_storage, entry_count)?;
    if entries.first().map(|entry| entry.offset) != Some(0) {
        bail!("BKTR 첫 entry가 0에서 시작하지 않습니다");
    }
    if bktr_offset == 0 {
        ensure!(
            entries.len() == 1 && entries[0].offset == 0,
            "BKTR empty physical patch requires one zero-offset crypto entry"
        );
    } else if entries.iter().any(|entry| entry.offset >= bktr_offset) {
        bail!("BKTR entry가 데이터 영역 밖을 가리킵니다");
    }
    for pair in entries.windows(2) {
        if pair[0].offset >= pair[1].offset {
            bail!("BKTR entry offset이 증가하지 않습니다");
        }
    }

    let secure_value =
        LittleEndian::read_u32(&fs_header[FS_COUNTER_OFFSET + 4..FS_COUNTER_OFFSET + 8]);
    Ok(BktrSectionInfo {
        section_offset,
        section_size,
        bktr_offset,
        secure_value,
        entries,
    })
}

pub fn aes_ctr_ex_counter(secure_value: u32, generation: u32) -> [u8; 16] {
    let mut counter = [0u8; 16];
    counter[..4].copy_from_slice(&secure_value.to_be_bytes());
    counter[4..8].copy_from_slice(&generation.to_be_bytes());
    counter
}

fn parse_entry_storage(data: &[u8], total_entry_count: usize) -> Result<Vec<AesCtrExEntry>> {
    let set_count = entry_set_count(total_entry_count)?;
    let max_per_node = entry_count_per_node();
    let mut entries = Vec::with_capacity(total_entry_count);
    for set_index in 0..set_count {
        let set_offset = set_index
            .checked_mul(NODE_SIZE)
            .context("BKTR entry set offset 오버플로")?;
        let header = data
            .get(set_offset..set_offset + NODE_HEADER_SIZE)
            .context("BKTR entry set header가 잘렸습니다")?;
        let node_index = LittleEndian::read_i32(&header[0..4]);
        let node_count = LittleEndian::read_i32(&header[4..8]);
        if node_index != set_index as i32 {
            bail!("BKTR entry set index 불일치: {node_index} != {set_index}");
        }
        if node_count <= 0 || node_count as usize > max_per_node {
            bail!("BKTR entry set count 범위 오류: {node_count}");
        }
        let entry_base = set_offset + NODE_HEADER_SIZE;
        for local_index in 0..node_count as usize {
            let offset = entry_base + local_index * ENTRY_SIZE;
            let raw = data
                .get(offset..offset + ENTRY_SIZE)
                .context("BKTR entry가 잘렸습니다")?;
            let virtual_offset = LittleEndian::read_i64(&raw[0..8]);
            if virtual_offset < 0 {
                bail!("BKTR entry offset이 음수입니다");
            }
            let encrypted = match raw[8] {
                0 => true,
                1 => false,
                other => bail!("BKTR encryption value가 올바르지 않습니다: {other}"),
            };
            let generation = LittleEndian::read_i32(&raw[12..16]) as u32;
            entries.push(AesCtrExEntry {
                offset: virtual_offset as u64,
                encrypted,
                generation,
            });
            if entries.len() == total_entry_count {
                break;
            }
        }
        if entries.len() == total_entry_count {
            break;
        }
    }
    if entries.len() != total_entry_count {
        bail!(
            "BKTR entry count 불일치: {} != {total_entry_count}",
            entries.len()
        );
    }
    Ok(entries)
}

fn query_node_storage_size(entry_count: usize) -> Result<usize> {
    if entry_count == 0 {
        return Ok(0);
    }
    let offsets_per_node = (NODE_SIZE - NODE_HEADER_SIZE) / 8;
    let sets = entry_set_count(entry_count)?;
    let l2 = if sets <= offsets_per_node {
        0
    } else {
        let node_l2_count = sets.div_ceil(offsets_per_node);
        (sets - (offsets_per_node - (node_l2_count - 1))).div_ceil(offsets_per_node)
    };
    (1usize + l2)
        .checked_mul(NODE_SIZE)
        .context("BKTR node storage size 오버플로")
}

fn query_entry_storage_size(entry_count: usize) -> Result<usize> {
    entry_set_count(entry_count)?
        .checked_mul(NODE_SIZE)
        .context("BKTR entry storage size 오버플로")
}

fn entry_set_count(entry_count: usize) -> Result<usize> {
    let per_node = entry_count_per_node();
    if per_node == 0 {
        bail!("BKTR node geometry 오류");
    }
    Ok(entry_count.div_ceil(per_node))
}

fn entry_count_per_node() -> usize {
    (NODE_SIZE - NODE_HEADER_SIZE) / ENTRY_SIZE
}

fn read_i64(data: &[u8], offset: usize, label: &str) -> Result<i64> {
    let raw = data
        .get(offset..offset + 8)
        .with_context(|| format!("BKTR {label} 필드 누락"))?;
    Ok(LittleEndian::read_i64(raw))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tree_header(reloc: i64, reloc_size: i64, encryption: i64, enc_size: i64) -> Vec<u8> {
        let mut fs = vec![0u8; 0x200];
        for (at, value) in [
            (PATCH_RELOC_OFFSET, reloc),
            (PATCH_RELOC_SIZE, reloc_size),
            (PATCH_ENC_OFFSET, encryption),
            (PATCH_ENC_SIZE, enc_size),
        ] {
            fs[at..at + 8].copy_from_slice(&value.to_le_bytes());
        }
        fs
    }

    #[test]
    fn bktr_metadata_ranges_reject_overlap_and_section_overflow() -> Result<()> {
        let valid = tree_header(0x8000, 0x8000, 0x10000, 0x8000);
        let layout = patch_table_ranges(&valid, 0x18000)?;
        assert_eq!(layout.relocation_offset, 0x8000);
        assert_eq!(layout.encryption_offset, 0x10000);
        // A legitimate gap between the indexes must be allowed.
        let gap = tree_header(0x8000, 0x8000, 0x11000, 0x8000);
        assert!(patch_table_ranges(&gap, 0x19000).is_ok());
        let overlap = tree_header(0x8000, 0x8000, 0xf000, 0x8000);
        assert!(patch_table_ranges(&overlap, 0x18000).is_err());
        let truncated = tree_header(0x8000, 0x8000, 0x10000, 0x8000);
        assert!(patch_table_ranges(&truncated, 0x17000).is_err());
        let negative = tree_header(-1, 0x8000, 0x10000, 0x8000);
        assert!(patch_table_ranges(&negative, 0x18000).is_err());
        let zero = tree_header(0, 0x8000, 0x8000, 0x8000);
        assert_eq!(patch_table_ranges(&zero, 0x10000)?.relocation_offset, 0);
        let zero_with_gap = tree_header(0, 0x8000, 0x9000, 0x8000);
        assert!(patch_table_ranges(&zero_with_gap, 0x11000).is_err());
        let zero_with_data = tree_header(0, 0x8000, 0x8000, 0x8000);
        assert!(patch_table_ranges(&zero_with_data, 0x12000).is_err());
        let zero_with_small_tree = tree_header(0, 0x4000, 0x4000, 0x8000);
        assert!(patch_table_ranges(&zero_with_small_tree, 0xc000).is_err());
        let mut zero_hashed = tree_header(0, 0x8000, 0x8000, 0);
        zero_hashed[5] = 1;
        zero_hashed[0x1a0..0x1a8].copy_from_slice(&0xc000u64.to_le_bytes());
        zero_hashed[0x1a8..0x1b0].copy_from_slice(&0xe8u64.to_le_bytes());
        let layout = patch_table_ranges(&zero_hashed, 0xc200)?;
        assert_eq!(layout.relocation_size, 0x8000);
        assert_eq!(layout.encryption_size, 0);
        let mut modified = zero_hashed.clone();
        modified[0x128..0x130].copy_from_slice(&0x8000i64.to_le_bytes());
        assert!(patch_table_ranges(&modified, 0xc200).is_err());
        modified = zero_hashed.clone();
        modified[5] = 0;
        assert!(patch_table_ranges(&modified, 0xc200).is_err());
        modified = zero_hashed;
        modified[0x1a0..0x1a8].copy_from_slice(&0xb000u64.to_le_bytes());
        assert!(patch_table_ranges(&modified, 0xc200).is_err());
        let huge = tree_header(i64::MAX, i64::MAX, i64::MAX, 0x8000);
        assert!(patch_table_ranges(&huge, u64::MAX).is_err());
        Ok(())
    }

    #[test]
    fn zero_offset_base_only_patch_decodes_and_rejects_patch_references() -> Result<()> {
        use std::io::Cursor;
        let mut fs = tree_header(0, 0x8000, 0x8000, 0x8000);
        fs[PATCH_RELOC_HEADER..PATCH_RELOC_HEADER + 4].copy_from_slice(b"BKTR");
        fs[PATCH_RELOC_HEADER + 8..PATCH_RELOC_HEADER + 12].copy_from_slice(&1i32.to_le_bytes());
        fs[PATCH_ENC_HEADER..PATCH_ENC_HEADER + 4].copy_from_slice(b"BKTR");
        fs[PATCH_ENC_HEADER + 8..PATCH_ENC_HEADER + 12].copy_from_slice(&1i32.to_le_bytes());
        let mut plain = vec![0u8; 0x10000];
        plain[4..8].copy_from_slice(&1u32.to_le_bytes());
        plain[8..16].copy_from_slice(&0x2000u64.to_le_bytes());
        plain[0x4004..0x4008].copy_from_slice(&1i32.to_le_bytes());
        plain[0x4008..0x4010].copy_from_slice(&0x2000u64.to_le_bytes());
        plain[0xc004..0xc008].copy_from_slice(&1i32.to_le_bytes());
        plain[0xc008..0xc010].copy_from_slice(&0u64.to_le_bytes());
        plain[0xc01c..0xc020].copy_from_slice(&7u32.to_le_bytes());
        let key = [0x46u8; 16];
        let mut encrypted = plain.clone();
        nca_ctr_xcrypt_range(&mut encrypted, &key, &[0u8; 16], 0)?;
        let mut reader = Cursor::new(encrypted);
        let reloc =
            collect_relocations_from_reader(&mut reader, 0, 0x10000, 0, 0x10000, &fs, &key)?;
        assert_eq!(reloc.virtual_size, 0x2000);
        assert_eq!(reloc.entries.len(), 1);
        assert!(!reloc.entries[0].from_patch);
        let crypto = collect_from_reader(&mut reader, 0, 0x10000, 0, 0x10000, &fs, &key)?;
        assert_eq!(crypto.bktr_offset, 0);
        assert_eq!(crypto.entries.len(), 1);
        assert_eq!(crypto.entries[0].offset, 0);
        let mut wrong = plain;
        wrong[0x4020..0x4024].copy_from_slice(&1u32.to_le_bytes());
        nca_ctr_xcrypt_range(&mut wrong, &key, &[0u8; 16], 0)?;
        let mut malicious = Cursor::new(wrong);
        assert!(
            collect_relocations_from_reader(&mut malicious, 0, 0x10000, 0, 0x10000, &fs, &key)
                .is_err(),
            "empty patch must never read data from an absent patch source"
        );
        Ok(())
    }

    #[test]
    fn bucket_tree_sizes_and_counter() -> Result<()> {
        assert_eq!(query_node_storage_size(1)?, 0x4000);
        assert_eq!(query_entry_storage_size(1)?, 0x4000);
        assert_eq!(
            query_entry_storage_size(entry_count_per_node() + 1)?,
            0x8000
        );
        let ctr = aes_ctr_ex_counter(0x11223344, 0xaabbccdd);
        assert_eq!(&ctr[..8], &[0x11, 0x22, 0x33, 0x44, 0xaa, 0xbb, 0xcc, 0xdd]);
        Ok(())
    }

    #[test]
    fn stage23_multiple_crypto_leaves_reject_swapped_generation_records() -> Result<()> {
        use std::io::Cursor;
        let per = entry_count_per_node();
        let count = per + 1;
        let size = 0x18000u64;
        let mut fs = tree_header(0x4000, 0x8000, 0xc000, 0xc000);
        fs[PATCH_ENC_HEADER..PATCH_ENC_HEADER + 4].copy_from_slice(b"BKTR");
        fs[PATCH_ENC_HEADER + 8..PATCH_ENC_HEADER + 12]
            .copy_from_slice(&(count as i32).to_le_bytes());
        let mut clear = vec![0u8; size as usize];
        for i in 0..count {
            let leaf = i / per;
            let local = i % per;
            let start = 0x10000 + leaf * NODE_SIZE;
            clear[start..start + 4].copy_from_slice(&(leaf as i32).to_le_bytes());
            clear[start + 4..start + 8]
                .copy_from_slice(&((if leaf == 0 { per } else { 1 }) as i32).to_le_bytes());
            let at = start + NODE_HEADER_SIZE + local * ENTRY_SIZE;
            clear[at..at + 8].copy_from_slice(&((i * ENTRY_SIZE) as u64).to_le_bytes());
            clear[at + 8] = 0;
            clear[at + 12..at + 16].copy_from_slice(&(i as u32).to_le_bytes());
        }
        let key = [0x46u8; 16];
        let mut encrypted = clear.clone();
        nca_ctr_xcrypt_range(&mut encrypted[0xc000..], &key, &[0u8; 16], 0xc000)?;
        let mut source = Cursor::new(encrypted);
        let parsed = collect_from_reader(&mut source, 0, size, 0, size, &fs, &key)?;
        assert_eq!(parsed.entries.len(), count);
        assert_eq!(parsed.entries[per].offset, (per * ENTRY_SIZE) as u64);
        let mut damaged = clear;
        let first = 0x10000 + NODE_HEADER_SIZE;
        let second = first + ENTRY_SIZE;
        let a = damaged[first..first + ENTRY_SIZE].to_vec();
        let b = damaged[second..second + ENTRY_SIZE].to_vec();
        damaged[first..first + ENTRY_SIZE].copy_from_slice(&b);
        damaged[second..second + ENTRY_SIZE].copy_from_slice(&a);
        nca_ctr_xcrypt_range(&mut damaged[0xc000..], &key, &[0u8; 16], 0xc000)?;
        let mut source = Cursor::new(damaged);
        assert!(
            collect_from_reader(&mut source, 0, size, 0, size, &fs, &key).is_err(),
            "swapped CTR-EX generation records must not be sorted into validity"
        );
        Ok(())
    }

    #[test]
    fn stage23_multiple_relocation_leaves_reject_cross_leaf_overlap() -> Result<()> {
        use std::io::Cursor;
        let per = (NODE_SIZE - NODE_HEADER_SIZE) / RELOC_ENTRY_SIZE;
        let count = per + 1;
        let size = 0x18000u64;
        let mut fs = tree_header(0x4000, 0xc000, 0x10000, 0x8000);
        fs[PATCH_RELOC_HEADER..PATCH_RELOC_HEADER + 4].copy_from_slice(b"BKTR");
        fs[PATCH_RELOC_HEADER + 8..PATCH_RELOC_HEADER + 12]
            .copy_from_slice(&(count as i32).to_le_bytes());
        let virtual_size = (count as u64) * 0x10;
        let mut clear = vec![0u8; size as usize];
        clear[0x4004..0x4008].copy_from_slice(&2u32.to_le_bytes());
        clear[0x4008..0x4010].copy_from_slice(&virtual_size.to_le_bytes());
        for i in 0..count {
            let leaf = i / per;
            let local = i % per;
            let start = 0x8000 + leaf * NODE_SIZE;
            clear[start..start + 4].copy_from_slice(&(leaf as i32).to_le_bytes());
            clear[start + 4..start + 8]
                .copy_from_slice(&((if leaf == 0 { per } else { 1 }) as i32).to_le_bytes());
            let leaf_end = (if leaf == 0 { per } else { count } as u64) * 0x10;
            clear[start + 8..start + 16].copy_from_slice(&leaf_end.to_le_bytes());
            let at = start + NODE_HEADER_SIZE + local * RELOC_ENTRY_SIZE;
            clear[at..at + 8].copy_from_slice(&((i as u64) * 0x10).to_le_bytes());
            clear[at + 8..at + 16].copy_from_slice(&((i as u64) * 0x10).to_le_bytes());
        }
        let key = [0x49u8; 16];
        let mut encrypted = clear.clone();
        nca_ctr_xcrypt_range(&mut encrypted[0x4000..0x10000], &key, &[0u8; 16], 0x4000)?;
        let mut source = Cursor::new(encrypted);
        let parsed = collect_relocations_from_reader(&mut source, 0, size, 0, size, &fs, &key)?;
        assert_eq!(parsed.entries.len(), count);
        assert_eq!(parsed.virtual_size, virtual_size);
        assert_eq!(parsed.entries[per].virtual_offset, (per as u64) * 0x10);
        let mut damaged = clear;
        let next_leaf = 0xc000 + NODE_HEADER_SIZE;
        damaged[next_leaf..next_leaf + 8].copy_from_slice(&0u64.to_le_bytes());
        nca_ctr_xcrypt_range(&mut damaged[0x4000..0x10000], &key, &[0u8; 16], 0x4000)?;
        let mut source = Cursor::new(damaged);
        assert!(
            collect_relocations_from_reader(&mut source, 0, size, 0, size, &fs, &key).is_err(),
            "overlapping physical relocation leaves must fail closed"
        );
        Ok(())
    }
}
