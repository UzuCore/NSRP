use crate::{
    crypto::{
        aes_ecb_decrypt_block, aes_ecb_encrypt_block, nca_ctr_xcrypt_range, nca_xts_transform,
    },
    formats::{
        bktr::{aes_ctr_ex_counter, collect_from_reader},
        ncz::{ENC_AES_CTR, ENC_NONE, NczSection},
    },
    keys::KeySet,
};
use anyhow::{Context, Result, bail};
use sha2::{Digest, Sha256};
use std::{
    fs::{File, OpenOptions},
    io::{BufReader, Read, Seek, SeekFrom, Write},
    path::Path,
};

pub const NCA_XTS_HEADER_SIZE: usize = 0xC00;
pub const NCA_NCZ_HEADER_SIZE: usize = 0x4000;
pub const MEDIA_UNIT: u64 = 0x200;

#[derive(Debug, Clone)]
pub struct NcaSection {
    pub index: usize,
    pub offset: u64,
    pub size: u64,
    pub encryption_type: u8,
    pub counter: [u8; 16],
}

#[derive(Debug, Clone)]
pub struct NcaInfo {
    pub decrypted_header: Vec<u8>,
    pub content_type: u8,
    pub key_generation: u8,
    pub key_area_index: u8,
    pub rights_id: [u8; 16],
    pub sections: Vec<NcaSection>,
}

#[derive(Debug, Clone)]
pub struct NczPlan {
    pub original_bytes: Vec<u8>,
    pub decrypted_recrypted_header: Vec<u8>,
    pub section_key: [u8; 16],
    pub sections: Vec<NczSection>,
    pub crypto_spans: Vec<CryptoSpan>,
    pub content_type: u8,
}

#[derive(Debug, Clone)]
pub struct CryptoSpan {
    pub offset: u64,
    pub size: u64,
    pub key: [u8; 16],
    pub counter: [u8; 16],
}

pub fn decrypt_header(encrypted_header: &[u8], keys: &KeySet) -> Result<NcaInfo> {
    if encrypted_header.len() < NCA_XTS_HEADER_SIZE {
        bail!("NCA header is too short");
    }
    let header_key = keys
        .prod_key("header_key")
        .context("header_key is missing from prod.keys")?;
    if header_key.len() != 32 {
        bail!("header_key must be 32 bytes");
    }
    let mut header = encrypted_header[..NCA_XTS_HEADER_SIZE].to_vec();
    nca_xts_transform(&mut header, header_key, false)?;
    if !matches!(&header[0x200..0x204], b"NCA0" | b"NCA1" | b"NCA2" | b"NCA3") {
        bail!("NCA magic mismatch");
    }

    let content_type = header[0x205];
    let key_area_index = header[0x207];
    let key_generation = header[0x206].max(header[0x220]);
    let mut rights_id = [0u8; 16];
    rights_id.copy_from_slice(&header[0x230..0x240]);

    let mut sections = Vec::new();
    for index in 0..4usize {
        let entry = 0x240 + index * 0x10;
        let start =
            u32::from_le_bytes(header[entry..entry + 4].try_into().unwrap()) as u64 * MEDIA_UNIT;
        let end = u32::from_le_bytes(header[entry + 4..entry + 8].try_into().unwrap()) as u64
            * MEDIA_UNIT;
        if start == 0 && end == 0 {
            continue;
        }
        if end <= start {
            bail!("NCA section {index} has an invalid range");
        }
        let fs = 0x400 + index * 0x200;
        let encryption_type = header[fs + 4];
        let raw_counter = &header[fs + 0x140..fs + 0x148];
        let mut counter = [0u8; 16];
        for i in 0..8 {
            counter[i] = raw_counter[7 - i];
        }
        sections.push(NcaSection {
            index,
            offset: start,
            size: end - start,
            encryption_type,
            counter,
        });
    }

    Ok(NcaInfo {
        decrypted_header: header,
        content_type,
        key_generation,
        key_area_index,
        rights_id,
        sections,
    })
}

pub fn derive_section_key(info: &NcaInfo, keys: &KeySet) -> Result<[u8; 16]> {
    let key_generation_index = info.key_generation.max(1) - 1;
    if info.rights_id.iter().any(|&byte| byte != 0) {
        let encrypted = keys
            .title_key(&info.rights_id)
            .context("no title key matches the NCA Rights ID")?;
        if encrypted.len() != 16 {
            bail!("title key must be 16 bytes");
        }

        let mut candidates = vec![key_generation_index];
        let rights_index = if info.rights_id[15] == 0 {
            0
        } else {
            info.rights_id[15].max(1) - 1
        };
        if rights_index != key_generation_index {
            candidates.push(rights_index);
        }
        for index in candidates {
            let name = format!("titlekek_{index:02x}");
            if let Some(titlekek) = keys.prod_key(&name)
                && titlekek.len() == 16
            {
                return aes_ecb_decrypt_block(encrypted, titlekek);
            }
        }
        bail!("titlekek_{key_generation_index:02x} is missing");
    }

    let kaek = get_kaek(keys, info.key_area_index, key_generation_index)?;
    let slot = &info.decrypted_header[0x320..0x330];
    if slot.iter().all(|&byte| byte == 0) {
        bail!("NCA key-area slot 2 is empty");
    }
    aes_ecb_decrypt_block(slot, kaek)
}

pub fn recrypt_header(
    encrypted_header: &[u8],
    keys: &KeySet,
    new_key_generation: Option<u8>,
) -> Result<Vec<u8>> {
    let mut info = decrypt_header(encrypted_header, keys)?;
    let old_generation = info.key_generation;
    let new_generation = new_key_generation.unwrap_or(old_generation);
    let old_index = old_generation.max(1) - 1;
    let new_index = new_generation.max(1) - 1;
    let plain_section_key = derive_section_key(&info, keys)?;

    if new_generation <= 2 {
        info.decrypted_header[0x206] = new_generation;
        info.decrypted_header[0x220] = 0;
    } else {
        info.decrypted_header[0x206] = 2;
        info.decrypted_header[0x220] = new_generation;
    }

    let had_rights = info.rights_id.iter().any(|&byte| byte != 0);
    if had_rights {
        let new_kaek = get_kaek(keys, info.key_area_index, new_index)?;
        let encrypted_key = aes_ecb_encrypt_block(&plain_section_key, new_kaek)?;
        info.decrypted_header[0x230..0x240].fill(0);
        info.decrypted_header[0x300..0x340].fill(0);
        info.decrypted_header[0x320..0x330].copy_from_slice(&encrypted_key);
    } else {
        let old_kaek = get_kaek(keys, info.key_area_index, old_index)?;
        let new_kaek = get_kaek(keys, info.key_area_index, new_index)?;
        for slot_index in 0..4 {
            let offset = 0x300 + slot_index * 16;
            let slot = info.decrypted_header[offset..offset + 16].to_vec();
            if slot.iter().all(|&byte| byte == 0) {
                continue;
            }
            let plain = aes_ecb_decrypt_block(&slot, old_kaek)?;
            let encrypted = aes_ecb_encrypt_block(&plain, new_kaek)?;
            info.decrypted_header[offset..offset + 16].copy_from_slice(&encrypted);
        }
    }

    let header_key = keys
        .prod_key("header_key")
        .context("header_key is missing")?;
    let mut output = info.decrypted_header;
    nca_xts_transform(&mut output, header_key, true)?;
    Ok(output)
}

/// Restore the original rights-managed NCA header used by legacy NSRP NCZ files.
/// The candidate is written only when the full reconstructed NCA SHA-256 matches
/// the hash recorded in CNMT, so normal rights-free NCA files are never guessed.
pub fn restore_legacy_rights_header_for_hash(
    path: &Path,
    title_id: &str,
    expected_hash: &[u8; 32],
    keys: &KeySet,
) -> Result<bool> {
    let size = std::fs::metadata(path)?.len();
    restore_legacy_rights_header_region_for_hash(path, 0, size, title_id, expected_hash, keys)
}

pub fn restore_legacy_rights_header_region_for_hash(
    path: &Path,
    offset: u64,
    size: u64,
    title_id: &str,
    expected_hash: &[u8; 32],
    keys: &KeySet,
) -> Result<bool> {
    restore_legacy_rights_header_region_policy(
        path,
        offset,
        size,
        title_id,
        expected_hash,
        keys,
        false,
    )
}

/// Only recover the retail Rights ID if the caller has a matching title key.
/// Legacy ticketless NCZ headers can be bootable as-is, but restoring a
/// retail Rights ID without its title key makes the merged NSP/NSZ fail to
/// launch. This policy is deliberately limited to the patch packaging path.
pub fn restore_legacy_rights_header_region_if_key_available(
    path: &Path,
    offset: u64,
    size: u64,
    title_id: &str,
    expected_hash: &[u8; 32],
    keys: &KeySet,
) -> Result<bool> {
    restore_legacy_rights_header_region_policy(
        path,
        offset,
        size,
        title_id,
        expected_hash,
        keys,
        true,
    )
}

fn restore_legacy_rights_header_region_policy(
    path: &Path,
    offset: u64,
    size: u64,
    title_id: &str,
    expected_hash: &[u8; 32],
    keys: &KeySet,
    require_title_key: bool,
) -> Result<bool> {
    if size < NCA_XTS_HEADER_SIZE as u64 {
        return Ok(false);
    }

    let mut reader = BufReader::with_capacity(8 * 1024 * 1024, File::open(path)?);
    reader.seek(SeekFrom::Start(offset))?;
    let mut encrypted_header = vec![0u8; NCA_XTS_HEADER_SIZE];
    reader.read_exact(&mut encrypted_header)?;
    let info = decrypt_header(&encrypted_header, keys)?;

    if info.rights_id.iter().any(|&byte| byte != 0) {
        return Ok(false);
    }
    if hash_region_with_header(&mut reader, offset, size, &encrypted_header)? == *expected_hash {
        return Ok(false);
    }

    let title_bytes = hex::decode(title_id.trim()).context("CNMT Title ID hex 오류")?;
    if title_bytes.len() != 8 {
        bail!("CNMT Title ID 길이 오류: {title_id}");
    }
    let header_key = keys
        .prod_key("header_key")
        .context("header_key is missing from prod.keys")?;

    let mut rights_last_candidates = vec![info.key_generation, 0];
    rights_last_candidates.dedup();
    for rights_last in rights_last_candidates {
        if require_title_key {
            let mut candidate_id = [0u8; 16];
            candidate_id[..8].copy_from_slice(&title_bytes);
            candidate_id[15] = rights_last;
            if keys.title_key(&candidate_id).is_none() {
                // Skipping this legacy header conversion keeps the known
                // working ticketless crypto accessible to Eden.
                continue;
            }
        }
        let mut plain = info.decrypted_header.clone();
        plain[0x230..0x240].fill(0);
        plain[0x230..0x238].copy_from_slice(&title_bytes);
        plain[0x23f] = rights_last;
        plain[0x300..0x340].fill(0);

        let mut candidate = plain;
        nca_xts_transform(&mut candidate, header_key, true)?;
        if hash_region_with_header(&mut reader, offset, size, &candidate)? != *expected_hash {
            continue;
        }

        let mut file = OpenOptions::new().write(true).open(path)?;
        file.seek(SeekFrom::Start(offset))?;
        file.write_all(&candidate)?;
        file.flush()?;
        return Ok(true);
    }
    Ok(false)
}

fn hash_region_with_header(
    reader: &mut BufReader<File>,
    offset: u64,
    size: u64,
    header: &[u8],
) -> Result<[u8; 32]> {
    if header.len() < NCA_XTS_HEADER_SIZE {
        bail!("NCA header hash input is too short");
    }
    let mut hash = Sha256::new();
    hash.update(&header[..NCA_XTS_HEADER_SIZE]);
    reader.seek(SeekFrom::Start(offset + NCA_XTS_HEADER_SIZE as u64))?;
    let mut left = size - NCA_XTS_HEADER_SIZE as u64;
    let mut buffer = vec![0u8; 8 * 1024 * 1024];
    while left > 0 {
        let take = left.min(buffer.len() as u64) as usize;
        reader.read_exact(&mut buffer[..take])?;
        hash.update(&buffer[..take]);
        left -= take as u64;
    }
    Ok(hash.finalize().into())
}

pub fn make_ncz_plan(nca_head_4000: &[u8], nca_size: u64, keys: &KeySet) -> Result<NczPlan> {
    if decrypt_header(nca_head_4000, keys)?
        .sections
        .iter()
        .any(|section| matches!(section.encryption_type, 4 | 6))
    {
        bail!("BKTR NCA requires a reader-aware NCZ plan");
    }
    let mut cursor = std::io::Cursor::new(nca_head_4000);
    make_ncz_plan_from_reader(&mut cursor, 0, nca_size, nca_head_4000, keys)
}

pub fn make_ncz_plan_from_reader<R: Read + Seek>(
    reader: &mut R,
    nca_base: u64,
    nca_size: u64,
    nca_head_4000: &[u8],
    keys: &KeySet,
) -> Result<NczPlan> {
    if nca_head_4000.len() < NCA_NCZ_HEADER_SIZE {
        bail!("NCA header for NCZ is shorter than 0x4000");
    }
    let original_info = decrypt_header(nca_head_4000, keys)?;
    if !matches!(original_info.content_type, 0 | 5) {
        bail!(
            "NCA is not compressible (ContentType={})",
            original_info.content_type
        );
    }
    if original_info.sections.iter().any(|section| {
        matches!(section.encryption_type, 2)
            || !matches!(section.encryption_type, 1 | 3 | 4 | 5 | 6)
    }) {
        bail!("NCA contains an unsupported section encryption type");
    }
    for section in &original_info.sections {
        if section
            .offset
            .checked_add(section.size)
            .context("NCA section range overflow")?
            > nca_size
        {
            bail!("NCA section {} is outside the file", section.index);
        }
    }

    let section_key = derive_section_key(&original_info, keys)?;

    // NCZ는 원본 NCA의 첫 0x4000 바이트를 그대로 보존해야 해제 시
    // CNMT content hash와 동일한 NCA를 재구성할 수 있다. 과거 구현은
    // rights-managed 헤더를 ticketless standard-crypto 헤더로 바꿔 저장해
    // 본문은 같아도 NCA SHA-256이 달라지는 문제가 있었다.
    let original_bytes = nca_head_4000[..NCA_NCZ_HEADER_SIZE].to_vec();

    let mut sections = Vec::new();
    let mut spans = Vec::new();
    for section in &original_info.sections {
        let original_section = section;

        if matches!(section.encryption_type, 4 | 6) {
            let fs_offset = 0x400 + section.index * 0x200;
            let fs_header = &original_info.decrypted_header[fs_offset..fs_offset + 0x200];
            let bktr = collect_from_reader(
                reader,
                nca_base,
                nca_size,
                original_section.offset,
                original_section.size,
                fs_header,
                &section_key,
            )?;

            for (index, entry) in bktr.entries.iter().enumerate() {
                let entry_end = bktr
                    .entries
                    .get(index + 1)
                    .map(|next| next.offset)
                    .unwrap_or(bktr.bktr_offset)
                    .min(bktr.bktr_offset);
                if entry_end <= entry.offset {
                    continue;
                }
                let offset = section.offset + entry.offset;
                let size = entry_end - entry.offset;
                let (crypto_type, key, counter) = if entry.encrypted {
                    (
                        ENC_AES_CTR,
                        section_key,
                        aes_ctr_ex_counter(bktr.secure_value, entry.generation),
                    )
                } else {
                    (ENC_NONE, [0u8; 16], [0u8; 16])
                };
                sections.push(NczSection {
                    offset,
                    size,
                    crypto_type,
                    crypto_key: key,
                    crypto_counter: counter,
                });
                if entry.encrypted {
                    spans.push(CryptoSpan {
                        offset,
                        size,
                        key: section_key,
                        counter,
                    });
                }
            }

            let metadata_offset = section.offset + bktr.bktr_offset;
            let metadata_size = section.size - bktr.bktr_offset;
            if metadata_size > 0 {
                sections.push(NczSection {
                    offset: metadata_offset,
                    size: metadata_size,
                    crypto_type: ENC_AES_CTR,
                    crypto_key: section_key,
                    crypto_counter: section.counter,
                });
                spans.push(CryptoSpan {
                    offset: metadata_offset,
                    size: metadata_size,
                    key: section_key,
                    counter: section.counter,
                });
            }
            continue;
        }

        let mut offset = section.offset;
        let mut size = section.size;
        if offset < NCA_NCZ_HEADER_SIZE as u64 {
            let overlap = NCA_NCZ_HEADER_SIZE as u64 - offset;
            if overlap >= size {
                continue;
            }
            offset = NCA_NCZ_HEADER_SIZE as u64;
            size -= overlap;
        }
        let (crypto_type, key, counter) = match section.encryption_type {
            1 => (ENC_NONE, [0u8; 16], [0u8; 16]),
            3 | 5 => (ENC_AES_CTR, section_key, section.counter),
            other => bail!("unsupported NCA encryption type: {other}"),
        };
        sections.push(NczSection {
            offset,
            size,
            crypto_type,
            crypto_key: key,
            crypto_counter: counter,
        });
        if matches!(section.encryption_type, 3 | 5) {
            spans.push(CryptoSpan {
                offset: section.offset,
                size: section.size,
                key: section_key,
                counter: section.counter,
            });
        }
    }

    if sections.is_empty() {
        bail!("no NCZ sections were generated");
    }
    sections.sort_by_key(|section| section.offset);
    spans.sort_by_key(|span| span.offset);

    Ok(NczPlan {
        original_bytes,
        decrypted_recrypted_header: original_info.decrypted_header,
        section_key,
        sections,
        crypto_spans: spans,
        content_type: original_info.content_type,
    })
}

pub fn decrypt_chunk_in_place(
    chunk: &mut [u8],
    absolute_offset: u64,
    spans: &[CryptoSpan],
) -> Result<()> {
    let chunk_end = absolute_offset
        .checked_add(chunk.len() as u64)
        .context("chunk range overflow")?;
    for span in spans {
        let span_end = span.offset + span.size;
        let start = absolute_offset.max(span.offset);
        let end = chunk_end.min(span_end);
        if start >= end {
            continue;
        }
        let local_start = (start - absolute_offset) as usize;
        let local_end = (end - absolute_offset) as usize;
        nca_ctr_xcrypt_range(
            &mut chunk[local_start..local_end],
            &span.key,
            &span.counter,
            start,
        )?;
    }
    Ok(())
}

fn get_kaek(keys: &KeySet, key_area_index: u8, key_generation_index: u8) -> Result<&[u8]> {
    let kind = match key_area_index.min(2) {
        0 => "application",
        1 => "ocean",
        _ => "system",
    };
    let name = format!("key_area_key_{kind}_{key_generation_index:02x}");
    let key = keys
        .prod_key(&name)
        .with_context(|| format!("{name} is missing"))?;
    if key.len() != 16 {
        bail!("{name} must be 16 bytes");
    }
    Ok(key)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    fn synthetic_keys() -> KeySet {
        let mut prod = HashMap::new();
        prod.insert("header_key".into(), (0..32u8).collect());
        prod.insert("key_area_key_application_00".into(), vec![0x31; 16]);
        KeySet {
            prod,
            title: HashMap::new(),
        }
    }

    #[test]
    fn standard_crypto_header_roundtrip_and_plan() -> Result<()> {
        let keys = synthetic_keys();
        let plain_section_key = [0x42u8; 16];
        let kaek = keys.prod_key("key_area_key_application_00").unwrap();
        let encrypted_slot = aes_ecb_encrypt_block(&plain_section_key, kaek)?;

        let mut header = vec![0u8; NCA_XTS_HEADER_SIZE];
        header[0x200..0x204].copy_from_slice(b"NCA3");
        header[0x205] = 0;
        header[0x206] = 1;
        header[0x207] = 0;
        header[0x320..0x330].copy_from_slice(&encrypted_slot);
        header[0x240..0x244].copy_from_slice(&(0x20u32).to_le_bytes());
        header[0x244..0x248].copy_from_slice(&(0x30u32).to_le_bytes());
        header[0x404] = 3;
        header[0x540..0x548].copy_from_slice(&0x1122334455667788u64.to_le_bytes());

        let mut encrypted = header.clone();
        nca_xts_transform(&mut encrypted, keys.prod_key("header_key").unwrap(), true)?;
        let info = decrypt_header(&encrypted, &keys)?;
        assert_eq!(derive_section_key(&info, &keys)?, plain_section_key);

        let mut head4000 = vec![0u8; NCA_NCZ_HEADER_SIZE];
        head4000[..NCA_XTS_HEADER_SIZE].copy_from_slice(&encrypted);
        let plan = make_ncz_plan(&head4000, 0x6000, &keys)?;
        assert_eq!(plan.sections.len(), 1);
        assert_eq!(plan.sections[0].offset, 0x4000);
        assert_eq!(
            &plan.original_bytes[..NCA_XTS_HEADER_SIZE],
            &encrypted[..],
            "NCZ must preserve the original NCA header verbatim"
        );
        Ok(())
    }

    #[test]
    fn ticketless_header_remains_bootable_without_matching_title_key() -> Result<()> {
        let keys = synthetic_keys();
        let title_id = "01006d901dbc6000";
        let mut plain = vec![0u8; NCA_XTS_HEADER_SIZE];
        plain[0x200..0x204].copy_from_slice(b"NCA3");
        plain[0x205] = 0;
        plain[0x206] = 1;
        plain[0x300..0x310].fill(0x44);
        let header_key = keys.prod_key("header_key").unwrap();

        let mut ticketless_header = plain.clone();
        nca_xts_transform(&mut ticketless_header, header_key, true)?;
        let mut retail_header = plain;
        retail_header[0x230..0x238].copy_from_slice(&hex::decode(title_id)?);
        retail_header[0x23f] = 1;
        retail_header[0x300..0x340].fill(0);
        nca_xts_transform(&mut retail_header, header_key, true)?;
        let expected_hash: [u8; 32] = Sha256::digest(&retail_header).into();

        let scratch = tempfile::tempdir()?;
        let target = scratch.path().join("base_program.nca");
        std::fs::write(&target, &ticketless_header)?;
        assert!(
            !restore_legacy_rights_header_region_if_key_available(
                &target,
                0,
                NCA_XTS_HEADER_SIZE as u64,
                title_id,
                &expected_hash,
                &keys,
            )?,
            "Do not restore Rights ID without a matching title key"
        );
        assert_eq!(std::fs::read(&target)?, ticketless_header);

        let mut with_title_key = keys;
        with_title_key
            .title
            .insert(title_id.to_ascii_uppercase(), vec![0x77; 16]);
        assert!(restore_legacy_rights_header_region_if_key_available(
            &target,
            0,
            NCA_XTS_HEADER_SIZE as u64,
            title_id,
            &expected_hash,
            &with_title_key,
        )?);
        assert_eq!(std::fs::read(target)?, retail_header);
        Ok(())
    }
}
