use super::{CompressOptions, compress_nsp, decompress_nsz};
use crate::{
    crypto::{aes_ecb_encrypt_block, nca_ctr_xcrypt_range, nca_xts_transform},
    formats::{
        bktr::aes_ctr_ex_counter,
        nca::{NCA_XTS_HEADER_SIZE, decrypt_header},
        pfs0::{Pfs0Index, build_from_paths},
    },
    keys::KeySet,
};
use anyhow::{Context, Result};
use std::{collections::HashMap, fs, path::Path, sync::atomic::AtomicBool};

fn synthetic_keys() -> KeySet {
    let mut prod = HashMap::new();
    prod.insert("header_key".into(), (0..32u8).collect());
    prod.insert("key_area_key_application_00".into(), vec![0x31; 16]);
    KeySet {
        prod,
        title: HashMap::new(),
    }
}

fn synthetic_bktr_nca(path: &Path, keys: &KeySet) -> Result<Vec<u8>> {
    const NCA_SIZE: usize = 0x14000;
    const SECTION_OFFSET: usize = 0x4000;
    const SECTION_SIZE: usize = 0x10000;
    const BKTR_OFFSET: usize = 0x4000;
    const ENC_TREE_OFFSET: usize = 0x8000;
    const ENTRY_STORAGE_OFFSET: usize = 0xC000;

    let section_key = [0x42u8; 16];
    let kaek = keys.prod_key("key_area_key_application_00").unwrap();
    let encrypted_slot = aes_ecb_encrypt_block(&section_key, kaek)?;

    let mut header = vec![0u8; NCA_XTS_HEADER_SIZE];
    header[0x200..0x204].copy_from_slice(b"NCA3");
    header[0x205] = 0;
    header[0x206] = 1;
    header[0x207] = 0;
    header[0x208..0x210].copy_from_slice(&(NCA_SIZE as u64).to_le_bytes());
    header[0x320..0x330].copy_from_slice(&encrypted_slot);
    header[0x240..0x244].copy_from_slice(&(0x20u32).to_le_bytes());
    header[0x244..0x248].copy_from_slice(&(0xA0u32).to_le_bytes());

    let fs_header = 0x400usize;
    header[fs_header + 4] = 4;
    header[fs_header + 0x100..fs_header + 0x108]
        .copy_from_slice(&(BKTR_OFFSET as i64).to_le_bytes());
    header[fs_header + 0x108..fs_header + 0x110].copy_from_slice(&(0x4000i64).to_le_bytes());
    header[fs_header + 0x120..fs_header + 0x128]
        .copy_from_slice(&(ENC_TREE_OFFSET as i64).to_le_bytes());
    header[fs_header + 0x128..fs_header + 0x130].copy_from_slice(&(0x8000i64).to_le_bytes());
    header[fs_header + 0x130..fs_header + 0x134].copy_from_slice(b"BKTR");
    header[fs_header + 0x134..fs_header + 0x138].copy_from_slice(&(1u32).to_le_bytes());
    header[fs_header + 0x138..fs_header + 0x13C].copy_from_slice(&(2i32).to_le_bytes());
    header[fs_header + 0x13C..fs_header + 0x140].copy_from_slice(&(0i32).to_le_bytes());
    header[fs_header + 0x140..fs_header + 0x148]
        .copy_from_slice(&0x11223344AABBCCDDu64.to_le_bytes());

    let mut section = vec![0u8; SECTION_SIZE];
    for (index, byte) in section[..BKTR_OFFSET].iter_mut().enumerate() {
        *byte = ((index * 29 + 11) % 251) as u8;
    }

    let entry_storage = ENTRY_STORAGE_OFFSET;
    section[entry_storage..entry_storage + 4].copy_from_slice(&(0i32).to_le_bytes());
    section[entry_storage + 4..entry_storage + 8].copy_from_slice(&(2i32).to_le_bytes());
    section[entry_storage + 8..entry_storage + 16]
        .copy_from_slice(&(BKTR_OFFSET as i64).to_le_bytes());

    let first = entry_storage + 0x10;
    section[first..first + 8].copy_from_slice(&(0i64).to_le_bytes());
    section[first + 8] = 0;
    section[first + 12..first + 16].copy_from_slice(&(7i32).to_le_bytes());

    let second = first + 0x10;
    section[second..second + 8].copy_from_slice(&(0x2000i64).to_le_bytes());
    section[second + 8] = 1;
    section[second + 12..second + 16].copy_from_slice(&(0i32).to_le_bytes());

    let mut encrypted_header = header;
    nca_xts_transform(
        &mut encrypted_header,
        keys.prod_key("header_key").unwrap(),
        true,
    )?;
    let info = decrypt_header(&encrypted_header, keys)?;
    let normal_counter = info.sections[0].counter;

    let mut encrypted_first = section[..0x2000].to_vec();
    let bktr_counter = aes_ctr_ex_counter(0x11223344, 7);
    nca_ctr_xcrypt_range(
        &mut encrypted_first,
        &section_key,
        &bktr_counter,
        SECTION_OFFSET as u64,
    )?;
    section[..0x2000].copy_from_slice(&encrypted_first);

    let mut encrypted_metadata = section[BKTR_OFFSET..].to_vec();
    nca_ctr_xcrypt_range(
        &mut encrypted_metadata,
        &section_key,
        &normal_counter,
        (SECTION_OFFSET + BKTR_OFFSET) as u64,
    )?;
    section[BKTR_OFFSET..].copy_from_slice(&encrypted_metadata);

    let mut nca = vec![0u8; NCA_SIZE];
    nca[..NCA_XTS_HEADER_SIZE].copy_from_slice(&encrypted_header);
    nca[SECTION_OFFSET..SECTION_OFFSET + SECTION_SIZE].copy_from_slice(&section);
    fs::write(path, &nca)?;
    Ok(nca)
}

fn roundtrip_bktr(block_mode: bool) -> Result<()> {
    let temp = tempfile::tempdir()?;
    let mut keys = synthetic_keys();
    let nca_path = temp.path().join("update_program.nca");
    let original = synthetic_bktr_nca(&nca_path, &keys)?;
    let nsp = temp.path().join("input_bktr.nsp");
    build_from_paths(&[("update_program.nca".into(), nca_path)], &nsp)?;
    let nsz = temp.path().join("output_bktr.nsz");
    let restored_nsp = temp.path().join("roundtrip_bktr.nsp");
    let cancel = AtomicBool::new(false);
    let mut progress = |_| {};
    let mut log = |_| {};

    let stats = compress_nsp(
        &nsp,
        &nsz,
        &mut keys,
        &CompressOptions {
            level: 3,
            threads: 2,
            block_mode,
            long_mode: false,
        },
        &cancel,
        &mut progress,
        &mut log,
    )?;
    assert_eq!(stats.ncz_count, 1);
    let compressed_index = Pfs0Index::parse(&nsz)?;
    assert!(compressed_index.entry("update_program.ncz").is_some());

    decompress_nsz(&nsz, &restored_nsp, &cancel, &mut progress, &mut log)?;
    let restored_index = Pfs0Index::parse(&restored_nsp)?;
    let entry = restored_index
        .entry("update_program.nca")
        .context("BKTR roundtrip NCA missing")?;
    let restored = restored_index.read_entry(&restored_nsp, entry)?;
    assert_eq!(restored, original);
    Ok(())
}

#[test]
fn nsp_nsz_bktr_roundtrip_stream() -> Result<()> {
    roundtrip_bktr(false)
}

#[test]
fn nsp_nsz_bktr_roundtrip_block() -> Result<()> {
    roundtrip_bktr(true)
}
