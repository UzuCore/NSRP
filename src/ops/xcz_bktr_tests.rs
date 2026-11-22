use super::{XczOptions, compress_xci, decompress_xcz};
use crate::{
    crypto::{aes_ecb_encrypt_block, nca_ctr_xcrypt_range, nca_xts_transform},
    formats::{
        bktr::aes_ctr_ex_counter,
        hfs0::{self, Hfs0Index},
        nca::{NCA_XTS_HEADER_SIZE, decrypt_header},
    },
    keys::KeySet,
};
use anyhow::{Context, Result};
use std::{
    collections::HashMap,
    fs::{self, File},
    io::{Read, Seek, SeekFrom},
    path::{Path, PathBuf},
    sync::atomic::AtomicBool,
};

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
        *byte = ((index * 31 + 7) % 251) as u8;
    }

    let entry_storage = ENTRY_STORAGE_OFFSET;
    section[entry_storage..entry_storage + 4].copy_from_slice(&(0i32).to_le_bytes());
    section[entry_storage + 4..entry_storage + 8].copy_from_slice(&(2i32).to_le_bytes());
    section[entry_storage + 8..entry_storage + 16]
        .copy_from_slice(&(BKTR_OFFSET as i64).to_le_bytes());
    let first = entry_storage + 0x10;
    section[first..first + 8].copy_from_slice(&(0i64).to_le_bytes());
    section[first + 8] = 0;
    section[first + 12..first + 16].copy_from_slice(&(9i32).to_le_bytes());
    let second = first + 0x10;
    section[second..second + 8].copy_from_slice(&(0x2000i64).to_le_bytes());
    section[second + 8] = 1;

    let mut encrypted_header = header;
    nca_xts_transform(
        &mut encrypted_header,
        keys.prod_key("header_key").unwrap(),
        true,
    )?;
    let info = decrypt_header(&encrypted_header, keys)?;
    let normal_counter = info.sections[0].counter;

    let mut encrypted_first = section[..0x2000].to_vec();
    let bktr_counter = aes_ctr_ex_counter(0x11223344, 9);
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

fn build_nested_xci(temp: &Path, nca_path: PathBuf) -> Result<PathBuf> {
    let secure = temp.join("secure.hfs0");
    hfs0::build_from_paths_layout(
        &[("update_program.nca".into(), nca_path)],
        &secure,
        0x200,
        1,
    )?;
    let root = temp.join("root.hfs0");
    hfs0::build_from_paths_layout(&[("secure".into(), secure)], &root, 0x200, 1)?;
    let xci = temp.join("input.xci");
    let mut image = vec![0u8; 0x200];
    image.extend_from_slice(&fs::read(root)?);
    fs::write(&xci, image)?;
    Ok(xci)
}

fn read_nested_entry(path: &Path, expected_name: &str) -> Result<Vec<u8>> {
    let mut file = File::open(path)?;
    let file_size = file.metadata()?.len();
    let root = hfs0::find_xci_root(path)?;
    let secure = root
        .entries
        .iter()
        .find(|entry| entry.name.eq_ignore_ascii_case("secure"))
        .context("secure partition missing")?;
    let secure_base = root.data_start + secure.offset;
    let sub = Hfs0Index::parse_at(&mut file, secure_base, file_size)?;
    let target = sub
        .entries
        .iter()
        .find(|entry| entry.name.eq_ignore_ascii_case(expected_name))
        .with_context(|| format!("nested entry missing: {expected_name}"))?;
    file.seek(SeekFrom::Start(sub.data_start + target.offset))?;
    let mut data = vec![0u8; target.size as usize];
    file.read_exact(&mut data)?;
    Ok(data)
}

fn roundtrip_bktr(block_mode: bool, long_mode: bool) -> Result<()> {
    let temp = tempfile::tempdir()?;
    let mut keys = synthetic_keys();
    let nca_path = temp.path().join("update_program.nca");
    let original = synthetic_bktr_nca(&nca_path, &keys)?;
    let input_xci = build_nested_xci(temp.path(), nca_path)?;
    let output_xcz = temp.path().join("output.xcz");
    let restored_xci = temp.path().join("restored.xci");
    let cancel = AtomicBool::new(false);
    let mut progress = |_| {};
    let mut log = |_| {};

    let stats = compress_xci(
        &input_xci,
        &output_xcz,
        &mut keys,
        &XczOptions {
            level: 3,
            threads: 2,
            block_mode,
            long_mode,
        },
        &cancel,
        &mut progress,
        &mut log,
    )?;
    assert_eq!(stats.ncz_count, 1);
    let compressed = read_nested_entry(&output_xcz, "update_program.ncz")?;
    assert!(compressed.len() > 0x4000);

    decompress_xcz(&output_xcz, &restored_xci, &cancel, &mut progress, &mut log)?;
    let restored = read_nested_entry(&restored_xci, "update_program.nca")?;
    assert_eq!(restored, original);
    Ok(())
}

#[test]
fn xci_xcz_bktr_roundtrip_stream() -> Result<()> {
    roundtrip_bktr(false, false)
}

#[test]
fn xci_xcz_bktr_roundtrip_block() -> Result<()> {
    roundtrip_bktr(true, false)
}

#[test]
fn xci_xcz_bktr_roundtrip_long_stream() -> Result<()> {
    roundtrip_bktr(false, true)
}

#[test]
fn xci_xcz_bktr_roundtrip_long_block() -> Result<()> {
    roundtrip_bktr(true, true)
}
