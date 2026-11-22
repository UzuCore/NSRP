//! Stage62 independently constructed NCA fixtures (no retail game or key).
//! Exercise the native paths that formerly could fall back to a GPL packer.
use super::*;
use crate::{
    crypto::aes_ecb_encrypt_block,
    formats::pfs0::Pfs0Index,
    ops::{
        native_fs::romfs_file_index,
        native_repack::{rebuild_ivfc, verify_ivfc},
    },
};
use std::collections::HashMap;

fn keys() -> KeySet {
    let mut prod = HashMap::new();
    prod.insert("header_key".to_owned(), (0..32u8).collect());
    prod.insert("key_area_key_application_00".to_owned(), vec![0x73; 16]);
    KeySet {
        prod,
        title: HashMap::new(),
    }
}

fn fake_romfs_section(root: &Path, scratch: &Path) -> Result<(Vec<u8>, Vec<u8>)> {
    let image_path = scratch.join("romfs-image.bin");
    build_romfs(root, &image_path, &AtomicBool::new(false))?;
    let image = fs::read(&image_path)?;
    let mut fs_header = vec![0u8; 0x200];
    fs_header[2..5].copy_from_slice(&[0, 3, 3]);
    fs_header[8..12].copy_from_slice(b"IVFC");
    fs_header[0x14..0x18].copy_from_slice(&3u32.to_le_bytes());
    // Initial source fixture: 512-byte hash layer and one data level.
    set64(&mut fs_header, 0x18, 0);
    set64(&mut fs_header, 0x20, 0x200);
    fs_header[0x28..0x2c].copy_from_slice(&9u32.to_le_bytes());
    set64(&mut fs_header, 0x30, 0x200);
    set64(&mut fs_header, 0x38, image.len() as u64);
    fs_header[0x40..0x44].copy_from_slice(&9u32.to_le_bytes());
    let total = aligned(0x200 + image.len() as u64, SECTOR)?;
    let mut section = vec![0u8; usize::try_from(total)?];
    section[0x200..0x200 + image.len()].copy_from_slice(&image);
    let levels = ivfc_levels(&fs_header, total)?;
    rebuild_ivfc(
        &mut section,
        &mut fs_header,
        &levels,
        &AtomicBool::new(false),
    )?;
    assert!(verify_ivfc(&section, &fs_header, &levels)?);
    Ok((fs_header, section))
}

fn fake_exefs_section(root: &Path, scratch: &Path) -> Result<(Vec<u8>, Vec<u8>)> {
    let image = scratch.join("exefs-image.pfs0");
    let mut fs_header = vec![0u8; 0x200];
    fs_header[2..5].copy_from_slice(&[1, 2, 3]);
    fs_header[0x28..0x2c].copy_from_slice(&512u32.to_le_bytes());
    build_exefs_input(root, &image)?;
    let output = scratch.join("exefs-section.bin");
    let header = rebuild_exefs_section(&fs_header, &image, &output, &AtomicBool::new(false))?;
    Ok((header, fs::read(output)?))
}

fn synthetic_nca(
    output: &Path,
    keys: &KeySet,
    content_type: u8,
    parts: &[(Vec<u8>, Vec<u8>)],
) -> Result<()> {
    let header_key = keys
        .prod_key("header_key")
        .context("synthetic header key missing")?;
    let kaek = keys
        .prod_key("key_area_key_application_00")
        .context("synthetic KAEK missing")?;
    let section_key = [0x31u8; 16];
    let mut head = vec![0u8; NCA_XTS_HEADER_SIZE];
    head[0x200..0x204].copy_from_slice(b"NCA3");
    head[0x205] = content_type;
    head[0x206] = 1;
    head[0x207] = 0;
    let wrapped = aes_ecb_encrypt_block(&section_key, kaek)?;
    head[0x320..0x330].copy_from_slice(&wrapped);
    let mut body = Vec::new();
    let mut current = NCA_XTS_HEADER_SIZE as u64;
    for (index, (fs_header, plain)) in parts.iter().enumerate() {
        ensure!(index < 4, "synthetic NCA section count exceeded");
        ensure!(
            plain.len().is_multiple_of(SECTOR as usize),
            "unaligned fixture"
        );
        let fs_offset = 0x400 + index * 0x200;
        head[fs_offset..fs_offset + 0x200].copy_from_slice(fs_header);
        head[0x280 + index * 0x20..0x2a0 + index * 0x20]
            .copy_from_slice(&Sha256::digest(fs_header));
        let end = current + plain.len() as u64;
        let entry = 0x240 + index * 0x10;
        head[entry..entry + 4].copy_from_slice(&u32::try_from(current / SECTOR)?.to_le_bytes());
        head[entry + 4..entry + 8].copy_from_slice(&u32::try_from(end / SECTOR)?.to_le_bytes());
        let mut encrypted = plain.clone();
        nca_ctr_xcrypt_range(&mut encrypted, &section_key, &[0u8; 16], current)?;
        body.extend_from_slice(&encrypted);
        current = end;
    }
    head[0x208..0x210].copy_from_slice(&current.to_le_bytes());
    nca_xts_transform(&mut head, header_key, true)?;
    let mut file = File::create(output)?;
    file.write_all(&head)?;
    file.write_all(&body)?;
    file.flush()?;
    ensure!(
        file.metadata()?.len() == current,
        "synthetic NCA output mismatch"
    );
    Ok(())
}

fn verify_rebuilt_romfs(nca: &Path, keys: &KeySet, expected: &Path) -> Result<()> {
    let file = fs::read(nca)?;
    let info = decrypt_header(&file[..NCA_XTS_HEADER_SIZE], keys)?;
    assert!(info.decrypted_header[..0x200].iter().all(|byte| *byte == 0));
    let section = info
        .sections
        .iter()
        .find(|section| info.decrypted_header[0x400 + section.index * 0x200 + 2] == 0)
        .context("no RomFS section in repacked fixture")?;
    let fs_start = 0x400 + section.index * 0x200;
    let fs_header = &info.decrypted_header[fs_start..fs_start + 0x200];
    assert_eq!(
        &info.decrypted_header[0x280 + section.index * 0x20..0x2a0 + section.index * 0x20],
        Sha256::digest(fs_header).as_slice(),
    );
    let start = usize::try_from(section.offset)?;
    let end = usize::try_from(section.offset + section.size)?;
    let mut plain = file[start..end].to_vec();
    let key = derive_section_key(&info, keys)?;
    nca_ctr_xcrypt_range(&mut plain, &key, &section.counter, section.offset)?;
    let levels = ivfc_levels(fs_header, section.size)?;
    assert!(verify_ivfc(&plain, fs_header, &levels)?);
    let data = *levels.last().context("RomFS data level missing")?;
    let romfs_files = romfs_file_index(&plain, data.0, data.1)?;
    let expected_files = walkdir::WalkDir::new(expected)
        .into_iter()
        .collect::<std::result::Result<Vec<_>, _>>()?
        .into_iter()
        .filter(|entry| entry.file_type().is_file())
        .count();
    assert_eq!(romfs_files.len(), expected_files);
    for (relative, offset, size, _) in romfs_files {
        let expected_bytes = fs::read(expected.join(&relative))?;
        assert_eq!(size, expected_bytes.len() as u64);
        let start = usize::try_from(offset)?;
        assert_eq!(&plain[start..start + expected_bytes.len()], expected_bytes);
    }
    Ok(())
}

#[test]
fn stage62_native_control_rebuild_add_delete_resize_icon_and_nacp() -> Result<()> {
    let tmp = tempfile::tempdir()?;
    let old_romfs = tmp.path().join("control_original");
    let new_romfs = tmp.path().join("control_modified");
    fs::create_dir(&old_romfs)?;
    fs::create_dir(&new_romfs)?;
    fs::write(
        old_romfs.join("control.nacp"),
        b"original title and language\0",
    )?;
    fs::write(old_romfs.join("icon_old.dat"), vec![0x65; 127])?;
    fs::write(
        new_romfs.join("control.nacp"),
        b"new Korean-language title with longer content\0",
    )?;
    fs::write(new_romfs.join("icon_ko.dat"), vec![0x36; 64 * 1024 + 13])?;
    fs::create_dir(new_romfs.join("images"))?;
    fs::write(new_romfs.join("images").join("new.dat"), vec![0xa2; 239])?;
    let keys = keys();
    let source = tmp.path().join("control-original.nca");
    synthetic_nca(
        &source,
        &keys,
        2,
        &[fake_romfs_section(&old_romfs, tmp.path())?],
    )?;
    let before_sha = Sha256::digest(fs::read(&source)?);
    let out = tmp.path().join("control-rebuilt.nca");
    let stats = repack_nca(
        &source,
        Some(&new_romfs),
        None,
        &out,
        &keys,
        &AtomicBool::new(false),
    )?;
    assert_eq!(stats.romfs_files, 3);
    assert_eq!(stats.exefs_files, 0);
    assert_eq!(stats.bytes, fs::metadata(&out)?.len());
    assert_eq!(Sha256::digest(fs::read(&source)?), before_sha);
    verify_rebuilt_romfs(&out, &keys, &new_romfs)?;
    assert!(fs::metadata(&out)?.len() > fs::metadata(&source)?.len());
    Ok(())
}

#[test]
fn stage62_native_program_rebuild_romfs_and_exefs_without_packer() -> Result<()> {
    let tmp = tempfile::tempdir()?;
    let romfs = tmp.path().join("romfs");
    let exefs = tmp.path().join("exefs");
    fs::create_dir(&romfs)?;
    fs::create_dir(&exefs)?;
    fs::write(romfs.join("level.dat"), b"small original RomFS")?;
    fs::write(exefs.join("main"), b"original dummy Program ELF")?;
    fs::write(exefs.join("main.npdm"), b"original metadata")?;
    let original_exefs = fake_exefs_section(&exefs, tmp.path())?;
    let original_romfs = fake_romfs_section(&romfs, tmp.path())?;
    let source = tmp.path().join("program-original.nca");
    let keys = keys();
    synthetic_nca(&source, &keys, 0, &[original_exefs, original_romfs])?;
    let old_sha = Sha256::digest(fs::read(&source)?);
    fs::write(romfs.join("level.dat"), vec![0x37; 4097])?;
    fs::write(romfs.join("custom.dat"), b"new user data")?;
    fs::write(exefs.join("main.npdm"), b"updated title ID and metadata")?;
    let rebuilt = tmp.path().join("program-rebuilt.nca");
    let stats = repack_nca(
        &source,
        Some(&romfs),
        Some(&exefs),
        &rebuilt,
        &keys,
        &AtomicBool::new(false),
    )?;
    assert_eq!(stats.romfs_files, 2);
    assert_eq!(stats.exefs_files, 2);
    assert_eq!(Sha256::digest(fs::read(&source)?), old_sha);
    verify_rebuilt_romfs(&rebuilt, &keys, &romfs)?;
    let bytes = fs::read(&rebuilt)?;
    let info = decrypt_header(&bytes[..NCA_XTS_HEADER_SIZE], &keys)?;
    assert_eq!(info.content_type, 0);
    assert_eq!(info.sections.len(), 2);
    let first = &info.sections[0];
    let mut section =
        bytes[usize::try_from(first.offset)?..usize::try_from(first.offset + first.size)?].to_vec();
    nca_ctr_xcrypt_range(
        &mut section,
        &derive_section_key(&info, &keys)?,
        &first.counter,
        first.offset,
    )?;
    let fs_header = &info.decrypted_header[0x400..0x600];
    let pfs_offset = u64::from_le_bytes(fs_header[0x40..0x48].try_into()?);
    let pfs_len = u64::from_le_bytes(fs_header[0x48..0x50].try_into()?);
    let mut reader = std::io::Cursor::new(section);
    let index = Pfs0Index::parse_reader(&mut reader, pfs_offset, pfs_len)?;
    assert!(index.entries.iter().any(|entry| entry.name == "main.npdm"));
    assert!(index.entries.iter().any(|entry| entry.name == "main"));
    Ok(())
}

#[test]
fn stage62_native_repack_fails_closed_on_unsupported_or_existing_output() -> Result<()> {
    let tmp = tempfile::tempdir()?;
    let invalid = tmp.path().join("invalid.nca");
    fs::write(&invalid, vec![0xa5; 0xC00])?;
    let before = Sha256::digest(fs::read(&invalid)?);
    let romfs = tmp.path().join("romfs");
    fs::create_dir(&romfs)?;
    fs::write(romfs.join("safe.dat"), b"data")?;
    let output = tmp.path().join("untouched.nca");
    let keys = keys();
    assert!(
        repack_nca(
            &invalid,
            Some(&romfs),
            None,
            &output,
            &keys,
            &AtomicBool::new(false)
        )
        .is_err()
    );
    assert!(!output.exists());
    fs::write(&output, b"existing user content must not change")?;
    let sentinel = fs::read(&output)?;
    assert!(
        repack_nca(
            &invalid,
            Some(&romfs),
            None,
            &output,
            &keys,
            &AtomicBool::new(false)
        )
        .is_err()
    );
    assert_eq!(fs::read(&output)?, sentinel);
    assert_eq!(Sha256::digest(fs::read(&invalid)?), before);
    let cancelled = AtomicBool::new(true);
    let cancelled_out = tmp.path().join("cancelled.nca");
    assert!(
        repack_nca(
            &invalid,
            Some(&romfs),
            None,
            &cancelled_out,
            &keys,
            &cancelled
        )
        .is_err()
    );
    assert!(!cancelled_out.exists());
    Ok(())
}

#[test]
fn stage63_romfs_expansion_preserves_relocated_unmodified_aes_ctr_exefs() -> Result<()> {
    // An unchanged encrypted section can move when the preceding RomFS
    // grows. CTR depends on the absolute NCA offset, so the ciphertext
    // must be re-encrypted when the unmodified ExeFS is relocated.
    let tmp = tempfile::tempdir()?;
    let romfs = tmp.path().join("original_romfs");
    let exefs = tmp.path().join("original_exefs");
    fs::create_dir(&romfs)?;
    fs::create_dir(&exefs)?;
    fs::write(romfs.join("small.dat"), b"original tiny RomFS")?;
    fs::write(exefs.join("main"), vec![0x39; 0x1003])?;
    fs::write(exefs.join("main.npdm"), b"unchanged program metadata")?;
    let source = tmp.path().join("program-original.nca");
    let keys = keys();
    synthetic_nca(
        &source,
        &keys,
        0,
        &[
            fake_romfs_section(&romfs, tmp.path())?,
            fake_exefs_section(&exefs, tmp.path())?,
        ],
    )?;
    let original = fs::read(&source)?;
    let old_info = decrypt_header(&original[..NCA_XTS_HEADER_SIZE], &keys)?;
    assert_eq!(old_info.sections.len(), 2);
    let old_exefs = &old_info.sections[1];
    let mut old_plain = original
        [usize::try_from(old_exefs.offset)?..usize::try_from(old_exefs.offset + old_exefs.size)?]
        .to_vec();
    nca_ctr_xcrypt_range(
        &mut old_plain,
        &derive_section_key(&old_info, &keys)?,
        &old_exefs.counter,
        old_exefs.offset,
    )?;

    let modified_romfs = tmp.path().join("modified_romfs");
    fs::create_dir(&modified_romfs)?;
    fs::write(
        modified_romfs.join("small.dat"),
        vec![0x72; 1024 * 1024 + 19],
    )?;
    fs::write(modified_romfs.join("added.dat"), b"second logical asset")?;
    let rebuilt = tmp.path().join("rebuilt.nca");
    let stats = repack_nca(
        &source,
        Some(&modified_romfs),
        None,
        &rebuilt,
        &keys,
        &AtomicBool::new(false),
    )?;
    assert_eq!(stats.romfs_files, 2);
    assert_eq!(stats.exefs_files, 0);
    verify_rebuilt_romfs(&rebuilt, &keys, &modified_romfs)?;

    let output = fs::read(&rebuilt)?;
    let new_info = decrypt_header(&output[..NCA_XTS_HEADER_SIZE], &keys)?;
    let new_exefs = &new_info.sections[1];
    assert!(new_exefs.offset > old_exefs.offset);
    assert_eq!(new_exefs.size, old_exefs.size);
    let mut new_plain = output
        [usize::try_from(new_exefs.offset)?..usize::try_from(new_exefs.offset + new_exefs.size)?]
        .to_vec();
    nca_ctr_xcrypt_range(
        &mut new_plain,
        &derive_section_key(&new_info, &keys)?,
        &new_exefs.counter,
        new_exefs.offset,
    )?;
    assert_eq!(new_plain, old_plain, "relocation must preserve ExeFS bytes");
    assert_eq!(fs::read(&source)?, original, "input must stay read-only");
    Ok(())
}
