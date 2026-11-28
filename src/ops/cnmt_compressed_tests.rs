//! Stage 38: synthetic encrypted CNMT inside actual PFS0/HFS0 NCZ entries.
//! No user games, Nintendo keys or external tools are used for these tests.

use super::*;
use crate::{
    crypto::{aes_ecb_encrypt_block, nca_ctr_xcrypt_range, nca_xts_transform},
    formats::{
        hfs0,
        nca::{NCA_XTS_HEADER_SIZE, make_ncz_plan_from_reader},
        ncz::{ENC_AES_CTR, ENC_XTS, NCZ_HEADER_SIZE},
        ncz_stream::write_nca_region_to_ncz,
        pfs0::build_from_paths,
    },
};
use sha2::{Digest, Sha256};
use std::{
    collections::HashMap,
    io::{Cursor, Read, Seek},
};

#[test]
#[ignore = "requires user-authorized local package samples and their runtime keys"]
fn stage89_native_metadata_real_package_matrix() -> Result<()> {
    let root =
        PathBuf::from(std::env::var_os("NSRP_STAGE89_SAMPLE_ROOT").context("Missing sample root")?);
    let prod = PathBuf::from(
        std::env::var_os("NSRP_STAGE89_PROD_KEYS").context("Missing runtime key path")?,
    );
    let keys = KeySet::load_with_local_title_keys(&prod)?;
    let cancel = AtomicBool::new(false);
    let mut checked = 0usize;
    let mut large = 0usize;
    let mut failures = Vec::new();
    for item in walkdir::WalkDir::new(&root).follow_links(false) {
        let item = item?;
        let path = item.path();
        if !item.file_type().is_file()
            || !path.extension().and_then(|s| s.to_str()).is_some_and(|s| {
                matches!(
                    s.to_ascii_lowercase().as_str(),
                    "nsp" | "nsz" | "xci" | "xcz"
                )
            })
        {
            continue;
        }
        let before = fs::metadata(path)?;
        let outcome = (|| -> Result<usize> {
            let entries = crate::ops::container::list_entries(path, true)?;
            let mut count = 0usize;
            for entry in entries
                .iter()
                .filter(|entry| is_cnmt_container_entry(&entry.name))
            {
                let info = read_cnmt_from_container_entry(path, entry, &keys, &cancel)?;
                ensure!(!info.contents.is_empty(), "Empty real CNMT content table");
                count += 1;
            }
            ensure!(count > 0, "No readable CNMT");
            Ok(count)
        })();
        let after = fs::metadata(path)?;
        assert_eq!(before.len(), after.len());
        assert_eq!(before.modified()?, after.modified()?);
        match outcome {
            Ok(count) => {
                checked += 1;
                large += usize::from(before.len() > (4u64 << 30));
                println!(
                    "STAGE89_NATIVE_METADATA_PASS bytes={} cnmt_count={count} file={}",
                    before.len(),
                    path.display()
                );
            }
            Err(error) => {
                failures.push(format!("{}: {error:#}", path.display()));
            }
        }
    }
    ensure!(checked > 0, "No authorized samples could be read");
    ensure!(
        failures.is_empty(),
        "Real sample metadata failures: {failures:?}"
    );
    println!("STAGE89_REAL_NATIVE_METADATA_SUMMARY samples={checked} over_4gib={large}");
    Ok(())
}

pub(crate) struct Fixture {
    pub keys: KeySet,
    pub nca: Vec<u8>,
    pub nsp: PathBuf,
    pub nsz: PathBuf,
    pub xcz: PathBuf,
    pub nca_path: PathBuf,
    pub ncz_path: PathBuf,
    pub content_paths: Vec<(String, PathBuf)>,
    pub meta_name: String,
}

pub(crate) fn fixture(root: &Path, block: bool) -> Result<Fixture> {
    let dir = root.join(if block { "block" } else { "stream" });
    fs::create_dir_all(&dir)?;
    let mut prod = HashMap::new();
    prod.insert("header_key".to_owned(), (0..32u8).collect());
    prod.insert("key_area_key_application_00".to_owned(), vec![0x31; 16]);
    let keys = KeySet {
        prod,
        title: HashMap::new(),
    };
    let section_key = [0x42u8; 16];

    let mut cnmt = vec![0u8; 0x20 + 0x38 * 3];
    cnmt[0..8].copy_from_slice(&0x0100_1234_5678_0000u64.to_le_bytes());
    cnmt[8..12].copy_from_slice(&65_536u32.to_le_bytes());
    cnmt[0x0c] = 0x80;
    cnmt[0x10..0x12].copy_from_slice(&3u16.to_le_bytes());
    let mut content_paths = Vec::new();
    for index in 0..3u8 {
        let name = format!("{:032x}.nca", u64::from(index) + 0xD00D);
        // A native XCI's verified card layout requires at least 1 MiB.
        let data = vec![0x43 + index; 512 * 1024 + index as usize * 0x200];
        let off = 0x20 + index as usize * 0x38;
        cnmt[off..off + 0x20].copy_from_slice(&Sha256::digest(&data));
        cnmt[off + 0x20..off + 0x30].copy_from_slice(&hex::decode(name.trim_end_matches(".nca"))?);
        cnmt[off + 0x30..off + 0x36].copy_from_slice(&(data.len() as u64).to_le_bytes()[..6]);
        cnmt[off + 0x36] = 1;
        let file = dir.join(&name);
        fs::write(&file, &data)?;
        content_paths.push((name, file));
    }
    let payload_path = dir.join("metadata.cnmt");
    fs::write(&payload_path, &cnmt)?;
    let pfs_path = dir.join("section.pfs0");
    build_from_paths(&[("metadata.cnmt".to_owned(), payload_path)], &pfs_path)?;
    let pfs = fs::read(&pfs_path)?;
    let section_offset = NCZ_HEADER_SIZE as u64;
    let section_size = (pfs.len() as u64).div_ceil(0x200) * 0x200;
    let mut header = [0u8; NCA_XTS_HEADER_SIZE];
    header[0x200..0x204].copy_from_slice(b"NCA3");
    header[0x205] = 0; // Meta NCA.
    header[0x206] = 1;
    header[0x240..0x244].copy_from_slice(&((section_offset / 0x200) as u32).to_le_bytes());
    header[0x244..0x248]
        .copy_from_slice(&(((section_offset + section_size) / 0x200) as u32).to_le_bytes());
    header[0x320..0x330].copy_from_slice(&aes_ecb_encrypt_block(
        &section_key,
        keys.prod_key("key_area_key_application_00").unwrap(),
    )?);
    header[0x404] = 3; // AES-CTR
    header[0x540..0x548].copy_from_slice(&0x1122_3344_5566_7788u64.to_le_bytes());
    nca_xts_transform(&mut header, keys.prod_key("header_key").unwrap(), true)?;
    let mut section = vec![0u8; section_size as usize];
    section[..pfs.len()].copy_from_slice(&pfs);
    let mut counter = [0u8; 16];
    // NCA stores these bytes in reverse order from the CTR counter.
    counter[..8].copy_from_slice(&0x1122_3344_5566_7788u64.to_be_bytes());
    nca_ctr_xcrypt_range(&mut section, &section_key, &counter, section_offset)?;
    let mut nca = vec![0u8; NCZ_HEADER_SIZE];
    nca[..NCA_XTS_HEADER_SIZE].copy_from_slice(&header);
    nca.extend_from_slice(&section);
    let nca_path = dir.join("base.cnmt.nca");
    fs::write(&nca_path, &nca)?;

    let mut reader = Cursor::new(&nca);
    let plan = make_ncz_plan_from_reader(
        &mut reader,
        0,
        nca.len() as u64,
        &nca[..NCZ_HEADER_SIZE],
        &keys,
    )?;
    ensure!(
        plan.sections
            .iter()
            .any(|section| section.crypto_type == ENC_AES_CTR),
        "Fixture must exercise real NCZ AES-CTR section handling"
    );
    let mut ncz = Cursor::new(Vec::new());
    write_nca_region_to_ncz(
        &mut reader,
        0,
        nca.len() as u64,
        &plan,
        &mut ncz,
        3,
        1,
        block,
        false,
        &AtomicBool::new(false),
        |_, _| {},
    )?;
    let ncz_path = dir.join("base.cnmt.ncz");
    fs::write(&ncz_path, ncz.into_inner())?;

    let meta_name = "base.cnmt.nca".to_owned();
    let plain_files = std::iter::once((meta_name.clone(), nca_path.clone()))
        .chain(content_paths.iter().cloned())
        .collect::<Vec<_>>();
    let zipped_files = std::iter::once(("base.cnmt.ncz".to_owned(), ncz_path.clone()))
        .chain(content_paths.iter().cloned())
        .collect::<Vec<_>>();
    let nsp = dir.join("plain.nsp");
    let nsz = dir.join("compressed.nsz");
    build_from_paths(&plain_files, &nsp)?;
    build_from_paths(&zipped_files, &nsz)?;

    let secure = dir.join("secure.hfs0");
    hfs0::build_from_paths_layout(&zipped_files, &secure, 0x200, 1)?;
    let root_hfs0 = dir.join("root.hfs0");
    hfs0::build_from_paths_layout(&[("secure".to_owned(), secure)], &root_hfs0, 0x200, 1)?;
    let root_bytes = fs::read(root_hfs0)?;
    let mut image = vec![0u8; 0x200];
    image[0x100..0x104].copy_from_slice(b"HEAD");
    image[0x130..0x138].copy_from_slice(&0x200u64.to_le_bytes());
    image[0x138..0x140].copy_from_slice(&(root_bytes.len() as u64).to_le_bytes());
    image.extend_from_slice(&root_bytes);
    let xcz = dir.join("compressed.xcz");
    fs::write(&xcz, image)?;
    Ok(Fixture {
        keys,
        nca,
        nsp,
        nsz,
        xcz,
        nca_path,
        ncz_path,
        content_paths,
        meta_name,
    })
}

fn read_fixture_meta(path: &Path, keys: &KeySet) -> Result<CnmtInfo> {
    let entries = list_entries(path, true)?;
    let entry = entries
        .iter()
        .find(|e| is_cnmt_container_entry(&e.name))
        .context("Synthetic CNMT entry missing")?;
    read_cnmt_from_container_entry(path, entry, keys, &AtomicBool::new(false))
}

#[test]
fn stage38_encrypted_cnmt_stream_and_block_match_plain_nsp_and_xcz() -> Result<()> {
    let temp = tempfile::tempdir()?;
    for block in [false, true] {
        let f = fixture(temp.path(), block)?;
        let plain = read_fixture_meta(&f.nsp, &f.keys)?;
        assert_eq!(plain.title_id, "0100123456780000");
        assert_eq!(plain.version, 65536);
        assert_eq!(plain.meta_type, ContentMetaType::Base);
        assert_eq!(plain.contents.len(), 3);
        let original_hash: [u8; 32] = Sha256::digest(&f.nca).into();
        for path in [&f.nsz, &f.xcz] {
            let parsed = read_fixture_meta(path, &f.keys)?;
            assert_eq!(parsed.cnmt_nca_name, f.meta_name);
            assert_eq!(parsed.title_id, plain.title_id);
            assert_eq!(parsed.version, plain.version);
            assert_eq!(parsed.raw, plain.raw);
            for (actual, expected) in parsed.contents.iter().zip(&plain.contents) {
                assert_eq!(actual.hash, expected.hash);
                assert_eq!(actual.nca_id, expected.nca_id);
                assert_eq!(actual.size, expected.size);
            }
        }
        let bytes = fs::read(&f.ncz_path)?;
        let mut restored = Vec::new();
        decompress_ncz_region_to_nca(
            &mut Cursor::new(&bytes),
            0,
            bytes.len() as u64,
            &mut restored,
            &AtomicBool::new(false),
            |_, _| {},
        )?;
        assert_eq!(Sha256::digest(&restored).as_slice(), original_hash);
        assert_eq!(restored, f.nca);
    }
    Ok(())
}

#[test]
fn stage38_rejects_oversize_bounds_truncation_crypto_and_cancellation() -> Result<()> {
    let temp = tempfile::tempdir()?;
    let f = fixture(temp.path(), false)?;
    let nsz_before = Sha256::digest(fs::read(&f.nsz)?);
    let xcz_before = Sha256::digest(fs::read(&f.xcz)?);
    let output = temp.path().join("previous.xci");
    fs::write(&output, b"protected previous verified output")?;
    let valid_entry = list_entries(&f.nsz, true)?
        .into_iter()
        .find(|e| e.name == "base.cnmt.ncz")
        .context("Missing fixture NCZ")?;
    let outside = ContainerEntry {
        offset: fs::metadata(&f.nsz)?.len().saturating_sub(1),
        size: 32,
        ..valid_entry.clone()
    };
    assert!(
        read_cnmt_from_container_entry(&f.nsz, &outside, &f.keys, &AtomicBool::new(false)).is_err()
    );
    assert!(
        read_cnmt_from_container_entry(&f.nsz, &valid_entry, &f.keys, &AtomicBool::new(true))
            .is_err()
    );

    let valid_ncz = fs::read(&f.ncz_path)?;
    let mut cases = Vec::new();
    let mut oversized = valid_ncz.clone();
    oversized[NCZ_HEADER_SIZE + 24..NCZ_HEADER_SIZE + 32]
        .copy_from_slice(&((MAX_IN_MEMORY_CNMT_NCA + 1) as i64).to_le_bytes());
    cases.push(("over_64_mib", oversized));
    let mut unsupported = valid_ncz.clone();
    unsupported[NCZ_HEADER_SIZE + 32..NCZ_HEADER_SIZE + 40].copy_from_slice(&ENC_XTS.to_le_bytes());
    cases.push(("unsupported_xts", unsupported));
    let mut truncated = valid_ncz;
    truncated.truncate(NCZ_HEADER_SIZE + 16 + 64 + 4);
    cases.push(("truncated_stream", truncated));
    for (name, data) in cases {
        let bad_ncz = temp.path().join(format!("{name}.ncz"));
        fs::write(&bad_ncz, data)?;
        let bad_nsz = temp.path().join(format!("{name}.nsz"));
        build_from_paths(&[("base.cnmt.ncz".to_owned(), bad_ncz)], &bad_nsz)?;
        let entry = list_entries(&bad_nsz, true)?
            .into_iter()
            .next()
            .context("Missing malformed NCZ entry")?;
        let error =
            read_cnmt_from_container_entry(&bad_nsz, &entry, &f.keys, &AtomicBool::new(false))
                .expect_err("Malformed compressed CNMT accepted");
        if name == "over_64_mib" {
            assert!(error.to_string().contains("64 MiB"), "{error:#}");
        }
    }
    let mut absent_keys = f.keys.clone();
    absent_keys.prod.remove("header_key");
    assert!(
        read_cnmt_from_container_entry(&f.nsz, &valid_entry, &absent_keys, &AtomicBool::new(false))
            .is_err()
    );
    assert_eq!(Sha256::digest(fs::read(&f.nsz)?), nsz_before);
    assert_eq!(Sha256::digest(fs::read(&f.xcz)?), xcz_before);
    assert_eq!(fs::read(output)?, b"protected previous verified output");
    Ok(())
}

/// Real-world metadata audit: the known corpus contains only small plain
/// CNMT NCAs, all shorter than the mandatory 16-KiB NCZ header. Reading
/// them through the native package and standalone paths covers actual title,
/// update and DLC CNMTs without pretending a renamed NCA is valid NCZ.
#[test]
#[ignore = "requires two SHA-protected real NSZ copies in isolated Stage42 NSRP_ROOT"]
fn stage42_real_cnmt_inventory_and_short_ncz_rejection() -> Result<()> {
    let root = PathBuf::from(
        std::env::var_os("NSRP_ROOT").context("isolated Stage42 NSRP_ROOT is required")?,
    );
    ensure!(
        root.to_string_lossy().contains("STAGE42_SAFETY"),
        "Real metadata QA must not use a regular game directory as work root"
    );
    let keys = KeySet::load(&root.join("prod.keys"), Some(&root.join("title.keys")))?;
    let samples = root.join("sample");
    let packages = fs::read_dir(&samples)?
        .map(|e| e.map(|e| e.path()))
        .collect::<std::io::Result<Vec<_>>>()?
        .into_iter()
        .filter(|p| p.extension().and_then(|ext| ext.to_str()) == Some("nsz"))
        .collect::<Vec<_>>();
    ensure!(packages.len() == 2, "Two isolated NSZ game copies required");
    let mut count = 0usize;
    let mut first_meta = None::<(String, Vec<u8>)>;
    for package in &packages {
        let mut reader = File::open(package)?;
        let entries = list_entries(package, true)?;
        let mut local_count = 0usize;
        for entry in entries.iter().filter(|e| e.name.ends_with(".cnmt.nca")) {
            ensure!(
                entry.size < NCZ_HEADER_SIZE as u64 && entry.size >= NCA_XTS_HEADER_SIZE as u64,
                "Unexpected actual CNMT geometry: {} ({} bytes)",
                entry.name,
                entry.size
            );
            let direct =
                read_cnmt_from_container_entry(package, entry, &keys, &AtomicBool::new(false))?;
            let mut original = vec![0u8; usize::try_from(entry.size)?];
            reader.seek(std::io::SeekFrom::Start(entry.offset))?;
            reader.read_exact(&mut original)?;
            let standalone = crate::ops::native_meta::read_cnmt_from_nca_bytes(&original, &keys)?;
            ensure!(
                direct.raw == standalone
                    && direct.cnmt_nca_name == entry.name
                    && direct.title_id.len() == 16,
                "Actual encrypted CNMT differs between container and standalone reads"
            );
            if first_meta.is_none() {
                first_meta = Some((entry.name.clone(), original));
            }
            count += 1;
            local_count += 1;
        }
        ensure!(local_count > 0, "No real CNMT in an isolated sample");
    }
    ensure!(
        count >= 14,
        "Expected all 14 actual CNMT entries to be checked"
    );
    eprintln!(
        "STAGE42_REAL_PLAIN_CNMTS_PASS packages={} meta_files={count} all_below_ncz_header={NCZ_HEADER_SIZE}",
        packages.len()
    );

    let (name, bytes) = first_meta.context("No real metadata NCA")?;
    let fake = root.join("invalid.cnmt.ncz");
    fs::write(&fake, bytes)?;
    let renamed = root.join("invalid_tiny_cnmt.nsz");
    build_from_paths(&[(name.replace(".nca", ".ncz"), fake)], &renamed)?;
    let before = Sha256::digest(fs::read(&renamed)?);
    let entry = list_entries(&renamed, true)?
        .into_iter()
        .next()
        .context("Corrupt NCZ package unexpectedly empty")?;
    ensure!(
        read_cnmt_from_container_entry(&renamed, &entry, &keys, &AtomicBool::new(false)).is_err(),
        "Renamed short NCA must never pass as an actual compressed CNMT"
    );
    ensure!(
        Sha256::digest(fs::read(&renamed)?) == before,
        "Rejected compressed metadata must not mutate its container"
    );
    eprintln!("STAGE42_TINY_RETAIL_NCA_AS_NCZ_REJECT_PASS");
    Ok(())
}
