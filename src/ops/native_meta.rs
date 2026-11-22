//! Small, independent NCA/PFS0 metadata reader for native CNMT inspection.
//!
//! This is an original Rust implementation using NSRP's existing format and
//! AES primitives; no code is imported from third-party ROM tools.
//! Unsupported section layouts continue through the established tool fallback.

use crate::{
    crypto::nca_ctr_xcrypt_range,
    formats::{
        nca::{NCA_XTS_HEADER_SIZE, NcaSection, decrypt_header, derive_section_key},
        pfs0::Pfs0Index,
    },
    keys::KeySet,
};
use anyhow::{Context, Result, bail};
use std::{
    fs::File,
    io::{Cursor, Read, Seek, SeekFrom},
    path::Path,
};

const MAX_CNMT_SIZE: u64 = 16 * 1024 * 1024;

/// Read only the CNMT payload from an NCA embedded in an NSP, XCI, or an
/// already extracted NCA. The entire NCA is never copied to a temporary file.
pub fn read_cnmt_from_nca_region(
    container: &Path,
    nca_offset: u64,
    nca_size: u64,
    keys: &KeySet,
) -> Result<Vec<u8>> {
    let mut file = File::open(container)?;
    let container_size = file.metadata()?.len();
    read_cnmt_from_nca_reader(&mut file, container_size, nca_offset, nca_size, keys)
}

/// Decode CNMT from an in-memory metadata NCA without a temporary file.
pub(crate) fn read_cnmt_from_nca_bytes(data: &[u8], keys: &KeySet) -> Result<Vec<u8>> {
    let mut reader = Cursor::new(data);
    read_cnmt_from_nca_reader(&mut reader, data.len() as u64, 0, data.len() as u64, keys)
}

fn read_cnmt_from_nca_reader<R: Read + Seek>(
    file: &mut R,
    container_size: u64,
    nca_offset: u64,
    nca_size: u64,
    keys: &KeySet,
) -> Result<Vec<u8>> {
    if nca_size < NCA_XTS_HEADER_SIZE as u64 {
        bail!("CNMT NCA header is truncated");
    }
    if nca_offset
        .checked_add(nca_size)
        .is_none_or(|end| end > container_size)
    {
        bail!("CNMT NCA region is outside the container");
    }
    file.seek(SeekFrom::Start(nca_offset))?;
    let mut header = [0u8; NCA_XTS_HEADER_SIZE];
    file.read_exact(&mut header)?;
    let info = decrypt_header(&header, keys)?;
    for section in &info.sections {
        if section
            .offset
            .checked_add(section.size)
            .is_none_or(|end| end > nca_size)
        {
            bail!("NCA section exceeds its container region");
        }
        let section_key = match section.encryption_type {
            1 => None,
            3 | 5 => Some(derive_section_key(&info, keys)?),
            _ => continue,
        };
        let mut plaintext = SectionReader::new(&mut *file, nca_offset, section, section_key);
        // SHA-256 PartitionFS sections normally begin with a 0x20-byte
        // master hash. Synthetic/simple PartitionFS sections may not.
        for pfs_base in [0u64, 0x20] {
            if pfs_base >= section.size {
                continue;
            }
            let Ok(pfs) =
                Pfs0Index::parse_reader(&mut plaintext, pfs_base, section.size - pfs_base)
            else {
                continue;
            };
            let Some(entry) = pfs
                .entries
                .iter()
                .find(|entry| entry.name.to_ascii_lowercase().ends_with(".cnmt"))
            else {
                continue;
            };
            if !(0x20..=MAX_CNMT_SIZE).contains(&entry.size) {
                bail!("CNMT size is outside the accepted range");
            }
            let data_start = pfs
                .data_start
                .checked_add(entry.offset)
                .context("CNMT payload offset overflow")?;
            plaintext.seek(SeekFrom::Start(data_start))?;
            let mut payload = vec![0u8; entry.size as usize];
            plaintext.read_exact(&mut payload)?;
            return Ok(payload);
        }
    }
    bail!("No supported CNMT PartitionFS section was found")
}

pub(crate) struct SectionReader<'a, R: Read + Seek> {
    file: &'a mut R,
    nca_base: u64,
    section: &'a NcaSection,
    section_key: Option<[u8; 16]>,
    position: u64,
}

impl<'a, R: Read + Seek> SectionReader<'a, R> {
    pub(crate) fn new(
        file: &'a mut R,
        nca_base: u64,
        section: &'a NcaSection,
        section_key: Option<[u8; 16]>,
    ) -> Self {
        Self {
            file,
            nca_base,
            section,
            section_key,
            position: 0,
        }
    }
}

impl<R: Read + Seek> Read for SectionReader<'_, R> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        if self.position >= self.section.size || buf.is_empty() {
            return Ok(0);
        }
        let count = (self.section.size - self.position).min(buf.len() as u64) as usize;
        let nca_position = self.section.offset + self.position;
        let file_position = self
            .nca_base
            .checked_add(nca_position)
            .ok_or_else(|| std::io::Error::other("NCA read offset overflow"))?;
        self.file.seek(SeekFrom::Start(file_position))?;
        let actual = self.file.read(&mut buf[..count])?;
        if let Some(key) = self.section_key {
            nca_ctr_xcrypt_range(
                &mut buf[..actual],
                &key,
                &self.section.counter,
                nca_position,
            )
            .map_err(|e| std::io::Error::other(e.to_string()))?;
        }
        self.position += actual as u64;
        Ok(actual)
    }
}

impl<R: Read + Seek> Seek for SectionReader<'_, R> {
    fn seek(&mut self, pos: SeekFrom) -> std::io::Result<u64> {
        let current = i128::from(self.position);
        let len = i128::from(self.section.size);
        let next = match pos {
            SeekFrom::Start(value) => i128::from(value),
            SeekFrom::End(value) => len + i128::from(value),
            SeekFrom::Current(value) => current + i128::from(value),
        };
        if !(0..=len).contains(&next) {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "seek outside NCA section",
            ));
        }
        self.position = next as u64;
        Ok(self.position)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        crypto::{aes_ecb_encrypt_block, nca_xts_transform},
        formats::pfs0::build_from_paths,
    };
    use std::{collections::HashMap, fs};

    fn verify_native_cnmt_with_pfs_offset(pfs_offset: usize, rights_managed: bool) -> Result<()> {
        let work = tempfile::tempdir()?;
        let cnmt_data = vec![0x19u8; 0x70];
        let payload = work.path().join("test.cnmt");
        fs::write(&payload, &cnmt_data)?;
        let pfs_file = work.path().join("section.bin");
        build_from_paths(&[("test.cnmt".into(), payload)], &pfs_file)?;
        let pfs_bytes = fs::read(&pfs_file)?;

        let mut prod = HashMap::new();
        prod.insert("header_key".into(), (0..32u8).collect());
        prod.insert("key_area_key_application_00".into(), vec![0x31u8; 16]);
        let mut keys = KeySet {
            prod,
            title: HashMap::new(),
        };
        let section_key = [0x42u8; 16];
        let encrypted_slot = aes_ecb_encrypt_block(
            &section_key,
            keys.prod_key("key_area_key_application_00").unwrap(),
        )?;
        let section_offset = 0x4000u64;
        let section_size = (pfs_bytes.len() as u64 + pfs_offset as u64).div_ceil(0x200) * 0x200;
        let mut header = [0u8; NCA_XTS_HEADER_SIZE];
        header[0x200..0x204].copy_from_slice(b"NCA3");
        header[0x205] = 1;
        header[0x206] = 1;
        header[0x240..0x244].copy_from_slice(&((section_offset / 0x200) as u32).to_le_bytes());
        header[0x244..0x248]
            .copy_from_slice(&(((section_offset + section_size) / 0x200) as u32).to_le_bytes());
        header[0x320..0x330].copy_from_slice(&encrypted_slot);
        if rights_managed {
            let rights_id = [0x5au8; 16];
            header[0x230..0x240].copy_from_slice(&rights_id);
            let titlekek = [0x67u8; 16];
            keys.prod.insert("titlekek_00".into(), titlekek.to_vec());
            keys.title.insert(
                hex::encode_upper(rights_id),
                aes_ecb_encrypt_block(&section_key, &titlekek)?.to_vec(),
            );
        }
        header[0x404] = 3;
        header[0x540..0x548].copy_from_slice(&[0x12, 0x34, 0x56, 0x78, 0x90, 0xab, 0xcd, 0xef]);
        nca_xts_transform(&mut header, keys.prod_key("header_key").unwrap(), true)?;

        let mut section = vec![0u8; section_size as usize];
        section[pfs_offset..pfs_offset + pfs_bytes.len()].copy_from_slice(&pfs_bytes);
        let mut counter = [0u8; 16];
        counter[..8].copy_from_slice(&[0xef, 0xcd, 0xab, 0x90, 0x78, 0x56, 0x34, 0x12]);
        nca_ctr_xcrypt_range(&mut section, &section_key, &counter, section_offset)?;

        let output = work.path().join("embedded.bin");
        let mut bytes = vec![0x80; 0x200];
        bytes.extend_from_slice(&header);
        bytes.resize(0x200 + section_offset as usize, 0);
        bytes.extend_from_slice(&section);
        fs::write(&output, bytes)?;
        let got = read_cnmt_from_nca_region(&output, 0x200, section_offset + section_size, &keys)?;
        assert_eq!(got, cnmt_data);
        let on_disk = fs::read(&output)?;
        let from_ram = read_cnmt_from_nca_bytes(&on_disk[0x200..], &keys)?;
        assert_eq!(from_ram, cnmt_data);
        if rights_managed {
            let missing_title_key = KeySet {
                prod: keys.prod,
                title: HashMap::new(),
            };
            assert!(
                read_cnmt_from_nca_region(
                    &output,
                    0x200,
                    section_offset + section_size,
                    &missing_title_key
                )
                .is_err(),
                "Rights-managed metadata without its title key must not decrypt"
            );
        }
        Ok(())
    }

    #[test]
    fn reads_ctr_encrypted_cnmt_without_external_programs_or_temp_extraction() -> Result<()> {
        verify_native_cnmt_with_pfs_offset(0, false)
    }

    #[test]
    fn reads_sha256_partitionfs_cnmt_with_master_hash_prefix() -> Result<()> {
        verify_native_cnmt_with_pfs_offset(0x20, false)
    }

    #[test]
    fn reads_rights_managed_cnmt_with_key_and_rejects_missing_key() -> Result<()> {
        verify_native_cnmt_with_pfs_offset(0x20, true)
    }

    #[test]
    fn rejects_out_of_bounds_nca_region() -> Result<()> {
        let work = tempfile::tempdir()?;
        let path = work.path().join("truncated.nca");
        fs::write(&path, vec![0u8; NCA_XTS_HEADER_SIZE])?;
        assert!(read_cnmt_from_nca_region(&path, 0, u64::MAX, &KeySet::default()).is_err());
        Ok(())
    }
}
