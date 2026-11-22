use aes::Aes128;
use aes::cipher::{BlockCipherDecrypt, BlockCipherEncrypt, KeyInit};
use anyhow::{Context, Result, bail};
use cipher::{KeyIvInit, StreamCipher, StreamCipherSeek};
use ctr::Ctr128BE;
use xts_mode::{Array, Xts128};

type Aes128Ctr = Ctr128BE<Aes128>;

pub fn aes_ecb_decrypt_block(data: &[u8], key: &[u8]) -> Result<[u8; 16]> {
    if data.len() != 16 || key.len() != 16 {
        bail!("AES-ECB 입력/키 길이는 16바이트여야 합니다");
    }
    let cipher = Aes128::new_from_slice(key).context("AES 키 길이 오류")?;
    let mut block = aes::cipher::Block::<Aes128>::default();
    block.copy_from_slice(data);
    cipher.decrypt_block(&mut block);
    Ok(block.into())
}

pub fn aes_ecb_encrypt_block(data: &[u8], key: &[u8]) -> Result<[u8; 16]> {
    if data.len() != 16 || key.len() != 16 {
        bail!("AES-ECB 입력/키 길이는 16바이트여야 합니다");
    }
    let cipher = Aes128::new_from_slice(key).context("AES 키 길이 오류")?;
    let mut block = aes::cipher::Block::<Aes128>::default();
    block.copy_from_slice(data);
    cipher.encrypt_block(&mut block);
    Ok(block.into())
}

pub fn aes_ctr_xcrypt(data: &mut [u8], key: &[u8], iv: &[u8]) -> Result<()> {
    if key.len() != 16 || iv.len() != 16 {
        bail!("AES-CTR 키/IV 길이는 16바이트여야 합니다");
    }
    let mut cipher = Aes128Ctr::new_from_slices(key, iv).context("AES-CTR 초기화 실패")?;
    cipher.apply_keystream(data);
    Ok(())
}

fn nintendo_tweak(sector_index: u128) -> Array<u8, aes::cipher::consts::U16> {
    Array(sector_index.to_be_bytes())
}

pub fn nca_xts_transform(data: &mut [u8], header_key: &[u8], encrypt: bool) -> Result<()> {
    if header_key.len() != 32 {
        bail!("header_key는 32바이트여야 합니다");
    }
    if !data.len().is_multiple_of(0x200) {
        bail!("NCA XTS 데이터는 0x200 정렬이어야 합니다");
    }
    let c1 = Aes128::new_from_slice(&header_key[..16]).context("XTS key1 오류")?;
    let c2 = Aes128::new_from_slice(&header_key[16..]).context("XTS key2 오류")?;
    let xts = Xts128::new(c1, c2);
    if encrypt {
        xts.encrypt_area(data, 0x200, 0, nintendo_tweak);
    } else {
        xts.decrypt_area(data, 0x200, 0, nintendo_tweak);
    }
    Ok(())
}

pub fn nca_ctr_xcrypt_range(
    data: &mut [u8],
    key: &[u8],
    counter: &[u8; 16],
    absolute_offset: u64,
) -> Result<()> {
    if key.len() != 16 {
        bail!("NCA CTR 키 길이 오류");
    }
    let mut iv = *counter;
    let upper_hi4 = iv[7] & 0xf0;
    let block = absolute_offset >> 4;
    let byte_in_block = absolute_offset & 0x0f;
    let off = block.to_be_bytes();
    iv[8..16].copy_from_slice(&off);
    iv[8] = upper_hi4 | (off[0] & 0x0f);
    let mut cipher = Aes128Ctr::new_from_slices(key, &iv).context("NCA AES-CTR 초기화 실패")?;
    if byte_in_block != 0 {
        cipher.seek(byte_in_block);
    }
    cipher.apply_keystream(data);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn xts_roundtrip() -> Result<()> {
        let key: Vec<u8> = (0..32u8).collect();
        let original: Vec<u8> = (0..0xc00).map(|i| (i % 251) as u8).collect();
        let mut data = original.clone();
        nca_xts_transform(&mut data, &key, true)?;
        assert_ne!(data, original);
        nca_xts_transform(&mut data, &key, false)?;
        assert_eq!(data, original);
        Ok(())
    }

    #[test]
    fn ctr_roundtrip() -> Result<()> {
        let key = [3u8; 16];
        let iv = [7u8; 16];
        let original = vec![9u8; 1027];
        let mut data = original.clone();
        aes_ctr_xcrypt(&mut data, &key, &iv)?;
        aes_ctr_xcrypt(&mut data, &key, &iv)?;
        assert_eq!(data, original);
        Ok(())
    }
}
