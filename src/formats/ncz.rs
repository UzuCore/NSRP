//! NSZ/NCZ container primitives.
//!
//! This module intentionally keeps the on-disk format independent from the
//! GUI. NCA-specific section discovery lives in `nca.rs`; this file handles
//! the NCZ section/block headers and the reversible zstd stream.

use crate::crypto::nca_ctr_xcrypt_range;
use anyhow::{Context, Result, bail, ensure};
use byteorder::{LittleEndian, ReadBytesExt, WriteBytesExt};
use std::io::{Cursor, Read, Write};

pub const NCZ_HEADER_SIZE: usize = 0x4000;
pub const STREAM_MAGIC: &[u8; 8] = b"NCZSECTN";
pub const BLOCK_MAGIC: &[u8; 8] = b"NCZBLOCK";
pub const ENC_NONE: i64 = 1;
pub const ENC_XTS: i64 = 2;
pub const ENC_AES_CTR: i64 = 3;
pub const ENC_AES_CTR_SKIP_LAYER_HASH: i64 = 5;
// Refuse an implausibly large claimed NCA before running a streaming
// decompressor. Legitimate multi-gigabyte Switch NCAs remain supported.
pub const MAX_NCZ_RECONSTRUCTED_NCA: u64 = 1 << 40;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NczSection {
    pub offset: u64,
    pub size: u64,
    pub crypto_type: i64,
    pub crypto_key: [u8; 16],
    pub crypto_counter: [u8; 16],
}

#[derive(Debug, Clone)]
pub struct NczHeader {
    pub original: Vec<u8>,
    pub sections: Vec<NczSection>,
    pub block: Option<NczBlockHeader>,
    pub compressed_start: usize,
}

#[derive(Debug, Clone)]
pub struct NczBlockHeader {
    pub block_size_exponent: u8,
    pub decompressed_size: u64,
    pub compressed_sizes: Vec<u32>,
}

/// Check the original NCA layout encoded by NCZ crypto spans before any
/// payload is decoded. Gaps are valid; overlap or arithmetic wrap is not.
pub fn validated_ncz_body_size(sections: &[NczSection]) -> Result<u64> {
    ensure!(
        !sections.is_empty() && sections.len() <= 4096,
        "NCZ section count is outside the supported range"
    );
    let mut previous_end = NCZ_HEADER_SIZE as u64;
    for section in sections {
        ensure!(
            section.size > 0 && section.offset >= previous_end,
            "NCZ section spans overlap or are outside the NCA body"
        );
        ensure!(
            matches!(
                section.crypto_type,
                ENC_NONE | ENC_AES_CTR | ENC_AES_CTR_SKIP_LAYER_HASH
            ),
            "NCZ section uses an unsupported encryption type"
        );
        previous_end = section
            .offset
            .checked_add(section.size)
            .context("NCZ section range overflow")?;
        ensure!(
            previous_end <= MAX_NCZ_RECONSTRUCTED_NCA,
            "NCZ section exceeds the supported NCA size limit"
        );
    }
    Ok(previous_end - NCZ_HEADER_SIZE as u64)
}

pub fn write_section_table<W: Write>(mut out: W, sections: &[NczSection]) -> Result<()> {
    validated_ncz_body_size(sections)?;
    out.write_all(STREAM_MAGIC)?;
    out.write_i64::<LittleEndian>(sections.len() as i64)?;
    for s in sections {
        out.write_i64::<LittleEndian>(s.offset as i64)?;
        out.write_i64::<LittleEndian>(s.size as i64)?;
        out.write_i64::<LittleEndian>(s.crypto_type)?;
        out.write_all(&[0u8; 8])?;
        out.write_all(&s.crypto_key)?;
        out.write_all(&s.crypto_counter)?;
    }
    Ok(())
}

pub fn parse_header(data: &[u8]) -> Result<NczHeader> {
    if data.len() < NCZ_HEADER_SIZE + 16 {
        bail!("NCZ가 너무 짧습니다");
    }
    if &data[NCZ_HEADER_SIZE..NCZ_HEADER_SIZE + 8] != STREAM_MAGIC {
        bail!("NCZSECTN magic 불일치");
    }
    let mut cur = Cursor::new(&data[NCZ_HEADER_SIZE + 8..]);
    let count = cur.read_i64::<LittleEndian>()?;
    if count <= 0 || count > 4096 {
        bail!("비정상 NCZ section 수: {count}");
    }
    let mut sections = Vec::with_capacity(count as usize);
    for _ in 0..count {
        let offset = cur.read_i64::<LittleEndian>()?;
        let size = cur.read_i64::<LittleEndian>()?;
        let crypto_type = cur.read_i64::<LittleEndian>()?;
        let _padding = cur.read_i64::<LittleEndian>()?;
        if offset < 0 || size <= 0 {
            bail!("비정상 NCZ section 범위");
        }
        let mut key = [0u8; 16];
        let mut counter = [0u8; 16];
        cur.read_exact(&mut key)?;
        cur.read_exact(&mut counter)?;
        sections.push(NczSection {
            offset: offset as u64,
            size: size as u64,
            crypto_type,
            crypto_key: key,
            crypto_counter: counter,
        });
    }
    validated_ncz_body_size(&sections)?;
    let mut pos = NCZ_HEADER_SIZE + 8 + cur.position() as usize;
    let mut block = None;
    if data.get(pos..pos + 8) == Some(BLOCK_MAGIC.as_slice()) {
        pos += 8;
        if pos + 16 > data.len() {
            bail!("NCZBLOCK 헤더가 잘렸습니다");
        }
        let version = data[pos];
        let _type = data[pos + 1];
        let _unused = data[pos + 2];
        let exponent = data[pos + 3];
        if version != 2 && version != 1 {
            bail!("지원하지 않는 NCZBLOCK 버전: {version}");
        }
        let mut bh = Cursor::new(&data[pos + 4..]);
        let count = bh.read_i32::<LittleEndian>()?;
        let decomp = bh.read_i64::<LittleEndian>()?;
        if count <= 0 || count > 4_000_000 || decomp < 0 {
            bail!("비정상 NCZBLOCK 헤더");
        }
        let sizes_pos = pos + 16;
        let sizes_end = sizes_pos
            .checked_add(count as usize * 4)
            .context("NCZBLOCK 크기 오버플로")?;
        if sizes_end > data.len() {
            bail!("NCZBLOCK size table이 잘렸습니다");
        }
        let mut sizes_cur = Cursor::new(&data[sizes_pos..sizes_end]);
        let mut sizes = Vec::with_capacity(count as usize);
        for _ in 0..count {
            sizes.push(sizes_cur.read_u32::<LittleEndian>()?);
        }
        block = Some(NczBlockHeader {
            block_size_exponent: exponent,
            decompressed_size: decomp as u64,
            compressed_sizes: sizes,
        });
        pos = sizes_end;
    }
    Ok(NczHeader {
        original: data[..NCZ_HEADER_SIZE].to_vec(),
        sections,
        block,
        compressed_start: pos,
    })
}

pub fn build_streaming(
    raw_header: &[u8],
    plain_body: &[u8],
    sections: &[NczSection],
    level: i32,
) -> Result<Vec<u8>> {
    if raw_header.len() != NCZ_HEADER_SIZE {
        bail!("NCZ OriginalBytes는 정확히 0x4000바이트여야 합니다");
    }
    let mut out = Vec::with_capacity(raw_header.len() + plain_body.len() / 2);
    out.extend_from_slice(raw_header);
    write_section_table(&mut out, sections)?;
    let compressed = zstd::stream::encode_all(Cursor::new(plain_body), level)?;
    out.extend_from_slice(&compressed);
    Ok(out)
}

pub fn decompress_to_nca(data: &[u8]) -> Result<Vec<u8>> {
    let header = parse_header(data)?;
    let plain_body = if let Some(block) = &header.block {
        decode_block_body(data, &header, block)?
    } else {
        zstd::stream::decode_all(Cursor::new(&data[header.compressed_start..]))
            .context("NCZ zstd 해제 실패")?
    };
    let expected_body = header
        .sections
        .iter()
        .map(|s| s.offset.saturating_add(s.size))
        .max()
        .unwrap_or(NCZ_HEADER_SIZE as u64)
        .saturating_sub(NCZ_HEADER_SIZE as u64) as usize;
    if plain_body.len() < expected_body {
        bail!("NCZ 본문이 section table보다 짧습니다");
    }
    let mut nca = header.original;
    nca.extend_from_slice(&plain_body);
    for s in &header.sections {
        match s.crypto_type {
            ENC_NONE => {}
            ENC_AES_CTR | ENC_AES_CTR_SKIP_LAYER_HASH => {
                let start = s.offset as usize;
                let end = start
                    .checked_add(s.size as usize)
                    .context("NCZ section 오버플로")?;
                if end > nca.len() {
                    bail!("NCZ section이 NCA 결과 범위를 벗어납니다");
                }
                nca_ctr_xcrypt_range(
                    &mut nca[start..end],
                    &s.crypto_key,
                    &s.crypto_counter,
                    s.offset,
                )?;
            }
            ENC_XTS => bail!("NCZ 내 XTS section 재암호화는 지원하지 않습니다"),
            other => bail!("알 수 없는 NCZ crypto type: {other}"),
        }
    }
    Ok(nca)
}

fn decode_block_body(data: &[u8], header: &NczHeader, block: &NczBlockHeader) -> Result<Vec<u8>> {
    let block_size = 1usize
        .checked_shl(block.block_size_exponent as u32)
        .context("NCZBLOCK 크기 오류")?;
    let mut pos = header.compressed_start;
    let mut out = Vec::with_capacity(block.decompressed_size as usize);
    for (i, &compressed_size) in block.compressed_sizes.iter().enumerate() {
        let csz = compressed_size as usize;
        let end = pos.checked_add(csz).context("NCZBLOCK 오버플로")?;
        if end > data.len() {
            bail!("NCZBLOCK {i} 데이터 범위 초과");
        }
        let expected = if i + 1 == block.compressed_sizes.len() {
            block.decompressed_size as usize - i * block_size
        } else {
            block_size
        };
        let chunk = &data[pos..end];
        if csz == expected {
            out.extend_from_slice(chunk);
        } else {
            let decoded = zstd::stream::decode_all(Cursor::new(chunk))?;
            if decoded.len() != expected {
                bail!("NCZBLOCK {i} 해제 크기 불일치");
            }
            out.extend_from_slice(&decoded);
        }
        pos = end;
    }
    if out.len() != block.decompressed_size as usize {
        bail!("NCZBLOCK 전체 해제 크기 불일치");
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn streaming_ncz_roundtrip_plain() -> Result<()> {
        let raw = vec![0x55u8; NCZ_HEADER_SIZE];
        let body = (0..2_000_000usize)
            .map(|i| (i % 239) as u8)
            .collect::<Vec<_>>();
        let section = NczSection {
            offset: NCZ_HEADER_SIZE as u64,
            size: body.len() as u64,
            crypto_type: ENC_NONE,
            crypto_key: [0; 16],
            crypto_counter: [0; 16],
        };
        let ncz = build_streaming(&raw, &body, &[section], 3)?;
        let nca = decompress_to_nca(&ncz)?;
        assert_eq!(&nca[..NCZ_HEADER_SIZE], raw.as_slice());
        assert_eq!(&nca[NCZ_HEADER_SIZE..], body.as_slice());
        Ok(())
    }
}
