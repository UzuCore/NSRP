use crate::formats::pfs0::Pfs0Index;
use anyhow::{Context, Result};
use std::{
    collections::{BTreeMap, HashMap},
    fs,
    path::Path,
};

#[derive(Debug, Clone, Default)]
pub struct KeySet {
    pub prod: HashMap<String, Vec<u8>>,
    pub title: HashMap<String, Vec<u8>>,
}

impl KeySet {
    pub fn load(prod_path: &Path, title_path: Option<&Path>) -> Result<Self> {
        let prod = parse_key_file(prod_path, false)?;
        let title = match title_path.filter(|p| p.is_file()) {
            // The tolerant title parser already accepts the historical
            // 17-byte+zero variant. Merely opening keys must be read-only.
            Some(path) => parse_key_file(path, true)?,
            None => HashMap::new(),
        };
        Ok(Self { prod, title })
    }

    /// Use the optional title-key DB alongside prod.keys without copying
    /// or rewriting either file. Native readers can avoid external hactool
    /// for title-rights-managed NCA metadata when these keys are available.
    pub fn load_with_local_title_keys(prod_path: &Path) -> Result<Self> {
        let nearby = prod_path
            .parent()
            .map(|directory| directory.join("title.keys"));
        Self::load(prod_path, nearby.as_deref())
    }

    pub fn prod_key(&self, name: &str) -> Option<&[u8]> {
        self.prod.get(&name.to_ascii_lowercase()).map(Vec::as_slice)
    }

    pub fn title_key(&self, rights_id: &[u8; 16]) -> Option<&[u8]> {
        let full = hex::encode_upper(rights_id);
        let tid = &full[..16];
        let trimmed = full.trim_end_matches('0');
        let trimmed16 = &trimmed[..trimmed.len().min(16)];
        [full.as_str(), tid, trimmed16]
            .into_iter()
            .find_map(|k| self.title.get(k).map(Vec::as_slice))
    }

    pub fn add_ticket_keys_from_nsp(&mut self, path: &Path) -> Result<usize> {
        let index = Pfs0Index::parse(path)?;
        let mut count = 0usize;
        for entry in &index.entries {
            if !entry.name.to_ascii_lowercase().ends_with(".tik") || entry.size > 1024 * 1024 {
                continue;
            }
            count += 1;
            let data = index.read_entry(path, entry)?;
            self.add_ticket_data(&entry.name, &data);
        }
        Ok(count)
    }

    pub fn add_ticket_data(&mut self, name: &str, data: &[u8]) -> bool {
        let stem = name.rsplit_once('.').map(|p| p.0).unwrap_or(name);
        if stem.len() != 32 || !stem.bytes().all(|b| b.is_ascii_hexdigit()) || data.len() < 0x190 {
            return false;
        }
        let key = data[0x180..0x190].to_vec();
        if key.iter().all(|&b| b == 0) {
            return false;
        }
        let full = stem.to_ascii_uppercase();
        let tid = full[..16].to_owned();
        self.title.entry(full).or_insert_with(|| key.clone());
        self.title.entry(tid.clone()).or_insert_with(|| key.clone());
        self.title
            .entry(format!("{tid}0000000000000000"))
            .or_insert(key);
        true
    }
}

pub fn parse_key_file(path: &Path, uppercase_names: bool) -> Result<HashMap<String, Vec<u8>>> {
    let text = fs::read_to_string(path)
        .with_context(|| format!("키 파일 읽기 실패: {}", path.display()))?;
    let mut out = HashMap::new();
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let Some((name, value)) = line.split_once('=') else {
            continue;
        };
        let name = name.trim();
        let value = value.trim();
        let bytes = if uppercase_names {
            if !matches!(name.len(), 16 | 32) || !name.bytes().all(|byte| byte.is_ascii_hexdigit())
            {
                continue;
            }
            let Some(bytes) = decode_title_key_value(value) else {
                continue;
            };
            bytes
        } else {
            if value.len() % 2 != 0 {
                continue;
            }
            let Ok(bytes) = hex::decode(value) else {
                continue;
            };
            bytes
        };
        let key = if uppercase_names {
            name.to_ascii_uppercase()
        } else {
            name.to_ascii_lowercase()
        };
        out.insert(key, bytes);
    }
    Ok(out)
}

fn decode_title_key_value(value: &str) -> Option<Vec<u8>> {
    if !value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return None;
    }
    match value.len() {
        32 => hex::decode(value).ok(),
        // 구 Python판에서 ticket 필드를 한 바이트 길게 읽어 17-byte title key를
        // title.keys에 남긴 사례를 호환한다. 끝의 padding 00일 때만 안전하게 복구한다.
        34 if value.ends_with("00") => hex::decode(&value[..32]).ok(),
        _ => None,
    }
}

/// 외부 hactool/hactoolnet에 넘기기 전에 legacy `title.keys`를 정리한다.
/// 17-byte + trailing 00 오염은 16-byte로 복구하고, 그 외 잘못된 assignment는 제거한다.
pub fn sanitize_title_keys_file(path: &Path) -> Result<usize> {
    if !path.is_file() {
        return Ok(0);
    }
    let original = fs::read_to_string(path)
        .with_context(|| format!("title.keys 읽기 실패: {}", path.display()))?;
    let mut changed = 0usize;
    let mut output = String::new();
    for raw in original.lines() {
        let line = raw.trim();
        if line.is_empty() || line.starts_with('#') {
            output.push_str(raw);
            output.push('\n');
            continue;
        }
        let Some((name, value)) = line.split_once('=') else {
            changed += 1;
            continue;
        };
        let name = name.trim();
        let value = value.trim();
        if !matches!(name.len(), 16 | 32) || !name.bytes().all(|byte| byte.is_ascii_hexdigit()) {
            changed += 1;
            continue;
        }
        let Some(bytes) = decode_title_key_value(value) else {
            changed += 1;
            continue;
        };
        let canonical = hex::encode_upper(bytes);
        if value.len() != 32 || !value.eq_ignore_ascii_case(&canonical) {
            changed += 1;
        }
        output.push_str(&format!("{} = {}\n", name.to_ascii_uppercase(), canonical));
    }
    if changed > 0 {
        fs::write(path, output)
            .with_context(|| format!("title.keys 정리 실패: {}", path.display()))?;
    }
    Ok(changed)
}

/// NSP 내부 ticket의 title key를 영구 `title.keys` DB에 병합한다.
/// Python판 압축 경로처럼 full rights-id, 16자리 title-id alias,
/// title-id + 16 zero alias를 함께 기록한다.
pub fn merge_ticket_keys_from_nsp_file(nsp: &Path, title_keys_path: &Path) -> Result<usize> {
    let _ = sanitize_title_keys_file(title_keys_path)?;
    let index = Pfs0Index::parse(nsp)?;
    let mut existing = if title_keys_path.is_file() {
        parse_key_file(title_keys_path, true).unwrap_or_default()
    } else {
        HashMap::new()
    };
    let mut new_ticket_count = 0usize;
    for entry in &index.entries {
        if !entry.name.to_ascii_lowercase().ends_with(".tik") || entry.size > 1024 * 1024 {
            continue;
        }
        let stem = entry
            .name
            .rsplit_once('.')
            .map(|pair| pair.0)
            .unwrap_or(&entry.name);
        if stem.len() != 32 || !stem.bytes().all(|byte| byte.is_ascii_hexdigit()) {
            continue;
        }
        let data = index.read_entry(nsp, entry)?;
        if data.len() < 0x190 {
            continue;
        }
        let title_key = data[0x180..0x190].to_vec();
        if title_key.iter().all(|&byte| byte == 0) {
            continue;
        }
        let full = stem.to_ascii_uppercase();
        let tid = full[..16].to_owned();
        if !existing.contains_key(&full) {
            new_ticket_count += 1;
        }
        existing.entry(full).or_insert_with(|| title_key.clone());
        existing
            .entry(tid.clone())
            .or_insert_with(|| title_key.clone());
        existing
            .entry(format!("{tid}0000000000000000"))
            .or_insert(title_key);
    }
    if new_ticket_count == 0 {
        return Ok(0);
    }
    if let Some(parent) = title_keys_path.parent() {
        fs::create_dir_all(parent)?;
    }
    let sorted = existing.into_iter().collect::<BTreeMap<_, _>>();
    let mut text = String::new();
    for (key_id, key) in sorted {
        if matches!(key_id.len(), 16 | 32) && key.len() == 16 {
            text.push_str(&format!("{key_id} = {}\n", hex::encode_upper(key)));
        }
    }
    fs::write(title_keys_path, text)
        .with_context(|| format!("title.keys 저장 실패: {}", title_keys_path.display()))?;
    Ok(new_ticket_count)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::formats::pfs0::build_from_paths;

    #[test]
    fn persists_ticket_key_aliases() -> Result<()> {
        let temp = tempfile::tempdir()?;
        let rights_id = "01001234567890000000000000000001";
        let ticket = temp.path().join("ticket.bin");
        let mut ticket_data = vec![0u8; 0x200];
        ticket_data[0x180..0x190].copy_from_slice(&[0xA5; 16]);
        fs::write(&ticket, ticket_data)?;
        let nsp = temp.path().join("sample.nsp");
        build_from_paths(&[(format!("{rights_id}.tik"), ticket)], &nsp)?;
        let database = temp.path().join("title.keys");
        assert_eq!(merge_ticket_keys_from_nsp_file(&nsp, &database)?, 1);
        let parsed = parse_key_file(&database, true)?;
        assert_eq!(
            parsed.get(rights_id).map(Vec::as_slice),
            Some(&[0xA5; 16][..])
        );
        assert_eq!(
            parsed.get("0100123456789000").map(Vec::as_slice),
            Some(&[0xA5; 16][..])
        );
        assert_eq!(merge_ticket_keys_from_nsp_file(&nsp, &database)?, 0);
        Ok(())
    }

    #[test]
    fn repairs_legacy_17_byte_title_key() -> Result<()> {
        let temp = tempfile::tempdir()?;
        let path = temp.path().join("title.keys");
        fs::write(
            &path,
            "010070100F782000 = 77605ad2ee6ef83c3f72e2599dac5e5600\n",
        )?;
        let parsed = parse_key_file(&path, true)?;
        assert_eq!(
            parsed.get("010070100F782000").map(Vec::as_slice),
            Some(&hex::decode("77605ad2ee6ef83c3f72e2599dac5e56")?[..])
        );
        assert_eq!(sanitize_title_keys_file(&path)?, 1);
        let text = fs::read_to_string(&path)?;
        assert!(text.contains("77605AD2EE6EF83C3F72E2599DAC5E56"));
        assert!(!text.contains("5E5600"));
        Ok(())
    }

    #[test]
    fn keyset_load_preserves_legacy_title_database() -> Result<()> {
        let temp = tempfile::tempdir()?;
        let prod = temp.path().join("prod.keys");
        fs::write(&prod, "")?;
        let title = temp.path().join("title.keys");
        fs::write(
            &title,
            "010070100F782000 = 77605ad2ee6ef83c3f72e2599dac5e5600\ninvalid = xyz\n",
        )?;
        let original = fs::read(&title)?;
        let keys = KeySet::load_with_local_title_keys(&prod)?;
        assert_eq!(
            keys.title.get("010070100F782000").map(Vec::as_slice),
            Some(&hex::decode("77605ad2ee6ef83c3f72e2599dac5e56")?[..])
        );
        assert_eq!(fs::read(&title)?, original, "key loading must not rewrite");
        let other = KeySet::load(&prod, Some(&title))?;
        assert_eq!(other.title, keys.title);
        fs::remove_file(&title)?;
        assert!(KeySet::load_with_local_title_keys(&prod)?.title.is_empty());
        Ok(())
    }
}
