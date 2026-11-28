//! Validate untrusted PFS0/HFS0 entry names before joining them to a Windows
//! filesystem path. In particular, NTFS ':' denotes an alternate data stream.

use anyhow::{Result, bail};

pub(super) fn validate_container_filename(name: &str) -> Result<()> {
    if name.is_empty()
        || name == "."
        || name == ".."
        || name.ends_with([' ', '.'])
        || name.encode_utf16().count() > 255
        || name.chars().any(|c| {
            c.is_control() || matches!(c, '/' | '\\' | ':' | '*' | '?' | '"' | '<' | '>' | '|')
        })
    {
        bail!("안전하지 않은 컨테이너 파일명: {name:?}");
    }
    let first_part = name
        .split('.')
        .next()
        .unwrap_or_default()
        .trim_end_matches(' ');
    let device = first_part.to_ascii_uppercase();
    if matches!(
        device.as_str(),
        "CON" | "PRN" | "AUX" | "NUL" | "CONIN$" | "CONOUT$"
    ) || device
        .strip_prefix("COM")
        .or_else(|| device.strip_prefix("LPT"))
        .is_some_and(|suffix| {
            matches!(
                suffix,
                "1" | "2" | "3" | "4" | "5" | "6" | "7" | "8" | "9" | "¹" | "²" | "³"
            )
        })
    {
        bail!("Windows 예약 장치명은 컨테이너 파일명으로 사용할 수 없습니다: {name:?}");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stage73_ntfs_ads_devices_and_path_variations_are_rejected() {
        for name in [
            "game.nca:hidden",
            "title.tik:overwritten",
            "CON",
            "con.nca",
            "nul.txt",
            "LPT1",
            "com9.tmp",
            "COM¹.dat",
            "lpt².txt",
            "NUL .txt",
            "a?b.nca",
            "a*b.nca",
            "a<b>.nca",
            "folder\\file.nca",
            "../file.nca",
            "trailing.",
            "trailing ",
            ".",
            "",
        ] {
            assert!(
                validate_container_filename(name).is_err(),
                "Unsafe name was accepted: {name:?}"
            );
        }
        for name in [
            "secure",
            "normal",
            "update",
            "0100123456789000.cnmt.nca",
            "game.ncz",
            "한국어タイトル.nca",
        ] {
            assert!(
                validate_container_filename(name).is_ok(),
                "Valid name was rejected: {name:?}"
            );
        }
    }
}
