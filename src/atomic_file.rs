//! Same-volume atomic publication for configuration, key databases and
//! already-built packages. No caller removes a completed destination first.

use crate::disk_space::ensure_disk_space;
use anyhow::{Context, Result, ensure};
use sha2::{Digest, Sha256};
use std::{
    fs::{self, File},
    io::{BufReader, BufWriter, Read, Write},
    path::Path,
    sync::{
        Mutex,
        atomic::{AtomicBool, Ordering},
    },
};

static USER_FILE_WRITE_LOCK: Mutex<()> = Mutex::new(());

fn output_parent(path: &Path) -> &Path {
    path.parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."))
}

/// Write a complete new text/database/configuration file before replacing
/// the old one. Independent temporary names also make concurrent saves safe.
pub(crate) fn write_atomic(path: &Path, bytes: &[u8]) -> Result<()> {
    // On Windows two concurrent rename-over-existing attempts can fail with
    // ERROR_ACCESS_DENIED. Serialize small settings/keys saves within the
    // process while retaining independent temporary files and atomic commit.
    let _guard = USER_FILE_WRITE_LOCK
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let parent = output_parent(path);
    fs::create_dir_all(parent)?;
    let mut stage = tempfile::Builder::new()
        .prefix("nsrp_atomic_config_")
        .tempfile_in(parent)?;
    stage.write_all(bytes)?;
    stage.as_file_mut().sync_all()?;
    stage
        .persist(path)
        .map_err(|err| err.error)
        .with_context(|| format!("원자적 파일 저장 실패: {}", path.display()))?;
    Ok(())
}

fn same_file(source: &Path, destination: &Path) -> Result<bool> {
    if source == destination {
        return Ok(true);
    }
    if let (Ok(left), Ok(right)) = (fs::canonicalize(source), fs::canonicalize(destination))
        && left == right
    {
        return Ok(true);
    }
    #[cfg(windows)]
    if let (Ok(src), Ok(dst)) = (File::open(source), File::open(destination)) {
        use std::os::windows::io::AsRawHandle;
        use windows::Win32::{
            Foundation::HANDLE,
            Storage::FileSystem::{BY_HANDLE_FILE_INFORMATION, GetFileInformationByHandle},
        };
        let mut a = BY_HANDLE_FILE_INFORMATION::default();
        let mut b = BY_HANDLE_FILE_INFORMATION::default();
        unsafe {
            GetFileInformationByHandle(HANDLE(src.as_raw_handle()), &mut a)?;
            GetFileInformationByHandle(HANDLE(dst.as_raw_handle()), &mut b)?;
        }
        if a.dwVolumeSerialNumber == b.dwVolumeSerialNumber
            && a.nFileIndexHigh == b.nFileIndexHigh
            && a.nFileIndexLow == b.nFileIndexLow
        {
            return Ok(true);
        }
    }
    Ok(false)
}

/// Move a generated file into place. First try a same-volume rename; on
/// cross-volume/locked-destination failure, copy into a *private sibling*,
/// checksum the complete copy and atomically persist it. Never truncate a
/// previous result, including after cancellation or storage exhaustion.
pub(crate) fn publish_generated_file(
    source: &Path,
    destination: &Path,
    cancel: &AtomicBool,
) -> Result<()> {
    ensure!(!cancel.load(Ordering::Relaxed), "작업이 중단되었습니다");
    ensure!(
        source.is_file(),
        "발행할 원본 파일이 없습니다: {}",
        source.display()
    );
    ensure!(
        !same_file(source, destination)?,
        "출력 파일이 입력 파일과 동일한 실제 파일입니다: {}",
        source.display()
    );
    let parent = output_parent(destination);
    fs::create_dir_all(parent)?;
    if fs::rename(source, destination).is_ok() {
        return Ok(());
    }

    let expected_len = fs::metadata(source)?.len();
    ensure_disk_space(parent, expected_len)?;
    let mut stage = tempfile::Builder::new()
        .prefix("nsrp_atomic_publish_")
        .tempfile_in(parent)?;
    let mut input = BufReader::with_capacity(2 * 1024 * 1024, File::open(source)?);
    let mut digest = Sha256::new();
    let mut written = 0u64;
    let mut buf = vec![0u8; 2 * 1024 * 1024];
    {
        let mut output = BufWriter::with_capacity(2 * 1024 * 1024, stage.as_file_mut());
        loop {
            ensure!(!cancel.load(Ordering::Relaxed), "작업이 중단되었습니다");
            let n = input.read(&mut buf)?;
            if n == 0 {
                break;
            }
            output.write_all(&buf[..n])?;
            digest.update(&buf[..n]);
            written = written
                .checked_add(n as u64)
                .context("출력 파일 크기 오버플로")?;
        }
        output.flush()?;
    }
    ensure!(
        written == expected_len && stage.as_file().metadata()?.len() == expected_len,
        "출력 파일 복사 중 원본 크기가 변경되었습니다"
    );
    stage.as_file_mut().sync_all()?;
    let expected_hash: [u8; 32] = digest.finalize().into();
    let mut verify = Sha256::new();
    let mut check_file = BufReader::with_capacity(2 * 1024 * 1024, stage.reopen()?);
    loop {
        ensure!(!cancel.load(Ordering::Relaxed), "작업이 중단되었습니다");
        let n = check_file.read(&mut buf)?;
        if n == 0 {
            break;
        }
        verify.update(&buf[..n]);
    }
    ensure!(
        verify.finalize().as_slice() == expected_hash,
        "출력 파일 복사 SHA-256 검증 실패"
    );
    ensure!(!cancel.load(Ordering::Relaxed), "작업이 중단되었습니다");
    stage
        .persist(destination)
        .map_err(|err| err.error)
        .with_context(|| format!("출력 파일 확정 실패: {}", destination.display()))?;
    fs::remove_file(source)
        .with_context(|| format!("임시 원본 정리 실패: {}", source.display()))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stage73_atomic_config_saves_never_leave_half_written_json() -> Result<()> {
        let temp = tempfile::tempdir()?;
        let dest = temp.path().join("config.json");
        write_atomic(&dest, br#"{"before":"complete"}"#)?;
        for i in 0..30 {
            write_atomic(&dest, format!("{{\"iteration\":{i}}}").as_bytes())?;
            let value: serde_json::Value = serde_json::from_slice(&fs::read(&dest)?)?;
            assert_eq!(value["iteration"], i);
        }
        Ok(())
    }

    #[test]
    fn stage73_cancel_and_hardlink_alias_cannot_destroy_old_package() -> Result<()> {
        let temp = tempfile::tempdir()?;
        let src = temp.path().join("new.nsp");
        let dst = temp.path().join("existing.nsp");
        fs::write(&src, b"new payload")?;
        fs::write(&dst, b"previous verified package")?;
        assert!(publish_generated_file(&src, &dst, &AtomicBool::new(true)).is_err());
        assert_eq!(fs::read(&dst)?, b"previous verified package");
        assert_eq!(fs::read(&src)?, b"new payload");

        let alias = temp.path().join("same-hardlink.nsp");
        fs::hard_link(&src, &alias)?;
        assert!(publish_generated_file(&src, &alias, &AtomicBool::new(false)).is_err());
        assert_eq!(fs::read(&src)?, b"new payload");
        assert_eq!(fs::read(&alias)?, b"new payload");
        Ok(())
    }

    #[test]
    fn stage73_failed_persist_does_not_delete_destination_directory() -> Result<()> {
        let temp = tempfile::tempdir()?;
        let folder = temp.path().join("settings.json");
        fs::create_dir_all(&folder)?;
        let sentinel = folder.join("keep.txt");
        fs::write(&sentinel, b"never truncate")?;
        assert!(write_atomic(&folder, b"new file").is_err());
        assert_eq!(fs::read(&sentinel)?, b"never truncate");
        Ok(())
    }

    #[cfg(windows)]
    #[test]
    #[ignore = "Requires a fresh explicit destination root on a different Windows volume"]
    fn stage73_cross_volume_publish_replaces_only_after_sha_verified_copy() -> Result<()> {
        let dest_root = std::path::PathBuf::from(
            std::env::var_os("NSRP_STAGE73_PUBLISH_OUTPUT")
                .context("Missing cross-volume QA destination")?,
        );
        ensure!(
            !dest_root.exists(),
            "Existing destination is never a disposable QA root"
        );
        let source_root = tempfile::tempdir()?;
        fs::create_dir_all(&dest_root)?;
        let source = source_root.path().join("generated.nsp");
        let destination = dest_root.join("generated.nsp");
        let payload = vec![0x6Au8; 4 * 1024 * 1024 + 113];
        fs::write(&source, &payload)?;
        fs::write(&destination, b"old verified package")?;
        publish_generated_file(&source, &destination, &AtomicBool::new(false))?;
        assert!(!source.exists());
        assert_eq!(fs::read(&destination)?, payload);
        assert_eq!(
            fs::read_dir(&dest_root)?.count(),
            1,
            "A successful cross-volume commit left orphan partial files"
        );
        println!("STAGE73_CROSS_VOLUME_SHA_VERIFIED_PUBLISH_PASS");
        Ok(())
    }
}
