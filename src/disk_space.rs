//! Shared, bounded free-space preflight for NCA extraction and PFS0 packaging.
//!
//! An existing destination occupies space until the *new* verified file is
//! published. Never credit that occupied space to a replacement operation.
//! This is an early rejection, not a reservation: a concurrent writer may
//! exhaust disk space after the check. Callers must still unwind temporary
//! output and preserve their previous final destination on I/O failure.
use anyhow::{Result, ensure};
use std::path::Path;

pub(crate) fn ensure_disk_space(directory: &Path, requested: u64) -> Result<()> {
    if requested == 0 {
        return Ok(());
    }
    #[cfg(windows)]
    {
        use std::os::windows::ffi::OsStrExt;
        use windows::{Win32::Storage::FileSystem::GetDiskFreeSpaceExW, core::PCWSTR};

        let wide = directory
            .as_os_str()
            .encode_wide()
            .chain(std::iter::once(0))
            .collect::<Vec<_>>();
        let mut caller_available = 0u64;
        unsafe {
            GetDiskFreeSpaceExW(
                PCWSTR(wide.as_ptr()),
                Some(&mut caller_available),
                None,
                None,
            )?;
        }
        // The 32 MiB floor covers filesystem metadata and other in-flight
        // operations, while the 5% term scales for large (>4 GiB) archives.
        let required = requested.saturating_add((requested / 20).max(32 * 1024 * 1024));
        ensure!(
            caller_available >= required,
            "출력 디스크 공간 부족: 필요 {} MiB, 사용 가능 {} MiB",
            required.div_ceil(1024 * 1024),
            caller_available / (1024 * 1024)
        );
    }
    #[cfg(not(windows))]
    let _ = directory;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn no_reservation_for_empty_output() -> Result<()> {
        ensure_disk_space(Path::new("missing-do-not-create"), 0)
    }

    #[test]
    fn disk_space_preflight_accepts_small_and_rejects_impossible() -> Result<()> {
        let temp = tempfile::tempdir()?;
        ensure_disk_space(temp.path(), 1024)?;
        #[cfg(windows)]
        assert!(
            ensure_disk_space(temp.path(), u64::MAX).is_err(),
            "known-output preflight must reject impossible archive size"
        );
        Ok(())
    }

    #[cfg(windows)]
    #[test]
    fn stage43_os_reported_available_space_is_a_strict_preflight_limit() -> Result<()> {
        use std::os::windows::ffi::OsStrExt;
        use windows::{Win32::Storage::FileSystem::GetDiskFreeSpaceExW, core::PCWSTR};

        // Read the caller's quota-aware free space without modifying a
        // volume's quota, consuming its capacity or touching other files.
        let temp = tempfile::tempdir()?;
        let previous = temp.path().join("previous_verified_output.xci");
        let original = b"pre-existing complete XCI before disk preflight";
        std::fs::write(&previous, original)?;
        let mut available = 0u64;
        let wide = temp
            .path()
            .as_os_str()
            .encode_wide()
            .chain(std::iter::once(0))
            .collect::<Vec<_>>();
        unsafe {
            GetDiskFreeSpaceExW(PCWSTR(wide.as_ptr()), Some(&mut available), None, None)?;
        }
        ensure!(available > 32 * 1024 * 1024, "Unexpectedly low free space");
        let err = ensure_disk_space(temp.path(), available)
            .expect_err("Output consuming ALL reported free bytes must fail headroom check");
        ensure!(
            err.to_string().contains("출력 디스크 공간 부족"),
            "Expected quota-aware error, got {err:#}"
        );
        assert_eq!(std::fs::read(&previous)?, original);
        assert_eq!(std::fs::read_dir(temp.path())?.count(), 1);
        // This is a real Windows free-space query, but NOT a physically
        // exhausted disk or a real failing WriteFile.
        Ok(())
    }
}
