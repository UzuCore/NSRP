//! Stage49: post-publication third-party writes must never be destroyed by
//! automatic cleanup after rollback, including cancellation and I/O faults.
//! All test files are generated under disposable temporary directories.

use super::*;

fn stage(root: &Path, names: &[&str]) -> Result<(tempfile::TempDir, PathBuf)> {
    let temporary = tempfile::Builder::new()
        .prefix("stage49_isolated_")
        .tempdir_in(root)?;
    for name in names {
        let dir = temporary.path().join(name);
        fs::create_dir(&dir)?;
        fs::write(dir.join("generated.bin"), name.as_bytes())?;
    }
    let path = temporary.path().to_owned();
    Ok((temporary, path))
}

#[test]
fn stage49_clean_publication_removes_temporary_stage() -> Result<()> {
    let root = tempfile::tempdir()?;
    let (temporary, staging_path) = stage(root.path(), &["romfs"])?;
    let destination = root.path().join("output");
    publish_isolated_program_with(
        temporary,
        &[("romfs", &destination)],
        &AtomicBool::new(false),
        |src, dst| fs::rename(src, dst),
    )?;
    assert_eq!(fs::read(destination.join("generated.bin"))?, b"romfs");
    assert!(!staging_path.exists());
    Ok(())
}

#[test]
fn stage49_cancel_before_publishing_does_not_keep_private_stage() -> Result<()> {
    let root = tempfile::tempdir()?;
    let (temporary, staging_path) = stage(root.path(), &["romfs"])?;
    let destination = root.path().join("old_empty");
    fs::create_dir(&destination)?;
    let error = publish_isolated_program_with(
        temporary,
        &[("romfs", &destination)],
        &AtomicBool::new(true),
        |src, dst| fs::rename(src, dst),
    )
    .unwrap_err();
    assert!(!format!("{error:#}").contains("recovery files were retained"));
    assert!(!staging_path.exists());
    assert!(destination.is_dir());
    assert_eq!(fs::read_dir(destination)?.count(), 0);
    Ok(())
}

#[test]
fn stage49_invalid_staging_does_not_keep_disposable_files() -> Result<()> {
    let root = tempfile::tempdir()?;
    let (temporary, staging_path) = stage(root.path(), &[])?;
    fs::create_dir(staging_path.join("romfs"))?;
    let destination = root.path().join("target");
    let result = publish_isolated_program_with(
        temporary,
        &[("romfs", &destination)],
        &AtomicBool::new(false),
        |src, dst| fs::rename(src, dst),
    );
    assert!(result.is_err());
    assert!(!staging_path.exists(), "no publication was attempted");
    assert!(!destination.exists());
    Ok(())
}

#[test]
fn stage49_late_cancel_preserves_third_party_file_after_rollback() -> Result<()> {
    let root = tempfile::tempdir()?;
    let (temporary, staging_path) = stage(root.path(), &["romfs", "exefs"])?;
    let romfs = root.path().join("old_empty");
    let exefs = root.path().join("never_written");
    fs::create_dir(&romfs)?;
    let cancel = AtomicBool::new(false);
    let mut calls = 0;
    let error = publish_isolated_program_with(
        temporary,
        &[("romfs", &romfs), ("exefs", &exefs)],
        &cancel,
        |src, dst| {
            calls += 1;
            fs::rename(src, dst)?;
            if calls == 1 {
                fs::write(dst.join("third_party_save.dat"), b"do not discard")?;
                cancel.store(true, Ordering::Relaxed);
            }
            Ok(())
        },
    )
    .unwrap_err();
    let message = format!("{error:#}");
    assert!(
        message.contains("recovery files were retained"),
        "{message}"
    );
    assert_eq!(calls, 1);
    assert!(romfs.is_dir());
    assert_eq!(fs::read_dir(&romfs)?.count(), 0);
    assert!(!exefs.exists());
    assert_eq!(
        fs::read(staging_path.join("romfs/third_party_save.dat"))?,
        b"do not discard"
    );
    assert_eq!(
        fs::read(staging_path.join("romfs/generated.bin"))?,
        b"romfs"
    );
    let guide = fs::read_to_string(staging_path.join("NSRP_RECOVERY_README.txt"))?;
    assert!(guide.contains("third-party files"));
    assert!(guide.contains(&romfs.display().to_string()));
    assert!(guide.contains(&exefs.display().to_string()));
    Ok(())
}

#[test]
fn stage49_second_publish_io_error_keeps_concurrent_user_content() -> Result<()> {
    let root = tempfile::tempdir()?;
    let (temporary, staging_path) = stage(root.path(), &["romfs", "exefs"])?;
    let first = root.path().join("first_absent");
    let second = root.path().join("second_empty");
    fs::create_dir(&second)?;
    let mut calls = 0;
    let error = publish_isolated_program_with(
        temporary,
        &[("romfs", &first), ("exefs", &second)],
        &AtomicBool::new(false),
        |src, dst| {
            calls += 1;
            if calls == 2 {
                return Err(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    "injected locked second destination",
                ));
            }
            fs::rename(src, dst)?;
            fs::write(dst.join("new_user_file.txt"), b"preserve after error")?;
            Ok(())
        },
    )
    .unwrap_err();
    assert!(
        format!("{error:#}").contains("Permission denied")
            || format!("{error:#}").contains("injected locked")
    );
    assert!(!first.exists());
    assert!(second.is_dir());
    assert_eq!(fs::read_dir(&second)?.count(), 0);
    assert_eq!(calls, 2);
    assert_eq!(
        fs::read(staging_path.join("romfs/new_user_file.txt"))?,
        b"preserve after error"
    );
    assert!(staging_path.join("NSRP_RECOVERY_README.txt").is_file());
    Ok(())
}

#[test]
fn stage49_external_edit_to_published_file_survives_late_cancel() -> Result<()> {
    let root = tempfile::tempdir()?;
    let (temporary, staging_path) = stage(root.path(), &["romfs"])?;
    let target = root.path().join("output");
    let cancel = AtomicBool::new(false);
    let error =
        publish_isolated_program_with(temporary, &[("romfs", &target)], &cancel, |src, dst| {
            fs::rename(src, dst)?;
            fs::write(dst.join("generated.bin"), b"third-party changed it")?;
            cancel.store(true, Ordering::Relaxed);
            Ok(())
        })
        .unwrap_err();
    assert!(format!("{error:#}").contains("recovery files were retained"));
    assert!(!target.exists());
    assert_eq!(
        fs::read(staging_path.join("romfs/generated.bin"))?,
        b"third-party changed it"
    );
    Ok(())
}

#[test]
fn stage49_rollback_collision_preserves_backup_and_new_user_files() -> Result<()> {
    let root = tempfile::tempdir()?;
    let (temporary, staging_path) = stage(root.path(), &["romfs"])?;
    let target = root.path().join("old_empty");
    fs::create_dir(&target)?;
    let error = publish_isolated_program_with(
        temporary,
        &[("romfs", &target)],
        &AtomicBool::new(false),
        |_, dst| {
            fs::create_dir(dst)?;
            fs::write(dst.join("external.bin"), b"user-owned")?;
            Err(io::Error::other("injected collision"))
        },
    )
    .unwrap_err();
    assert!(format!("{error:#}").contains("rollback failed"));
    assert!(format!("{error:#}").contains(&staging_path.display().to_string()));
    assert_eq!(fs::read(target.join("external.bin"))?, b"user-owned");
    assert!(staging_path.join("previous_empty_0").is_dir());
    assert!(staging_path.join("NSRP_RECOVERY_README.txt").is_file());
    assert_eq!(
        fs::read(staging_path.join("romfs/generated.bin"))?,
        b"romfs"
    );
    Ok(())
}

#[test]
fn stage49_post_rename_error_keeps_public_and_original_folders() -> Result<()> {
    let root = tempfile::tempdir()?;
    let (temporary, staging_path) = stage(root.path(), &["romfs"])?;
    let target = root.path().join("previous_empty");
    fs::create_dir(&target)?;
    let error = publish_isolated_program_with(
        temporary,
        &[("romfs", &target)],
        &AtomicBool::new(false),
        |src, dst| {
            fs::rename(src, dst)?;
            fs::write(dst.join("post_rename_external.txt"), b"do not delete")?;
            Err(io::Error::other("simulated error after successful rename"))
        },
    )
    .unwrap_err();
    assert!(format!("{error:#}").contains("recovery files were retained"));
    assert_eq!(
        fs::read(target.join("post_rename_external.txt"))?,
        b"do not delete"
    );
    assert!(staging_path.join("previous_empty_0").is_dir());
    assert!(staging_path.join("NSRP_RECOVERY_README.txt").is_file());
    Ok(())
}

#[test]
fn stage49_first_publish_permission_denied_keeps_recovery_hint() -> Result<()> {
    let root = tempfile::tempdir()?;
    let (temporary, staging_path) = stage(root.path(), &["romfs"])?;
    let target = root.path().join("original_empty");
    fs::create_dir(&target)?;
    let result = publish_isolated_program_with(
        temporary,
        &[("romfs", &target)],
        &AtomicBool::new(false),
        |_, _| Err(io::Error::new(io::ErrorKind::PermissionDenied, "locked")),
    );
    let error = format!("{:#}", result.unwrap_err());
    assert!(error.contains("recovery files were retained"));
    assert!(target.is_dir());
    assert_eq!(fs::read_dir(&target)?.count(), 0);
    assert_eq!(
        fs::read(staging_path.join("romfs/generated.bin"))?,
        b"romfs"
    );
    assert!(staging_path.join("NSRP_RECOVERY_README.txt").is_file());
    Ok(())
}
