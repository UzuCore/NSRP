//! Stage51: synced event-phase boundaries and real Windows file sharing locks.
//! These tests create disposable test-only folders and use no retail content.
use super::*;
use crate::ops::program_recovery::{
    PROGRAM_RECOVERY_EVENTS, ProgramRecoveryPhase as Phase, read_program_recovery_events,
};

fn stage(root: &Path, names: &[&str]) -> Result<(tempfile::TempDir, PathBuf)> {
    let temporary = tempfile::Builder::new()
        .prefix("nsrp_program_extract_")
        .tempdir_in(root)?;
    for name in names {
        fs::create_dir(temporary.path().join(name))?;
        fs::write(
            temporary.path().join(name).join("generated.bin"),
            name.as_bytes(),
        )?;
    }
    let path = temporary.path().to_owned();
    Ok((temporary, path))
}

#[test]
fn stage51_success_records_ordered_before_and_after_rename_events() -> Result<()> {
    let root = tempfile::tempdir()?;
    let (_guard, dir) = stage(root.path(), &["romfs", "exefs"])?;
    let old = root.path().join("existing");
    let new = root.path().join("new");
    fs::create_dir(&old)?;
    publish_staged_program_with(
        &dir,
        &[("romfs", &old), ("exefs", &new)],
        &AtomicBool::new(false),
        |source, dest| fs::rename(source, dest),
    )?;
    assert_eq!(fs::read(old.join("generated.bin"))?, b"romfs");
    assert_eq!(fs::read(new.join("generated.bin"))?, b"exefs");
    let events = read_program_recovery_events(&dir)?;
    let phases = events
        .iter()
        .map(|e| (e.phase, e.output_index))
        .collect::<Vec<_>>();
    assert_eq!(
        phases,
        vec![
            (Phase::PublicationStarted, None),
            (Phase::BackupRenameStarted, Some(0)),
            (Phase::BackupRenamed, Some(0)),
            (Phase::PublishRenameStarted, Some(0)),
            (Phase::Published, Some(0)),
            (Phase::PublishRenameStarted, Some(1)),
            (Phase::Published, Some(1)),
            (Phase::BackupCleanupStarted, Some(0)),
            (Phase::BackupRemoved, Some(0)),
            (Phase::PublicationCompleted, None),
        ]
    );
    assert!(
        events
            .iter()
            .enumerate()
            .all(|(i, e)| e.sequence == i as u64)
    );
    assert!(!dir.join("previous_empty_0").exists());
    Ok(())
}

#[test]
fn stage51_second_rename_failure_journals_reverse_compensation() -> Result<()> {
    let root = tempfile::tempdir()?;
    let (_guard, dir) = stage(root.path(), &["romfs", "exefs"])?;
    let old = root.path().join("existing");
    let absent = root.path().join("absent");
    fs::create_dir(&old)?;
    let mut calls = 0;
    let error = publish_staged_program_with(
        &dir,
        &[("romfs", &old), ("exefs", &absent)],
        &AtomicBool::new(false),
        |src, dst| {
            calls += 1;
            if calls == 2 {
                return Err(io::Error::other("Stage51 injected second rename failure"));
            }
            fs::rename(src, dst)
        },
    )
    .unwrap_err();
    assert!(format!("{error:#}").contains("Stage51 injected"));
    assert_eq!(fs::read_dir(&old)?.count(), 0);
    assert!(!absent.exists());
    assert_eq!(fs::read(dir.join("romfs/generated.bin"))?, b"romfs");
    let phases = read_program_recovery_events(&dir)?
        .iter()
        .map(|e| e.phase)
        .collect::<Vec<_>>();
    assert!(phases.contains(&Phase::BackupRenamed));
    assert!(phases.contains(&Phase::Published));
    assert!(phases.contains(&Phase::RollbackPublishStarted));
    assert!(phases.contains(&Phase::RollbackPublished));
    assert!(phases.contains(&Phase::RollbackBackupRestored));
    assert_eq!(phases.last(), Some(&Phase::RollbackFinished));
    Ok(())
}

#[test]
fn stage51_post_rename_failure_retains_ambiguous_event_and_backup() -> Result<()> {
    let root = tempfile::tempdir()?;
    let (guard, dir) = stage(root.path(), &["romfs"])?;
    let target = root.path().join("original_empty");
    fs::create_dir(&target)?;
    let result = publish_isolated_program_with(
        guard,
        &[("romfs", &target)],
        &AtomicBool::new(false),
        |src, dst| {
            fs::rename(src, dst)?;
            fs::write(dst.join("third_party.txt"), b"user data")?;
            Err(io::Error::other("injected after successful rename"))
        },
    );
    assert!(format!("{:#}", result.unwrap_err()).contains("recovery files were retained"));
    assert_eq!(fs::read(target.join("third_party.txt"))?, b"user data");
    assert!(dir.join("previous_empty_0").is_dir());
    let phases = read_program_recovery_events(&dir)?;
    assert_eq!(
        phases.last().map(|e| e.phase),
        // The third-party write blocks restoration of the previous
        // empty directory. This must be a *failed* rollback record.
        Some(Phase::RollbackFailed)
    );
    assert!(
        phases
            .iter()
            .any(|e| e.phase == Phase::PublishRenameStarted)
    );
    assert!(!phases.iter().any(|e| e.phase == Phase::Published));
    Ok(())
}

#[test]
fn stage51_corrupt_event_log_fails_closed_before_destination_rename() -> Result<()> {
    let root = tempfile::tempdir()?;
    let (guard, dir) = stage(root.path(), &["romfs"])?;
    fs::write(dir.join(PROGRAM_RECOVERY_EVENTS), b"{broken event JSON\n")?;
    let dest = root.path().join("destination");
    let error = publish_isolated_program_with(
        guard,
        &[("romfs", &dest)],
        &AtomicBool::new(false),
        |src, dst| fs::rename(src, dst),
    )
    .unwrap_err();
    assert!(format!("{error:#}").contains("recovery files were retained"));
    assert!(!dest.exists());
    assert_eq!(fs::read(dir.join("romfs/generated.bin"))?, b"romfs");
    Ok(())
}

#[test]
fn stage51_recovery_event_corrupt_sequence_rejected_read_only() -> Result<()> {
    let root = tempfile::tempdir()?;
    let (_guard, dir) = stage(root.path(), &["romfs"])?;
    crate::ops::program_recovery::record_program_recovery_phase(
        &dir,
        Phase::PublicationStarted,
        None,
    )?;
    let file = dir.join(PROGRAM_RECOVERY_EVENTS);
    let original = fs::read(&file)?;
    let mut record: serde_json::Value = serde_json::from_slice(&original[..original.len() - 1])?;
    record["sequence"] = serde_json::json!(42);
    let changed = format!("{}\n", serde_json::to_string(&record)?);
    fs::write(&file, changed)?;
    assert!(read_program_recovery_events(&dir).is_err());
    assert!(!dir.join("previous_empty_0").exists());
    Ok(())
}

#[cfg(windows)]
#[test]
fn stage51_windows_real_exclusive_file_handle_blocks_directory_rename() -> Result<()> {
    use std::os::windows::fs::OpenOptionsExt;
    let root = tempfile::tempdir()?;
    let (guard, dir) = stage(root.path(), &["romfs"])?;
    let dest = root.path().join("old_empty");
    fs::create_dir(&dest)?;
    let locked = std::fs::OpenOptions::new()
        .read(true)
        .share_mode(0)
        .open(dir.join("romfs/generated.bin"))?;
    // A real no-share handle should block renaming the containing directory
    // on Windows. The API, not an injected closure, produces this failure.
    let failure = publish_isolated_program_with(
        guard,
        &[("romfs", &dest)],
        &AtomicBool::new(false),
        |src, dst| fs::rename(src, dst),
    );
    drop(locked);
    let error = format!("{:#}", failure.unwrap_err());
    assert!(error.contains("recovery files were retained"), "{error}");
    assert!(dest.is_dir());
    assert_eq!(fs::read_dir(&dest)?.count(), 0);
    assert_eq!(fs::read(dir.join("romfs/generated.bin"))?, b"romfs");
    assert_eq!(
        read_program_recovery_events(&dir)?.last().map(|e| e.phase),
        Some(Phase::RollbackFinished)
    );
    Ok(())
}
