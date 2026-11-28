//! Stage51: read-only event history validation with bounded, synced appends.
use super::*;

#[test]
fn stage112_complete_json_without_newline_remains_incomplete_after_interruption() -> Result<()> {
    let root = tempfile::tempdir()?;
    let (_guard, path) = private_stage(root.path())?;
    let output = root.path().join("romfs");
    write_program_publish_journal(&path, &[("romfs", &output)])?;
    record_program_recovery_phase(&path, ProgramRecoveryPhase::PublicationStarted, None)?;
    let log = path.join(PROGRAM_RECOVERY_EVENTS);
    let mut bytes = fs::read(&log)?;
    assert_eq!(bytes.pop(), Some(b'\n'));
    fs::write(&log, &bytes)?;
    assert!(read_program_recovery_events(&path).is_err());
    assert!(
        record_program_recovery_phase(&path, ProgramRecoveryPhase::Published, Some(0)).is_err()
    );
    assert_eq!(fs::read(&log)?, bytes);
    assert!(!output.exists());
    Ok(())
}

#[test]
fn stage113_oversized_recovery_records_are_preserved_read_only() -> Result<()> {
    let root = tempfile::tempdir()?;
    let (_guard, path) = private_stage(root.path())?;
    let output = root.path().join("romfs");
    write_program_publish_journal(&path, &[("romfs", &output)])?;
    let log = path.join(PROGRAM_RECOVERY_EVENTS);
    let bytes = vec![b'x'; MAX_EVENT_BYTES as usize + 1];
    fs::write(&log, &bytes)?;
    assert!(read_program_recovery_events(&path).is_err());
    assert!(scan_program_recovery(root.path()).is_err());
    assert_eq!(fs::read(&log)?, bytes);
    assert!(!output.exists());
    Ok(())
}

fn private_stage(root: &Path) -> Result<(tempfile::TempDir, PathBuf)> {
    let guard = tempfile::Builder::new()
        .prefix(PROGRAM_EXTRACT_STAGING_PREFIX)
        .tempdir_in(root)?;
    let path = guard.path().to_owned();
    Ok((guard, path))
}

#[test]
fn stage51_events_persist_in_sequence_and_expose_last_phase_read_only() -> Result<()> {
    let root = tempfile::tempdir()?;
    let (_guard, path) = private_stage(root.path())?;
    let output = root.path().join("romfs");
    write_program_publish_journal(&path, &[("romfs", &output)])?;
    record_program_recovery_phase(&path, ProgramRecoveryPhase::PublicationStarted, None)?;
    record_program_recovery_phase(&path, ProgramRecoveryPhase::PublishRenameStarted, Some(0))?;
    record_program_recovery_phase(&path, ProgramRecoveryPhase::Published, Some(0))?;
    let found = scan_program_recovery(root.path())?;
    assert_eq!(found.len(), 1);
    assert_eq!(found[0].events.len(), 3);
    assert_eq!(found[0].events[2].phase, ProgramRecoveryPhase::Published);
    assert_eq!(found[0].events[2].sequence, 2);
    assert!(
        !output.exists(),
        "reading phase history must not publish output"
    );
    Ok(())
}

#[test]
fn stage51_truncated_event_log_is_refused_without_auto_repair() -> Result<()> {
    let root = tempfile::tempdir()?;
    let (_guard, path) = private_stage(root.path())?;
    let output = root.path().join("out");
    write_program_publish_journal(&path, &[("romfs", &output)])?;
    let event_path = path.join(PROGRAM_RECOVERY_EVENTS);
    fs::write(&event_path, b"{\"sequence\":")?;
    assert!(scan_program_recovery(root.path()).is_err());
    assert_eq!(fs::read(&event_path)?, b"{\"sequence\":");
    assert!(!output.exists());
    Ok(())
}

#[test]
fn stage51_invalid_output_index_cannot_append_or_publish() -> Result<()> {
    let root = tempfile::tempdir()?;
    let (_guard, path) = private_stage(root.path())?;
    assert!(
        record_program_recovery_phase(&path, ProgramRecoveryPhase::Published, Some(2)).is_err()
    );
    assert!(!path.join(PROGRAM_RECOVERY_EVENTS).exists());
    Ok(())
}

#[test]
fn stage51_old_stage50_journal_without_events_is_backward_readable() -> Result<()> {
    let root = tempfile::tempdir()?;
    let (_guard, path) = private_stage(root.path())?;
    let target = root.path().join("old_output");
    write_program_publish_journal(&path, &[("romfs", &target)])?;
    let found = scan_program_recovery(root.path())?;
    assert_eq!(found.len(), 1);
    assert!(found[0].events.is_empty());
    assert!(path.join(PROGRAM_RECOVERY_README).is_file());
    Ok(())
}
