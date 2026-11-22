//! Stage50 journal durability and safe read-only discovery tests.
//! No test touches an actual game or persistent output folder.

use super::*;

fn stage(parent: &Path) -> Result<(tempfile::TempDir, PathBuf)> {
    let guard = tempfile::Builder::new()
        .prefix(PROGRAM_EXTRACT_STAGING_PREFIX)
        .tempdir_in(parent)?;
    let dir = guard.path().to_owned();
    fs::create_dir(dir.join("romfs"))?;
    fs::write(dir.join("romfs/generated.bin"), b"candidate")?;
    Ok((guard, dir))
}

#[test]
fn stage50_journal_records_existing_and_absent_targets() -> Result<()> {
    let root = tempfile::tempdir()?;
    let (_guard, dir) = stage(root.path())?;
    let existing = root.path().join("previous_romfs");
    let missing = root.path().join("new_exefs");
    fs::create_dir(&existing)?;
    write_program_publish_journal(&dir, &[("romfs", &existing), ("exefs", &missing)])?;
    let records = scan_program_recovery(root.path())?;
    assert_eq!(records.len(), 1);
    assert_eq!(records[0].journal.version, 1);
    assert!(records[0].journal.pid > 0);
    assert_eq!(records[0].journal.outputs.len(), 2);
    assert_eq!(records[0].journal.outputs[0].name, "romfs");
    assert_eq!(records[0].journal.outputs[1].name, "exefs");
    assert!(records[0].journal.outputs[0].existed_before);
    assert!(!records[0].journal.outputs[1].existed_before);
    assert!(records[0].journal.outputs[0].destination.is_absolute());
    assert!(dir.join(PROGRAM_RECOVERY_JOURNAL).is_file());
    Ok(())
}

#[test]
fn stage50_nested_patch_workspace_is_visible_from_workspace_root() -> Result<()> {
    let root = tempfile::tempdir()?;
    let outer = tempfile::Builder::new()
        .prefix("nsrp_patch_")
        .tempdir_in(root.path())?;
    let (_guard, staging) = stage(outer.path())?;
    let dest = outer.path().join("merged_romfs");
    write_program_publish_journal(&staging, &[("romfs", &dest)])?;
    let pending = scan_patch_workspace_recovery(root.path())?;
    assert_eq!(pending.len(), 1);
    assert_eq!(pending[0].staging, staging);
    assert!(
        pending[0].journal.outputs[0]
            .destination
            .ends_with("merged_romfs")
    );
    Ok(())
}

#[test]
fn stage50_abrupt_interruption_preserves_external_file_and_blocks_reuse() -> Result<()> {
    let root = tempfile::tempdir()?;
    let (guard, dir) = stage(root.path())?;
    let old = root.path().join("target_romfs");
    let new = root.path().join("target_exefs");
    fs::create_dir(&old)?;
    write_program_publish_journal(&dir, &[("romfs", &old), ("exefs", &new)])?;
    fs::rename(&old, dir.join("previous_empty_0"))?;
    fs::rename(dir.join("romfs"), &old)?;
    fs::write(old.join("other_process.bin"), b"must survive")?;
    // A terminated process cannot drop its TempDir. Preserve it to simulate
    // the OS leaving private staging and a half-published user directory.
    let surviving = guard.keep();
    let pending = scan_program_recovery(root.path())?;
    assert_eq!(pending.len(), 1);
    assert_eq!(pending[0].staging, surviving);
    let error = ensure_no_pending_program_output(root.path(), &[&old, &new]).unwrap_err();
    assert!(format!("{error:#}").contains("unfinished publication"));
    assert_eq!(fs::read(old.join("other_process.bin"))?, b"must survive");
    assert!(surviving.join("previous_empty_0").is_dir());
    assert!(!surviving.join("exefs").exists());
    // The second output was not staged for this synthetic fixture: inspection
    // must only report state, never attempt a possibly destructive repair.
    assert!(!new.exists());
    Ok(())
}

#[test]
fn stage50_pending_unrelated_target_does_not_block_new_work() -> Result<()> {
    let root = tempfile::tempdir()?;
    let (_guard, dir) = stage(root.path())?;
    let first = root.path().join("first");
    let unrelated = root.path().join("unrelated");
    write_program_publish_journal(&dir, &[("romfs", &first)])?;
    ensure_no_pending_program_output(root.path(), &[&unrelated])?;
    assert!(!first.exists());
    assert!(dir.join("romfs/generated.bin").is_file());
    Ok(())
}

#[test]
fn stage50_unpublished_incomplete_stage_without_marker_does_not_block() -> Result<()> {
    let root = tempfile::tempdir()?;
    let (_guard, dir) = stage(root.path())?;
    assert!(scan_program_recovery(root.path())?.is_empty());
    ensure_no_pending_program_output(root.path(), &[&root.path().join("new")])?;
    assert!(dir.join("romfs/generated.bin").is_file());
    Ok(())
}

#[test]
fn stage50_unreadable_or_corrupt_journal_is_not_trusted() -> Result<()> {
    let root = tempfile::tempdir()?;
    let (_guard, dir) = stage(root.path())?;
    fs::write(dir.join(PROGRAM_RECOVERY_JOURNAL), b"{ malformed")?;
    assert!(
        format!("{:#}", scan_program_recovery(root.path()).unwrap_err())
            .contains("Invalid Program journal")
    );
    assert!(dir.join("romfs/generated.bin").is_file());
    Ok(())
}

#[test]
fn stage50_unknown_version_is_rejected_without_modification() -> Result<()> {
    let root = tempfile::tempdir()?;
    let (_guard, dir) = stage(root.path())?;
    let destination = root.path().join("target");
    write_program_publish_journal(&dir, &[("romfs", &destination)])?;
    let file = dir.join(PROGRAM_RECOVERY_JOURNAL);
    let mut raw: serde_json::Value = serde_json::from_slice(&fs::read(&file)?)?;
    raw["version"] = serde_json::json!(999);
    fs::write(&file, serde_json::to_vec(&raw)?)?;
    assert!(scan_program_recovery(root.path()).is_err());
    assert!(!destination.exists());
    Ok(())
}

#[test]
fn stage50_duplicate_journal_is_rejected_without_overwriting_it() -> Result<()> {
    let root = tempfile::tempdir()?;
    let (_guard, dir) = stage(root.path())?;
    let destination = root.path().join("target");
    write_program_publish_journal(&dir, &[("romfs", &destination)])?;
    let journal = dir.join(PROGRAM_RECOVERY_JOURNAL);
    let original = fs::read(&journal)?;
    assert!(write_program_publish_journal(&dir, &[("romfs", &destination)]).is_err());
    assert_eq!(fs::read(&journal)?, original);
    Ok(())
}

#[test]
fn stage50_legacy_marker_without_journal_requires_manual_review() -> Result<()> {
    let root = tempfile::tempdir()?;
    let (_guard, dir) = stage(root.path())?;
    fs::write(dir.join(".nsrp_program_publish_started"), b"old version")?;
    assert!(
        format!("{:#}", scan_program_recovery(root.path()).unwrap_err())
            .contains("Legacy Program recovery folder")
    );
    Ok(())
}

#[cfg(windows)]
#[test]
fn stage50_junction_staging_cannot_impersonate_recovery_record() -> Result<()> {
    let root = tempfile::tempdir()?;
    let protected = root.path().join("protected");
    fs::create_dir(&protected)?;
    fs::write(protected.join("keep.txt"), b"caller owned")?;
    let junction = root
        .path()
        .join(format!("{PROGRAM_EXTRACT_STAGING_PREFIX}redirect"));
    let status = std::process::Command::new("cmd.exe")
        .args(["/c", "mklink", "/J"])
        .arg(&junction)
        .arg(&protected)
        .status()?;
    ensure!(status.success(), "Unable to prepare test-only junction");
    assert!(scan_program_recovery(root.path()).is_err());
    assert_eq!(fs::read(protected.join("keep.txt"))?, b"caller owned");
    Ok(())
}
