//! Stage53: preserve caller output when unfinished nested recovery exists.
use super::*;
use crate::ops::program_recovery::{PROGRAM_EXTRACT_STAGING_PREFIX, write_program_publish_journal};

#[test]
fn stage53_pending_recovery_does_not_create_new_output_folder() -> Result<()> {
    let sandbox = tempfile::tempdir()?;
    let workspace_root = sandbox.path().join("workspace");
    fs::create_dir(&workspace_root)?;
    let outer = tempfile::Builder::new()
        .prefix("nsrp_patch_")
        .tempdir_in(&workspace_root)?;
    let inner = tempfile::Builder::new()
        .prefix(PROGRAM_EXTRACT_STAGING_PREFIX)
        .tempdir_in(outer.path())?;
    let protected = sandbox.path().join("previous_output");
    fs::create_dir(&protected)?;
    fs::write(protected.join("external.bin"), b"never delete")?;
    write_program_publish_journal(inner.path(), &[("romfs", &protected)])?;
    let before = fs::read(inner.path().join(PROGRAM_RECOVERY_JOURNAL))?;
    let never_create = sandbox.path().join("new_output");
    let error = prepare_patch_output_dir(&never_create, &workspace_root).unwrap_err();
    assert!(format!("{error:#}").contains("manual recovery"));
    assert!(
        !never_create.exists(),
        "blocked patch must not create output"
    );
    assert_eq!(fs::read(protected.join("external.bin"))?, b"never delete");
    assert_eq!(
        fs::read(inner.path().join(PROGRAM_RECOVERY_JOURNAL))?,
        before
    );
    Ok(())
}

#[test]
fn stage53_corrupt_recovery_preflight_fails_closed_without_output_creation() -> Result<()> {
    let sandbox = tempfile::tempdir()?;
    let workspace_root = sandbox.path().join("workspace");
    fs::create_dir(&workspace_root)?;
    let outer = tempfile::Builder::new()
        .prefix("nsrp_patch_")
        .tempdir_in(&workspace_root)?;
    let inner = tempfile::Builder::new()
        .prefix(PROGRAM_EXTRACT_STAGING_PREFIX)
        .tempdir_in(outer.path())?;
    let journal = inner.path().join(PROGRAM_RECOVERY_JOURNAL);
    fs::write(&journal, b"{\"incomplete\":")?;
    let requested = sandbox.path().join("new_output");
    assert!(prepare_patch_output_dir(&requested, &workspace_root).is_err());
    assert!(!requested.exists());
    assert_eq!(fs::read(journal)?, b"{\"incomplete\":");
    Ok(())
}

#[test]
fn stage53_clean_workspace_allows_output_after_readonly_preflight() -> Result<()> {
    let sandbox = tempfile::tempdir()?;
    let workspace_root = sandbox.path().join("workspace");
    fs::create_dir(&workspace_root)?;
    let requested = sandbox.path().join("new_output");
    prepare_patch_output_dir(&requested, &workspace_root)?;
    assert!(requested.is_dir());
    Ok(())
}
