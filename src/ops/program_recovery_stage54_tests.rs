//! Stage54: stale PIDs and journal ownership never authorize silent reuse.
use super::*;

#[test]
fn stage54_stale_pid_cannot_bypass_pending_output_protection() -> Result<()> {
    let sandbox = tempfile::tempdir()?;
    let staging = tempfile::Builder::new()
        .prefix(PROGRAM_EXTRACT_STAGING_PREFIX)
        .tempdir_in(sandbox.path())?;
    let output = sandbox.path().join("romfs");
    write_program_publish_journal(staging.path(), &[("romfs", &output)])?;
    let journal = staging.path().join(PROGRAM_RECOVERY_JOURNAL);
    let mut intent: ProgramPublicationIntent = serde_json::from_slice(&fs::read(&journal)?)?;
    intent.pid = 1; // May be reused; it is not an ownership proof.
    let changed = serde_json::to_vec_pretty(&intent)?;
    fs::write(&journal, &changed)?;

    let error = ensure_no_pending_program_output(sandbox.path(), &[output.as_path()])
        .expect_err("Unknown or reused PID must not bypass a pending journal");
    assert!(format!("{error:#}").contains("blocked"));
    assert!(!output.exists());
    assert_eq!(fs::read(journal)?, changed);
    Ok(())
}
