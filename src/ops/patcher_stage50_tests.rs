//! Stage50: an inner recovery folder must also survive its outer workspace.
use super::*;

#[test]
fn stage50_outer_patch_workspace_survives_nested_publication_error() -> Result<()> {
    let root = tempfile::tempdir()?;
    let outer = tempfile::Builder::new()
        .prefix("nsrp_patch_")
        .tempdir_in(root.path())?;
    let saved_outer = outer.path().to_owned();
    let stage = tempfile::Builder::new()
        .prefix("nsrp_program_extract_")
        .tempdir_in(outer.path())?;
    fs::create_dir(stage.path().join("romfs"))?;
    fs::write(stage.path().join("romfs/generated"), b"original generated")?;
    let output = outer.path().join("merged_romfs");
    fs::create_dir(&output)?;
    let failure = publish_isolated_program_with(
        stage,
        &[("romfs", &output)],
        &AtomicBool::new(false),
        |src, dst| {
            fs::rename(src, dst)?;
            fs::write(dst.join("external.txt"), b"external user write")?;
            Err(io::Error::other("injected post-rename I/O error"))
        },
    )
    .unwrap_err();
    let described = preserve_patch_workspace_if_needed(outer, failure);
    assert!(format!("{described:#}").contains(&saved_outer.display().to_string()));
    assert_eq!(
        fs::read(output.join("external.txt"))?,
        b"external user write"
    );
    let pending = scan_program_recovery(&saved_outer)?;
    assert_eq!(pending.len(), 1);
    assert_eq!(pending[0].journal.outputs.len(), 1);
    assert!(pending[0].staging.join(PROGRAM_RECOVERY_JOURNAL).is_file());
    fs::remove_dir_all(&saved_outer)?;
    Ok(())
}

#[test]
fn stage50_clean_patch_workspace_still_auto_deletes_on_unrelated_error() -> Result<()> {
    let root = tempfile::tempdir()?;
    let outer = tempfile::Builder::new()
        .prefix("nsrp_patch_")
        .tempdir_in(root.path())?;
    let previous_path = outer.path().to_owned();
    let error = preserve_patch_workspace_if_needed(outer, anyhow::anyhow!("before publication"));
    assert!(format!("{error:#}").contains("before publication"));
    assert!(
        !previous_path.exists(),
        "no recovery data requires retaining the workspace"
    );
    Ok(())
}

#[test]
fn stage50_extract_program_rejects_previous_orphan_before_loading_bad_nca() -> Result<()> {
    let root = tempfile::tempdir()?;
    let stage = tempfile::Builder::new()
        .prefix("nsrp_program_extract_")
        .tempdir_in(root.path())?;
    let output = root.path().join("romfs");
    fs::create_dir(&output)?;
    crate::ops::program_recovery::write_program_publish_journal(
        stage.path(),
        &[("romfs", &output)],
    )?;
    let bad_nca = root.path().join("invalid.nca");
    fs::write(&bad_nca, b"not an NCA")?;
    let result = extract_program(
        &bad_nca,
        None,
        Some(&output),
        None,
        &root.path().join("missing_hactool.exe"),
        &root.path().join("missing_prod.keys"),
        &KeySet::default(),
        &AtomicBool::new(false),
    );
    assert!(
        format!("{:#}", result.unwrap_err()).contains("unfinished publication"),
        "Unfinished output was not checked before NCA decode"
    );
    assert!(fs::read_dir(&output)?.next().is_none());
    Ok(())
}
