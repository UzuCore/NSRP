//! Stage48: destination aliases, reparse paths and late backup races.
//! Every test uses disposable filesystem data, never game or key originals.

use super::*;

fn staged_tree(root: &Path) -> Result<PathBuf> {
    let stage = root.join("stage");
    fs::create_dir_all(stage.join("romfs"))?;
    fs::write(stage.join("romfs").join("asset.bin"), b"generated content")?;
    Ok(stage)
}

#[test]
fn stage48_rejects_parent_traversal_in_output_paths() -> Result<()> {
    let root = tempfile::tempdir()?;
    fs::create_dir(root.path().join("sub"))?;
    let unsafe_path = root.path().join("sub").join("..").join("output");
    assert!(ensure_empty_extraction_target(&unsafe_path).is_err());
    let stage = staged_tree(root.path())?;
    assert!(
        publish_staged_program_with(
            &stage,
            &[("romfs", &unsafe_path)],
            &AtomicBool::new(false),
            |from, to| fs::rename(from, to)
        )
        .is_err()
    );
    assert!(!root.path().join("output").exists());
    assert!(stage.join("romfs/asset.bin").is_file());
    Ok(())
}

#[cfg(windows)]
#[test]
fn stage48_rejects_case_aliases_before_publishing() -> Result<()> {
    let root = tempfile::tempdir()?;
    let stage = staged_tree(root.path())?;
    fs::create_dir_all(stage.join("exefs"))?;
    fs::write(stage.join("exefs/main"), b"other content")?;
    let first = root.path().join("result");
    let second = root.path().join("RESULT");
    let error = publish_staged_program_with(
        &stage,
        &[("romfs", &first), ("exefs", &second)],
        &AtomicBool::new(false),
        |from, to| fs::rename(from, to),
    )
    .unwrap_err();
    assert!(format!("{error:#}").contains("same directory"));
    assert!(!first.exists() && !second.exists());
    assert_eq!(
        fs::read(stage.join("romfs/asset.bin"))?,
        b"generated content"
    );
    Ok(())
}

#[cfg(windows)]
fn make_junction(link: &Path, real: &Path) -> Result<()> {
    let status = std::process::Command::new("cmd.exe")
        .args(["/c", "mklink", "/J"])
        .arg(link)
        .arg(real)
        .status()?;
    ensure!(status.success(), "test-only junction creation failed");
    Ok(())
}

#[cfg(windows)]
#[test]
fn stage48_rejects_windows_junction_as_output_and_as_parent() -> Result<()> {
    let root = tempfile::tempdir()?;
    let protected = root.path().join("protected");
    fs::create_dir(&protected)?;
    fs::write(protected.join("keep.txt"), b"do not overwrite")?;
    let alias = root.path().join("redirect");
    make_junction(&alias, &protected)?;
    assert!(ensure_empty_extraction_target(&alias).is_err());
    assert!(ensure_empty_extraction_target(&alias.join("romfs")).is_err());
    assert_eq!(fs::read(protected.join("keep.txt"))?, b"do not overwrite");
    assert!(!protected.join("romfs").exists());
    Ok(())
}

#[cfg(windows)]
#[test]
fn stage48_rejects_junction_hidden_inside_staged_tree() -> Result<()> {
    let root = tempfile::tempdir()?;
    let stage = staged_tree(root.path())?;
    let protected = root.path().join("protected");
    fs::create_dir(&protected)?;
    fs::write(protected.join("untouched.txt"), b"original")?;
    make_junction(&stage.join("romfs").join("shortcut"), &protected)?;
    let out = root.path().join("result");
    let result = publish_staged_program_with(
        &stage,
        &[("romfs", &out)],
        &AtomicBool::new(false),
        |from, to| fs::rename(from, to),
    );
    assert!(result.is_err());
    assert!(!out.exists());
    assert_eq!(fs::read(protected.join("untouched.txt"))?, b"original");
    Ok(())
}

#[test]
fn stage48_rejects_empty_staging_before_any_destination_change() -> Result<()> {
    let root = tempfile::tempdir()?;
    let stage = root.path().join("stage");
    fs::create_dir_all(stage.join("romfs"))?;
    let output = root.path().join("existing");
    fs::create_dir(&output)?;
    let result = publish_staged_program_with(
        &stage,
        &[("romfs", &output)],
        &AtomicBool::new(false),
        |from, to| fs::rename(from, to),
    );
    assert!(result.is_err());
    assert!(output.is_dir());
    assert_eq!(fs::read_dir(&output)?.count(), 0);
    Ok(())
}

#[test]
fn stage48_concurrent_file_in_old_folder_is_restored_on_publish_failure() -> Result<()> {
    let root = tempfile::tempdir()?;
    let stage = staged_tree(root.path())?;
    let output = root.path().join("existing");
    fs::create_dir(&output)?;
    let error = publish_staged_program_with(
        &stage,
        &[("romfs", &output)],
        &AtomicBool::new(false),
        |_, _| {
            // Simulate another process adding a file after the old empty
            // folder was renamed into the private backup location.
            fs::write(stage.join("previous_empty_0/new.bin"), b"new user data")?;
            Err(io::Error::other("simulated publish failure"))
        },
    )
    .unwrap_err();
    assert!(format!("{error:#}").contains("simulated publish failure"));
    assert_eq!(fs::read(output.join("new.bin"))?, b"new user data");
    assert!(stage.join("romfs/asset.bin").is_file());
    assert!(!stage.join("previous_empty_0").exists());
    Ok(())
}

#[test]
fn stage48_concurrent_file_in_old_folder_is_restored_after_publish() -> Result<()> {
    let root = tempfile::tempdir()?;
    let stage = staged_tree(root.path())?;
    let output = root.path().join("existing");
    fs::create_dir(&output)?;
    let result = publish_staged_program_with(
        &stage,
        &[("romfs", &output)],
        &AtomicBool::new(false),
        |from, to| {
            fs::rename(from, to)?;
            fs::write(stage.join("previous_empty_0/new.bin"), b"late user data")?;
            Ok(())
        },
    );
    assert!(
        result.is_err(),
        "nonempty old backup must reject publication"
    );
    assert_eq!(fs::read(output.join("new.bin"))?, b"late user data");
    assert_eq!(
        fs::read(stage.join("romfs/asset.bin"))?,
        b"generated content"
    );
    assert!(!stage.join("previous_empty_0").exists());
    Ok(())
}

#[test]
fn stage48_unrecoverable_directory_collision_retains_previous_backup() -> Result<()> {
    let root = tempfile::tempdir()?;
    let stage = staged_tree(root.path())?;
    let output = root.path().join("existing");
    fs::create_dir(&output)?;
    let result = publish_staged_program_with(
        &stage,
        &[("romfs", &output)],
        &AtomicBool::new(false),
        |_, to| {
            // Another process creates a directory at the destination between
            // our move-to-backup and the attempted publication.
            fs::create_dir(to)?;
            fs::write(to.join("other.txt"), b"concurrent user data")?;
            Err(io::Error::other("simulated rename collision"))
        },
    );
    let message = format!("{:#}", result.unwrap_err());
    assert!(message.contains("rollback failed"));
    assert_eq!(fs::read(output.join("other.txt"))?, b"concurrent user data");
    let backup = stage.join("previous_empty_0");
    assert!(backup.is_dir(), "old output must remain recoverable");
    assert_eq!(fs::read_dir(backup)?.count(), 0);
    assert_eq!(
        fs::read(stage.join("romfs/asset.bin"))?,
        b"generated content"
    );
    Ok(())
}

#[test]
fn stage48_cancellation_during_staging_validation_preserves_output() -> Result<()> {
    let root = tempfile::tempdir()?;
    let stage = staged_tree(root.path())?;
    let target = root.path().join("existing");
    fs::create_dir(&target)?;
    let result = publish_staged_program_with(
        &stage,
        &[("romfs", &target)],
        &AtomicBool::new(true),
        |from, to| fs::rename(from, to),
    );
    assert!(result.is_err());
    assert!(target.is_dir());
    assert_eq!(fs::read_dir(&target)?.count(), 0);
    assert_eq!(
        fs::read(stage.join("romfs/asset.bin"))?,
        b"generated content"
    );
    Ok(())
}
