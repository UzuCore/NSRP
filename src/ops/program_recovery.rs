//! Read-only discovery and durable intent records for Program RomFS/ExeFS
//! publication. Never automatically discard or restore caller-owned data.

use anyhow::{Context, Result, bail, ensure};
use serde::{Deserialize, Serialize};
use std::{
    fs::{self, File, OpenOptions},
    io::{self, Read, Write},
    path::{Path, PathBuf},
    time::{SystemTime, UNIX_EPOCH},
};

pub const PROGRAM_RECOVERY_JOURNAL: &str = "NSRP_PROGRAM_RECOVERY.json";
pub const PROGRAM_RECOVERY_README: &str = "NSRP_RECOVERY_README.txt";
pub const PROGRAM_RECOVERY_EVENTS: &str = "NSRP_PROGRAM_RECOVERY_EVENTS.jsonl";
pub const PROGRAM_EXTRACT_STAGING_PREFIX: &str = "nsrp_program_extract_";
const MAX_JOURNAL_BYTES: u64 = 32 * 1024;
const MAX_EVENT_BYTES: u64 = 64 * 1024;
const MAX_EVENT_COUNT: usize = 128;

/// Every durable transition is recorded around a specific filesystem action.
/// A start record means the action *may* have happened after a crash; it is
/// not proof of a successful rename, and no automatic recovery is attempted.
#[derive(Debug, Copy, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProgramRecoveryPhase {
    PublicationStarted,
    BackupRenameStarted,
    BackupRenamed,
    PublishRenameStarted,
    Published,
    BackupCleanupStarted,
    BackupRemoved,
    RollbackPublishStarted,
    RollbackPublished,
    RollbackBackupStarted,
    RollbackBackupRestored,
    RollbackEmptyCreateStarted,
    RollbackEmptyRestored,
    RollbackFailed,
    RollbackFinished,
    PublicationCompleted,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProgramRecoveryEvent {
    pub sequence: u64,
    pub timestamp_unix_seconds: u64,
    pub phase: ProgramRecoveryPhase,
    pub output_index: Option<usize>,
}

/// An in-flight step can have succeeded on disk even if its completion
/// event did not reach the journal before the process terminated.
/// This deliberately cannot be used to authorize automatic cleanup.
pub fn recovery_has_ambiguous_mutation(events: &[ProgramRecoveryEvent]) -> bool {
    matches!(
        events.last().map(|entry| entry.phase),
        Some(
            ProgramRecoveryPhase::BackupRenameStarted
                | ProgramRecoveryPhase::PublishRenameStarted
                | ProgramRecoveryPhase::BackupCleanupStarted
                | ProgramRecoveryPhase::RollbackPublishStarted
                | ProgramRecoveryPhase::RollbackBackupStarted
                | ProgramRecoveryPhase::RollbackEmptyCreateStarted
        )
    )
}

/// Human-facing, read-only safety guidance. Never predicts which physical
/// files belong to the process or suggests unattended rollback/deletion.
pub fn recovery_manual_review_hint_ko(events: &[ProgramRecoveryEvent]) -> &'static str {
    if recovery_has_ambiguous_mutation(events) {
        "파일 이동 시작만 기록되었습니다. 완료 여부를 추측하지 말고 원래 출력 폴더와 복구 폴더를 모두 비교하여 수동 확인하세요. 자동 이동 및 삭제는 금지합니다."
    } else if matches!(
        events.last().map(|entry| entry.phase),
        Some(ProgramRecoveryPhase::RollbackFailed)
    ) {
        "롤백 실패가 기록되었습니다. 다른 프로세스가 만든 파일이 포함될 수 있으므로 원본 및 백업을 모두 보존하고 수동으로 확인하세요."
    } else if matches!(
        events.last().map(|entry| entry.phase),
        Some(ProgramRecoveryPhase::PublicationCompleted)
    ) {
        "게시 완료 이벤트가 존재해도 복구 폴더가 남은 이유가 확인되지 않았습니다. 실제 출력 및 백업을 확인하기 전에는 삭제하지 마세요."
    } else if events.is_empty() {
        "이전 버전 또는 기록이 시작되기 전에 중단된 작업입니다. 원본 출력과 복구 폴더를 비교하고 자동 복원하지 마세요."
    } else {
        "작업 이력이 불완전할 수 있습니다. 원본 출력·임시 파일·이전 폴더 백업을 확인한 뒤 수동으로 복구 여부를 결정하세요."
    }
}

/// Only reads small, bounded journals and never resolves target paths.
/// Missing events are allowed for old Stage50 journals.
pub fn read_program_recovery_events(staging: &Path) -> Result<Vec<ProgramRecoveryEvent>> {
    let path = staging.join(PROGRAM_RECOVERY_EVENTS);
    let meta = match fs::symlink_metadata(&path) {
        Ok(meta) => meta,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(error) => return Err(error.into()),
    };
    ensure!(
        meta.is_file() && !meta.file_type().is_symlink() && meta.len() <= MAX_EVENT_BYTES,
        "Recovery event log size or file type is unsafe: {}",
        path.display()
    );
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt;
        ensure!(
            meta.file_attributes() & 0x400 == 0,
            "Recovery event log is a reparse point: {}",
            path.display()
        );
    }
    // Bound the actual read as well as the metadata snapshot. A file can
    // grow between the size check and the read, especially on a share.
    let mut contents = Vec::new();
    File::open(&path)?
        .take(MAX_EVENT_BYTES + 1)
        .read_to_end(&mut contents)?;
    ensure!(
        contents.len() as u64 <= MAX_EVENT_BYTES,
        "Recovery event log grew beyond its size limit: {}",
        path.display()
    );
    ensure!(
        contents.is_empty() || contents.last() == Some(&b'\n'),
        "Incomplete Program recovery event record: {}",
        path.display()
    );
    let text = std::str::from_utf8(&contents)?;
    let mut events = Vec::new();
    for line in text.lines() {
        ensure!(
            events.len() < MAX_EVENT_COUNT,
            "Recovery event log is too long"
        );
        let event: ProgramRecoveryEvent = serde_json::from_str(line).with_context(|| {
            format!(
                "Corrupted/incomplete Program recovery event: {}",
                path.display()
            )
        })?;
        ensure!(
            event.sequence == events.len() as u64
                && event.output_index.is_none_or(|index| index < 2),
            "Recovery event sequence or output index is invalid: {}",
            path.display()
        );
        events.push(event);
    }
    Ok(events)
}

/// Append and sync a transition before or after each output mutation.
/// This gives an operator a durable progress history, not a guarantee that
/// an interrupted rename can be inferred solely from the last event.
pub fn record_program_recovery_phase(
    staging: &Path,
    phase: ProgramRecoveryPhase,
    output_index: Option<usize>,
) -> Result<()> {
    ensure!(
        output_index.is_none_or(|index| index < 2),
        "Invalid Program recovery output index"
    );
    let previous = read_program_recovery_events(staging)?;
    ensure!(
        previous.len() < MAX_EVENT_COUNT,
        "Program recovery event log is full"
    );
    let event = ProgramRecoveryEvent {
        sequence: previous.len() as u64,
        timestamp_unix_seconds: SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs(),
        phase,
        output_index,
    };
    let path = staging.join(PROGRAM_RECOVERY_EVENTS);
    let mut file = OpenOptions::new()
        .append(true)
        .create(true)
        .open(&path)
        .with_context(|| {
            format!(
                "Unable to append Program recovery event: {}",
                path.display()
            )
        })?;
    let mut record = serde_json::to_vec(&event)?;
    record.push(b'\n');
    ensure!(
        file.metadata()?
            .len()
            .checked_add(record.len() as u64)
            .is_some_and(|len| len <= MAX_EVENT_BYTES),
        "Program recovery event log would exceed its size limit"
    );
    file.write_all(&record)?;
    file.sync_all()?;
    Ok(())
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ProgramOutputIntent {
    pub name: String,
    pub destination: PathBuf,
    pub existed_before: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ProgramPublicationIntent {
    pub version: u32,
    pub created_unix_seconds: u64,
    pub pid: u32,
    pub outputs: Vec<ProgramOutputIntent>,
}

#[derive(Clone, Debug)]
pub struct PendingProgramPublication {
    pub staging: PathBuf,
    pub journal: ProgramPublicationIntent,
    pub events: Vec<ProgramRecoveryEvent>,
}

/// Record every requested output before *any* destination rename.
/// sync_all flushes journal file contents; crash/power loss still needs
/// filesystem-level durability and is not claimed to be fully atomic.
pub fn write_program_publish_journal(staging: &Path, outputs: &[(&str, &Path)]) -> Result<()> {
    ensure!(
        (1..=2).contains(&outputs.len()),
        "Program recovery requires one or two output targets"
    );
    let entries = outputs
        .iter()
        .map(|(name, path)| {
            ensure!(
                matches!(*name, "romfs" | "exefs"),
                "Invalid Program publication output type"
            );
            ensure!(
                path.parent().is_some_and(|p| p.is_dir()),
                "Program output parent is missing"
            );
            let parent = fs::canonicalize(path.parent().unwrap())?;
            let basename = path
                .file_name()
                .context("Program output missing basename")?;
            let destination = parent.join(basename);
            let existed_before = match fs::symlink_metadata(path) {
                Ok(meta) => {
                    ensure!(meta.is_dir(), "Program output is not a directory");
                    true
                }
                Err(error) if error.kind() == io::ErrorKind::NotFound => false,
                Err(error) => return Err(error.into()),
            };
            Ok(ProgramOutputIntent {
                name: name.to_string(),
                destination,
                existed_before,
            })
        })
        .collect::<Result<Vec<_>>>()?;
    let intent = ProgramPublicationIntent {
        version: 1,
        created_unix_seconds: SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs(),
        pid: std::process::id(),
        outputs: entries,
    };
    let encoded = serde_json::to_vec_pretty(&intent)?;
    ensure!(
        (1..=MAX_JOURNAL_BYTES as usize).contains(&encoded.len()),
        "Program recovery journal is too large to inspect safely"
    );
    let journal = staging.join(PROGRAM_RECOVERY_JOURNAL);
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&journal)
        .with_context(|| {
            format!(
                "Unable to create Program recovery journal: {}",
                journal.display()
            )
        })?;
    file.write_all(&encoded)?;
    file.flush()?;
    file.sync_all()?;
    // This guidance must exist *before* any destination is renamed. A process
    // terminated through ExitProcess cannot run the error-handler that would
    // normally generate the more detailed Stage49 recovery README.
    let instructions = format!(
        "NSRP Program extraction recovery record (version 1).\nPublication may have been interrupted.\nDO NOT delete this directory or overwrite any output until inspection.\nThis is a read-only/manual recovery workflow, not an automatic restore.\nOperation PID: {}\nRequested outputs:\n{}\nCheck both the original destinations and staged romfs/exefs/previous_empty_N directories.\nJournal: {}\n",
        intent.pid,
        intent
            .outputs
            .iter()
            .map(|out| format!(
                "  {}: {} (existed_before={})",
                out.name,
                out.destination.display(),
                out.existed_before
            ))
            .collect::<Vec<_>>()
            .join("\n"),
        journal.display()
    );
    let guide_path = staging.join(PROGRAM_RECOVERY_README);
    let mut guide = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&guide_path)
        .with_context(|| {
            format!(
                "Unable to create recovery guidance: {}",
                guide_path.display()
            )
        })?;
    guide.write_all(instructions.as_bytes())?;
    guide.sync_all()?;
    Ok(())
}

/// Never follows a symlink/junction when reading private recovery records.
/// Incomplete or unreadable marker-only folders are treated conservatively
/// as an error instead of being silently discarded.
pub fn scan_program_recovery(parent: &Path) -> Result<Vec<PendingProgramPublication>> {
    let mut found = Vec::new();
    for entry in fs::read_dir(parent)? {
        let entry = entry?;
        if !entry
            .file_name()
            .to_string_lossy()
            .starts_with(PROGRAM_EXTRACT_STAGING_PREFIX)
        {
            continue;
        }
        let path = entry.path();
        let meta = fs::symlink_metadata(&path)?;
        if meta.file_type().is_symlink() {
            bail!(
                "Program staging symlink requires inspection: {}",
                path.display()
            );
        }
        #[cfg(windows)]
        {
            use std::os::windows::fs::MetadataExt;
            ensure!(
                meta.file_attributes() & 0x400 == 0,
                "Program staging reparse point requires inspection: {}",
                path.display()
            );
        }
        if !meta.is_dir() {
            continue;
        }
        let journal_path = path.join(PROGRAM_RECOVERY_JOURNAL);
        let journal_meta = match fs::symlink_metadata(&journal_path) {
            Ok(meta) => meta,
            Err(err) if err.kind() == io::ErrorKind::NotFound => {
                // Previous release used a marker without a destination
                // journal. Without a path map, don't guess what to restore.
                if path.join(".nsrp_program_publish_started").exists() {
                    bail!(
                        "Legacy Program recovery folder lacks target mapping; inspect manually: {}",
                        path.display()
                    );
                }
                continue;
            }
            Err(err) => return Err(err.into()),
        };
        ensure!(
            journal_meta.is_file()
                && journal_meta.len() > 0
                && journal_meta.len() <= MAX_JOURNAL_BYTES,
            "Program recovery journal has an invalid size/type: {}",
            journal_path.display()
        );
        #[cfg(windows)]
        {
            use std::os::windows::fs::MetadataExt;
            ensure!(
                journal_meta.file_attributes() & 0x400 == 0,
                "Program recovery journal is a reparse point: {}",
                journal_path.display()
            );
        }
        ensure!(
            !journal_meta.file_type().is_symlink(),
            "Program recovery journal is a symlink: {}",
            journal_path.display()
        );
        let mut journal_bytes = Vec::new();
        File::open(&journal_path)?
            .take(MAX_JOURNAL_BYTES + 1)
            .read_to_end(&mut journal_bytes)?;
        ensure!(
            !journal_bytes.is_empty() && journal_bytes.len() as u64 <= MAX_JOURNAL_BYTES,
            "Program recovery journal grew beyond its size limit: {}",
            journal_path.display()
        );
        let journal: ProgramPublicationIntent = serde_json::from_slice(&journal_bytes)
            .with_context(|| format!("Invalid Program journal: {}", journal_path.display()))?;
        ensure!(
            journal.version == 1
                && (1..=2).contains(&journal.outputs.len())
                && journal
                    .outputs
                    .iter()
                    .all(|out| matches!(out.name.as_str(), "romfs" | "exefs")),
            "Unsupported Program journal: {}",
            journal_path.display()
        );
        let events = read_program_recovery_events(&path)?;
        found.push(PendingProgramPublication {
            staging: path,
            journal,
            events,
        });
    }
    found.sort_by(|a, b| a.staging.cmp(&b.staging));
    Ok(found)
}

/// Patch package workspaces are themselves temporary, and may contain a
/// nested Program recovery journal. Inspect them before starting another
/// patch, rather than silently deleting an interrupted child's data.
pub fn scan_patch_workspace_recovery(root: &Path) -> Result<Vec<PendingProgramPublication>> {
    if !root.exists() {
        return Ok(Vec::new());
    }
    let mut all = Vec::new();
    for candidate in fs::read_dir(root)? {
        let candidate = candidate?;
        if !candidate
            .file_name()
            .to_string_lossy()
            .starts_with("nsrp_patch_")
        {
            continue;
        }
        let dir = candidate.path();
        let meta = fs::symlink_metadata(&dir)?;
        ensure!(
            meta.is_dir() && !meta.file_type().is_symlink(),
            "Potential patch recovery workspace is not a regular directory: {}",
            dir.display()
        );
        #[cfg(windows)]
        {
            use std::os::windows::fs::MetadataExt;
            ensure!(
                meta.file_attributes() & 0x400 == 0,
                "Potential patch recovery workspace is a reparse point: {}",
                dir.display()
            );
        }
        all.extend(scan_program_recovery(&dir)?);
    }
    all.sort_by(|a, b| a.staging.cmp(&b.staging));
    Ok(all)
}

/// Read-only and conservative: another invocation may currently be writing
/// its target. Never overwrite that output until a human resolves the record.
pub fn ensure_no_pending_program_output(parent: &Path, targets: &[&Path]) -> Result<()> {
    let pending = scan_program_recovery(parent)?;
    #[cfg(windows)]
    fn key(path: &Path) -> String {
        path.to_string_lossy().to_lowercase()
    }
    #[cfg(not(windows))]
    fn key(path: &Path) -> String {
        path.to_string_lossy().into_owned()
    }
    let requested = targets
        .iter()
        .map(|target| -> Result<String> {
            Ok(key(&fs::canonicalize(
                target.parent().context("Program output has no parent")?,
            )?
            .join(
                target
                    .file_name()
                    .context("Program output has no basename")?,
            )))
        })
        .collect::<Result<Vec<_>>>()?;
    for item in pending {
        if item
            .journal
            .outputs
            .iter()
            .any(|output| requested.contains(&key(&output.destination)))
        {
            bail!(
                "Program extraction blocked: unfinished publication record at {}. Review {} and both the output and staging directories. No existing files were modified.",
                item.staging.display(),
                item.staging.join(PROGRAM_RECOVERY_JOURNAL).display()
            );
        }
    }
    Ok(())
}

#[cfg(test)]
#[path = "program_recovery_stage50_tests.rs"]
mod tests;

#[cfg(test)]
#[path = "program_recovery_stage51_tests.rs"]
mod stage51_tests;

#[cfg(test)]
#[path = "program_recovery_stage52_tests.rs"]
mod stage52_tests;

#[cfg(test)]
#[path = "program_recovery_stage54_tests.rs"]
mod stage54_tests;
