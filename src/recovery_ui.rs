//! Stage53 GUI presentation of read-only Program publication journals.
//! No repair, deletion, rename, or reading game/key data occurs here.

use anyhow::{Result, ensure};
use nsrp::ops::program_recovery::{
    PROGRAM_RECOVERY_JOURNAL, recovery_has_ambiguous_mutation, recovery_manual_review_hint_ko,
    scan_patch_workspace_recovery, scan_program_recovery,
};
use slint::{ComponentHandle, ModelRc, SharedString, VecModel};
use std::{
    fs, io,
    path::{Path, PathBuf},
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
    thread,
};

const MAX_VISIBLE_RECORDS: usize = 64;

/// `canonicalize` can return Win32 extended-length paths on hosted Windows
/// runners (\\\\?\\C:\\...), while the user originally selected the ordinary
/// drive/UNC spelling. Preserve the canonical path for I/O and the journal,
/// but show an ordinary, complete path in the read-only recovery inspector.
fn display_recovery_path(path: &Path) -> String {
    let raw = path.display().to_string();
    #[cfg(windows)]
    {
        if let Some(rest) = raw.strip_prefix(r"\\?\UNC\") {
            return format!(r"\\{rest}");
        }
        if let Some(rest) = raw.strip_prefix(r"\\?\") {
            let bytes = rest.as_bytes();
            if bytes.len() >= 3
                && bytes[0].is_ascii_alphabetic()
                && bytes[1] == b':'
                && bytes[2] == b'\\'
            {
                return rest.to_owned();
            }
        }
    }
    raw
}

pub(crate) struct RecoveryInspection {
    pub(crate) count: usize,
    pub(crate) lines: Vec<String>,
}

fn observed_kind(path: &Path) -> &'static str {
    match fs::symlink_metadata(path) {
        Ok(meta) if meta.file_type().is_symlink() => "링크: 수동 검토",
        #[cfg(windows)]
        Ok(meta)
            if {
                use std::os::windows::fs::MetadataExt;
                meta.file_attributes() & 0x400 != 0
            } =>
        {
            "재분석 지점: 수동 검토"
        }
        Ok(meta) if meta.is_dir() => "폴더 존재",
        Ok(meta) if meta.is_file() => "파일 존재: 수동 검토",
        Ok(_) => "기타 항목: 수동 검토",
        Err(error) if error.kind() == io::ErrorKind::NotFound => "없음",
        Err(_) => "접근 불가: 수동 검토",
    }
}

pub(crate) fn inspect_recovery_root(root: &Path) -> Result<RecoveryInspection> {
    // An unavailable default workspace must not be created just to show the
    // inspector. User-selected locations are only inspected, never changed.
    let info = match fs::symlink_metadata(root) {
        Ok(meta) => meta,
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            return Ok(RecoveryInspection {
                count: 0,
                lines: vec!["선택한 경로가 없습니다. 검사 중 폴더를 생성하지 않았습니다.".into()],
            });
        }
        Err(error) => return Err(error.into()),
    };
    ensure!(
        info.is_dir() && !info.file_type().is_symlink(),
        "복구 검사 경로가 일반 폴더가 아닙니다. 수동 확인이 필요합니다."
    );
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt;
        ensure!(
            info.file_attributes() & 0x400 == 0,
            "복구 검사 경로가 재분석 지점입니다. 수동 확인이 필요합니다."
        );
    }

    let mut pending = scan_program_recovery(root)?;
    pending.extend(scan_patch_workspace_recovery(root)?);
    pending.sort_by(|a, b| a.staging.cmp(&b.staging));
    pending.dedup_by(|a, b| a.staging == b.staging);
    let count = pending.len();
    if count == 0 {
        return Ok(RecoveryInspection {
            count,
            lines: vec![
                "이 위치에서 복구 기록을 찾지 못했습니다.".into(),
                "이 결과는 다른 폴더의 복구 기록이 없다는 뜻은 아닙니다.".into(),
            ],
        });
    }

    let mut lines = Vec::new();
    for (index, item) in pending.iter().take(MAX_VISIBLE_RECORDS).enumerate() {
        let stage = item
            .events
            .last()
            .map_or("이벤트 없음".to_owned(), |e| format!("{:?}", e.phase));
        let uncertain = recovery_has_ambiguous_mutation(&item.events);
        lines.push(format!(
            "▶ 복구 기록 {} / {}  |  이벤트 {}개  |  마지막 단계: {}  |  이동 완료 불확실: {}",
            index + 1,
            count,
            item.events.len(),
            stage,
            if uncertain {
                "예"
            } else {
                "기록상 아니오"
            }
        ));
        lines.push(format!(
            "복구 폴더: {}",
            display_recovery_path(&item.staging)
        ));
        lines.push(format!(
            "최초 기록: {}  |  당시 PID: {}  |  자동 복원: 안 함",
            item.journal.created_unix_seconds, item.journal.pid
        ));
        for (output_index, output) in item.journal.outputs.iter().enumerate() {
            lines.push(format!(
                "출력 {} ({})  |  기존 존재: {}  |  현재 상태: {}",
                output_index + 1,
                output.name,
                if output.existed_before {
                    "예"
                } else {
                    "아니오"
                },
                observed_kind(&output.destination)
            ));
            lines.push(format!(
                "출력 경로: {}",
                display_recovery_path(&output.destination)
            ));
            lines.push(format!(
                "임시 출력: {}  |  백업: {}",
                observed_kind(&item.staging.join(&output.name)),
                observed_kind(&item.staging.join(format!("previous_empty_{output_index}")))
            ));
        }
        lines.push(format!(
            "저널: {}",
            display_recovery_path(&item.staging.join(PROGRAM_RECOVERY_JOURNAL))
        ));
        lines.push(format!(
            "⚠ {}",
            recovery_manual_review_hint_ko(&item.events)
        ));
        lines.push("────────────────────────────────────────────────".to_owned());
    }
    if count > MAX_VISIBLE_RECORDS {
        lines.push(format!(
            "표시 한도 {}개 초과. 나머지 {}개는 삭제·복원하지 말고 별도 확인하세요.",
            MAX_VISIBLE_RECORDS,
            count - MAX_VISIBLE_RECORDS
        ));
    }
    Ok(RecoveryInspection { count, lines })
}

/// Keep directory enumeration off the Slint event loop; a newer request
/// invalidates stale results, and closing the panel does not mutate files.
fn begin_readonly_scan(
    weak: slint::Weak<crate::AppWindow>,
    root: PathBuf,
    generation: Arc<AtomicU64>,
) {
    let ticket = generation.fetch_add(1, Ordering::SeqCst) + 1;
    if let Some(window) = weak.upgrade() {
        window.set_recovery_loading(true);
        window.set_recovery_count(0);
        window.set_recovery_lines(ModelRc::new(VecModel::from(vec![SharedString::from(
            "선택한 폴더의 복구 기록을 읽는 중...",
        )])));
    }
    thread::spawn(move || {
        let result = inspect_recovery_root(&root);
        let _ = slint::invoke_from_event_loop(move || {
            if generation.load(Ordering::SeqCst) != ticket {
                return;
            }
            let Some(window) = weak.upgrade() else {
                return;
            };
            if !window.get_recovery_open() {
                return;
            }
            window.set_recovery_loading(false);
            match result {
                Ok(found) => {
                    window.set_recovery_count(i32::try_from(found.count).unwrap_or(i32::MAX));
                    window.set_recovery_lines(ModelRc::new(VecModel::from(
                        found
                            .lines
                            .into_iter()
                            .map(SharedString::from)
                            .collect::<Vec<_>>(),
                    )));
                }
                Err(error) => {
                    // A corrupt journal, inaccessible workspace or junction
                    // is visible as an error. Nothing is repaired or hidden.
                    window.set_recovery_lines(ModelRc::new(VecModel::from(vec![
                        SharedString::from(format!("복구 이력 검사 실패: {error:#}")),
                        SharedString::from(
                            "기록을 임의로 수정·삭제하지 마세요. 복구 폴더와 원본을 수동 확인하세요.",
                        ),
                    ])));
                }
            }
        });
    });
}

pub(crate) fn wire_recovery_inspector(window: &crate::AppWindow, default_root: PathBuf) {
    window.set_recovery_open(false);
    window.set_recovery_loading(false);
    window.set_recovery_root(default_root.to_string_lossy().into_owned().into());
    window.set_recovery_lines(ModelRc::new(VecModel::<SharedString>::default()));
    let generation = Arc::new(AtomicU64::new(0));

    {
        let weak = window.as_weak();
        let generation = generation.clone();
        window.on_show_recovery(move || {
            let Some(ui) = weak.upgrade() else {
                return;
            };
            ui.set_recovery_open(true);
            let root = PathBuf::from(ui.get_recovery_root().to_string());
            begin_readonly_scan(weak.clone(), root, generation.clone());
        });
    }
    {
        let weak = window.as_weak();
        let generation = generation.clone();
        window.on_refresh_recovery(move || {
            let Some(ui) = weak.upgrade() else {
                return;
            };
            if !ui.get_recovery_open() {
                return;
            }
            let root = PathBuf::from(ui.get_recovery_root().to_string());
            begin_readonly_scan(weak.clone(), root, generation.clone());
        });
    }
    {
        let weak = window.as_weak();
        window.on_choose_recovery_root(move || {
            let Some(ui) = weak.upgrade() else {
                return;
            };
            if ui.get_recovery_loading() || !ui.get_recovery_open() {
                return;
            }
            let Some(folder) = rfd::FileDialog::new().pick_folder() else {
                return;
            };
            ui.set_recovery_root(folder.to_string_lossy().into_owned().into());
            ui.invoke_refresh_recovery();
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use nsrp::ops::program_recovery::{
        PROGRAM_EXTRACT_STAGING_PREFIX, ProgramRecoveryPhase, record_program_recovery_phase,
        write_program_publish_journal,
    };

    #[test]
    fn stage53_recovery_gui_readonly_displays_pending_and_preserves_files() -> Result<()> {
        let root = tempfile::tempdir()?;
        let private = tempfile::Builder::new()
            .prefix(PROGRAM_EXTRACT_STAGING_PREFIX)
            .tempdir_in(root.path())?;
        let output = root.path().join("romfs");
        fs::create_dir(&output)?;
        fs::write(output.join("other_user.bin"), b"preserve me")?;
        write_program_publish_journal(private.path(), &[("romfs", &output)])?;
        record_program_recovery_phase(
            private.path(),
            ProgramRecoveryPhase::PublishRenameStarted,
            Some(0),
        )?;
        let events_before = fs::read(
            private
                .path()
                .join(nsrp::ops::program_recovery::PROGRAM_RECOVERY_EVENTS),
        )?;
        let view = inspect_recovery_root(root.path())?;
        assert_eq!(view.count, 1);
        assert!(
            view.lines
                .iter()
                .any(|s| s.contains("이동 완료 불확실: 예")),
            "Stage53 GUI rows: {:?}",
            view.lines
        );
        assert!(view.lines.iter().any(|s| s.contains("자동 복원: 안 함")));
        assert!(view.lines.iter().any(|s| s.contains("수동")));
        assert_eq!(fs::read(output.join("other_user.bin"))?, b"preserve me");
        assert_eq!(
            fs::read(
                private
                    .path()
                    .join(nsrp::ops::program_recovery::PROGRAM_RECOVERY_EVENTS)
            )?,
            events_before
        );
        Ok(())
    }

    #[test]
    fn stage53_recovery_gui_missing_folder_does_not_create_it() -> Result<()> {
        let root = tempfile::tempdir()?;
        let missing = root.path().join("not_created");
        let view = inspect_recovery_root(&missing)?;
        assert_eq!(view.count, 0);
        assert!(!missing.exists());
        assert!(view.lines[0].contains("생성하지 않았습니다"));
        Ok(())
    }

    #[test]
    fn stage53_recovery_gui_corrupt_journal_fails_closed() -> Result<()> {
        let root = tempfile::tempdir()?;
        let private = tempfile::Builder::new()
            .prefix(PROGRAM_EXTRACT_STAGING_PREFIX)
            .tempdir_in(root.path())?;
        let journal = private.path().join(PROGRAM_RECOVERY_JOURNAL);
        fs::write(&journal, b"{\"broken\":")?;
        assert!(inspect_recovery_root(root.path()).is_err());
        assert_eq!(fs::read(journal)?, b"{\"broken\":");
        Ok(())
    }

    #[test]
    fn stage54_stage55_slint_callback_pointer_and_dpi_paths() -> Result<()> {
        // Construct but do not show a second NSRP window.
        let sandbox = tempfile::tempdir()?;
        let window = crate::AppWindow::new()?;
        wire_recovery_inspector(&window, sandbox.path().to_path_buf());
        assert!(!window.get_recovery_open());
        assert!(!window.get_recovery_loading());
        window.invoke_show_recovery();
        assert!(window.get_recovery_open());
        assert!(window.get_recovery_loading());
        assert_eq!(
            window.get_recovery_root().as_str(),
            sandbox.path().to_string_lossy()
        );
        window.set_recovery_open(false);
        // Keep all AppWindow construction in this single test thread. The
        // Slint platform is bound to its first test thread for the process.
        // A single component instance exercises Slint's logical coordinates
        // under 100/125/150% synthetic scale-factor events. These are NOT
        // actual changes to the user's Windows desktop DPI setting.
        for factor in [1.0_f32, 1.25, 1.5] {
            window
                .window()
                .dispatch_event(slint::platform::WindowEvent::ScaleFactorChanged {
                    scale_factor: factor,
                });
            window
                .window()
                .dispatch_event(slint::platform::WindowEvent::Resized {
                    size: slint::LogicalSize::new(1400.0, 760.0),
                });
            stage54_click(&window, 60.0, 11.0); // Help menu
            assert_eq!(window.get_menu_open(), 2, "scale={factor}");
            stage54_click(&window, 105.0, 99.0); // Recovery entry
            assert_eq!(window.get_menu_open(), 0, "scale={factor}");
            assert!(window.get_recovery_open(), "scale={factor}");
            window
                .window()
                .dispatch_event(slint::platform::WindowEvent::PointerScrolled {
                    position: slint::LogicalPosition::new(850.0, 400.0),
                    delta_x: 0.0,
                    delta_y: -500.0,
                });
            assert!(window.get_recovery_open(), "wheel, scale={factor}");
            stage54_click(&window, 4.0, 699.0); // Modal backdrop
            assert!(window.get_recovery_open(), "backdrop, scale={factor}");
            stage54_click(&window, 1165.0, 94.0); // Close button
            assert!(!window.get_recovery_open(), "close, scale={factor}");
        }
        assert_eq!(fs::read_dir(sandbox.path())?.count(), 0);
        Ok(())
    }

    fn stage54_click(window: &crate::AppWindow, x: f32, y: f32) {
        use slint::platform::{PointerEventButton, WindowEvent};
        let position = slint::LogicalPosition::new(x, y);
        window.window().dispatch_event(WindowEvent::PointerPressed {
            position,
            button: PointerEventButton::Left,
        });
        window
            .window()
            .dispatch_event(WindowEvent::PointerReleased {
                position,
                button: PointerEventButton::Left,
            });
    }

    #[test]
    fn stage54_many_journals_have_visible_limit_and_keep_all_records() -> Result<()> {
        let root = tempfile::tempdir()?;
        let output = root.path().join("user_owns_romfs");
        let mut initial_journal = Vec::new();
        for index in 0..66 {
            let staging = root
                .path()
                .join(format!("{PROGRAM_EXTRACT_STAGING_PREFIX}{index:03}"));
            fs::create_dir(&staging)?;
            write_program_publish_journal(&staging, &[("romfs", &output)])?;
            if index == 0 {
                initial_journal = fs::read(staging.join(PROGRAM_RECOVERY_JOURNAL))?;
            }
        }
        let found = inspect_recovery_root(root.path())?;
        assert_eq!(found.count, 66);
        assert!(found.lines.iter().any(|s| s.contains("나머지 2개")));
        assert_eq!(
            fs::read(
                root.path()
                    .join(format!("{PROGRAM_EXTRACT_STAGING_PREFIX}000"))
                    .join(PROGRAM_RECOVERY_JOURNAL)
            )?,
            initial_journal
        );
        assert!(!output.exists());
        Ok(())
    }

    #[test]
    fn stage54_corrupt_event_log_is_not_ignored_or_overwritten() -> Result<()> {
        let root = tempfile::tempdir()?;
        let staging = tempfile::Builder::new()
            .prefix(PROGRAM_EXTRACT_STAGING_PREFIX)
            .tempdir_in(root.path())?;
        let output = root.path().join("untouched");
        write_program_publish_journal(staging.path(), &[("romfs", &output)])?;
        let invalid = b"{\"sequence\":0,\"phase\":"; // torn append
        let log = staging
            .path()
            .join(nsrp::ops::program_recovery::PROGRAM_RECOVERY_EVENTS);
        fs::write(&log, invalid)?;
        assert!(inspect_recovery_root(root.path()).is_err());
        assert_eq!(fs::read(log)?, invalid);
        assert!(!output.exists());
        Ok(())
    }

    #[cfg(windows)]
    #[test]
    fn stage63_extended_windows_paths_display_without_device_prefix() {
        let local = Path::new(r"\\?\C:\Users\runneradmin\AppData\Local\Temp\journal\romfs");
        assert_eq!(
            display_recovery_path(local),
            r"C:\Users\runneradmin\AppData\Local\Temp\journal\romfs"
        );
        let unc = Path::new(r"\\?\UNC\server\share\journal\romfs");
        assert_eq!(display_recovery_path(unc), r"\\server\share\journal\romfs");
        let special = Path::new(r"\\?\Volume{A1}\journal");
        assert_eq!(
            display_recovery_path(special),
            special.display().to_string()
        );
    }

    #[test]
    fn stage54_long_output_path_keeps_complete_readonly_detail() -> Result<()> {
        let root = tempfile::tempdir()?;
        let staging = tempfile::Builder::new()
            .prefix(PROGRAM_EXTRACT_STAGING_PREFIX)
            .tempdir_in(root.path())?;
        let directory = root.path().join("nested_".repeat(26));
        fs::create_dir(&directory)?;
        let output = directory.join("romfs");
        write_program_publish_journal(staging.path(), &[("romfs", &output)])?;
        let found = inspect_recovery_root(root.path())?;
        assert_eq!(found.count, 1);
        // Journals deliberately record the canonical parent. On some hosted
        // Windows runners that path uses the extended-length spelling and
        // resolves differently from the original temporary-root spelling.
        // Test the full canonical destination without requiring verbatim
        // input-path spelling (which is not the journal's contract).
        let canonical_output = fs::canonicalize(&directory)?.join("romfs");
        let expected = display_recovery_path(&canonical_output);
        assert!(expected.contains(&"nested_".repeat(26)));
        assert!(
            found.lines.iter().any(|s| s.contains(&expected)),
            "Long canonical recovery path was truncated or changed: expected={expected:?}, lines={:?}",
            found.lines
        );
        assert!(!output.exists());
        Ok(())
    }

    #[cfg(windows)]
    #[test]
    fn stage54_locked_recovery_journal_fails_closed_and_remains_intact() -> Result<()> {
        use std::os::windows::fs::OpenOptionsExt;

        let root = tempfile::tempdir()?;
        let staging = tempfile::Builder::new()
            .prefix(PROGRAM_EXTRACT_STAGING_PREFIX)
            .tempdir_in(root.path())?;
        let output = root.path().join("old_output");
        write_program_publish_journal(staging.path(), &[("romfs", &output)])?;
        let journal = staging.path().join(PROGRAM_RECOVERY_JOURNAL);
        let before = fs::read(&journal)?;
        let locked = fs::OpenOptions::new()
            .read(true)
            .share_mode(0)
            .open(&journal)?;
        assert!(
            inspect_recovery_root(root.path()).is_err(),
            "Exclusive journal lock must not be silently ignored"
        );
        drop(locked);
        assert_eq!(fs::read(&journal)?, before);
        assert_eq!(inspect_recovery_root(root.path())?.count, 1);
        assert!(!output.exists());
        Ok(())
    }
}
