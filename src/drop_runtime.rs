//! GUI-thread commit and background folder enumeration for OS file drops.
use super::*;

pub(super) fn apply_native_drop(ui: &AppWindow, payload: NativeDropPayload) {
    if payload.context_generation != DROP_CONTEXT_GENERATION.load(Ordering::SeqCst) {
        // An OLE burst can cross a tab switch/reset while waiting in the
        // 160ms queue. Ignore stale paths instead of using the *new* tab.
        return;
    }
    let tab = ui.get_selected_tab();
    if ui.get_busy() || ui_has_background_analysis(ui) || !(0..=8).contains(&tab) {
        ui.set_status_text("작업 또는 분석 중입니다. 완료 후 다시 드롭하세요.".into());
        return;
    }

    let mut input = Vec::new();
    let mut folders = Vec::new();
    let mut patch = Vec::new();
    let mut output = None;
    let mut icon = None;
    for path in payload.paths {
        match classify_drop(tab, &path, payload.x, payload.y) {
            DropDestination::InputFile => input.push(path),
            DropDestination::InputDirectory => folders.push(path),
            DropDestination::Patch => patch.push(path),
            DropDestination::OutputDirectory => output = Some(path),
            DropDestination::TitleIcon => icon = Some(path),
            DropDestination::Unsupported => {}
        }
    }
    if input.is_empty()
        && folders.is_empty()
        && patch.is_empty()
        && output.is_none()
        && icon.is_none()
    {
        ui.set_status_text("현재 탭에서 지원하는 파일 또는 폴더가 없습니다".into());
        return;
    }

    let generation = INPUT_SCAN_GENERATION.fetch_add(1, Ordering::SeqCst) + 1;
    if folders.is_empty() {
        commit_drop(ui, tab, input, patch, output, icon);
        return;
    }
    ui.set_status_text(format!("드롭한 폴더 {}개 검색 중...", folders.len()).into());
    let weak = ui.as_weak();
    thread::spawn(move || {
        let extensions = allowed_input_extensions(tab);
        for folder in folders {
            input.extend(scan_folder_until(&folder, extensions, generation));
            if INPUT_SCAN_GENERATION.load(Ordering::Relaxed) != generation {
                return;
            }
            if is_single_input_tab(tab) && !input.is_empty() {
                break;
            }
        }
        let _ = slint::invoke_from_event_loop(move || {
            if INPUT_SCAN_GENERATION.load(Ordering::Relaxed) != generation {
                return;
            }
            if let Some(ui) = weak.upgrade()
                && ui.get_selected_tab() == tab
                && !ui.get_busy()
                && !ui_has_background_analysis(&ui)
            {
                commit_drop(&ui, tab, input, patch, output, icon);
            }
        });
    });
}

fn scan_folder_until(folder: &Path, extensions: &[&str], generation: u64) -> Vec<PathBuf> {
    let mut results = Vec::new();
    for entry in walkdir::WalkDir::new(folder).follow_links(false) {
        if INPUT_SCAN_GENERATION.load(Ordering::Relaxed) != generation {
            break;
        }
        let Ok(entry) = entry else {
            continue;
        };
        if !entry.file_type().is_file() {
            continue;
        }
        let path = entry.into_path();
        if path
            .extension()
            .and_then(|ext| ext.to_str())
            .is_some_and(|ext| {
                extensions
                    .iter()
                    .any(|allowed| ext.eq_ignore_ascii_case(allowed))
            })
        {
            results.push(path);
        }
    }
    sort_package_paths(&mut results);
    results
}

pub(super) fn choose_folder_async(ui: &AppWindow, folder: PathBuf) {
    let tab = ui.get_selected_tab();
    if ui.get_busy() || ui_has_background_analysis(ui) {
        ui.set_status_text("현재 작업/분석이 완료된 뒤 폴더를 선택하세요".into());
        return;
    }
    let generation = INPUT_SCAN_GENERATION.fetch_add(1, Ordering::SeqCst) + 1;
    let weak = ui.as_weak();
    ui.set_status_text("선택한 폴더에서 게임 검색 중...".into());
    thread::spawn(move || {
        let found = scan_folder_until(&folder, allowed_input_extensions(tab), generation);
        let _ = slint::invoke_from_event_loop(move || {
            if INPUT_SCAN_GENERATION.load(Ordering::Relaxed) != generation {
                return;
            }
            if let Some(ui) = weak.upgrade()
                && ui.get_selected_tab() == tab
                && !ui.get_busy()
                && !ui_has_background_analysis(&ui)
            {
                if found.is_empty() {
                    ui.set_status_text("선택한 폴더에 지원하는 게임 파일이 없습니다".into());
                } else {
                    commit_drop(&ui, tab, found, Vec::new(), None, None);
                }
            }
        });
    });
}

fn commit_drop(
    ui: &AppWindow,
    tab: i32,
    mut input: Vec<PathBuf>,
    patches: Vec<PathBuf>,
    output: Option<PathBuf>,
    icon: Option<PathBuf>,
) {
    let mut status = Vec::new();

    if let Some(dir) = output {
        ui.set_output_dir(dir.to_string_lossy().replace('\\', "/").into());
        status.push("출력 폴더".to_owned());
    }
    if let Some(path) = icon {
        match Image::load_from_path(&path) {
            Ok(image) => {
                ui.set_title_new_image(image);
                ui.set_title_has_new_image(true);
                ui.set_title_icon(path.to_string_lossy().into_owned().into());
                status.push("타이틀 아이콘".to_owned());
            }
            Err(e) => ui.set_status_text(format!("아이콘 열기 실패: {e}").into()),
        }
    }
    if !patches.is_empty() {
        let mut items = split_paths(&ui.get_patch_paths());
        let old_count = items.len();
        items.extend(patches);
        dedup_paths(&mut items);
        if items.len() != old_count {
            status.push(format!("패치 {}개", items.len() - old_count));
            sync_patch_ui(ui, &items);
        }
    }
    if !input.is_empty() {
        dedup_paths(&mut input);
        let old = split_paths(&ui.get_input_paths());
        let mut items = if is_single_input_tab(tab) {
            Vec::new()
        } else {
            old.clone()
        };
        items.extend(input);
        dedup_paths(&mut items);
        if is_single_input_tab(tab) {
            items.truncate(1);
        }
        if items != old {
            status.push(format!("입력 {}개", items.len()));
            sync_input_ui(ui, &items);
            match tab {
                0 => ui.invoke_analyze_patch(),
                1 => ui.invoke_analyze_title(),
                2 => ui.invoke_analyze_extract(),
                3 => ui.invoke_analyze_package(),
                _ => {}
            }
        }
    }
    if status.is_empty() {
        ui.set_status_text("새로 추가된 파일이 없습니다".into());
    } else {
        let message = format!("드롭 등록 완료: {}", status.join(", "));
        append_log_direct_with_tone(ui, &message, 1);
        if !ui_has_background_analysis(ui) {
            ui.set_status_text(message.into());
        }
    }
}

#[cfg(all(test, windows))]
mod stage60_tests {
    use super::*;

    #[test]
    #[ignore = "Win32 Winit backend can only initialize once per process; run this GUI test alone"]
    fn stage60_drop_output_state_and_tab_epoch_are_preserved() -> anyhow::Result<()> {
        let scratch = tempfile::tempdir()?;
        let folder_a = scratch.path().join("output_first");
        let folder_b = scratch.path().join("output_second");
        std::fs::create_dir(&folder_a)?;
        std::fs::create_dir(&folder_b)?;

        let ui = AppWindow::new()?;
        ui.set_selected_tab(0);
        let old_epoch = DROP_CONTEXT_GENERATION.load(Ordering::SeqCst);
        let drop = |dir: PathBuf, generation| NativeDropPayload {
            paths: vec![dir],
            x: 400,
            y: 620,
            context_generation: generation,
            source: NativeDropSource::Shell,
        };

        apply_native_drop(&ui, drop(folder_a.clone(), old_epoch));
        let expected_a = folder_a.to_string_lossy().replace('\\', "/");
        assert_eq!(ui.get_output_dir().as_str(), expected_a);

        // A gesture originating in tab 0 cannot be interpreted as a drop
        // on another tab after an intervening user tab switch.
        ui.set_selected_tab(1);
        DROP_CONTEXT_GENERATION.fetch_add(1, Ordering::SeqCst);
        apply_native_drop(&ui, drop(folder_b.clone(), old_epoch));
        assert_eq!(ui.get_output_dir().as_str(), expected_a);

        let new_epoch = DROP_CONTEXT_GENERATION.load(Ordering::SeqCst);
        apply_native_drop(&ui, drop(folder_b.clone(), new_epoch));
        let expected_b = folder_b.to_string_lossy().replace('\\', "/");
        assert_eq!(ui.get_output_dir().as_str(), expected_b);
        Ok(())
    }
}
