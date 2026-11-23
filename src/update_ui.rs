//! Menu-driven, opt-in updates. Download/verification runs off the Slint
//! thread and the existing GUI is not stopped until the installer confirms
//! it has staged and verified the exact executable it intends to replace.
use super::*;

pub(super) fn wire_updates(
    window: &AppWindow,
    paths: AppPaths,
    busy: Arc<AtomicBool>,
    config: Arc<Mutex<AppConfig>>,
    states: Arc<Mutex<Vec<TabUiState>>>,
) {
    let updating = Arc::new(AtomicBool::new(false));
    let weak = window.as_weak();

    window.on_open_updates(move || {
        let Some(ui) = weak.upgrade() else {
            return;
        };
        if busy.load(Ordering::SeqCst) || ui_has_background_analysis(&ui) {
            ui.set_status_text("작업/분석 중에는 업데이트할 수 없습니다".into());
            return;
        }
        if updating.swap(true, Ordering::SeqCst) {
            ui.set_status_text("업데이트를 이미 확인하고 있습니다".into());
            return;
        }
        ui.set_status_text("GitHub Release 업데이트 확인 중...".into());
        append_log_direct_with_tone(&ui, "업데이트 확인 중...", 0);
        drop(ui);

        let weak_check = weak.clone();
        let updating_check = updating.clone();
        let paths_check = paths.clone();
        let config_check = config.clone();
        let states_check = states.clone();
        let busy_check = busy.clone();
        thread::spawn(move || {
            let check = updater::check_latest();
            let _ = slint::invoke_from_event_loop(move || {
                let Some(ui) = weak_check.upgrade() else {
                    updating_check.store(false, Ordering::SeqCst);
                    return;
                };
                let info = match check {
                    Err(error) => {
                        append_log_direct_with_tone(
                            &ui,
                            &format!("업데이트 확인 오류: {error:#}"),
                            3,
                        );
                        ui.set_status_text("업데이트 확인 실패".into());
                        popup_ui::notice(
                            &ui,
                            "업데이트 확인 실패",
                            format!("공식 릴리스 확인에 실패했습니다.\n{error:#}"),
                        );
                        updating_check.store(false, Ordering::SeqCst);
                        return;
                    }
                    Ok(updater::UpdateCheck::NoPublishedRelease) => {
                        ui.set_status_text("공개된 NSRP Release가 아직 없습니다".into());
                        popup_ui::notice(&ui, "업데이트", "아직 GitHub에 공개된 NSRP 빌드가 없습니다.");
                        updating_check.store(false, Ordering::SeqCst);
                        return;
                    }
                    Ok(updater::UpdateCheck::Current) => {
                        append_log_direct_with_tone(&ui, "이미 최신 공개 빌드입니다", 4);
                        ui.set_status_text("이미 최신 빌드입니다".into());
                        popup_ui::notice(
                            &ui,
                            "업데이트",
                            format!("현재 커밋: {}\n최신 공개 빌드입니다.", updater::current_version()),
                        );
                        updating_check.store(false, Ordering::SeqCst);
                        return;
                    }
                    Ok(updater::UpdateCheck::Available(info)) => info,
                };

                let brief_notes = info.notes.chars().take(3200).collect::<String>();
                popup_ui::confirm(
                    &ui,
                    "공식 NSRP 업데이트",
                    format!(
                        "현재 커밋: {}\n최신 커밋: {}\n\n공식 GitHub ZIP을 확인·다운로드하시겠습니까?\n\n{}",
                        updater::current_version(),
                        info.latest,
                        brief_notes,
                    ),
                    move |confirmed| {
                        let Some(ui) = weak_check.upgrade() else {
                            updating_check.store(false, Ordering::SeqCst);
                            return;
                        };
                        if !confirmed {
                            updating_check.store(false, Ordering::SeqCst);
                            ui.set_status_text("업데이트 취소".into());
                            return;
                        }
                        ui.set_status_text("업데이트 다운로드 및 SHA-256 검증 중...".into());
                        ui.set_progress(0.0);
                        let weak_download = weak_check.clone();
                        let update_for_download = updating_check.clone();
                        let busy_download = busy_check.clone();
                        let workspace = paths_check.workspace_root.clone();
                        thread::spawn(move || {
                            let prepared = updater::download_and_prepare(&info, &workspace);
                            let _ = slint::invoke_from_event_loop(move || {
                                let Some(ui) = weak_download.upgrade() else {
                                    update_for_download.store(false, Ordering::SeqCst);
                                    return;
                                };
                                match prepared {
                                    Err(error) => {
                                        append_log_direct_with_tone(
                                            &ui,
                                            &format!("업데이트 검증 실패: {error:#}"),
                                            3,
                                        );
                                        ui.set_status_text("업데이트 다운로드/검증 실패".into());
                                        popup_ui::notice(
                                            &ui,
                                            "업데이트 검증 실패",
                                            format!(
                                                "기존 설치 파일은 변경하지 않았습니다.\n{error:#}"
                                            ),
                                        );
                                        update_for_download.store(false, Ordering::SeqCst);
                                    }
                                    Ok(task) => {
                                        ui.set_progress(1.0);
                                        ui.set_status_text("검증 완료 · 설치 준비됨".into());
                                        let weak_install = weak_download.clone();
                                        let updating_install = update_for_download.clone();
                                        popup_ui::confirm(
                                            &ui,
                                            "업데이트 설치",
                                            "SHA-256 검증에 성공했습니다.\n\n지금 프로그램을 종료하고 실행파일만 안전하게 교체한 뒤 재시작할까요?\n설정·키·게임 파일은 유지됩니다.",
                                            move |install| {
                                                let Some(ui) = weak_install.upgrade() else {
                                                    updating_install.store(false, Ordering::SeqCst);
                                                    return;
                                                };
                                                if install
                                                    && !busy_download.load(Ordering::SeqCst)
                                                    && !ui_has_background_analysis(&ui)
                                                {
                                                    let tab = ui.get_selected_tab().clamp(0, 8);
                                                    persist_settings(
                                                        &ui,
                                                        tab,
                                                        &config_check,
                                                        &paths_check,
                                                    );
                                                    capture_tab_state(
                                                        &ui,
                                                        &mut states_check.lock()[tab as usize],
                                                    );
                                                    if let Err(error) =
                                                        updater::launch_apply_and_exit(
                                                            &task, &workspace,
                                                        )
                                                    {
                                                        append_log_direct_with_tone(
                                                            &ui,
                                                            &format!("안전한 업데이트 시작 실패: {error:#}"),
                                                            3,
                                                        );
                                                        ui.set_status_text(
                                                            "업데이트 적용 실패 · 기존 버전 유지"
                                                                .into(),
                                                        );
                                                        popup_ui::notice(
                                                            &ui,
                                                            "업데이트 적용 실패",
                                                            format!(
                                                                "기존 버전을 유지했습니다.\n{error:#}"
                                                            ),
                                                        );
                                                    }
                                                } else {
                                                    ui.set_status_text(
                                                        "업데이트 설치 취소 · 기존 버전 유지"
                                                            .into(),
                                                    );
                                                }
                                                updating_install.store(false, Ordering::SeqCst);
                                            },
                                        );
                                    }
                                }
                            });
                        });
                    },
                );
            });
        });
    });
}
