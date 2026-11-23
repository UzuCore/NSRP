#![cfg_attr(windows, windows_subsystem = "windows")]

mod drop_runtime;
#[cfg(windows)]
mod native_drop_win;
#[cfg(windows)]
use native_drop_win::{schedule_native_file_drop_subclass, start_native_file_drop_bridge};
mod drop_support;
#[cfg(windows)]
mod gui_scale;
mod popup_ui;
mod recovery_ui;
mod update_ui;
mod updater;

use anyhow::{Context, Result, bail};
use drop_support::{
    DropDestination, bounded_client_physical_to_logical, classify_drop, sort_package_paths,
};
use nsrp::{
    config::AppConfig,
    keys::{KeySet, merge_ticket_keys_from_nsp_file},
    ops::{
        analyze,
        compress::{self, CompressOptions},
        convert::{self, ConvertOptions, TargetFormat},
        extract::{self, ExtractOptions},
        merge::{self, MergeFormat, MergeOptions},
        patcher::{self, PatchOptions},
        split,
        title::{self, TitlePatch},
        xcz::{self, XczOptions},
    },
    workspace::AppPaths,
};
use parking_lot::Mutex;
use slint::{
    CloseRequestResponse, ComponentHandle, Image, Model, ModelRc, SharedString, VecModel,
    language::StandardListViewItem,
};
use std::{
    cell::RefCell,
    fs,
    path::{Path, PathBuf},
    rc::Rc,
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering},
    },
    thread,
    time::{Duration, Instant},
};

slint::include_modules!();

const APP_VERSION: &str = env!("CARGO_PKG_VERSION");

#[cfg(windows)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum NativeDropSource {
    Shell,
    Ole,
}

#[cfg(windows)]
#[derive(Debug)]
struct NativeDropPayload {
    paths: Vec<PathBuf>,
    x: i32,
    y: i32,
    // UI operations and tab switches invalidate old arrivals, but accepting
    // one file drop does not invalidate other drops from the same gesture.
    context_generation: u64,
    source: NativeDropSource,
}

#[cfg(windows)]
static DROP_SENDER: std::sync::OnceLock<std::sync::mpsc::Sender<NativeDropPayload>> =
    std::sync::OnceLock::new();

#[cfg(windows)]
static NATIVE_DROP_SCALE_BITS: AtomicU32 = AtomicU32::new(1.0f32.to_bits());

static INPUT_SCAN_GENERATION: AtomicU64 = AtomicU64::new(0);
#[cfg(windows)]
static DROP_CONTEXT_GENERATION: AtomicU64 = AtomicU64::new(0);
static LAST_PROGRESS_BUCKET: AtomicU32 = AtomicU32::new(u32::MAX);

#[cfg(windows)]
struct InstanceGuard(windows::Win32::Foundation::HANDLE);

#[cfg(windows)]
impl Drop for InstanceGuard {
    fn drop(&mut self) {
        unsafe {
            let _ = windows::Win32::Foundation::CloseHandle(self.0);
        }
    }
}

#[cfg(windows)]
fn try_instance_guard(name: windows::core::PCWSTR) -> Result<Option<InstanceGuard>> {
    use windows::Win32::{
        Foundation::{CloseHandle, ERROR_ALREADY_EXISTS, GetLastError},
        System::Threading::CreateMutexW,
    };
    let mutex = unsafe { CreateMutexW(None, false, name)? };
    if unsafe { GetLastError() } == ERROR_ALREADY_EXISTS {
        unsafe { CloseHandle(mutex)? };
        return Ok(None);
    }
    Ok(Some(InstanceGuard(mutex)))
}

thread_local! {
    static FULL_LOG_BUFFER: RefCell<String> = const { RefCell::new(String::new()) };
}

#[derive(Debug, Clone)]
struct OperationRequest {
    tab: i32,
    inputs: Vec<PathBuf>,
    patches: Vec<PathBuf>,
    output_dir: PathBuf,
    output_dir_explicit: bool,
    compression: CompressOptions,
    remove_source: bool,
    notify_done: bool,
    save_log: bool,
    compress_after: bool,
    use_game_title: bool,
    unpack_nca: bool,
    extract_selected_names: Vec<String>,
    verify_base_count: usize,
    target_format: String,
    zip_password: Option<String>,
    required_system_version: Option<u64>,
    title_english: Option<String>,
    title_japanese: Option<String>,
    title_korean: Option<String>,
    title_icon: Option<PathBuf>,
}

#[derive(Debug, Clone)]
struct TabUiState {
    inputs: Vec<PathBuf>,
    output_dir: String,
    input_current: i32,
    notify_done: bool,
    save_log: bool,
    remove_source: bool,
    block_mode: bool,
    compression_level: f32,
    thread_count: f32,
    compress_after: bool,
    use_game_title: bool,
    unpack_nca: bool,
    target_format: String,
}

impl Default for TabUiState {
    fn default() -> Self {
        Self {
            inputs: Vec::new(),
            output_dir: String::new(),
            input_current: -1,
            notify_done: false,
            save_log: false,
            remove_source: false,
            block_mode: true,
            compression_level: 18.0,
            thread_count: (num_cpus::get().max(1) + 1) as f32,
            compress_after: false,
            use_game_title: false,
            unpack_nca: false,
            target_format: "NSP".to_owned(),
        }
    }
}

fn build_tab_states(cfg: &AppConfig) -> Vec<TabUiState> {
    let mut states = vec![TabUiState::default(); 9];
    states[0].notify_done = cfg.patcher.notify_done;
    states[0].save_log = cfg.patcher.save_log;
    states[2].notify_done = cfg.extractor.notify_done;
    states[5].notify_done = cfg.compressor.notify_done;
    states[5].remove_source = cfg.compressor.rm_source;
    states[5].block_mode = cfg.compressor.block_mode;
    states[5].compression_level = cfg.compressor.level.clamp(1, 23) as f32;
    states[5].thread_count = cfg.compressor.thread.max(1) as f32;
    states[6].notify_done = cfg.decompressor.notify_done;
    states[6].remove_source = cfg.decompressor.rm_source;
    states[6].thread_count = cfg.decompressor.thread.max(1) as f32;
    states[7].notify_done = cfg.merger.notify_done;
    states[7].thread_count = cfg.merger.thread.max(1) as f32;
    states[7].target_format = cfg.merger.output_format.to_ascii_uppercase();
    states[7].compress_after = cfg.merger.compress_after;
    states[7].use_game_title = cfg.merger.fetch_title;
    states[8].use_game_title = true;
    states
}

fn capture_tab_state(ui: &AppWindow, state: &mut TabUiState) {
    state.inputs = split_paths(&ui.get_input_paths());
    state.output_dir = ui.get_output_dir().to_string();
    state.input_current = ui.get_input_current();
    state.notify_done = ui.get_notify_done();
    state.save_log = ui.get_save_log();
    state.remove_source = ui.get_remove_source();
    state.block_mode = ui.get_block_mode();
    state.compression_level = ui.get_compression_level();
    state.thread_count = ui.get_thread_count();
    state.compress_after = ui.get_compress_after();
    state.use_game_title = ui.get_use_game_title();
    state.unpack_nca = ui.get_unpack_nca();
    state.target_format = ui.get_target_format().to_string();
}

fn apply_tab_state(ui: &AppWindow, state: &TabUiState) {
    sync_input_ui(ui, &state.inputs);
    if state.input_current >= 0 && (state.input_current as usize) < state.inputs.len() {
        ui.set_input_current(state.input_current);
    }
    ui.set_output_dir(state.output_dir.clone().into());
    ui.set_notify_done(state.notify_done);
    ui.set_save_log(state.save_log);
    ui.set_remove_source(state.remove_source);
    ui.set_block_mode(state.block_mode);
    ui.set_compression_level(state.compression_level);
    ui.set_thread_count(state.thread_count);
    ui.set_compress_after(state.compress_after);
    ui.set_use_game_title(state.use_game_title);
    ui.set_unpack_nca(state.unpack_nca);
    ui.set_target_format(state.target_format.clone().into());
}

fn main() -> Result<()> {
    #[cfg(windows)]
    let Some(_instance_guard) =
        try_instance_guard(windows::core::w!("Local\\NSRP_Rust_GUI_Single_Instance"))?
    else {
        use windows::Win32::UI::WindowsAndMessaging::{MB_ICONINFORMATION, MB_OK, MessageBoxW};
        unsafe {
            MessageBoxW(
                None,
                windows::core::w!("NSRP가 이미 실행 중입니다. 기존 창을 사용하세요."),
                windows::core::w!("NSRP"),
                MB_OK | MB_ICONINFORMATION,
            );
        }
        return Ok(());
    };
    // Make the legacy fixed-width UI visible on high-DPI small screens.
    // This does not change any Windows system display preferences.
    #[cfg(windows)]
    gui_scale::configure_initial_scale();
    let paths = AppPaths::discover()?;
    let config = Arc::new(Mutex::new(AppConfig::load(&paths.config_path)));
    let cancel = Arc::new(AtomicBool::new(false));
    let busy = Arc::new(AtomicBool::new(false));
    let initial_config = config.lock().clone();
    let tab_states = Arc::new(Mutex::new(build_tab_states(&initial_config)));

    let window = AppWindow::new()?;
    popup_ui::wire(&window);
    window.set_app_version(updater::current_version().into());
    let initial_tab = initial_config.main.last_tab.clamp(0, 8);
    window.set_selected_tab(initial_tab);
    window.set_core_count(num_cpus::get().max(1) as i32);
    apply_tab_state(&window, &tab_states.lock()[initial_tab as usize]);
    window.set_log_text(SharedString::new());
    window.set_log_rows(ModelRc::new(VecModel::<LogRow>::default()));
    append_log_direct_with_tone(&window, "NSRP 준비 완료", 1);
    if paths.config_path.is_file()
        && let Ok(text) = fs::read_to_string(&paths.config_path)
        && serde_json::from_str::<AppConfig>(&text).is_err()
    {
        append_log_direct_with_tone(
            &window,
            "[경고] 기존 설정 파일의 JSON 형식이 잘못되었습니다. 복구 전까지 자동 덮어쓰기를 차단합니다.",
            2,
        );
    }
    append_log_direct_with_tone(
        &window,
        &format!("  └ 작업 영역: {}", paths.workspace_root.display()),
        0,
    );
    if paths.key("prod.keys").is_file() {
        append_log_direct_with_tone(&window, "  └ 키 파일: 확인됨", 0);
    } else {
        append_log_direct_with_tone(&window, "[경고] 키 파일이 없습니다", 2);
    }
    window.set_input_items(path_list_model(&[]));
    window.set_patch_items(path_list_model(&[]));
    window.set_extract_rows(ModelRc::new(VecModel::<TreeRow>::default()));
    window.set_analyze_languages(ModelRc::new(VecModel::<StandardListViewItem>::default()));
    window.set_analyze_file_rows(ModelRc::new(VecModel::<TreeRow>::default()));
    window.set_analyze_base_rows(ModelRc::new(VecModel::<ContentRow>::default()));
    window.set_analyze_update_rows(ModelRc::new(VecModel::<ContentRow>::default()));
    window.set_analyze_dlc_rows(ModelRc::new(VecModel::<ContentRow>::default()));
    window.set_resource_text(SharedString::new());
    window.set_resource_char_count(0);
    let _resource_timer = start_resource_timer(&window);
    recovery_ui::wire_recovery_inspector(&window, paths.workspace_root.clone());

    wire_file_dialogs(&window);
    wire_tab_switching(&window, tab_states.clone(), config.clone(), paths.clone());
    wire_window_actions(
        &window,
        paths.clone(),
        busy.clone(),
        cancel.clone(),
        config.clone(),
        tab_states.clone(),
    );
    wire_title_analyzer(&window, paths.clone());
    wire_patch_analyzer(&window, paths.clone());
    wire_extract_analyzer(&window);
    wire_extract_selection(&window);
    wire_analyze_package(&window, paths.clone());

    {
        let weak = window.as_weak();
        window.on_clear_log(move || {
            if let Some(ui) = weak.upgrade() {
                ui.set_log_text(SharedString::new());
                ui.set_log_rows(ModelRc::new(VecModel::<LogRow>::default()));
                FULL_LOG_BUFFER.with(|buffer| buffer.borrow_mut().clear());
            }
        });
    }

    {
        let weak = window.as_weak();
        let cancel = cancel.clone();
        window.on_stop_operation(move || {
            if let Some(ui) = weak.upgrade() {
                if ui.get_stop_requested() {
                    return;
                }
                ui.set_stop_requested(true);
                append_log_direct_with_tone(
                    &ui,
                    "[중지 요청] 현재 단계가 끝나는 대로 중단됩니다",
                    2,
                );
            }
            cancel.store(true, Ordering::Relaxed);
            set_status(&weak, "중지 요청 중...");
        });
    }

    {
        let weak = window.as_weak();
        let paths = paths.clone();
        let cancel = cancel.clone();
        let busy = busy.clone();
        let config = config.clone();
        let tab_states = tab_states.clone();
        window.on_start_operation(move |tab| {
            let Some(ui) = weak.upgrade() else {
                return;
            };
            if busy.swap(true, Ordering::SeqCst) {
                ui.set_status_text("이미 작업이 진행 중입니다".into());
                return;
            }
            INPUT_SCAN_GENERATION.fetch_add(1, Ordering::SeqCst);
            #[cfg(windows)]
            DROP_CONTEXT_GENERATION.fetch_add(1, Ordering::SeqCst);
            ui.set_busy(true);
            ui.set_stop_requested(false);
            cancel.store(false, Ordering::Relaxed);
            let request = match collect_request(&ui, tab) {
                Ok(r) => r,
                Err(err) => {
                    busy.store(false, Ordering::SeqCst);
                    ui.set_busy(false);
                    ui.set_stop_requested(false);
                    ui.set_status_text(format!("입력 오류: {err}").into());
                    append_log_direct(&ui, &format!("[오류] {err}"));
                    show_input_validation_dialog(&ui, tab, &err);
                    return;
                }
            };
            persist_settings(&ui, tab, &config, &paths);
            LAST_PROGRESS_BUCKET.store(u32::MAX, Ordering::Relaxed);
            if tab != 3 {
                ui.set_progress(0.0);
            }
            ui.set_status_text("작업 시작".into());
            append_log_direct(&ui, &format!("\n▶ {}", tab_name(tab)));
            drop(ui);

            let weak_thread = weak.clone();
            let paths_thread = paths.clone();
            let cancel_thread = cancel.clone();
            let busy_thread = busy.clone();
            let states_thread = tab_states.clone();
            thread::spawn(move || {
                let operation_tab = request.tab;
                let notify = request.notify_done;
                let save_log = request.save_log;
                let log_output_dir = request.output_dir.clone();
                let result = run_operation(request, &paths_thread, &cancel_thread, &weak_thread);
                let cancelled = cancel_thread.load(Ordering::Relaxed);
                busy_thread.store(false, Ordering::SeqCst);
                cancel_thread.store(false, Ordering::Relaxed);
                let weak_finish = weak_thread.clone();
                let _ = slint::invoke_from_event_loop(move || {
                    if let Some(ui) = weak_finish.upgrade() {
                        ui.set_busy(false);
                        ui.set_stop_requested(false);
                        match result {
                            Ok(summary) => {
                                append_log_direct(&ui, &format!("✓ {summary}"));
                                if notify {
                                    popup_ui::notice(&ui, "NSRP", &summary);
                                }
                                apply_success_cleanup(&ui, operation_tab);
                                capture_tab_state(
                                    &ui,
                                    &mut states_thread.lock()[operation_tab.clamp(0, 8) as usize],
                                );
                            }
                            Err(_err) if cancelled => {
                                ui.set_status_text("중지됨".into());
                                append_log_direct(&ui, "■ 작업이 중지되었습니다");
                            }
                            Err(err) => {
                                ui.set_status_text("오류".into());
                                append_log_direct(&ui, &format!("[오류] {err:#}"));
                                if operation_tab != 3 {
                                    popup_ui::notice(
                                        &ui,
                                        operation_error_title(operation_tab),
                                        operation_error_message(operation_tab, &err),
                                    );
                                }
                            }
                        }
                        if save_log {
                            let log_path = log_output_dir.join("NSRP.log");
                            if fs::write(&log_path, log_snapshot()).is_ok() {
                                append_log_direct(
                                    &ui,
                                    &format!("로그 저장: {}", log_path.display()),
                                );
                            }
                        }
                    }
                });
            });
        });
    }

    let _drop_timer = start_native_file_drop_bridge(&window);
    window.show()?;
    slint::Timer::single_shot(Duration::from_millis(100), force_light_title_bar);
    // Retry only on the owned Slint event loop until the native HWND is
    // realized. A single hard-coded 250ms attempt can fail on slow systems,
    // permanently disabling legacy Shell drop handling and the DPI guard.
    #[cfg(windows)]
    schedule_native_file_drop_subclass(window.as_weak(), 40);
    slint::run_event_loop()?;
    window.hide()?;
    Ok(())
}

#[cfg(windows)]
fn force_light_title_bar() {
    use std::os::windows::ffi::OsStrExt;
    use windows::{
        Win32::{
            Foundation::{LPARAM, WPARAM},
            Graphics::Dwm::{
                DWMWA_CAPTION_COLOR, DWMWA_USE_IMMERSIVE_DARK_MODE, DwmSetWindowAttribute,
            },
            UI::WindowsAndMessaging::{
                FindWindowW, ICON_SMALL, ICON_SMALL2, IMAGE_ICON, LR_LOADFROMFILE, LoadImageW,
                SendMessageW, WM_SETICON,
            },
        },
        core::PCWSTR,
    };

    unsafe {
        let caption = format!("NSRP v{}", updater::current_version());
        let wide_caption = caption
            .encode_utf16()
            .chain(std::iter::once(0))
            .collect::<Vec<_>>();
        let Ok(hwnd) = FindWindowW(None, PCWSTR(wide_caption.as_ptr())) else {
            return;
        };
        let dark_mode: i32 = 0;
        let _ = DwmSetWindowAttribute(
            hwnd,
            DWMWA_USE_IMMERSIVE_DARK_MODE,
            (&dark_mode as *const i32).cast(),
            std::mem::size_of_val(&dark_mode) as u32,
        );
        let caption_color: u32 = 0x00F3F3F3;
        let _ = DwmSetWindowAttribute(
            hwnd,
            DWMWA_CAPTION_COLOR,
            (&caption_color as *const u32).cast(),
            std::mem::size_of_val(&caption_color) as u32,
        );

        if let Ok(paths) = AppPaths::discover() {
            let icon_path = paths.resource_dir.join("assets").join("icon.ico");
            let wide = icon_path
                .as_os_str()
                .encode_wide()
                .chain(std::iter::once(0))
                .collect::<Vec<_>>();
            if let Ok(icon) = LoadImageW(
                None,
                PCWSTR(wide.as_ptr()),
                IMAGE_ICON,
                16,
                16,
                LR_LOADFROMFILE,
            ) {
                let lparam = LPARAM(icon.0 as isize);
                let _ = SendMessageW(
                    hwnd,
                    WM_SETICON,
                    Some(WPARAM(ICON_SMALL as usize)),
                    Some(lparam),
                );
                let _ = SendMessageW(
                    hwnd,
                    WM_SETICON,
                    Some(WPARAM(ICON_SMALL2 as usize)),
                    Some(lparam),
                );
            }
        }
    }
}

#[cfg(not(windows))]
fn force_light_title_bar() {}

#[cfg(not(windows))]
fn start_native_file_drop_bridge(_window: &AppWindow) -> slint::Timer {
    slint::Timer::default()
}

#[cfg(windows)]
fn apply_native_drop(ui: &AppWindow, payload: NativeDropPayload) {
    drop_runtime::apply_native_drop(ui, payload);
}

fn wire_tab_switching(
    window: &AppWindow,
    states: Arc<Mutex<Vec<TabUiState>>>,
    config: Arc<Mutex<AppConfig>>,
    paths: AppPaths,
) {
    let weak = window.as_weak();
    window.on_select_tab(move |target| {
        let Some(ui) = weak.upgrade() else {
            return;
        };
        let target = target.clamp(0, 8);
        let current = ui.get_selected_tab().clamp(0, 8);
        if target == current {
            return;
        }
        let analyzing = match current {
            0 => ui.get_patch_analyzing(),
            1 => ui.get_title_analyzing(),
            2 => ui.get_extract_analyzing(),
            3 => ui.get_analyze_analyzing(),
            _ => false,
        };
        if ui.get_busy() || analyzing {
            ui.set_status_text(
                format!(
                    "[{}] 탭의 작업/분석이 완료될 때까지 다른 탭으로 이동할 수 없습니다.",
                    tab_name(current)
                )
                .into(),
            );
            return;
        }

        INPUT_SCAN_GENERATION.fetch_add(1, Ordering::SeqCst);
        #[cfg(windows)]
        DROP_CONTEXT_GENERATION.fetch_add(1, Ordering::SeqCst);
        persist_settings(&ui, current, &config, &paths);

        let next = {
            let mut states = states.lock();
            let current_state = &mut states[current as usize];
            capture_tab_state(&ui, current_state);
            states[target as usize].clone()
        };

        ui.set_selected_tab(target);
        apply_tab_state(&ui, &next);
    });
}

fn wire_file_dialogs(window: &AppWindow) {
    {
        let weak = window.as_weak();
        window.on_choose_input(move || {
            if let Some(ui) = weak.upgrade() {
                let tab = ui.get_selected_tab();
                let extensions = allowed_input_extensions(tab);
                let dialog = rfd::FileDialog::new().add_filter("Switch Packages", extensions);
                let picked = if is_single_input_tab(tab) {
                    dialog.pick_file().map(|path| vec![path])
                } else {
                    dialog.pick_files()
                };
                let Some(files) = picked else {
                    return;
                };
                INPUT_SCAN_GENERATION.fetch_add(1, Ordering::SeqCst);
                #[cfg(windows)]
                DROP_CONTEXT_GENERATION.fetch_add(1, Ordering::SeqCst);
                let mut current = if is_single_input_tab(tab) {
                    Vec::new()
                } else {
                    split_paths(&ui.get_input_paths())
                };
                current.extend(files);
                dedup_paths(&mut current);
                if is_single_input_tab(tab) {
                    current.truncate(1);
                }
                sync_input_ui(&ui, &current);
                if tab == 0 {
                    ui.invoke_analyze_patch();
                } else if tab == 1 && !current.is_empty() {
                    ui.invoke_analyze_title();
                } else if tab == 2 {
                    ui.invoke_analyze_extract();
                } else if tab == 3 {
                    ui.invoke_analyze_package();
                }
            }
        });
    }
    {
        let weak = window.as_weak();
        window.on_choose_input_folder(move || {
            let Some(folder) = rfd::FileDialog::new().pick_folder() else {
                return;
            };
            if let Some(ui) = weak.upgrade() {
                drop_runtime::choose_folder_async(&ui, folder);
            }
        });
    }
    {
        let weak = window.as_weak();
        window.on_remove_input(move |index| {
            if let Some(ui) = weak.upgrade() {
                INPUT_SCAN_GENERATION.fetch_add(1, Ordering::SeqCst);
                #[cfg(windows)]
                DROP_CONTEXT_GENERATION.fetch_add(1, Ordering::SeqCst);
                let mut current = split_paths(&ui.get_input_paths());
                if index >= 0 && (index as usize) < current.len() {
                    current.remove(index as usize);
                }
                sync_input_ui(&ui, &current);
                if ui.get_selected_tab() == 0 {
                    ui.invoke_analyze_patch();
                } else if ui.get_selected_tab() == 2 {
                    ui.invoke_analyze_extract();
                } else if ui.get_selected_tab() == 3 {
                    ui.invoke_analyze_package();
                }
            }
        });
    }
    {
        let weak = window.as_weak();
        window.on_clear_input(move || {
            if let Some(ui) = weak.upgrade() {
                INPUT_SCAN_GENERATION.fetch_add(1, Ordering::SeqCst);
                #[cfg(windows)]
                DROP_CONTEXT_GENERATION.fetch_add(1, Ordering::SeqCst);
                let tab = ui.get_selected_tab();
                sync_input_ui(&ui, &[]);
                if tab == 0 {
                    ui.invoke_analyze_patch();
                } else if tab == 2 {
                    ui.invoke_analyze_extract();
                } else if tab == 3 {
                    ui.invoke_analyze_package();
                }
            }
        });
    }
    {
        let weak = window.as_weak();
        window.on_choose_patches(move || {
            let Some(files) = rfd::FileDialog::new()
                .add_filter("패치 파일", &["zip", "7z"])
                .pick_files()
            else {
                return;
            };
            if let Some(ui) = weak.upgrade() {
                let mut current = split_paths(&ui.get_patch_paths());
                current.extend(files);
                dedup_paths(&mut current);
                sync_patch_ui(&ui, &current);
            }
        });
    }
    {
        let weak = window.as_weak();
        window.on_choose_patch_folder(move || {
            let Some(folder) = rfd::FileDialog::new().pick_folder() else {
                return;
            };
            if let Some(ui) = weak.upgrade() {
                let mut current = split_paths(&ui.get_patch_paths());
                current.push(folder);
                dedup_paths(&mut current);
                sync_patch_ui(&ui, &current);
            }
        });
    }
    {
        let weak = window.as_weak();
        window.on_remove_patch(move |index| {
            if let Some(ui) = weak.upgrade() {
                let mut current = split_paths(&ui.get_patch_paths());
                if index >= 0 && (index as usize) < current.len() {
                    current.remove(index as usize);
                }
                sync_patch_ui(&ui, &current);
            }
        });
    }
    {
        let weak = window.as_weak();
        window.on_clear_patches(move || {
            if let Some(ui) = weak.upgrade() {
                sync_patch_ui(&ui, &[]);
            }
        });
    }
    {
        let weak = window.as_weak();
        window.on_choose_output(move || {
            let Some(folder) = rfd::FileDialog::new().pick_folder() else {
                return;
            };
            if let Some(ui) = weak.upgrade() {
                ui.set_output_dir(folder.to_string_lossy().replace('\\', "/").into());
            }
        });
    }
    {
        let weak = window.as_weak();
        window.on_choose_title_icon(move || {
            let Some(file) = rfd::FileDialog::new()
                .add_filter("Image", &["png", "jpg", "jpeg", "bmp"])
                .pick_file()
            else {
                return;
            };
            if let Some(ui) = weak.upgrade() {
                match Image::load_from_path(&file) {
                    Ok(image) => {
                        ui.set_title_new_image(image);
                        ui.set_title_has_new_image(true);
                        ui.set_title_icon(file.to_string_lossy().into_owned().into());
                    }
                    Err(err) => {
                        ui.set_status_text(format!("이미지 열기 실패: {err}").into());
                    }
                }
            }
        });
    }
}

fn ui_has_background_analysis(ui: &AppWindow) -> bool {
    ui.get_patch_analyzing()
        || ui.get_title_analyzing()
        || ui.get_extract_analyzing()
        || ui.get_analyze_analyzing()
}

#[derive(Clone)]
struct ExitContext {
    weak: slint::Weak<AppWindow>,
    paths: AppPaths,
    busy: Arc<AtomicBool>,
    cancel: Arc<AtomicBool>,
    config: Arc<Mutex<AppConfig>>,
    states: Arc<Mutex<Vec<TabUiState>>>,
}

impl ExitContext {
    fn is_active(&self, ui: &AppWindow) -> bool {
        self.busy.load(Ordering::SeqCst) || ui_has_background_analysis(ui)
    }

    fn finalize(&self, ui: &AppWindow) {
        if self.busy.load(Ordering::SeqCst) {
            self.cancel.store(true, Ordering::Relaxed);
        }
        if ui.get_analyze_analyzing() {
            ui.invoke_stop_analyze();
        }
        let tab = ui.get_selected_tab().clamp(0, 8);
        persist_settings(ui, tab, &self.config, &self.paths);
        capture_tab_state(ui, &mut self.states.lock()[tab as usize]);
    }

    fn ask_then_exit(&self, ui: &AppWindow) {
        // Never allow another close event to bypass an open modal.
        if ui.get_popup_open() || ui.get_about_open() || ui.get_recovery_open() {
            return;
        }
        let context = self.clone();
        popup_ui::confirm(
            ui,
            "작업 진행 중",
            "현재 작업이 진행 중입니다.\n지금 종료하면 작업이 중단됩니다.\n\n정말 종료하시겠습니까?",
            move |accepted| {
                if accepted && let Some(ui) = context.weak.upgrade() {
                    context.finalize(&ui);
                    let _ = ui.hide();
                }
            },
        );
    }
}

fn wire_window_actions(
    window: &AppWindow,
    paths: AppPaths,
    busy: Arc<AtomicBool>,
    cancel: Arc<AtomicBool>,
    config: Arc<Mutex<AppConfig>>,
    states: Arc<Mutex<Vec<TabUiState>>>,
) {
    {
        let weak = window.as_weak();
        window.on_reset_current(move || {
            if let Some(ui) = weak.upgrade() {
                INPUT_SCAN_GENERATION.fetch_add(1, Ordering::SeqCst);
                #[cfg(windows)]
                DROP_CONTEXT_GENERATION.fetch_add(1, Ordering::SeqCst);
                sync_input_ui(&ui, &[]);
                ui.set_output_dir("".into());
                if ui.get_selected_tab() == 0 {
                    sync_patch_ui(&ui, &[]);
                    ui.set_zip_password("".into());
                    ui.set_required_system_version("".into());
                    ui.set_required_system_version_display("".into());
                    ui.set_patch_current_system_version("".into());
                    ui.set_patch_analysis_text("NSP를 등록하면 자동 분석됩니다.".into());
                    ui.set_patch_analysis_ready(false);
                    ui.set_patch_analyzing(false);
                    ui.set_patch_version_enabled(false);
                }
                if ui.get_selected_tab() == 1 {
                    ui.set_title_english("".into());
                    ui.set_title_japanese("".into());
                    ui.set_title_korean("".into());
                    ui.set_title_icon("".into());
                    ui.set_title_current_image(Image::default());
                    ui.set_title_new_image(Image::default());
                    ui.set_title_has_current_image(false);
                    ui.set_title_has_new_image(false);
                    ui.set_title_analyzing(false);
                    ui.set_title_analysis_done(false);
                }
                if ui.get_selected_tab() == 2 {
                    ui.set_extract_rows(ModelRc::new(VecModel::<TreeRow>::default()));
                    ui.set_extract_analyzing(false);
                }
                if ui.get_selected_tab() == 3 {
                    clear_analyze_ui(&ui);
                }
                ui.set_progress(0.0);
                ui.set_status_text("대기".into());
            }
        });
    }

    let exit_context = ExitContext {
        weak: window.as_weak(),
        paths: paths.clone(),
        busy: busy.clone(),
        cancel: cancel.clone(),
        config: config.clone(),
        states: states.clone(),
    };
    {
        let context = exit_context.clone();
        window.on_exit_app(move || {
            let Some(ui) = context.weak.upgrade() else {
                return;
            };
            if ui.get_popup_open() || ui.get_about_open() || ui.get_recovery_open() {
                return;
            }
            if context.is_active(&ui) {
                context.ask_then_exit(&ui);
                return;
            }
            context.finalize(&ui);
            let _ = ui.hide();
        });
    }

    {
        let context = exit_context;
        window.window().on_close_requested(move || {
            let Some(ui) = context.weak.upgrade() else {
                return CloseRequestResponse::HideWindow;
            };
            if ui.get_popup_open() || ui.get_about_open() || ui.get_recovery_open() {
                return CloseRequestResponse::KeepWindowShown;
            }
            if context.is_active(&ui) {
                context.ask_then_exit(&ui);
                return CloseRequestResponse::KeepWindowShown;
            }
            context.finalize(&ui);
            CloseRequestResponse::HideWindow
        });
    }

    wire_about_dialog(window, &paths.workspace_root);

    update_ui::wire_updates(window, paths, busy, config, states);
}

fn wire_about_dialog(window: &AppWindow, workspace_root: &Path) {
    let about_workspace = workspace_root.to_path_buf();
    let about_window = window.as_weak();
    window.on_show_about(move || {
        if let Some(ui) = about_window.upgrade() {
            ui.set_about_details(
                format!(
                    "NSRP v{APP_VERSION}\n빌드 커밋: {}\n\n작업 디렉터리: {}",
                    updater::build_commit(),
                    about_workspace.display()
                )
                .into(),
            );
            ui.set_about_open(true);
        }
    });
}

fn wire_patch_analyzer(window: &AppWindow, paths: AppPaths) {
    let weak = window.as_weak();
    window.on_analyze_patch(move || {
        let Some(ui) = weak.upgrade() else {
            return;
        };
        let inputs = split_paths(&ui.get_input_paths());
        if inputs.is_empty() {
            ui.set_patch_analyzing(false);
            ui.set_patch_analysis_text("NSP를 등록하면 자동 분석됩니다.".into());
            ui.set_patch_analysis_ready(false);
            ui.set_patch_version_enabled(false);
            ui.set_required_system_version("".into());
            ui.set_required_system_version_display("".into());
            ui.set_patch_current_system_version("".into());
            ui.set_firmware_choices(ModelRc::new(VecModel::<FirmwareChoice>::default()));
            ui.set_firmware_menu_open(false);
            return;
        }
        ui.set_patch_analyzing(true);
        ui.set_patch_analysis_text("분석 중...".into());
        ui.set_patch_analysis_ready(false);
        ui.set_patch_version_enabled(false);
        ui.set_required_system_version("".into());
        ui.set_required_system_version_display("".into());
        ui.set_patch_current_system_version("".into());
        ui.set_progress(0.0);
        ui.set_status_text("입력 파일 분석 중...".into());
        append_log_direct(
            &ui,
            &format!("[안내] 입력 파일 분석 시작 ({}개)", inputs.len()),
        );
        drop(ui);

        let weak_thread = weak.clone();
        let paths_thread = paths.clone();
        thread::spawn(move || {
            let local_cancel = AtomicBool::new(false);
            let result = (|| -> Result<Vec<nsrp::ops::cnmt::CnmtInfo>> {
                let workspace = paths_thread.reset_workspace("patch_analyze")?;
                let mut sink = |_line: String| {};
                patcher::analyze_packages_metadata(
                    &inputs,
                    &workspace,
                    &paths_thread.tool("hactool.exe"),
                    &paths_thread.key("prod.keys"),
                    &local_cancel,
                    &mut sink,
                )
            })();
            let _ = slint::invoke_from_event_loop(move || {
                let Some(ui) = weak_thread.upgrade() else {
                    return;
                };
                let still_current = split_paths(&ui.get_input_paths()) == inputs;
                if !still_current {
                    ui.set_patch_analyzing(false);
                    return;
                }
                ui.set_patch_analyzing(false);
                match result {
                    Ok(cnmts) if !cnmts.is_empty() => {
                        let mut text = String::new();
                        for info in &cnmts {
                            text.push_str(&format!(
                                "[{}] {} v{}\n  ↳ {}\n",
                                info.meta_type.label(),
                                info.title_id,
                                info.version,
                                info.cnmt_nca_name
                            ));
                        }
                        let base = cnmts.iter().find(|info| info.meta_type.label() == "Base");
                        let req = base.map(|info| info.required_system_version).unwrap_or(0);
                        ui.set_patch_analysis_text(text.trim_end().into());
                        ui.set_patch_analysis_ready(true);
                        if req > 0 {
                            let choices = firmware_choices(req);
                            let current_label = choices
                                .first()
                                .map(|choice| choice.label.clone())
                                .unwrap_or_else(|| format!("0x{req:08X} (현재)").into());
                            ui.set_patch_version_enabled(true);
                            ui.set_required_system_version(req.to_string().into());
                            ui.set_patch_current_system_version(req.to_string().into());
                            ui.set_required_system_version_display(current_label);
                            ui.set_firmware_choices(ModelRc::new(VecModel::from(choices)));
                            ui.set_firmware_menu_open(false);
                        } else {
                            ui.set_patch_version_enabled(false);
                            ui.set_required_system_version("".into());
                            ui.set_required_system_version_display("".into());
                            ui.set_patch_current_system_version("".into());
                            ui.set_firmware_choices(ModelRc::new(
                                VecModel::<FirmwareChoice>::default(),
                            ));
                            ui.set_firmware_menu_open(false);
                        }
                        ui.set_progress(1.0);
                        ui.set_status_text("분석 완료".into());
                        append_log_direct(&ui, "[완료] 입력 파일 분석 완료");
                    }
                    Ok(_) => {
                        ui.set_patch_analysis_text(
                            "분석 실패\n사유: CNMT를 찾지 못했습니다.".into(),
                        );
                        ui.set_patch_analysis_ready(false);
                        ui.set_patch_version_enabled(false);
                        ui.set_patch_current_system_version("".into());
                        ui.set_progress(1.0);
                        ui.set_status_text("오류".into());
                    }
                    Err(err) => {
                        ui.set_patch_analysis_text(format!("분석 실패\n사유: {err:#}").into());
                        ui.set_patch_analysis_ready(false);
                        ui.set_patch_version_enabled(false);
                        ui.set_required_system_version("".into());
                        ui.set_required_system_version_display("".into());
                        ui.set_patch_current_system_version("".into());
                        ui.set_firmware_choices(
                            ModelRc::new(VecModel::<FirmwareChoice>::default()),
                        );
                        ui.set_firmware_menu_open(false);
                        ui.set_progress(1.0);
                        ui.set_status_text("오류".into());
                        append_log_direct(&ui, &format!("[오류] 입력 파일 분석 실패: {err:#}"));
                    }
                }
            });
        });
    });
}

fn firmware_value(major: u64, minor: u64, patch: u64) -> u64 {
    (major << 26) | (minor << 20) | (patch << 16)
}

fn firmware_choices(current: u64) -> Vec<FirmwareChoice> {
    const KNOWN: &[(u64, u64, u64)] = &[
        (1, 0, 0),
        (2, 0, 0),
        (2, 1, 0),
        (2, 2, 0),
        (2, 3, 0),
        (3, 0, 0),
        (3, 0, 1),
        (3, 0, 2),
        (4, 0, 0),
        (4, 0, 1),
        (4, 1, 0),
        (5, 0, 0),
        (5, 0, 1),
        (5, 0, 2),
        (5, 1, 0),
        (6, 0, 0),
        (6, 0, 1),
        (6, 1, 0),
        (6, 2, 0),
        (7, 0, 0),
        (7, 0, 1),
        (8, 0, 0),
        (8, 0, 1),
        (8, 1, 0),
        (8, 1, 1),
        (9, 0, 0),
        (9, 0, 1),
        (9, 1, 0),
        (9, 2, 0),
        (10, 0, 0),
        (10, 0, 1),
        (10, 0, 2),
        (10, 0, 3),
        (10, 0, 4),
        (10, 1, 0),
        (10, 1, 1),
        (10, 2, 0),
        (11, 0, 0),
        (11, 0, 1),
        (12, 0, 0),
        (12, 0, 1),
        (12, 0, 2),
        (12, 0, 3),
        (12, 1, 0),
        (13, 0, 0),
        (13, 1, 0),
        (13, 2, 0),
        (13, 2, 1),
        (14, 0, 0),
        (14, 1, 0),
        (14, 1, 1),
        (14, 1, 2),
        (15, 0, 0),
        (15, 0, 1),
        (16, 0, 0),
        (16, 0, 1),
        (16, 0, 2),
        (16, 0, 3),
        (17, 0, 0),
        (17, 0, 1),
        (18, 0, 0),
        (18, 0, 1),
        (18, 1, 0),
        (19, 0, 0),
        (20, 0, 0),
    ];
    let known_current = KNOWN
        .iter()
        .any(|&(a, b, c)| firmware_value(a, b, c) == current);
    let mut out = Vec::new();
    if !known_current {
        out.push(FirmwareChoice {
            label: format!("0x{current:08X} (현재)").into(),
            value: current.to_string().into(),
        });
    }
    for &(major, minor, patch) in KNOWN.iter().rev() {
        let value = firmware_value(major, minor, patch);
        if value > current {
            continue;
        }
        let label = if value == current {
            format!("{major}.{minor}.{patch} (현재)")
        } else {
            format!("{major}.{minor}.{patch}")
        };
        out.push(FirmwareChoice {
            label: label.into(),
            value: value.to_string().into(),
        });
    }
    out
}

fn wire_extract_analyzer(window: &AppWindow) {
    let weak = window.as_weak();
    window.on_analyze_extract(move || {
        let Some(ui) = weak.upgrade() else {
            return;
        };
        let inputs = split_paths(&ui.get_input_paths());
        let Some(input) = inputs.first().cloned() else {
            ui.set_extract_rows(ModelRc::new(VecModel::<TreeRow>::default()));
            ui.set_extract_analyzing(false);
            return;
        };
        ui.set_extract_rows(ModelRc::new(VecModel::<TreeRow>::default()));
        ui.set_extract_analyzing(true);
        ui.set_status_text("구조 분석 중...".into());
        let weak_thread = weak.clone();
        thread::spawn(move || {
            let result = (|| {
                let paths = AppPaths::discover()?;
                let workspace = paths.workspace_for("extract_analyze")?;
                extract::list_display_entries(
                    &input,
                    &workspace,
                    &paths.tool("hactool.exe"),
                    &paths.key("prod.keys"),
                )
            })();
            let _ = slint::invoke_from_event_loop(move || {
                let Some(ui) = weak_thread.upgrade() else {
                    return;
                };
                let still_current = split_paths(&ui.get_input_paths())
                    .first()
                    .is_some_and(|current| current == &input);
                if !still_current {
                    return;
                }
                ui.set_extract_analyzing(false);
                match result {
                    Ok(entries) => {
                        let rows = entries
                            .into_iter()
                            .map(|entry| TreeRow {
                                name: entry.name.into(),
                                size: format_file_size(entry.size).into(),
                                offset: format!("0x{:X}", entry.offset).into(),
                                selected: false,
                            })
                            .collect::<Vec<_>>();
                        ui.set_extract_rows(ModelRc::new(VecModel::from(rows)));
                        ui.set_status_text("대기".into());
                    }
                    Err(err) => {
                        ui.set_extract_rows(ModelRc::new(VecModel::<TreeRow>::default()));
                        sync_input_ui(&ui, &[]);
                        ui.set_status_text("오류".into());
                        append_log_direct(&ui, &format!("[오류] 구조 분석 실패: {err:#}"));
                        popup_ui::notice(
                            &ui,
                            "분석 실패",
                            format!("파일을 읽어오는데 실패했습니다.\n\n{err:#}"),
                        );
                    }
                }
            });
        });
    });
}

fn wire_extract_selection(window: &AppWindow) {
    let weak = window.as_weak();
    window.on_toggle_extract_row(move |index| {
        let Some(ui) = weak.upgrade() else {
            return;
        };
        let model = ui.get_extract_rows();
        if index < 0 || index as usize >= model.row_count() {
            return;
        }
        let mut rows = (0..model.row_count())
            .filter_map(|row| model.row_data(row))
            .collect::<Vec<_>>();
        if let Some(row) = rows.get_mut(index as usize) {
            row.selected = !row.selected;
        }
        ui.set_extract_rows(ModelRc::new(VecModel::from(rows)));
    });
}

fn format_file_size(size: u64) -> String {
    if size >= 1024 * 1024 * 1024 {
        format!("{:.2} GB", size as f64 / (1024.0 * 1024.0 * 1024.0))
    } else if size >= 1024 * 1024 {
        format!("{:.2} MB", size as f64 / (1024.0 * 1024.0))
    } else if size >= 1024 {
        format!("{:.2} KB", size as f64 / 1024.0)
    } else {
        format!("{:.2} B", size as f64)
    }
}

fn clear_analyze_ui(ui: &AppWindow) {
    ui.set_analyze_result_ready(false);
    ui.set_analyze_analyzing(false);
    ui.set_analyze_stop_requested(false);
    ui.set_analyze_inner_tab(0);
    ui.set_analyze_game_title("".into());
    ui.set_analyze_title_id("".into());
    ui.set_analyze_package_type("".into());
    ui.set_analyze_publisher("".into());
    ui.set_analyze_display_version("".into());
    ui.set_analyze_age_rating("".into());
    ui.set_analyze_build_kind("".into());
    ui.set_analyze_languages(ModelRc::new(VecModel::<StandardListViewItem>::default()));
    ui.set_analyze_language_titles(ModelRc::new(VecModel::<SharedString>::default()));
    ui.set_analyze_language_publishers(ModelRc::new(VecModel::<SharedString>::default()));
    ui.set_analyze_icon(Image::default());
    ui.set_analyze_has_icon(false);
    ui.set_analyze_file_rows(ModelRc::new(VecModel::<TreeRow>::default()));
    ui.set_analyze_base_rows(ModelRc::new(VecModel::<ContentRow>::default()));
    ui.set_analyze_update_rows(ModelRc::new(VecModel::<ContentRow>::default()));
    ui.set_analyze_dlc_rows(ModelRc::new(VecModel::<ContentRow>::default()));
}

fn format_system_version_plain(value: u64) -> String {
    if value == 0 {
        return String::new();
    }
    let major = (value >> 26) & 0x3f;
    let minor = (value >> 20) & 0x3f;
    let micro = (value >> 16) & 0x0f;
    if major == 0 && minor == 0 && micro == 0 {
        value.to_string()
    } else {
        format!("{major}.{minor}.{micro}")
    }
}

fn cnmt_build_id(name: &str) -> String {
    let value = name.chars().take(32).collect::<String>();
    if value.len() == 32 && value.chars().all(|ch| ch.is_ascii_hexdigit()) {
        value.to_ascii_uppercase()
    } else {
        String::new()
    }
}

fn content_row(info: &nsrp::ops::cnmt::CnmtInfo) -> ContentRow {
    ContentRow {
        title_id: info.title_id.clone().into(),
        version: info.version.to_string().into(),
        system_version: format_system_version_plain(info.required_system_version).into(),
        build_id: cnmt_build_id(&info.cnmt_nca_name).into(),
    }
}

fn wire_analyze_package(window: &AppWindow, paths: AppPaths) {
    let analyzing = Arc::new(AtomicBool::new(false));
    let analysis_cancel = Arc::new(AtomicBool::new(false));

    {
        let weak = window.as_weak();
        let cancel = analysis_cancel.clone();
        window.on_stop_analyze(move || {
            let Some(ui) = weak.upgrade() else {
                return;
            };
            if !ui.get_analyze_analyzing() || ui.get_analyze_stop_requested() {
                return;
            }
            ui.set_analyze_stop_requested(true);
            ui.set_status_text("중지 요청 중...".into());
            append_log_direct_with_tone(&ui, "[중지 요청] 현재 단계가 끝나는 대로 중단됩니다", 2);
            cancel.store(true, Ordering::Relaxed);
        });
    }

    let weak = window.as_weak();
    let analyzing_cb = analyzing.clone();
    let analysis_cancel_cb = analysis_cancel.clone();
    window.on_analyze_package(move || {
        let Some(ui) = weak.upgrade() else {
            return;
        };
        let inputs = split_paths(&ui.get_input_paths());
        let Some(input) = inputs.first().cloned() else {
            clear_analyze_ui(&ui);
            return;
        };
        if analyzing_cb.swap(true, Ordering::SeqCst) {
            return;
        }
        analysis_cancel_cb.store(false, Ordering::Relaxed);
        clear_analyze_ui(&ui);
        ui.set_analyze_analyzing(true);
        ui.set_analyze_stop_requested(false);
        ui.set_status_text("파일 구조 읽는 중".into());
        ui.set_progress(0.05);
        let basename = input
            .file_name()
            .and_then(|name| name.to_str())
            .unwrap_or("input");
        append_log_direct_with_tone(&ui, &format!("─── 파일 분석 시작: {basename} ───"), 1);
        drop(ui);

        let weak_thread = weak.clone();
        let paths_thread = paths.clone();
        let analyzing_thread = analyzing_cb.clone();
        let cancel_thread = analysis_cancel_cb.clone();
        thread::spawn(move || {
            let weak_progress = weak_thread.clone();
            let result = (|| -> Result<analyze::AnalysisReport> {
                let workspace = paths_thread.reset_workspace("analyze_ui")?;
                analyze::analyze_metadata(
                    &input,
                    &workspace,
                    &paths_thread.tool("hactool.exe"),
                    &paths_thread.key("prod.keys"),
                    cancel_thread.as_ref(),
                    &mut |progress| set_progress(&weak_progress, progress),
                )
            })();
            let cancelled = cancel_thread.load(Ordering::Relaxed);
            analyzing_thread.store(false, Ordering::SeqCst);
            let _ = slint::invoke_from_event_loop(move || {
                let Some(ui) = weak_thread.upgrade() else {
                    return;
                };
                let still_current = split_paths(&ui.get_input_paths())
                    .first()
                    .is_some_and(|current| current == &input);
                if !still_current {
                    return;
                }
                ui.set_analyze_analyzing(false);
                ui.set_analyze_stop_requested(false);
                if cancelled {
                    clear_analyze_ui(&ui);
                    ui.set_status_text("중지됨".into());
                    append_log_direct_with_tone(&ui, "■ 파일 분석이 중지되었습니다", 2);
                    return;
                }
                match result {
                    Ok(report) => {
                        let file_rows = report
                            .entries
                            .iter()
                            .map(|entry| TreeRow {
                                name: entry.name.clone().into(),
                                size: format_file_size(entry.size).into(),
                                offset: format!("0x{:X}", entry.offset).into(),
                                selected: false,
                            })
                            .collect::<Vec<_>>();
                        let base_infos = report
                            .cnmts
                            .iter()
                            .filter(|info| info.meta_type.label() == "Base")
                            .collect::<Vec<_>>();
                        let base_rows = base_infos
                            .iter()
                            .map(|info| content_row(info))
                            .collect::<Vec<_>>();
                        let update_rows = report
                            .cnmts
                            .iter()
                            .filter(|info| info.meta_type.label() == "Update")
                            .max_by_key(|info| info.version)
                            .map(content_row)
                            .into_iter()
                            .collect::<Vec<_>>();
                        let dlc_rows = report
                            .cnmts
                            .iter()
                            .filter(|info| info.meta_type.label() == "DLC")
                            .map(content_row)
                            .collect::<Vec<_>>();
                        let title_id = base_infos
                            .first()
                            .map(|info| info.title_id.clone())
                            .or_else(|| report.cnmts.first().map(|info| info.title_id.clone()))
                            .unwrap_or_default();
                        let mut package_type = if base_infos.len() >= 2 {
                            format!("멀티 {}", report.package_type)
                        } else {
                            report.package_type.clone()
                        };
                        if !report.ncz_mode.is_empty() {
                            package_type = format!("{package_type}  ({} 모드)", report.ncz_mode);
                        }

                        ui.set_analyze_title_id(title_id.into());
                        ui.set_analyze_package_type(package_type.into());
                        ui.set_analyze_file_rows(ModelRc::new(VecModel::from(file_rows)));
                        ui.set_analyze_base_rows(ModelRc::new(VecModel::from(base_rows)));
                        ui.set_analyze_update_rows(ModelRc::new(VecModel::from(update_rows)));
                        ui.set_analyze_dlc_rows(ModelRc::new(VecModel::from(dlc_rows)));

                        if let Some(nacp) = report.nacp {
                            ui.set_analyze_game_title(nacp.primary_title.into());
                            ui.set_analyze_publisher(nacp.primary_publisher.into());
                            ui.set_analyze_display_version(nacp.display_version.into());
                            ui.set_analyze_age_rating(nacp.age_rating.into());
                            ui.set_analyze_build_kind(nacp.build_kind.into());
                            let languages = nacp
                                .languages
                                .iter()
                                .map(|language| {
                                    StandardListViewItem::from(SharedString::from(
                                        language.as_str(),
                                    ))
                                })
                                .collect::<Vec<_>>();
                            ui.set_analyze_languages(ModelRc::new(VecModel::from(languages)));
                            ui.set_analyze_language_titles(ModelRc::new(VecModel::from(
                                nacp.language_titles
                                    .into_iter()
                                    .map(SharedString::from)
                                    .collect::<Vec<_>>(),
                            )));
                            ui.set_analyze_language_publishers(ModelRc::new(VecModel::from(
                                nacp.language_publishers
                                    .into_iter()
                                    .map(SharedString::from)
                                    .collect::<Vec<_>>(),
                            )));
                            if let Some(icon) = nacp.icon_path
                                && let Ok(image) = Image::load_from_path(&icon)
                            {
                                ui.set_analyze_icon(image);
                                ui.set_analyze_has_icon(true);
                            }
                        }
                        ui.set_analyze_inner_tab(0);
                        ui.set_analyze_result_ready(true);
                        ui.set_progress(1.0);
                        ui.set_status_text("대기".into());
                        append_log_direct_with_tone(&ui, "─── 파일 분석 완료 ───", 4);
                    }
                    Err(err) => {
                        clear_analyze_ui(&ui);
                        ui.set_progress(1.0);
                        ui.set_status_text("오류".into());
                        append_log_direct(&ui, &format!("[오류] 분석 실패: {err:#}"));
                        popup_ui::notice(&ui, "분석 실패", format!("파일 분석 실패\n\n{err:#}"));
                    }
                }
            });
        });
    });
}

fn wire_title_analyzer(window: &AppWindow, paths: AppPaths) {
    let analyzing = Arc::new(AtomicBool::new(false));
    let weak = window.as_weak();
    let analyzing_cb = analyzing.clone();
    window.on_analyze_title(move || {
        let Some(ui) = weak.upgrade() else {
            return;
        };
        let inputs = split_paths(&ui.get_input_paths());
        let Some(input) = inputs.first().cloned() else {
            ui.set_status_text("타이틀을 읽을 입력 파일을 선택하세요".into());
            return;
        };
        if analyzing_cb.swap(true, Ordering::SeqCst) {
            return;
        }
        ui.set_title_analyzing(true);
        ui.set_title_analysis_done(false);
        ui.set_title_english("".into());
        ui.set_title_japanese("".into());
        ui.set_title_korean("".into());
        ui.set_title_icon("".into());
        ui.set_title_current_image(Image::default());
        ui.set_title_new_image(Image::default());
        ui.set_title_has_current_image(false);
        ui.set_title_has_new_image(false);
        ui.set_status_text("타이틀 정보 분석 중".into());
        ui.set_progress(0.0);
        append_log_direct_with_tone(
            &ui,
            &format!(
                "─── 타이틀 분석 시작: {} ───",
                input
                    .file_name()
                    .and_then(|name| name.to_str())
                    .unwrap_or("input")
            ),
            1,
        );
        drop(ui);
        let weak_thread = weak.clone();
        let paths_thread = paths.clone();
        let analyzing_thread = analyzing_cb.clone();
        thread::spawn(move || {
            let local_cancel = AtomicBool::new(false);
            let result = (|| -> Result<title::TitleInfo> {
                let workspace = paths_thread.reset_workspace("title_analyze")?;
                title::analyze_title(
                    &input,
                    &workspace,
                    &paths_thread.tool("hactool.exe"),
                    &paths_thread.key("prod.keys"),
                    &local_cancel,
                )
            })();
            analyzing_thread.store(false, Ordering::SeqCst);
            let weak_done = weak_thread.clone();
            let _ = slint::invoke_from_event_loop(move || {
                if let Some(ui) = weak_done.upgrade() {
                    ui.set_title_analyzing(false);
                    match result {
                        Ok(info) => {
                            ui.set_title_english(info.english.into());
                            ui.set_title_japanese(info.japanese.into());
                            ui.set_title_korean(info.korean.into());
                            ui.set_title_analysis_done(true);
                            if let Some(icon) = info.icon_path
                                && let Ok(image) = Image::load_from_path(&icon)
                            {
                                ui.set_title_current_image(image);
                                ui.set_title_has_current_image(true);
                            }
                            ui.set_progress(1.0);
                            ui.set_status_text("대기".into());
                            append_log_direct_with_tone(&ui, "─── 타이틀 분석 완료 ───", 4);
                        }
                        Err(err) => {
                            sync_input_ui(&ui, &[]);
                            ui.set_title_analysis_done(false);
                            ui.set_title_current_image(Image::default());
                            ui.set_title_has_current_image(false);
                            ui.set_progress(1.0);
                            ui.set_status_text("오류".into());
                            append_log_direct(&ui, &format!("[오류] 타이틀 분석 실패: {err:#}"));
                            popup_ui::notice(
                                &ui,
                                "분석 실패",
                                format!("타이틀 정보를 읽어오는데 실패했습니다.\n\n{err:#}"),
                            );
                        }
                    }
                }
            });
        });
    });
}

fn collect_request(ui: &AppWindow, tab: i32) -> Result<OperationRequest> {
    let inputs = split_paths(&ui.get_input_paths());
    if inputs.is_empty() {
        let message = match tab {
            4 => "변환할 파일을 추가하세요.",
            5 => "압축할 파일이 없습니다.",
            6 => "압축 해제할 NSZ / XCZ 파일을 추가하세요.",
            7 => "병합하려면 최소 2개 이상의 파일을 선택하세요.",
            8 => "분할할 파일을 추가하세요.",
            _ => "입력 파일을 선택하세요.",
        };
        bail!(message);
    }
    if tab == 7 && inputs.len() < 2 {
        bail!(
            "병합하려면 최소 2개 이상의 파일을 선택하세요.\n(단일 파일은 이미 통합된 파일이므로 병합할 필요가 없습니다)"
        );
    }
    for input in &inputs {
        if !input.is_file() {
            bail!("입력 파일이 없습니다: {}", input.display());
        }
    }
    let patches = split_paths(&ui.get_patch_paths());
    if tab == 0 && patches.is_empty() {
        bail!("패치 ZIP·7z 또는 폴더를 선택하세요");
    }
    for patch in &patches {
        if !patch.exists() {
            bail!("패치 경로가 없습니다: {}", patch.display());
        }
    }
    let output_dir_explicit = !ui.get_output_dir().trim().is_empty();
    let output_dir = if !output_dir_explicit {
        inputs[0]
            .parent()
            .unwrap_or_else(|| Path::new("."))
            .to_path_buf()
    } else {
        PathBuf::from(ui.get_output_dir().as_str())
    };
    fs::create_dir_all(&output_dir)?;
    let selected_level = ui.get_compression_level().round().clamp(1.0, 23.0) as i32;
    let long_mode = selected_level >= 23;
    let level = selected_level.min(22);
    let selected_threads = ui.get_thread_count().round().clamp(1.0, 64.0) as usize;
    let core_count = ui.get_core_count().max(1) as usize;
    let threads = if selected_threads > core_count {
        if tab == 6 {
            (core_count + 2).min(core_count.saturating_mul(2)).max(1)
        } else {
            core_count
        }
    } else {
        selected_threads
    };
    let selected_system_version = parse_optional_u64(ui.get_required_system_version().as_str())?;
    let current_system_version =
        parse_optional_u64(ui.get_patch_current_system_version().as_str())?;
    let required_system_version = if tab == 0 && selected_system_version == current_system_version {
        None
    } else {
        selected_system_version
    };
    let extract_selected_names = if tab == 2 {
        let rows = ui.get_extract_rows();
        (0..rows.row_count())
            .filter_map(|index| rows.row_data(index))
            .filter(|row| row.selected)
            .map(|row| row.name.to_string())
            .collect()
    } else {
        Vec::new()
    };
    let verify_base_count = if tab == 3 {
        ui.get_analyze_base_rows().row_count()
    } else {
        0
    };
    Ok(OperationRequest {
        tab,
        inputs,
        patches,
        output_dir,
        output_dir_explicit,
        compression: CompressOptions {
            level,
            threads,
            block_mode: ui.get_block_mode(),
            long_mode,
        },
        remove_source: ui.get_remove_source(),
        notify_done: ui.get_notify_done(),
        save_log: ui.get_save_log(),
        compress_after: ui.get_compress_after(),
        use_game_title: ui.get_use_game_title(),
        unpack_nca: ui.get_unpack_nca(),
        extract_selected_names,
        verify_base_count,
        target_format: ui.get_target_format().to_string(),
        zip_password: nonempty(ui.get_zip_password().as_str()),
        required_system_version,
        title_english: nonempty(ui.get_title_english().as_str()),
        title_japanese: nonempty(ui.get_title_japanese().as_str()),
        title_korean: nonempty(ui.get_title_korean().as_str()),
        title_icon: nonempty(ui.get_title_icon().as_str()).map(PathBuf::from),
    })
}

fn per_input_output_dir(request: &OperationRequest, input: &Path) -> PathBuf {
    if request.output_dir_explicit {
        request.output_dir.clone()
    } else {
        input
            .parent()
            .unwrap_or_else(|| Path::new("."))
            .to_path_buf()
    }
}

fn global_compression_options(paths: &AppPaths) -> CompressOptions {
    let cfg = AppConfig::load(&paths.config_path).compressor;
    let core_count = num_cpus::get().max(1);
    let configured_threads = cfg.thread.max(1) as usize;
    let threads = if configured_threads > core_count {
        core_count
    } else {
        configured_threads
    };
    let selected_level = cfg.level.clamp(1, 23);
    CompressOptions {
        level: selected_level.min(22),
        threads,
        block_mode: cfg.block_mode,
        long_mode: selected_level >= 23,
    }
}

fn run_operation(
    request: OperationRequest,
    paths: &AppPaths,
    cancel: &AtomicBool,
    weak: &slint::Weak<AppWindow>,
) -> Result<String> {
    if request.tab == 3 {
        if request.inputs.len() != 1 {
            bail!("헤더 검사는 입력 파일 1개만 선택하세요");
        }
        let progress = |p: f32| set_progress(weak, p.clamp(0.0, 1.0));
        let mut log = |line: String| append_log(weak, line);
        log(format!(
            "─── 헤더 검사 시작: {} ───",
            request.inputs[0]
                .file_name()
                .and_then(|name| name.to_str())
                .unwrap_or("input")
        ));
        analyze::verify_headers(
            &request.inputs[0],
            request.verify_base_count,
            cancel,
            &mut log,
        )?;
        progress(1.0);
        return Ok("헤더 검사 완료".to_owned());
    }

    let prod_keys = paths.key("prod.keys");
    if !prod_keys.is_file() {
        bail!("prod.keys가 없습니다: {}", prod_keys.display());
    }
    let title_keys = paths.key("title.keys");
    let mut keys = KeySet::load(
        &prod_keys,
        title_keys.is_file().then_some(title_keys.as_path()),
    )?;
    let hactool = paths.tool("hactool.exe");
    let global_compression = global_compression_options(paths);
    let mut progress = |p: f32| set_progress(weak, p.clamp(0.0, 1.0));
    let mut log = |line: String| append_log(weak, line);

    match request.tab {
        0 => {
            let out = patcher::patch_packages(
                &request.inputs,
                &request.patches,
                &request.output_dir,
                &paths.resource_dir,
                &hactool,
                &prod_keys,
                &mut keys,
                &PatchOptions {
                    zip_password: request.zip_password.clone(),
                    required_system_version: request.required_system_version,
                    compression: global_compression.clone(),
                },
                cancel,
                &mut progress,
                &mut log,
            )?;
            Ok(format!("패치 완료: {}", out.display()))
        }
        1 => {
            if request.inputs.len() != 1 {
                bail!("타이틀 편집은 입력 파일 1개만 선택하세요");
            }
            let out = title::patch_title(
                &request.inputs[0],
                &request.output_dir,
                &paths.resource_dir,
                &hactool,
                &prod_keys,
                &mut keys,
                &TitlePatch {
                    english: request.title_english.clone(),
                    japanese: request.title_japanese.clone(),
                    korean: request.title_korean.clone(),
                    icon_path: request.title_icon.clone(),
                    compression: global_compression.clone(),
                },
                cancel,
                &mut progress,
                &mut log,
            )?;
            Ok(format!("타이틀 편집 완료: {}", out.display()))
        }
        2 => {
            let extract_workspace = paths.reset_workspace("extract_hactool")?;
            for (i, input) in request.inputs.iter().enumerate() {
                let stem = input
                    .file_stem()
                    .and_then(|s| s.to_str())
                    .unwrap_or("extract");
                let target = request.output_dir.join(format!("[Disassembled] {stem}"));
                let n = request.inputs.len() as f32;
                extract::extract(
                    input,
                    &target,
                    &extract_workspace,
                    &hactool,
                    &prod_keys,
                    &ExtractOptions {
                        selected_names: request.extract_selected_names.clone(),
                        unpack_nca: request.unpack_nca,
                    },
                    cancel,
                    &mut |p| progress((i as f32 + p) / n),
                    &mut log,
                )?;
            }
            Ok(format!("분해 완료: {}개 파일", request.inputs.len()))
        }
        3 => unreachable!("분석 탭 검사는 상단 fast path에서 처리됩니다"),
        4 => {
            let target = if request.target_format.eq_ignore_ascii_case("NSP") {
                TargetFormat::Nsp
            } else if request.target_format.eq_ignore_ascii_case("XCI") {
                TargetFormat::Xci
            } else {
                bail!("지원하지 않는 변환 출력 포맷: {}", request.target_format);
            };
            let count = request.inputs.len() as f32;
            let mut outputs = Vec::new();
            let mut failed = 0usize;
            for (i, input) in request.inputs.iter().enumerate() {
                let item_output_dir = per_input_output_dir(&request, input);
                let result = convert::convert(
                    input,
                    &item_output_dir,
                    &paths.resource_dir,
                    &prod_keys,
                    &mut keys,
                    &ConvertOptions {
                        target,
                        compress_after: request.compress_after,
                        compression: global_compression.clone(),
                    },
                    cancel,
                    &mut |p| progress((i as f32 + p) / count),
                    &mut log,
                );
                match result {
                    Ok(out) => outputs.push(out),
                    Err(err) if cancel.load(Ordering::Relaxed) => return Err(err),
                    Err(err) => {
                        failed += 1;
                        log(format!("  └ [실패] {err:#}"));
                        progress((i + 1) as f32 / count);
                    }
                }
            }
            finish_batch("변환", outputs.len(), failed)
        }
        5 => {
            let count = request.inputs.len() as f32;
            let mut succeeded = 0usize;
            let mut failed = 0usize;
            for (i, input) in request.inputs.iter().enumerate() {
                let item_output_dir = per_input_output_dir(&request, input);
                let ext = extension(input);
                let stem = input
                    .file_stem()
                    .and_then(|s| s.to_str())
                    .unwrap_or("output");
                let result = match ext.as_str() {
                    "nsp" => {
                        if let Ok(added) =
                            merge_ticket_keys_from_nsp_file(input, &paths.key("title.keys"))
                            && added > 0
                        {
                            log(format!("  └ 키 데이터베이스 갱신: {added}개 추가"));
                        }
                        let out = item_output_dir.join(format!("{stem}.nsz"));
                        compress::compress_nsp(
                            input,
                            &out,
                            &mut keys,
                            &request.compression,
                            cancel,
                            &mut |p| progress((i as f32 + p) / count),
                            &mut log,
                        )
                        .map(|_| ())
                    }
                    "xci" => {
                        let out = item_output_dir.join(format!("{stem}.xcz"));
                        xcz::compress_xci(
                            input,
                            &out,
                            &mut keys,
                            &XczOptions {
                                level: request.compression.level,
                                threads: request.compression.threads,
                                block_mode: request.compression.block_mode,
                                long_mode: request.compression.long_mode,
                            },
                            cancel,
                            &mut |p| progress((i as f32 + p) / count),
                            &mut log,
                        )
                        .map(|_| ())
                    }
                    _ => Err(anyhow::anyhow!(
                        "압축 입력은 NSP/XCI만 지원합니다: {}",
                        input.display()
                    )),
                };
                match result {
                    Ok(()) => {
                        succeeded += 1;
                        if request.remove_source
                            && input.exists()
                            && let Err(err) = fs::remove_file(input)
                        {
                            log(format!(
                                "  └ [경고] 원본 삭제 실패: {} ({err})",
                                input
                                    .file_name()
                                    .and_then(|name| name.to_str())
                                    .unwrap_or("input")
                            ));
                        }
                    }
                    Err(err) if cancel.load(Ordering::Relaxed) => return Err(err),
                    Err(err) => {
                        failed += 1;
                        log(format!(
                            "  ✗ {} → 실패 ({err:#})",
                            input
                                .file_name()
                                .and_then(|name| name.to_str())
                                .unwrap_or("input")
                        ));
                        progress((i + 1) as f32 / count);
                    }
                }
            }
            finish_batch("압축", succeeded, failed)
        }
        6 => {
            let count = request.inputs.len() as f32;
            let mut succeeded = 0usize;
            let mut failed = 0usize;
            for (i, input) in request.inputs.iter().enumerate() {
                let item_output_dir = per_input_output_dir(&request, input);
                let ext = extension(input);
                let stem = input
                    .file_stem()
                    .and_then(|s| s.to_str())
                    .unwrap_or("output");
                let result = match ext.as_str() {
                    "nsz" => {
                        let out = item_output_dir.join(format!("{stem}.nsp"));
                        compress::decompress_nsz_repaired(
                            input,
                            &out,
                            &hactool,
                            &prod_keys,
                            cancel,
                            &mut |p| progress((i as f32 + p) / count),
                            &mut log,
                        )
                    }
                    "xcz" => {
                        let out = item_output_dir.join(format!("{stem}.xci"));
                        xcz::decompress_xcz_repaired(
                            input,
                            &out,
                            &hactool,
                            &prod_keys,
                            cancel,
                            &mut |p| progress((i as f32 + p) / count),
                            &mut log,
                        )
                        .map(|_| ())
                    }
                    _ => Err(anyhow::anyhow!(
                        "압축 해제 입력은 NSZ/XCZ만 지원합니다: {}",
                        input.display()
                    )),
                };
                match result {
                    Ok(()) => {
                        succeeded += 1;
                        if request.remove_source
                            && input.exists()
                            && let Err(err) = fs::remove_file(input)
                        {
                            log(format!(
                                "  └ [경고] 원본 삭제 실패: {} ({err})",
                                input
                                    .file_name()
                                    .and_then(|name| name.to_str())
                                    .unwrap_or("input")
                            ));
                        }
                    }
                    Err(err) if cancel.load(Ordering::Relaxed) => return Err(err),
                    Err(err) => {
                        failed += 1;
                        log(format!(
                            "  ✗ {} → 실패 ({err:#})",
                            input
                                .file_name()
                                .and_then(|name| name.to_str())
                                .unwrap_or("input")
                        ));
                        progress((i + 1) as f32 / count);
                    }
                }
            }
            finish_batch("압축 해제", succeeded, failed)
        }
        7 => {
            let format = if request.target_format.eq_ignore_ascii_case("NSP") {
                MergeFormat::Nsp
            } else if request.target_format.eq_ignore_ascii_case("XCI") {
                MergeFormat::Xci
            } else {
                bail!("지원하지 않는 병합 출력 포맷: {}", request.target_format);
            };
            let expected_extension = format.output_extension(request.compress_after);
            log(format!(
                "  └ 선택한 출력: {} / 병합 후 압축: {} → 최종 형식: .{}",
                request.target_format.to_ascii_uppercase(),
                if request.compress_after {
                    "사용"
                } else {
                    "미사용"
                },
                expected_extension.to_ascii_uppercase()
            ));
            let outputs = merge::merge_packages(
                &request.inputs,
                &request.output_dir,
                request.output_dir_explicit,
                &paths.resource_dir,
                &hactool,
                &prod_keys,
                &mut keys,
                &MergeOptions {
                    output_format: format,
                    compress_after: request.compress_after,
                    use_game_title: request.use_game_title,
                    decompression_threads: request.compression.threads,
                    compression: global_compression.clone(),
                },
                cancel,
                &mut progress,
                &mut log,
            )?;
            for path in &outputs {
                if !path
                    .extension()
                    .and_then(|ext| ext.to_str())
                    .is_some_and(|ext| ext.eq_ignore_ascii_case(expected_extension))
                {
                    bail!(
                        "병합 결과 포맷 불일치: 요청한 .{expected_extension} 대신 {}",
                        path.display()
                    );
                }
                log(format!("  └ 생성된 병합 파일: {}", path.display()));
            }
            Ok(format!(
                "병합 완료: {}개 결과 (.{expected_extension})",
                outputs.len()
            ))
        }
        8 => {
            let count = request.inputs.len() as f32;
            let mut output_count = 0usize;
            for (i, input) in request.inputs.iter().enumerate() {
                let item_output_dir = per_input_output_dir(&request, input);
                let outputs = split::split_package(
                    input,
                    &item_output_dir,
                    &hactool,
                    &prod_keys,
                    request.use_game_title,
                    cancel,
                    &mut |p| progress((i as f32 + p) / count),
                    &mut log,
                )?;
                output_count += outputs.len();
            }
            Ok(format!("분할 완료: {output_count}개 패키지"))
        }
        _ => bail!("알 수 없는 탭 번호: {}", request.tab),
    }
}

fn finish_batch(operation: &str, succeeded: usize, failed: usize) -> Result<String> {
    if failed > 0 {
        bail!(
            "{operation} 작업 일부 실패 — 성공 {succeeded}개, 실패 {failed}개. 작업 로그를 확인하세요."
        );
    }
    Ok(format!("{operation} 완료: {succeeded}개 파일"))
}

fn apply_success_cleanup(ui: &AppWindow, tab: i32) {
    match tab {
        0 => {
            sync_input_ui(ui, &[]);
            sync_patch_ui(ui, &[]);
            ui.set_zip_password("".into());
            ui.set_required_system_version("".into());
            ui.set_required_system_version_display("".into());
            ui.set_patch_current_system_version("".into());
            ui.set_patch_analysis_text("NSP를 등록하면 자동 분석됩니다.".into());
            ui.set_patch_analysis_ready(false);
            ui.set_patch_analyzing(false);
            ui.set_patch_version_enabled(false);
            ui.set_progress(0.0);
            ui.set_status_text("대기".into());
            append_log_direct_with_tone(ui, "[안내] 패치 탭이 초기화되었습니다", 0);
        }
        1 => {
            sync_input_ui(ui, &[]);
            ui.set_title_english("".into());
            ui.set_title_japanese("".into());
            ui.set_title_korean("".into());
            ui.set_title_icon("".into());
            ui.set_title_current_image(Image::default());
            ui.set_title_new_image(Image::default());
            ui.set_title_has_current_image(false);
            ui.set_title_has_new_image(false);
            ui.set_title_analyzing(false);
            ui.set_title_analysis_done(false);
            ui.set_progress(0.0);
            ui.set_status_text("대기".into());
            append_log_direct_with_tone(ui, "[안내] 타이틀 탭이 초기화되었습니다", 0);
        }
        2 => {
            ui.set_progress(0.0);
            ui.set_status_text("대기".into());
        }
        3 => {
            ui.set_status_text("대기".into());
        }
        4 => {
            sync_input_ui(ui, &[]);
            ui.set_status_text("대기".into());
        }
        5 | 6 | 8 => {
            sync_input_ui(ui, &[]);
            ui.set_progress(0.0);
            ui.set_status_text("대기".into());
        }
        7 => {
            sync_input_ui(ui, &[]);
            ui.set_status_text("대기".into());
        }
        _ => {
            ui.set_status_text("대기".into());
        }
    }
}

fn operation_error_title(tab: i32) -> &'static str {
    match tab {
        0 => "오류",
        1 => "오류",
        2 => "분해 실패",
        4 => "오류",
        5 => "압축 실패",
        6 => "압축 해제 실패",
        7 => "오류",
        8 => "오류",
        _ => "오류",
    }
}

fn show_input_validation_dialog(ui: &AppWindow, _tab: i32, err: &anyhow::Error) {
    popup_ui::notice(ui, "알림", err.to_string());
}

fn operation_error_message(tab: i32, err: &anyhow::Error) -> String {
    let detail = format!("{err:#}");
    match tab {
        0 => format!("빌드 중 오류가 발생했습니다.\n\n{detail}"),
        1 => format!("타이틀 수정 실패\n\n{detail}"),
        2 => format!("작업 중 오류가 발생했습니다.\n\n{detail}"),
        4 => format!("오류가 발생했습니다.\n\n{detail}"),
        5 => format!("압축 중 오류가 발생했습니다.\n\n{detail}"),
        6 => format!("압축 해제 중 오류가 발생했습니다.\n\n{detail}"),
        7 => format!("병합 중 오류가 발생했습니다.\n\n{detail}"),
        8 => format!("분할 중 오류가 발생했습니다.\n\n{detail}"),
        _ => detail,
    }
}

fn persist_settings(ui: &AppWindow, tab: i32, config: &Arc<Mutex<AppConfig>>, paths: &AppPaths) {
    let mut cfg = config.lock();
    cfg.main.last_tab = tab.clamp(0, 8);
    match tab {
        0 => {
            cfg.patcher.save_log = ui.get_save_log();
            cfg.patcher.notify_done = ui.get_notify_done();
        }
        2 => {
            cfg.extractor.notify_done = ui.get_notify_done();
        }
        5 => {
            cfg.compressor.level = ui.get_compression_level().round().clamp(1.0, 23.0) as i32;
            cfg.compressor.thread = ui.get_thread_count().round().clamp(1.0, 64.0) as i32;
            cfg.compressor.rm_source = ui.get_remove_source();
            cfg.compressor.notify_done = ui.get_notify_done();
            cfg.compressor.block_mode = ui.get_block_mode();
        }
        6 => {
            cfg.decompressor.thread = ui.get_thread_count().round().clamp(1.0, 64.0) as i32;
            cfg.decompressor.rm_source = ui.get_remove_source();
            cfg.decompressor.notify_done = ui.get_notify_done();
        }
        7 => {
            cfg.merger.thread = ui.get_thread_count().round().clamp(1.0, 64.0) as i32;
            cfg.merger.notify_done = ui.get_notify_done();
            cfg.merger.output_format = ui.get_target_format().to_ascii_lowercase();
            cfg.merger.compress_after = ui.get_compress_after();
            cfg.merger.fetch_title = ui.get_use_game_title();
        }
        _ => {}
    }
    if let Err(err) = cfg.save(&paths.config_path) {
        append_log_direct_with_tone(
            ui,
            &format!("[경고] 설정 저장 실패 — 기존 설정은 보존했습니다: {err:#}"),
            2,
        );
    }
}

fn set_progress(weak: &slint::Weak<AppWindow>, value: f32) {
    if !value.is_finite() {
        return;
    }
    let value = value.clamp(0.0, 1.0);
    let bucket = (value * 200.0).round() as u32;
    // At most 201 distinct visible updates per operation, instead of
    // posting thousands of per-buffer callbacks into Slint's event loop.
    if LAST_PROGRESS_BUCKET.swap(bucket, Ordering::Relaxed) == bucket {
        return;
    }
    let weak = weak.clone();
    let _ = slint::invoke_from_event_loop(move || {
        if let Some(ui) = weak.upgrade() {
            ui.set_progress(value);
        }
    });
}

fn set_status(weak: &slint::Weak<AppWindow>, text: &str) {
    let weak = weak.clone();
    let text = text.to_owned();
    let _ = slint::invoke_from_event_loop(move || {
        if let Some(ui) = weak.upgrade() {
            ui.set_status_text(text.into());
        }
    });
}

fn append_log(weak: &slint::Weak<AppWindow>, line: String) {
    let weak = weak.clone();
    let _ = slint::invoke_from_event_loop(move || {
        if let Some(ui) = weak.upgrade() {
            append_log_direct(&ui, &line);
        }
    });
}

fn append_log_direct(ui: &AppWindow, line: &str) {
    append_log_direct_with_tone(ui, line, infer_log_tone(line));
}

fn append_log_direct_with_tone(ui: &AppWindow, line: &str, tone: i32) {
    let time = current_log_time();
    let existing = ui.get_log_rows();
    let leading_blank = line.starts_with('\n');
    let mut new_rows = Vec::new();
    if leading_blank {
        new_rows.push(LogRow {
            text: SharedString::new(),
            tone: 0,
        });
    }
    let normalized = line.trim_start_matches('\n');
    for segment in normalized.split('\n') {
        if segment.is_empty() {
            continue;
        }
        new_rows.push(LogRow {
            text: format!("[{time}] {segment}").into(),
            tone,
        });
    }
    if let Some(model) = existing.as_any().downcast_ref::<VecModel<LogRow>>() {
        model.extend(new_rows);
        if model.row_count() > 3000 {
            let start = model.row_count().saturating_sub(2500);
            let retained = (start..model.row_count())
                .filter_map(|index| model.row_data(index))
                .collect::<Vec<_>>();
            model.set_vec(retained);
        }
    } else {
        ui.set_log_rows(ModelRc::new(VecModel::from(new_rows)));
    }

    let formatted = if leading_blank {
        format!("\n[{time}] {}", line.trim_start_matches('\n'))
    } else {
        format!("[{time}] {line}")
    };
    FULL_LOG_BUFFER.with(|buffer| {
        let mut buffer = buffer.borrow_mut();
        if !buffer.is_empty() {
            buffer.push('\n');
        }
        buffer.push_str(&formatted);
    });
}

fn log_snapshot() -> String {
    FULL_LOG_BUFFER.with(|buffer| buffer.borrow().clone())
}

fn infer_log_tone(line: &str) -> i32 {
    let trimmed = line.trim_start();
    if trimmed.starts_with("[오류]") {
        3
    } else if trimmed.starts_with("[경고]") || trimmed.starts_with('■') {
        2
    } else if trimmed.starts_with("[완료]") || trimmed.starts_with('✓') {
        4
    } else {
        0
    }
}

#[cfg(windows)]
fn current_log_time() -> String {
    use windows::Win32::System::SystemInformation::GetLocalTime;
    let now = unsafe { GetLocalTime() };
    format!("{:02}:{:02}:{:02}", now.wHour, now.wMinute, now.wSecond)
}

#[cfg(not(windows))]
fn current_log_time() -> String {
    "00:00:00".to_owned()
}

#[derive(Clone, Copy)]
struct ResourceSample {
    working_set: usize,
    cpu_100ns: u64,
}

fn start_resource_timer(window: &AppWindow) -> slint::Timer {
    let timer = slint::Timer::default();
    let weak = window.as_weak();
    let previous = Rc::new(RefCell::new(None::<(u64, Instant)>));
    timer.start(
        slint::TimerMode::Repeated,
        Duration::from_secs(2),
        move || {
            let Some(sample) = query_resource_sample() else {
                return;
            };
            let now = Instant::now();
            let old = *previous.borrow();
            let cpu_percent = old
                .map(|(old_cpu, old_time)| {
                    let elapsed = now.duration_since(old_time).as_secs_f64();
                    if elapsed <= 0.0 {
                        0.0
                    } else {
                        sample.cpu_100ns.saturating_sub(old_cpu) as f64 / (elapsed * 10_000_000.0)
                            * 100.0
                    }
                })
                .unwrap_or(0.0);
            *previous.borrow_mut() = Some((sample.cpu_100ns, now));
            if let Some(ui) = weak.upgrade() {
                let text = format!(
                    "RAM: {:.1} MB  |  CPU: {:.1}%",
                    sample.working_set as f64 / 1_048_576.0,
                    cpu_percent
                );
                let python_width_compensation = if sample.working_set < 100 * 1_048_576 {
                    1
                } else {
                    0
                };
                ui.set_resource_char_count(text.chars().count() as i32 + python_width_compensation);
                ui.set_resource_text(text.into());
            }
        },
    );
    timer
}

#[cfg(windows)]
fn query_resource_sample() -> Option<ResourceSample> {
    use windows::Win32::{
        Foundation::FILETIME,
        System::{
            ProcessStatus::{GetProcessMemoryInfo, PROCESS_MEMORY_COUNTERS},
            Threading::{GetCurrentProcess, GetProcessTimes},
        },
    };

    fn filetime_value(value: FILETIME) -> u64 {
        ((value.dwHighDateTime as u64) << 32) | value.dwLowDateTime as u64
    }

    unsafe {
        let process = GetCurrentProcess();
        let mut memory = PROCESS_MEMORY_COUNTERS {
            cb: std::mem::size_of::<PROCESS_MEMORY_COUNTERS>() as u32,
            ..Default::default()
        };
        GetProcessMemoryInfo(process, &mut memory, memory.cb).ok()?;

        let mut creation = FILETIME::default();
        let mut exit = FILETIME::default();
        let mut kernel = FILETIME::default();
        let mut user = FILETIME::default();
        GetProcessTimes(process, &mut creation, &mut exit, &mut kernel, &mut user).ok()?;
        Some(ResourceSample {
            working_set: memory.WorkingSetSize,
            cpu_100ns: filetime_value(kernel).saturating_add(filetime_value(user)),
        })
    }
}

#[cfg(not(windows))]
fn query_resource_sample() -> Option<ResourceSample> {
    None
}
fn path_list_model(paths: &[PathBuf]) -> ModelRc<StandardListViewItem> {
    let items = paths
        .iter()
        .map(|path| {
            StandardListViewItem::from(SharedString::from(
                path.to_string_lossy().replace('\\', "/"),
            ))
        })
        .collect::<Vec<_>>();
    ModelRc::new(VecModel::from(items))
}

fn sync_input_ui(ui: &AppWindow, paths: &[PathBuf]) {
    ui.set_input_paths(join_paths(paths).into());
    ui.set_input_items(path_list_model(paths));
    ui.set_input_current(-1);
}

fn sync_patch_ui(ui: &AppWindow, paths: &[PathBuf]) {
    ui.set_patch_paths(join_paths(paths).into());
    ui.set_patch_items(path_list_model(paths));
    ui.set_patch_current(-1);
}

fn is_single_input_tab(tab: i32) -> bool {
    matches!(tab, 1..=3)
}

fn allowed_input_extensions(tab: i32) -> &'static [&'static str] {
    match tab {
        5 => &["nsp", "xci"],
        6 => &["nsz", "xcz"],
        _ => &["nsp", "nsz", "xci", "xcz"],
    }
}

fn split_paths(value: &str) -> Vec<PathBuf> {
    value
        .split(['|', '\n'])
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(PathBuf::from)
        .collect()
}

fn join_paths(paths: &[PathBuf]) -> String {
    paths
        .iter()
        .map(|p| p.to_string_lossy())
        .collect::<Vec<_>>()
        .join("|")
}

fn dedup_paths(paths: &mut Vec<PathBuf>) {
    let mut seen = std::collections::HashSet::with_capacity(paths.len());
    paths.retain(|p| seen.insert(p.to_string_lossy().to_lowercase()));
}

fn nonempty(value: &str) -> Option<String> {
    let value = value.trim();
    (!value.is_empty()).then(|| value.to_owned())
}

fn parse_optional_u64(value: &str) -> Result<Option<u64>> {
    let value = value.trim();
    if value.is_empty() {
        return Ok(None);
    }
    let parsed = if let Some(hex) = value
        .strip_prefix("0x")
        .or_else(|| value.strip_prefix("0X"))
    {
        u64::from_str_radix(hex, 16).context("시스템 버전 16진수 형식 오류")?
    } else {
        value
            .parse::<u64>()
            .context("시스템 버전은 10진수 또는 0x16진수로 입력하세요")?
    };
    Ok(Some(parsed))
}

fn extension(path: &Path) -> String {
    path.extension()
        .and_then(|s| s.to_str())
        .unwrap_or("")
        .to_ascii_lowercase()
}

fn tab_name(tab: i32) -> &'static str {
    match tab {
        0 => "패치",
        1 => "타이틀",
        2 => "분해",
        3 => "분석",
        4 => "변환",
        5 => "압축",
        6 => "압축 해제",
        7 => "병합",
        8 => "분할",
        _ => "작업",
    }
}

#[cfg(test)]
mod stage75_status_footer_tests {
    // Slint privately nests the footer components, so lock down their shared
    // sizing contract in addition to the pixel-level Windows screenshot QA.
    #[test]
    fn stage75_status_progress_and_cpu_ram_share_21px_center_line() {
        let ui = include_str!("../ui/main.slint");
        let resource = ui
            .split("component ResourceLabel inherits Rectangle {")
            .nth(1)
            .expect("ResourceLabel must not use a separately sized HorizontalLayout")
            .split("component PathBox")
            .next()
            .unwrap();
        assert!(resource.contains("height: 21px;"));
        assert!(resource.contains("height: parent.height;"));
        assert!(resource.contains("y: 2px;"));
        assert!(resource.contains("vertical-alignment: center;"));
        assert!(!resource.contains("height: 16px;"));

        let progress = ui
            .split("component StatusProgress inherits Rectangle {")
            .nth(1)
            .expect("Missing footer progress component")
            .split("component ResourceLabel")
            .next()
            .unwrap();
        assert!(progress.contains("height: 21px;"));
        assert!(progress.contains("y: (parent.height - 14px) / 2;"));

        let footer = ui
            .split("height: 21px; background: #f0f0f0; border-width: 0px;")
            .nth(1)
            .expect("Missing footer row")
            .split("if root.menu-open")
            .next()
            .unwrap();
        assert!(footer.contains("height: parent.height;"));
        assert!(footer.contains("Text { height: 21px; text: root.status-text;"));
        assert!(footer.contains("StatusProgress { width: 180px;"));
        assert!(footer.contains("ResourceLabel { text: root.resource-text;"));
    }
}

#[cfg(test)]
mod stage73_batch_outcome_tests {
    use super::*;

    #[test]
    fn stage73_partial_or_all_failed_batch_cannot_report_success() {
        assert_eq!(finish_batch("압축", 2, 0).unwrap(), "압축 완료: 2개 파일");
        for (success, failed) in [(0, 1), (1, 2), (4, 1)] {
            let result = finish_batch("압축 해제", success, failed);
            assert!(
                result.is_err(),
                "A partially failing batch was reported as success"
            );
            let message = result.unwrap_err().to_string();
            assert!(message.contains(&format!("성공 {success}개")));
            assert!(message.contains(&format!("실패 {failed}개")));
        }
    }
}

#[cfg(all(test, windows))]
mod about_ui_tests {
    use super::*;
    use std::cell::Cell;

    #[test]
    #[ignore = "Run alone: Slint/Winit GUI backend allows one event-loop instance per process"]
    fn stage74_title_logo_original_and_replacement_top_edge_clicks_align() -> Result<()> {
        let ui = AppWindow::new()?;
        let fixture = tempfile::tempdir()?;
        let input = fixture.path().join("title-preview.nsp");
        fs::write(&input, b"UI fixture only")?;
        sync_input_ui(&ui, &[input]);

        let clicks = Rc::new(Cell::new(0usize));
        let captured = clicks.clone();
        ui.on_choose_title_icon(move || captured.set(captured.get() + 1));

        for scale in [1.0_f32, 1.25, 1.5] {
            ui.window()
                .dispatch_event(slint::platform::WindowEvent::ScaleFactorChanged {
                    scale_factor: scale,
                });
            ui.window()
                .dispatch_event(slint::platform::WindowEvent::Resized {
                    size: slint::LogicalSize::new(1400.0, 760.0),
                });
            ui.set_selected_tab(1);
            ui.set_title_analyzing(false);
            ui.set_busy(false);
            ui.set_title_has_new_image(true);

            let click = |x, y| {
                let position = slint::LogicalPosition::new(x, y);
                ui.window()
                    .dispatch_event(slint::platform::WindowEvent::PointerMoved { position });
                ui.window()
                    .dispatch_event(slint::platform::WindowEvent::PointerPressed {
                        position,
                        button: slint::platform::PointerEventButton::Left,
                    });
                ui.window()
                    .dispatch_event(slint::platform::WindowEvent::PointerReleased {
                        position,
                        button: slint::platform::PointerEventButton::Left,
                    });
            };
            // The title tab begins at window y=67. Both 175px previews now
            // start at local y=218, so they must accept clicks at window
            // y=291; the old destination started 12px lower and missed it.
            let initial = clicks.get();
            click(105.0, 291.0); // Source preview, near top edge.
            click(320.0, 291.0); // Destination preview, same top edge.
            click(105.0, 370.0); // Source preview, middle.
            click(320.0, 370.0); // Destination preview, middle.
            assert_eq!(
                clicks.get(),
                initial + 4,
                "Original/replacement logo click regions differ at {scale}x"
            );
            click(230.0, 370.0); // Arrow must not open a file chooser.
            assert_eq!(
                clicks.get(),
                initial + 4,
                "Arrow should not behave like a logo preview at {scale}x"
            );
        }
        Ok(())
    }

    #[test]
    #[ignore = "Run alone: Slint/Winit GUI backend allows one event-loop instance per process"]
    fn stage72_merge_format_radio_and_compression_checkbox_pointer_regression() -> Result<()> {
        let ui = AppWindow::new()?;
        let temp = tempfile::tempdir()?;
        let input_a = temp.path().join("base.nsp");
        let input_b = temp.path().join("update.nsp");
        fs::write(&input_a, b"test-base")?;
        fs::write(&input_b, b"test-update")?;
        sync_input_ui(&ui, &[input_a, input_b]);
        ui.set_output_dir(
            temp.path()
                .join("output")
                .to_string_lossy()
                .to_string()
                .into(),
        );
        ui.set_core_count(8);
        ui.set_thread_count(2.0);
        for scale in [1.0_f32, 1.25, 1.5] {
            ui.window()
                .dispatch_event(slint::platform::WindowEvent::ScaleFactorChanged {
                    scale_factor: scale,
                });
            ui.window()
                .dispatch_event(slint::platform::WindowEvent::Resized {
                    size: slint::LogicalSize::new(1400.0, 760.0),
                });
            let click = |x, y| {
                let position = slint::LogicalPosition::new(x, y);
                ui.window()
                    .dispatch_event(slint::platform::WindowEvent::PointerMoved { position });
                ui.window()
                    .dispatch_event(slint::platform::WindowEvent::PointerPressed {
                        position,
                        button: slint::platform::PointerEventButton::Left,
                    });
                ui.window()
                    .dispatch_event(slint::platform::WindowEvent::PointerReleased {
                        position,
                        button: slint::platform::PointerEventButton::Left,
                    });
            };
            ui.set_selected_tab(7);
            ui.set_target_format("XCI".into());
            ui.set_compress_after(false);
            click(111.0, 579.0);
            assert_eq!(
                ui.get_target_format().as_str(),
                "NSP",
                "Merge NSP click, {scale}x"
            );
            click(230.0, 579.0);
            assert!(ui.get_compress_after(), "Merge compress check, {scale}x");
            let nsz_request = collect_request(&ui, 7)?;
            assert_eq!(nsz_request.target_format, "NSP");
            assert!(nsz_request.compress_after);
            assert_eq!(
                MergeFormat::Nsp.output_extension(nsz_request.compress_after),
                "nsz",
                "NSP + compress must pass NSZ to worker at {scale}x"
            );
            click(160.0, 579.0);
            assert_eq!(
                ui.get_target_format().as_str(),
                "XCI",
                "Merge XCI click, {scale}x"
            );
            let xcz_request = collect_request(&ui, 7)?;
            assert_eq!(xcz_request.target_format, "XCI");
            assert_eq!(
                MergeFormat::Xci.output_extension(xcz_request.compress_after),
                "xcz",
                "XCI + compress must pass XCZ to worker at {scale}x"
            );
            click(111.0, 579.0);
            assert_eq!(
                ui.get_target_format().as_str(),
                "NSP",
                "Merge NSP reselect, {scale}x"
            );
            assert!(
                ui.get_compress_after(),
                "Compression unexpectedly reset, {scale}x"
            );
            let mut remembered = TabUiState::default();
            capture_tab_state(&ui, &mut remembered);
            ui.set_target_format("XCI".into());
            ui.set_compress_after(false);
            apply_tab_state(&ui, &remembered);
            assert_eq!(
                ui.get_target_format().as_str(),
                "NSP",
                "Tab restore, {scale}x"
            );
            assert!(
                ui.get_compress_after(),
                "Tab restored compression flag, {scale}x"
            );
            click(230.0, 579.0);
            assert!(!ui.get_compress_after(), "Uncheck compression, {scale}x");
            let nsp_request = collect_request(&ui, 7)?;
            assert_eq!(
                MergeFormat::Nsp.output_extension(nsp_request.compress_after),
                "nsp",
                "NSP without compression must remain NSP at {scale}x"
            );
            click(160.0, 579.0);
            let xci_request = collect_request(&ui, 7)?;
            assert_eq!(
                MergeFormat::Xci.output_extension(xci_request.compress_after),
                "xci",
                "XCI without compression must remain XCI at {scale}x"
            );
            // Conversion uses the same legacy radio assets and must not
            // regress into a permanently NSP-looking selector either.
            ui.set_selected_tab(4);
            ui.set_target_format("XCI".into());
            ui.set_compress_after(false);
            click(120.0, 579.0);
            assert_eq!(
                ui.get_target_format().as_str(),
                "NSP",
                "Conversion NSP click at {scale}x"
            );
            click(237.0, 579.0);
            assert!(
                ui.get_compress_after(),
                "Conversion compress click at {scale}x"
            );
            click(167.0, 579.0);
            assert_eq!(
                ui.get_target_format().as_str(),
                "XCI",
                "Conversion XCI click at {scale}x"
            );
        }
        Ok(())
    }

    #[test]
    #[ignore = "Run alone: Slint/Winit GUI backend allows one event-loop instance per process"]
    fn stage69_menubar_hover_switches_open_dropdown_without_click() -> Result<()> {
        let ui = AppWindow::new()?;
        wire_about_dialog(&ui, Path::new("C:\\NSRP_Menu_Hover_Test"));

        for factor in [1.0_f32, 1.25, 1.5] {
            ui.window()
                .dispatch_event(slint::platform::WindowEvent::ScaleFactorChanged {
                    scale_factor: factor,
                });
            ui.window()
                .dispatch_event(slint::platform::WindowEvent::Resized {
                    size: slint::LogicalSize::new(1400.0, 760.0),
                });

            let move_to = |x, y| {
                ui.window()
                    .dispatch_event(slint::platform::WindowEvent::PointerMoved {
                        position: slint::LogicalPosition::new(x, y),
                    });
            };
            let click = |x, y| {
                let position = slint::LogicalPosition::new(x, y);
                ui.window()
                    .dispatch_event(slint::platform::WindowEvent::PointerPressed {
                        position,
                        button: slint::platform::PointerEventButton::Left,
                    });
                ui.window()
                    .dispatch_event(slint::platform::WindowEvent::PointerReleased {
                        position,
                        button: slint::platform::PointerEventButton::Left,
                    });
            };

            ui.set_menu_open(0);
            move_to(220.0, 110.0);
            move_to(20.0, 10.0);
            assert_eq!(
                ui.get_menu_open(),
                0,
                "Hover alone opened a menu at {factor}"
            );

            // Open File by clicking, then move right to Help and left again.
            click(20.0, 10.0);
            assert_eq!(ui.get_menu_open(), 1, "File click at {factor}");
            move_to(65.0, 10.0);
            assert_eq!(ui.get_menu_open(), 2, "File -> Help hover at {factor}");
            move_to(20.0, 10.0);
            assert_eq!(ui.get_menu_open(), 1, "Help -> File hover at {factor}");
            move_to(65.0, 10.0);
            assert_eq!(
                ui.get_menu_open(),
                2,
                "File -> Help repeat hover at {factor}"
            );

            // Clicking the active title and the backdrop still closes it.
            click(65.0, 10.0);
            assert_eq!(
                ui.get_menu_open(),
                0,
                "Active title did not close at {factor}"
            );
            move_to(20.0, 10.0);
            assert_eq!(
                ui.get_menu_open(),
                0,
                "Closed menu reopened on hover at {factor}"
            );
            click(20.0, 10.0);
            assert_eq!(ui.get_menu_open(), 1);
            click(300.0, 220.0);
            assert_eq!(ui.get_menu_open(), 0, "Backdrop did not close at {factor}");

            // Switching the menu must also expose Help's actual submenu
            // actions, rather than just changing the top bar highlight.
            click(20.0, 10.0);
            move_to(65.0, 10.0);
            click(105.0, 72.0); // Help > About (not in File's dropdown).
            assert_eq!(ui.get_menu_open(), 0);
            assert!(
                ui.get_about_open(),
                "Help submenu did not switch at {factor}"
            );
            ui.set_about_open(false);
        }
        Ok(())
    }

    #[test]
    #[ignore = "Run alone: Slint/Winit GUI backend allows one event-loop instance per process"]
    fn stage63_help_about_opens_slint_attribution_dialog() -> Result<()> {
        let ui = AppWindow::new()?;
        popup_ui::wire(&ui);
        // A deliberately long workspace path exercises the scrollable About
        // detail area instead of only the short default test path.
        let workspace = PathBuf::from(format!(
            "C:\\NSRP_Stage63_ReadOnly_UI_Test\\{}",
            "long_workspace_directory_name\\".repeat(10)
        ));
        wire_about_dialog(&ui, &workspace);

        assert!(!ui.get_about_open(), "About dialog must start closed");
        for factor in [1.0_f32, 1.25, 1.5] {
            ui.window()
                .dispatch_event(slint::platform::WindowEvent::ScaleFactorChanged {
                    scale_factor: factor,
                });
            ui.window()
                .dispatch_event(slint::platform::WindowEvent::Resized {
                    size: slint::LogicalSize::new(1400.0, 760.0),
                });
            ui.invoke_show_about();
            assert!(
                ui.get_about_open(),
                "Help > About must open at scale {factor}"
            );
            let details = ui.get_about_details().to_string();
            assert!(details.contains(&format!("NSRP v{APP_VERSION}")));
            assert!(details.contains(&workspace.to_string_lossy().to_string()));

            let click = |position: slint::LogicalPosition| {
                ui.window()
                    .dispatch_event(slint::platform::WindowEvent::PointerPressed {
                        position,
                        button: slint::platform::PointerEventButton::Left,
                    });
                ui.window()
                    .dispatch_event(slint::platform::WindowEvent::PointerReleased {
                        position,
                        button: slint::platform::PointerEventButton::Left,
                    });
            };

            // The 620x440 dialog remains modal like the native Windows
            // confirmations; clicking the backdrop must not dismiss it.
            click(slint::LogicalPosition::new(20.0, 700.0));
            assert!(
                ui.get_about_open(),
                "Backdrop dismissed the dialog at scale {factor}"
            );

            // Top-right Windows-style titlebar X.
            click(slint::LogicalPosition::new(985.0, 180.0));
            assert!(
                !ui.get_about_open(),
                "Caption close button failed at scale {factor}"
            );

            // The bottom confirmation button must remain clickable with
            // the official AboutSlint widget displayed immediately above.
            ui.invoke_show_about();
            assert!(ui.get_about_open());
            click(slint::LogicalPosition::new(940.0, 573.0));
            assert!(
                !ui.get_about_open(),
                "Bottom OK button failed at scale {factor}"
            );

            // Stage 68: notifications and Yes/No prompts share the same
            // white caption/footer widgets as About. Queued prompts must
            // not overwrite one another or allow backdrop click-through.
            let decisions = Rc::new(RefCell::new(Vec::<bool>::new()));
            popup_ui::notice(
                &ui,
                "알림",
                format!(
                    "오류 메시지와 긴 파일 경로:\n{}",
                    "C:\\very-long\\path\\".repeat(150)
                ),
            );
            assert!(ui.get_popup_open(), "notice did not open at {factor}");
            assert_eq!(ui.get_popup_title(), "알림", "notice title at {factor}");
            assert!(!ui.get_popup_confirm(), "notice should be OK-only");

            let rejected = decisions.clone();
            popup_ui::confirm(
                &ui,
                "업데이트 설치",
                "확인하시겠습니까?",
                move |yes| {
                    rejected.borrow_mut().push(yes);
                },
            );
            assert_eq!(ui.get_popup_title(), "알림", "queue replaced notice");
            click(slint::LogicalPosition::new(20.0, 700.0));
            assert!(ui.get_popup_open(), "backdrop leaked at {factor}");
            // Titlebar X closes only the notice, then advances FIFO.
            click(slint::LogicalPosition::new(985.0, 207.0));
            assert!(ui.get_popup_open(), "queued Yes/No not displayed");
            assert_eq!(ui.get_popup_title(), "업데이트 설치");
            assert!(ui.get_popup_confirm());

            // '아니요' is a negative answer; it must never run the Yes path.
            click(slint::LogicalPosition::new(839.0, 542.0));
            assert!(!ui.get_popup_open(), "No button did not close at {factor}");
            assert_eq!(&*decisions.borrow(), &[false]);

            let approved = decisions.clone();
            popup_ui::confirm(&ui, "종료 확인", "테스트 중", move |yes| {
                approved.borrow_mut().push(yes);
            });
            click(slint::LogicalPosition::new(941.0, 542.0));
            assert!(!ui.get_popup_open(), "Yes button did not close at {factor}");
            assert_eq!(&*decisions.borrow(), &[false, true]);

            let dismissed = decisions.clone();
            popup_ui::confirm(&ui, "중단 확인", "테스트 중", move |yes| {
                dismissed.borrow_mut().push(yes);
            });
            click(slint::LogicalPosition::new(985.0, 207.0));
            // A stray duplicate click must not deliver a second response.
            ui.invoke_popup_response(true);
            assert!(!ui.get_popup_open(), "X button did not close at {factor}");
            assert_eq!(&*decisions.borrow(), &[false, true, false]);
        }
        Ok(())
    }
}

#[cfg(all(test, windows))]
mod instance_guard_tests {
    use super::*;

    #[test]
    fn prevents_duplicate_processes_and_releases_instance_guard() -> Result<()> {
        let name = format!("Local\\NSRP_Stage9_Mutex_Test_{}", std::process::id());
        let wide = name
            .encode_utf16()
            .chain(std::iter::once(0))
            .collect::<Vec<_>>();
        let mutex_name = windows::core::PCWSTR(wide.as_ptr());
        let first = try_instance_guard(mutex_name)?.expect("first instance must acquire guard");
        assert!(try_instance_guard(mutex_name)?.is_none());
        drop(first);
        assert!(try_instance_guard(mutex_name)?.is_some());
        Ok(())
    }
}
