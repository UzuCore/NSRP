//! Owned Win32 file-drop subclass and Winit OLE bridge.
//!
//! Kept separate from main.rs so runtime processing, UI startup, and
//! platform-specific HWND handling stay easy to audit independently.
use super::*;

// ScreenToClient is in user32.dll, but windows 0.61 gates its generated
// projection behind optional GDI features unrelated to file drops.
#[cfg(windows)]
#[link(name = "user32")]
unsafe extern "system" {
    fn ScreenToClient(
        hwnd: *mut core::ffi::c_void,
        point: *mut windows::Win32::Foundation::POINT,
    ) -> i32;
}

#[cfg(windows)]
unsafe extern "system" fn file_drop_subclass_proc(
    hwnd: windows::Win32::Foundation::HWND,
    message: u32,
    wparam: windows::Win32::Foundation::WPARAM,
    lparam: windows::Win32::Foundation::LPARAM,
    _subclass_id: usize,
    _ref_data: usize,
) -> windows::Win32::Foundation::LRESULT {
    use std::{ffi::OsString, os::windows::ffi::OsStringExt};
    use windows::Win32::{
        Foundation::{POINT, RECT},
        UI::{
            Shell::{DefSubclassProc, DragFinish, DragQueryFileW, DragQueryPoint, HDROP},
            WindowsAndMessaging::{GetClientRect, WM_DPICHANGED, WM_DROPFILES},
        },
    };

    if message == WM_DPICHANGED
        && gui_scale::prevent_offscreen_dpi_change(hwnd, (wparam.0 & 0xffff) as u32)
    {
        // Retain the existing visible window instead of forwarding the
        // OS's oversized suggested RECT to the fixed-size Slint layout.
        return windows::Win32::Foundation::LRESULT(0);
    }
    if message == WM_DROPFILES {
        let hdrop = HDROP(wparam.0 as *mut core::ffi::c_void);
        let mut point = POINT::default();
        let in_client = unsafe { DragQueryPoint(hdrop, &mut point) }.as_bool();
        let mut bounds = RECT::default();
        let scale = f32::from_bits(NATIVE_DROP_SCALE_BITS.load(Ordering::Relaxed));
        let position = if in_client && unsafe { GetClientRect(hwnd, &mut bounds) }.is_ok() {
            bounded_client_physical_to_logical(
                point.x,
                point.y,
                bounds.right - bounds.left,
                bounds.bottom - bounds.top,
                scale,
            )
        } else {
            None
        };
        let Some((x, y)) = position else {
            // The title bar and non-client decorations are not drop
            // targets, nor are forged coordinates outside the client.
            // Always release the Shell's HDROP exactly once.
            unsafe { DragFinish(hdrop) };
            return windows::Win32::Foundation::LRESULT(0);
        };
        let count = unsafe { DragQueryFileW(hdrop, u32::MAX, None) };
        let mut paths = Vec::with_capacity(count as usize);
        for index in 0..count {
            let length = unsafe { DragQueryFileW(hdrop, index, None) };
            if length == 0 {
                continue;
            }
            let mut buffer = vec![0u16; length as usize + 1];
            let written = unsafe { DragQueryFileW(hdrop, index, Some(&mut buffer)) };
            if written > 0 {
                paths.push(PathBuf::from(OsString::from_wide(
                    &buffer[..written as usize],
                )));
            }
        }
        unsafe { DragFinish(hdrop) };
        if !paths.is_empty()
            && let Some(sender) = DROP_SENDER.get()
        {
            let _ = sender.send(NativeDropPayload {
                paths,
                x,
                y,
                context_generation: DROP_CONTEXT_GENERATION.load(Ordering::SeqCst),
                source: NativeDropSource::Shell,
            });
        }
        return windows::Win32::Foundation::LRESULT(0);
    }
    unsafe { DefSubclassProc(hwnd, message, wparam, lparam) }
}

#[cfg(windows)]
const OLE_BATCH_IDLE: Duration = Duration::from_millis(160);

/// Winit raises one OLE DroppedFile event per file in a single gesture.
/// Never merge two complete Shell WM_DROPFILES messages, nearby but distinct
/// hit targets, or files from before a tab/input reset. The time boundary is
/// checked *before* merging, including when both payloads arrive in the same
/// 60ms UI timer tick.
#[cfg(windows)]
fn same_ole_gesture(
    previous: &NativeDropPayload,
    next: &NativeDropPayload,
    idle_since_last: Duration,
) -> bool {
    previous.source == NativeDropSource::Ole
        && next.source == NativeDropSource::Ole
        && previous.context_generation == next.context_generation
        && previous.x == next.x
        && previous.y == next.y
        && idle_since_last < OLE_BATCH_IDLE
}

#[cfg(windows)]
fn enable_native_file_drop(window: &AppWindow) -> bool {
    use slint::winit_030::{
        WinitWindowAccessor,
        winit::raw_window_handle::{HasWindowHandle, RawWindowHandle},
    };
    use windows::{
        Win32::Foundation::HWND,
        Win32::UI::Shell::{DragAcceptFiles, SetWindowSubclass},
    };
    // Never subclass another NSRP process' window by searching its title.
    // Bind legacy WM_DROPFILES support to this exact Winit window instead.
    let hwnd = window
        .window()
        .with_winit_window(|native| {
            let raw = native.window_handle().ok()?.as_raw();
            match raw {
                RawWindowHandle::Win32(handle) => {
                    Some(HWND(handle.hwnd.get() as *mut core::ffi::c_void))
                }
                _ => None,
            }
        })
        .flatten();
    let Some(hwnd) = hwnd else {
        return false;
    };
    let installed =
        unsafe { SetWindowSubclass(hwnd, Some(file_drop_subclass_proc), 0x4E535250, 0).as_bool() };
    if installed {
        // Only enable legacy WM_DROPFILES once its handler is installed.
        unsafe { DragAcceptFiles(hwnd, true) };
    }
    installed
}

#[cfg(windows)]
pub(super) fn schedule_native_file_drop_subclass(
    window: slint::Weak<AppWindow>,
    attempts_remaining: u8,
) {
    slint::Timer::single_shot(Duration::from_millis(150), move || {
        let Some(window) = window.upgrade() else {
            return;
        };
        NATIVE_DROP_SCALE_BITS.store(window.window().scale_factor().to_bits(), Ordering::Relaxed);
        if enable_native_file_drop(&window) {
            return;
        }
        if attempts_remaining > 0 {
            schedule_native_file_drop_subclass(window.as_weak(), attempts_remaining - 1);
        } else {
            append_log_direct_with_tone(
                &window,
                "Win32 파일 드롭 보조 처리기를 등록하지 못했습니다. 일반 탐색기 드롭을 확인하세요.",
                2,
            );
        }
    });
}

#[cfg(windows)]
pub(super) fn start_native_file_drop_bridge(window: &AppWindow) -> slint::Timer {
    use slint::winit_030::{EventResult, WinitWindowAccessor, winit::event::WindowEvent};

    let (sender, receiver) = std::sync::mpsc::channel::<NativeDropPayload>();
    let _ = DROP_SENDER.set(sender.clone());
    let weak_hover = window.as_weak();

    // winit has already registered an OLE IDropTarget for this window.
    // Explorer delivers normal file drops through WindowEvent::DroppedFile,
    // NOT through the legacy WM_DROPFILES message alone.
    window
        .window()
        .on_winit_window_event(move |slint_window, event| {
            NATIVE_DROP_SCALE_BITS.store(slint_window.scale_factor().to_bits(), Ordering::Relaxed);
            match event {
                WindowEvent::DroppedFile(path) => {
                    use slint::winit_030::winit::raw_window_handle::{
                        HasWindowHandle, RawWindowHandle,
                    };
                    use windows::Win32::{
                        Foundation::{HWND, POINT, RECT},
                        UI::WindowsAndMessaging::{GetClientRect, GetCursorPos},
                    };

                    // OLE/Winit emits a path without a drop position. Read the
                    // real Win32 client coordinate from this exact HWND; the
                    // native Winit inner-window offset is not a substitute for
                    // ScreenToClient on mixed DPI/Windows chrome layouts.
                    let position = slint_window
                        .with_winit_window(|winit_window| {
                            let raw = winit_window.window_handle().ok()?.as_raw();
                            let RawWindowHandle::Win32(handle) = raw else {
                                return None;
                            };
                            let hwnd = HWND(handle.hwnd.get() as *mut core::ffi::c_void);
                            let mut point = POINT::default();
                            let mut bounds = RECT::default();
                            unsafe {
                                GetCursorPos(&mut point).ok()?;
                                if ScreenToClient(hwnd.0, &raw mut point) == 0 {
                                    return None;
                                }
                                GetClientRect(hwnd, &mut bounds).ok()?;
                            }
                            bounded_client_physical_to_logical(
                                point.x,
                                point.y,
                                bounds.right - bounds.left,
                                bounds.bottom - bounds.top,
                                slint_window.scale_factor(),
                            )
                        })
                        .flatten();
                    let Some((x, y)) = position else {
                        // No guessed default position: a missing or invalid
                        // pointer must not import an input file by accident.
                        if let Some(ui) = weak_hover.upgrade() {
                            ui.set_status_text(
                                "드롭 위치가 창 밖이거나 확인되지 않아 등록하지 않았습니다".into(),
                            );
                        }
                        return EventResult::Propagate;
                    };
                    let _ = sender.send(NativeDropPayload {
                        paths: vec![path.clone()],
                        x,
                        y,
                        context_generation: DROP_CONTEXT_GENERATION.load(Ordering::SeqCst),
                        source: NativeDropSource::Ole,
                    });
                }
                WindowEvent::HoveredFile(_) => {
                    if let Some(ui) = weak_hover.upgrade()
                        && !ui.get_busy()
                        && !ui_has_background_analysis(&ui)
                    {
                        ui.set_status_text("파일/폴더를 놓으면 현재 탭에 등록됩니다".into());
                    }
                }
                WindowEvent::CursorLeft { .. } | WindowEvent::HoveredFileCancelled => {
                    if let Some(ui) = weak_hover.upgrade()
                        && ui.get_status_text().as_str()
                            == "파일/폴더를 놓으면 현재 탭에 등록됩니다"
                    {
                        ui.set_status_text("대기".into());
                    }
                }
                _ => {}
            }
            EventResult::Propagate
        });

    let weak = window.as_weak();
    let timer = slint::Timer::default();
    let mut pending: Option<NativeDropPayload> = None;
    let mut last_received = Instant::now();
    timer.start(
        slint::TimerMode::Repeated,
        Duration::from_millis(60),
        move || {
            if let Some(ui) = weak.upgrade() {
                NATIVE_DROP_SCALE_BITS
                    .store(ui.window().scale_factor().to_bits(), Ordering::Relaxed);
            }
            // A tab change, input reset or user-started operation invalidates
            // queued OLE files before they can be routed into a different UI.
            let current_generation = DROP_CONTEXT_GENERATION.load(Ordering::SeqCst);
            if pending
                .as_ref()
                .is_some_and(|p| p.context_generation != current_generation)
            {
                pending = None;
            }
            while let Ok(payload) = receiver.try_recv() {
                let now = Instant::now();
                if let Some(previous) = &mut pending
                    && same_ole_gesture(previous, &payload, now.duration_since(last_received))
                {
                    previous.paths.extend(payload.paths);
                    last_received = now;
                    continue;
                }
                if let Some(previous) = pending.take()
                    && let Some(ui) = weak.upgrade()
                {
                    apply_native_drop(&ui, previous);
                }
                if payload.source == NativeDropSource::Shell {
                    // A Shell message already contains the complete file
                    // selection. Do not leave it waiting for OLE event bursts.
                    if let Some(ui) = weak.upgrade() {
                        apply_native_drop(&ui, payload);
                    }
                } else {
                    pending = Some(payload);
                    last_received = now;
                }
            }
            // Winit emits one DroppedFile event for every file. Group a
            // complete drag before triggering expensive package analysis.
            if last_received.elapsed() >= OLE_BATCH_IDLE
                && let Some(payload) = pending.take()
                && let Some(ui) = weak.upgrade()
            {
                apply_native_drop(&ui, payload);
            }
        },
    );
    timer
}

#[cfg(all(test, windows))]
mod stage60_tests {
    use super::*;

    fn payload(source: NativeDropSource, generation: u64, x: i32, y: i32) -> NativeDropPayload {
        NativeDropPayload {
            paths: vec![PathBuf::from("example.nsp")],
            x,
            y,
            context_generation: generation,
            source,
        }
    }

    #[test]
    fn stage60_ole_event_batch_only_matches_one_gesture() {
        let a = payload(NativeDropSource::Ole, 9, 400, 310);
        let b = payload(NativeDropSource::Ole, 9, 400, 310);
        assert!(same_ole_gesture(&a, &b, Duration::from_millis(0)));
        assert!(same_ole_gesture(&a, &b, Duration::from_millis(159)));
        assert!(!same_ole_gesture(&a, &b, Duration::from_millis(160)));
        assert!(!same_ole_gesture(&a, &b, Duration::from_millis(161)));
        assert!(!same_ole_gesture(
            &a,
            &payload(NativeDropSource::Ole, 10, 400, 310),
            Duration::from_millis(1)
        ));
    }

    #[test]
    fn stage60_shell_and_nearby_different_targets_never_coalesce() {
        let ole = payload(NativeDropSource::Ole, 4, 400, 413);
        let nearby = payload(NativeDropSource::Ole, 4, 400, 420);
        assert!(!same_ole_gesture(&ole, &nearby, Duration::from_millis(1)));
        let shell = payload(NativeDropSource::Shell, 4, 400, 413);
        assert!(!same_ole_gesture(&shell, &ole, Duration::from_millis(1)));
        assert!(!same_ole_gesture(&ole, &shell, Duration::from_millis(1)));
        assert!(!same_ole_gesture(&shell, &shell, Duration::from_millis(1)));
        // Do not subtract i32 coordinates: the old +/-24 check could
        // overflow for malformed extreme positions in a debug build.
        assert!(!same_ole_gesture(
            &payload(NativeDropSource::Ole, 4, i32::MIN, 0),
            &payload(NativeDropSource::Ole, 4, i32::MAX, 0),
            Duration::from_millis(1)
        ));
    }
}
