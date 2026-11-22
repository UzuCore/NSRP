//! Initial Windows UI scaling for the legacy 1400x760 Slint layout.
//!
//! A 150%-scaled 1400x760 layout can exceed a 1920x1080 work area.
//! Limit effective scale only when the primary monitor requires it.
use std::sync::atomic::{AtomicBool, Ordering};
use windows::Win32::{
    Foundation::{HWND, RECT},
    UI::WindowsAndMessaging::{
        SPI_GETWORKAREA, SYSTEM_PARAMETERS_INFO_UPDATE_FLAGS, SystemParametersInfoW,
    },
};

const LOGICAL_WIDTH: f64 = 1400.0;
const LOGICAL_HEIGHT: f64 = 760.0;
// Measured 16x39 Windows decorations, padded conservatively.
const CHROME_WIDTH: f64 = 24.0;
const CHROME_HEIGHT: f64 = 47.0;
const MIN_LEGIBLE_SCALE: f64 = 0.80;
static EXPLICIT_SCALE_OVERRIDE: AtomicBool = AtomicBool::new(false);

#[repr(C)]
struct MonitorInfo {
    cb_size: u32,
    rc_monitor: RECT,
    rc_work: RECT,
    flags: u32,
}

#[link(name = "user32")]
unsafe extern "system" {
    fn GetDpiForSystem() -> u32;
    fn SetProcessDpiAwarenessContext(value: isize) -> i32;
    fn MonitorFromWindow(hwnd: *mut core::ffi::c_void, flags: u32) -> *mut core::ffi::c_void;
    fn GetMonitorInfoW(monitor: *mut core::ffi::c_void, info: *mut MonitorInfo) -> i32;
}

/// The fully absolute-positioned legacy UI cannot fit at a scale whose
/// 1400x760 minimum exceeds a monitor's physical work area.
fn window_exceeds_work_area(scale: f64, width: f64, height: f64) -> bool {
    scale.is_finite()
        && scale > 0.0
        && width.is_finite()
        && height.is_finite()
        && (LOGICAL_WIDTH * scale + CHROME_WIDTH > width
            || LOGICAL_HEIGHT * scale + CHROME_HEIGHT > height)
}

/// Last-resort guard for a *runtime* WM_DPICHANGED. The startup scale
/// adjustment cannot prevent Winit from accepting the OS's suggested
/// 2100+-pixel window rectangle later, and no Slint API currently
/// changes the whole legacy absolute layout into a scrollable view.
/// When the native DPI would make controls inaccessible, preserve the
/// current rendered size rather than accepting an off-screen window.
///
/// This is a conservative visibility fallback, not independent
/// per-monitor DPI correctness or a complete responsive redesign.
pub(crate) fn prevent_offscreen_dpi_change(hwnd: HWND, dpi_x: u32) -> bool {
    if EXPLICIT_SCALE_OVERRIDE.load(Ordering::Relaxed) || dpi_x == 0 {
        return false;
    }
    // SAFETY: hwnd is the exact Slint application HWND already subclassed
    // for native file drops. MONITOR_DEFAULTTONEAREST=2 finds the monitor
    // closest to the active app without changing any display properties.
    let monitor = unsafe { MonitorFromWindow(hwnd.0, 2) };
    if monitor.is_null() {
        return false;
    }
    let mut info = MonitorInfo {
        cb_size: std::mem::size_of::<MonitorInfo>() as u32,
        rc_monitor: RECT::default(),
        rc_work: RECT::default(),
        flags: 0,
    };
    // SAFETY: GetMonitorInfoW populates the complete C-layout struct,
    // which remains valid until the call returns.
    if unsafe { GetMonitorInfoW(monitor, &raw mut info) } == 0 {
        return false;
    }
    window_exceeds_work_area(
        f64::from(dpi_x) / 96.0,
        f64::from(info.rc_work.right - info.rc_work.left),
        f64::from(info.rc_work.bottom - info.rc_work.top),
    )
}

/// Returns a lower effective UI scale only if the window cannot fit.
fn choose_scale(native: f64, work_width: f64, work_height: f64) -> Option<f64> {
    if !native.is_finite() || !work_width.is_finite() || !work_height.is_finite() || native <= 0.0 {
        return None;
    }
    let width_limit = (work_width - CHROME_WIDTH) / LOGICAL_WIDTH;
    let height_limit = (work_height - CHROME_HEIGHT) / LOGICAL_HEIGHT;
    let capped = ((width_limit.min(height_limit)) * 20.0).floor() / 20.0;
    if capped < MIN_LEGIBLE_SCALE || capped >= native - f64::EPSILON {
        None
    } else {
        Some(capped)
    }
}

/// Run before Slint or background threads. Never change Windows DPI
/// preferences or override an explicitly supplied SLINT_SCALE_FACTOR.
pub(crate) fn configure_initial_scale() {
    if std::env::var_os("SLINT_SCALE_FACTOR").is_some() {
        EXPLICIT_SCALE_OVERRIDE.store(true, Ordering::Relaxed);
        return;
    }
    // Winit normally enables per-monitor DPI awareness when it starts,
    // which is too late for querying physical work-area dimensions here.
    // Set the same mode before the query. A predeclared manifest may
    // already have set it, in which case Windows simply rejects this
    // redundant request and the current context remains unchanged.
    // SAFETY: Called before any window or thread; no HWND is affected.
    unsafe {
        if SetProcessDpiAwarenessContext(-4) == 0 {
            let _ = SetProcessDpiAwarenessContext(-3);
        }
    }
    let mut work = RECT::default();
    // SAFETY: SPI_GETWORKAREA reads the work area into the valid RECT.
    let result = unsafe {
        SystemParametersInfoW(
            SPI_GETWORKAREA,
            0,
            Some((&raw mut work).cast()),
            SYSTEM_PARAMETERS_INFO_UPDATE_FLAGS(0),
        )
    };
    if result.is_err() {
        return;
    }
    // SAFETY: Windows 10+ user32 GetDpiForSystem takes no pointers.
    let native = f64::from(unsafe { GetDpiForSystem() }) / 96.0;
    let width = f64::from(work.right - work.left);
    let height = f64::from(work.bottom - work.top);
    if let Some(scale) = choose_scale(native, width, height) {
        // SAFETY: Main thread startup; Slint and worker threads are not
        // created yet, so no concurrent environment access exists.
        unsafe { std::env::set_var("SLINT_SCALE_FACTOR", format!("{scale:.2}")) };
    }
}

#[cfg(test)]
mod tests {
    use super::{choose_scale, window_exceeds_work_area};

    #[test]
    fn stage56_150_percent_1920x1080_desktop_fits_its_work_area() {
        assert_eq!(choose_scale(1.0, 1920.0, 1032.0), None);
        assert_eq!(choose_scale(1.25, 1920.0, 1032.0), None);
        assert_eq!(choose_scale(1.5, 1920.0, 1032.0), Some(1.25));
    }

    #[test]
    fn stage56_large_screen_and_low_resolution_are_conservative() {
        assert_eq!(choose_scale(1.5, 2560.0, 1440.0), None);
        assert_eq!(choose_scale(1.0, 1366.0, 728.0), Some(0.85));
        assert_eq!(choose_scale(1.5, 800.0, 570.0), None);
    }

    #[test]
    fn stage56_invalid_work_areas_cannot_override_native_scale() {
        assert_eq!(choose_scale(1.5, f64::NAN, 1032.0), None);
        assert_eq!(choose_scale(f64::INFINITY, 1920.0, 1032.0), None);
        assert_eq!(choose_scale(0.0, 1920.0, 1032.0), None);
    }

    #[test]
    fn stage57_runtime_dpi_change_must_not_push_legacy_controls_offscreen() {
        assert!(!window_exceeds_work_area(1.0, 1920.0, 1032.0));
        assert!(!window_exceeds_work_area(1.25, 1920.0, 1032.0));
        assert!(window_exceeds_work_area(1.5, 1920.0, 1032.0));
        assert!(!window_exceeds_work_area(1.5, 2560.0, 1440.0));
        assert!(window_exceeds_work_area(1.0, 800.0, 570.0));
        assert!(!window_exceeds_work_area(0.0, 1920.0, 1032.0));
        assert!(!window_exceeds_work_area(f64::NAN, 1920.0, 1032.0));
    }
}
