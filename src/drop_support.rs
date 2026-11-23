//! Classify file-manager drops independently of the GUI event backend.
//! Pixel positions are *logical* Slint client coordinates, not screen pixels.
use std::path::Path;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DropDestination {
    InputFile,
    InputDirectory,
    Patch,
    OutputDirectory,
    TitleIcon,
    Unsupported,
}

/// Both Shell WM_DROPFILES and Winit drop points are physical client
/// pixels. The fixed Slint hit rectangles use logical client points,
/// and Slint's effective scale can differ from the Windows DPI.
pub fn client_physical_to_logical(x: i32, y: i32, scale: f32) -> (i32, i32) {
    let effective = if scale.is_finite() && scale >= 0.1 {
        f64::from(scale)
    } else {
        1.0
    };
    (
        (f64::from(x) / effective).round() as i32,
        (f64::from(y) / effective).round() as i32,
    )
}

/// Validate a Windows client pixel before converting it to a Slint logical
/// point. In particular, do not invent the old (100,120) input target when
/// OLE cannot provide a valid client drop location.
pub fn bounded_client_physical_to_logical(
    x: i32,
    y: i32,
    width: i32,
    height: i32,
    scale: f32,
) -> Option<(i32, i32)> {
    if width <= 0
        || height <= 0
        || x < 0
        || y < 0
        || x >= width
        || y >= height
        || !scale.is_finite()
        || scale < 0.1
    {
        return None;
    }
    Some(client_physical_to_logical(x, y, scale))
}

pub fn classify_drop(tab: i32, path: &Path, x: i32, y: i32) -> DropDestination {
    let extension = path
        .extension()
        .and_then(|ext| ext.to_str())
        .unwrap_or("")
        .to_ascii_lowercase();
    let is_dir = path.is_dir();

    // The output row is common to every tab. It is below the main list and
    // above the action buttons (with a little room for DPI rounding).
    if is_dir && (25..=825).contains(&x) && (592..=646).contains(&y) {
        return DropDestination::OutputDirectory;
    }
    // The title editor accepts images on its logo previews only, not
    // on its unrelated language fields. Tab content starts at client
    // x=12/y=57; the preview bounds are Slint-local (20,218)..(195,393)
    // and (273,230)..(448,405). Allow small border/DPI rounding.
    let on_title_preview = ((27..=212).contains(&x) && (270..=455).contains(&y))
        || ((280..=465).contains(&x) && (282..=467).contains(&y));
    if tab == 1
        && on_title_preview
        && path.is_file()
        && matches!(extension.as_str(), "png" | "jpg" | "jpeg" | "bmp")
    {
        return DropDestination::TitleIcon;
    }
    if tab == 0 {
        let in_patch_region = (25..=825).contains(&x) && (251..=413).contains(&y);
        // ZIP/7z archives are patch sources, not package files, regardless of landing
        // point. A folder is a patch only when dropped on the patch panel.
        if path.is_file() && matches!(extension.as_str(), "zip" | "7z") || is_dir && in_patch_region
        {
            return DropDestination::Patch;
        }
    }
    if is_dir {
        return DropDestination::InputDirectory;
    }
    if !path.is_file() {
        return DropDestination::Unsupported;
    }
    let valid = match tab {
        5 => matches!(extension.as_str(), "nsp" | "xci"),
        6 => matches!(extension.as_str(), "nsz" | "xcz"),
        0..=4 | 7..=8 => matches!(extension.as_str(), "nsp" | "xci" | "nsz" | "xcz"),
        _ => false,
    };
    if valid {
        DropDestination::InputFile
    } else {
        DropDestination::Unsupported
    }
}

pub fn sort_package_paths(paths: &mut [std::path::PathBuf]) {
    // sort_by_cached_key avoids allocating a lowercase path on every
    // comparison (an O(N log N) allocation hotspot for large folders).
    paths.sort_by_cached_key(|path| path.to_string_lossy().to_lowercase());
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn windows_drop_routes_file_folder_patch_and_output() {
        let qa = tempfile::tempdir().unwrap();
        let nsp = qa.path().join("게임.NSP");
        let nsz = qa.path().join("압축.NSZ");
        let zip = qa.path().join("한글패치.ZIP");
        let sevenz = qa.path().join("한글패치.7Z");
        let png = qa.path().join("한글.png");
        std::fs::write(&nsp, b"x").unwrap();
        std::fs::write(&nsz, b"x").unwrap();
        std::fs::write(&zip, b"x").unwrap();
        std::fs::write(&sevenz, b"x").unwrap();
        std::fs::write(&png, b"x").unwrap();

        assert_eq!(classify_drop(0, &nsp, 400, 130), DropDestination::InputFile);
        assert_eq!(classify_drop(0, &zip, 400, 130), DropDestination::Patch);
        assert_eq!(classify_drop(0, &sevenz, 400, 130), DropDestination::Patch);
        assert_eq!(classify_drop(0, &sevenz, 400, 310), DropDestination::Patch);
        assert_eq!(
            classify_drop(1, &sevenz, 400, 130),
            DropDestination::Unsupported
        );
        assert_eq!(
            classify_drop(0, qa.path(), 400, 310),
            DropDestination::Patch
        );
        assert_eq!(
            classify_drop(0, qa.path(), 400, 130),
            DropDestination::InputDirectory
        );
        assert_eq!(
            classify_drop(0, qa.path(), 400, 620),
            DropDestination::OutputDirectory
        );
        assert_eq!(classify_drop(1, &png, 160, 310), DropDestination::TitleIcon);
        assert_eq!(classify_drop(1, &png, 310, 345), DropDestination::TitleIcon);
        assert_eq!(
            classify_drop(1, &png, 160, 180),
            DropDestination::Unsupported
        );
        assert_eq!(
            classify_drop(1, &png, 560, 310),
            DropDestination::Unsupported
        );
        assert_eq!(classify_drop(1, &nsp, 100, 115), DropDestination::InputFile);
        assert_eq!(
            classify_drop(5, &nsz, 100, 115),
            DropDestination::Unsupported
        );
        assert_eq!(
            classify_drop(6, &nsp, 100, 115),
            DropDestination::Unsupported
        );
        assert_eq!(classify_drop(8, &nsz, 100, 115), DropDestination::InputFile);
    }

    #[test]
    fn case_insensitive_package_sort_and_unicode_names() {
        let mut names = vec![
            "Zeta.nsp".into(),
            "alpha.nsp".into(),
            "가나다.nsp".into(),
            "BETA.nsp".into(),
        ];
        sort_package_paths(&mut names);
        assert_eq!(
            names,
            vec![
                std::path::PathBuf::from("alpha.nsp"),
                "BETA.nsp".into(),
                "Zeta.nsp".into(),
                "가나다.nsp".into()
            ]
        );
    }

    #[test]
    fn stage58_client_physical_to_logical_dpi_round_trip() {
        assert_eq!(client_physical_to_logical(400, 620, 1.0), (400, 620));
        assert_eq!(client_physical_to_logical(500, 775, 1.25), (400, 620));
        assert_eq!(client_physical_to_logical(600, 930, 1.5), (400, 620));
        assert_eq!(client_physical_to_logical(200, 388, 1.25), (160, 310));
        assert_eq!(client_physical_to_logical(-25, -50, 1.25), (-20, -40));
        for bad in [0.0, -1.0, f32::NAN, f32::INFINITY] {
            assert_eq!(client_physical_to_logical(400, 620, bad), (400, 620));
        }
    }

    #[test]
    fn stage58_scaled_drop_hit_targets_do_not_confuse_output_and_patch() {
        let qa = tempfile::tempdir().unwrap();
        let zip = qa.path().join("patch.zip");
        let icon = qa.path().join("icon.png");
        std::fs::write(&zip, b"qa").unwrap();
        std::fs::write(&icon, b"qa").unwrap();
        for scale in [1.0, 1.25, 1.5] {
            let hit = |x: i32, y: i32| {
                client_physical_to_logical(
                    (x as f32 * scale).round() as i32,
                    (y as f32 * scale).round() as i32,
                    scale,
                )
            };
            let (x, y) = hit(400, 620);
            assert_eq!(
                classify_drop(0, qa.path(), x, y),
                DropDestination::OutputDirectory,
                "output panel must remain selectable at effective scale {scale}"
            );
            let (x, y) = hit(400, 310);
            assert_eq!(classify_drop(0, qa.path(), x, y), DropDestination::Patch);
            assert_eq!(classify_drop(0, &zip, x, y), DropDestination::Patch);
            let (x, y) = hit(160, 310);
            assert_eq!(classify_drop(1, &icon, x, y), DropDestination::TitleIcon);
            let (x, y) = hit(160, 180);
            assert_eq!(classify_drop(1, &icon, x, y), DropDestination::Unsupported);
        }
    }

    #[test]
    fn stage59_bounded_windows_client_points_for_all_common_scales() {
        for scale in [1.0f32, 1.25, 1.5] {
            let width = (1400.0 * scale).round() as i32;
            let height = (760.0 * scale).round() as i32;
            for (x, y) in [(400, 120), (400, 310), (400, 620), (160, 310)] {
                let physical_x = (x as f32 * scale).round() as i32;
                let physical_y = (y as f32 * scale).round() as i32;
                assert_eq!(
                    bounded_client_physical_to_logical(
                        physical_x, physical_y, width, height, scale
                    ),
                    Some((x, y)),
                    "client physical-to-logical at {scale}"
                );
            }
            for (x, y) in [(-1, 310), (400, -1), (width, 310), (400, height)] {
                assert_eq!(
                    bounded_client_physical_to_logical(x, y, width, height, scale),
                    None,
                    "non-client location must not be imported at {scale}"
                );
            }
        }
        for bad_scale in [0.0, -1.0, f32::NAN, f32::INFINITY] {
            assert_eq!(
                bounded_client_physical_to_logical(400, 120, 1400, 760, bad_scale),
                None,
                "invalid scaling must not invent a drop target"
            );
        }
        assert_eq!(
            bounded_client_physical_to_logical(400, 120, 0, 760, 1.0),
            None
        );
        assert_eq!(
            bounded_client_physical_to_logical(400, 120, 1400, -1, 1.0),
            None
        );
    }
}
