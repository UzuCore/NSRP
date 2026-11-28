use anyhow::{Context, Result};
use std::{
    env, fs,
    io::{Read, Write},
    path::{Path, PathBuf},
};

const HACTOOL_EXE: &[u8] = include_bytes!("../bin/hactool.exe");
const HACTOOLNET_EXE: &[u8] = include_bytes!("../bin/hactoolnet.exe");
const HACBUILD_EXE: &[u8] = include_bytes!("../bin/hacbuild.exe");
const GAME_INFO_PRESET: &[u8] = include_bytes!("../bin/game_info_preset.ini");
const LIBHAC_LICENSE: &[u8] = include_bytes!("../bin/LibHac_LICENSE.txt");
const HACTOOLNET_BUILD_INFO: &[u8] = include_bytes!("../bin/hactoolnet_BUILD_INFO.txt");
const HACBUILD_LICENSE: &[u8] = include_bytes!("../licenses/hacbuild-MIT.txt");
const APP_ICON: &[u8] = include_bytes!("../assets/icon.ico");

pub fn default_workspace_root() -> PathBuf {
    // Runtime helper extraction and external tools may create temporary key
    // files. These must not live below the shared Windows Public directory.
    // Keep application data and scratch space private to the current user.
    if let Some(local) = env::var_os("LOCALAPPDATA") {
        return PathBuf::from(local).join("NSRP").join("Workspace");
    }
    #[cfg(windows)]
    {
        if let Some(profile) = env::var_os("USERPROFILE") {
            return PathBuf::from(profile)
                .join("AppData")
                .join("Local")
                .join("NSRP")
                .join("Workspace");
        }
        env::temp_dir().join("NSRP").join("Workspace")
    }
    #[cfg(not(windows))]
    {
        env::temp_dir().join("NSRP").join("Workspace")
    }
}

pub fn temp_workspace(prefix: &str) -> Result<tempfile::TempDir> {
    let root = default_workspace_root();
    fs::create_dir_all(&root)
        .with_context(|| format!("작업 영역 생성 실패: {}", root.display()))?;
    tempfile::Builder::new()
        .prefix(prefix)
        .tempdir_in(&root)
        .with_context(|| format!("임시 작업 영역 생성 실패: {}", root.display()))
}

#[derive(Debug, Clone)]
pub struct AppPaths {
    pub app_dir: PathBuf,
    pub resource_dir: PathBuf,
    pub data_dir: PathBuf,
    pub workspace_root: PathBuf,
    pub config_path: PathBuf,
}

impl AppPaths {
    pub fn discover() -> Result<Self> {
        let exe = env::current_exe().context("실행 파일 경로 확인 실패")?;
        let app_dir = exe
            .parent()
            .context("실행 파일 상위 경로 확인 실패")?
            .to_path_buf();

        let mut candidates = Vec::new();
        candidates.push(app_dir.clone());
        for ancestor in app_dir.ancestors().skip(1).take(5) {
            candidates.push(ancestor.to_path_buf());
        }
        if let Ok(cwd) = env::current_dir() {
            candidates.push(cwd.clone());
            candidates.extend(cwd.ancestors().skip(1).take(4).map(Path::to_path_buf));
        }
        // A self-contained public source checkout has bin/assets, but
        // installed users keep their private prod.keys one directory higher.
        // Always prefer the *existing* key location over source assets.
        let data_dir = candidates
            .iter()
            .find(|p| p.join("prod.keys").is_file() || p.join("title.keys").is_file())
            .or_else(|| {
                candidates
                    .iter()
                    .find(|p| p.join("bin").is_dir() && p.join("assets").is_dir())
            })
            .cloned()
            .unwrap_or_else(|| app_dir.clone());

        let workspace_root = default_workspace_root();
        fs::create_dir_all(&workspace_root)
            .with_context(|| format!("작업 영역 생성 실패: {}", workspace_root.display()))?;
        let resource_dir = prepare_embedded_runtime(&workspace_root)?;

        let config_path = if app_dir.join("nsrp_config.json").exists() || app_dir == data_dir {
            app_dir.join("nsrp_config.json")
        } else {
            data_dir.join("nsrp_config.json")
        };

        Ok(Self {
            app_dir,
            resource_dir,
            data_dir,
            workspace_root,
            config_path,
        })
    }

    pub fn tool(&self, name: &str) -> PathBuf {
        self.resource_dir.join("bin").join(name)
    }

    pub fn key(&self, name: &str) -> PathBuf {
        self.data_dir.join(name)
    }

    pub fn workspace_for(&self, key: &str) -> Result<PathBuf> {
        let path = self.workspace_root.join(key);
        fs::create_dir_all(&path)?;
        Ok(path)
    }

    pub fn reset_workspace(&self, key: &str) -> Result<PathBuf> {
        let path = self.workspace_root.join(key);
        if path.exists() {
            fs::remove_dir_all(&path)
                .with_context(|| format!("작업 영역 초기화 실패: {}", path.display()))?;
        }
        fs::create_dir_all(&path)?;
        Ok(path)
    }
}

fn prepare_embedded_runtime(workspace_root: &Path) -> Result<PathBuf> {
    let root = workspace_root.join(format!("runtime-{}", env!("CARGO_PKG_VERSION")));
    let bin = root.join("bin");
    let assets = root.join("assets");
    fs::create_dir_all(&bin)
        .with_context(|| format!("내장 도구 폴더 생성 실패: {}", bin.display()))?;
    fs::create_dir_all(&assets)
        .with_context(|| format!("내장 리소스 폴더 생성 실패: {}", assets.display()))?;

    ensure_embedded_file(&bin.join("hactool.exe"), HACTOOL_EXE)?;
    ensure_embedded_file(&bin.join("hactoolnet.exe"), HACTOOLNET_EXE)?;
    ensure_embedded_file(&bin.join("hacbuild.exe"), HACBUILD_EXE)?;
    ensure_embedded_file(&bin.join("game_info_preset.ini"), GAME_INFO_PRESET)?;
    ensure_embedded_file(&bin.join("LibHac_LICENSE.txt"), LIBHAC_LICENSE)?;
    ensure_embedded_file(
        &bin.join("hactoolnet_BUILD_INFO.txt"),
        HACTOOLNET_BUILD_INFO,
    )?;
    ensure_embedded_file(&bin.join("hacbuild_LICENSE.txt"), HACBUILD_LICENSE)?;
    ensure_embedded_file(&assets.join("icon.ico"), APP_ICON)?;
    Ok(root)
}

fn ensure_embedded_file(path: &Path, bytes: &[u8]) -> Result<()> {
    let current_matches = (|| -> Result<bool> {
        let mut file = fs::File::open(path)?;
        if file.metadata()?.len() != bytes.len() as u64 {
            return Ok(false);
        }
        // Compare existing embedded tools in fixed-size chunks instead of
        // allocating a separate complete copy of every helper at startup.
        let mut buffer = [0u8; 64 * 1024];
        for expected in bytes.chunks(buffer.len()) {
            if file.read_exact(&mut buffer[..expected.len()]).is_err()
                || buffer[..expected.len()] != *expected
            {
                return Ok(false);
            }
        }
        Ok(true)
    })()
    .unwrap_or(false);
    if current_matches {
        return Ok(());
    }
    // Multiple GUI instances can initialize the runtime concurrently. Never
    // truncate a cached helper in place: publish a fully written sibling.
    let parent = path
        .parent()
        .context("Embedded runtime path has no parent")?;
    let mut stage = tempfile::Builder::new()
        .prefix(".nsrp-resource-")
        .tempfile_in(parent)?;
    stage.write_all(bytes)?;
    stage.as_file_mut().sync_all()?;
    stage
        .persist(path)
        .map_err(|error| error.error)
        .with_context(|| format!("내장 리소스 추출 실패: {}", path.display()))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeSet;

    #[cfg(windows)]
    #[test]
    fn runtime_workspace_uses_per_user_local_app_data() {
        if let Some(local) = env::var_os("LOCALAPPDATA") {
            assert_eq!(
                default_workspace_root(),
                PathBuf::from(local).join("NSRP").join("Workspace")
            );
        }
    }

    #[test]
    fn embedded_file_streaming_check_detects_same_length_corruption() -> Result<()> {
        let temp = tempfile::tempdir()?;
        let target = temp.path().join("embedded.exe");
        let mut bytes = (0..(128 * 1024 + 17))
            .map(|index| (index % 251) as u8)
            .collect::<Vec<_>>();
        ensure_embedded_file(&target, &bytes)?;
        assert_eq!(fs::read(&target)?, bytes);
        bytes[65536] ^= 0x5a;
        fs::write(&target, &bytes)?;
        bytes[65536] ^= 0x5a;
        ensure_embedded_file(&target, &bytes)?;
        assert_eq!(fs::read(&target)?, bytes);
        Ok(())
    }

    #[test]
    fn stage94_failed_embedded_publication_does_not_truncate_existing_target() -> Result<()> {
        let temp = tempfile::tempdir()?;
        let target = temp.path().join("embedded.exe");
        fs::create_dir(&target)?;
        fs::write(target.join("keep.bin"), b"existing user file")?;
        assert!(ensure_embedded_file(&target, b"replacement").is_err());
        assert_eq!(fs::read(target.join("keep.bin"))?, b"existing user file");
        assert_eq!(fs::read_dir(temp.path())?.count(), 1);
        Ok(())
    }

    #[test]
    fn embedded_runtime_contains_only_required_helpers() -> Result<()> {
        let temp = tempfile::tempdir()?;
        let runtime = prepare_embedded_runtime(temp.path())?;
        let executables = fs::read_dir(runtime.join("bin"))?
            .filter_map(|entry| entry.ok())
            .filter_map(|entry| {
                let path = entry.path();
                path.extension()
                    .and_then(|ext| ext.to_str())
                    .is_some_and(|ext| ext.eq_ignore_ascii_case("exe"))
                    .then(|| entry.file_name().to_string_lossy().into_owned())
            })
            .collect::<BTreeSet<_>>();
        let expected = ["hacbuild.exe", "hactool.exe", "hactoolnet.exe"]
            .into_iter()
            .map(str::to_owned)
            .collect::<BTreeSet<_>>();
        assert_eq!(executables, expected);
        assert!(!runtime.join("bin/hacpack.exe").exists());
        assert!(runtime.join("assets/icon.ico").is_file());
        assert!(runtime.join("bin/game_info_preset.ini").is_file());
        assert!(runtime.join("bin/hacbuild_LICENSE.txt").is_file());
        assert!(!runtime.join("bin/nstool.exe").exists());
        Ok(())
    }
}
