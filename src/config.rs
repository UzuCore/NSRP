use crate::atomic_file::write_atomic;
use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::{fs, path::Path};

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
#[derive(Default)]
pub struct AppConfig {
    pub main: MainConfig,
    pub compressor: CompressorConfig,
    pub patcher: PatcherConfig,
    pub extractor: ExtractorConfig,
    pub decompressor: DecompressorConfig,
    pub merger: MergerConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
#[derive(Default)]
pub struct MainConfig {
    pub last_tab: i32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct CompressorConfig {
    pub level: i32,
    pub thread: i32,
    pub rm_source: bool,
    pub notify_done: bool,
    pub block_mode: bool,
}

impl Default for CompressorConfig {
    fn default() -> Self {
        Self {
            level: 18,
            thread: num_cpus::get().max(1) as i32 + 1,
            rm_source: false,
            notify_done: false,
            block_mode: true,
        }
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct PatcherConfig {
    pub save_log: bool,
    pub notify_done: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct DecompressorConfig {
    pub thread: i32,
    pub rm_source: bool,
    pub notify_done: bool,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct ExtractorConfig {
    pub notify_done: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct MergerConfig {
    pub thread: i32,
    pub notify_done: bool,
    pub output_format: String,
    pub compress_after: bool,
    pub fetch_title: bool,
}

impl Default for MergerConfig {
    fn default() -> Self {
        Self {
            thread: num_cpus::get().max(1) as i32 + 1,
            notify_done: false,
            output_format: "nsp".to_owned(),
            compress_after: false,
            fetch_title: true,
        }
    }
}

impl Default for DecompressorConfig {
    fn default() -> Self {
        Self {
            thread: num_cpus::get().max(1) as i32 + 1,
            rm_source: false,
            notify_done: false,
        }
    }
}

impl AppConfig {
    pub fn load(path: &Path) -> Self {
        fs::read_to_string(path)
            .ok()
            .and_then(|text| serde_json::from_str::<Self>(&text).ok())
            .unwrap_or_default()
    }

    pub fn save(&self, path: &Path) -> Result<()> {
        // A malformed existing configuration must not be replaced by
        // defaults silently loaded after a parse error.
        if path.is_file() {
            let existing = fs::read_to_string(path).with_context(|| {
                format!("기존 설정 파일을 읽을 수 없습니다: {}", path.display())
            })?;
            serde_json::from_str::<Self>(&existing).with_context(|| {
                format!(
                    "기존 설정 파일에 오류가 있어 덮어쓰지 않습니다: {}",
                    path.display()
                )
            })?;
        }
        let text = serde_json::to_string_pretty(self)?;
        write_atomic(path, format!("{text}\n").as_bytes())
    }
}

#[cfg(test)]
mod stage73_config_tests {
    use super::*;

    #[test]
    fn stage73_multiple_settings_saves_do_not_create_shared_tmp_collisions() -> Result<()> {
        let temp = tempfile::tempdir()?;
        let path = temp.path().join("nsrp_config.json");
        let mut handles = Vec::new();
        for id in 0..6 {
            let path = path.clone();
            handles.push(std::thread::spawn(move || -> Result<()> {
                for turn in 0..12 {
                    let mut config = AppConfig::default();
                    config.main.last_tab = (id + turn) % 9;
                    config.save(&path)?;
                }
                Ok(())
            }));
        }
        for handle in handles {
            handle.join().expect("settings test worker panicked")?;
        }
        let value: serde_json::Value = serde_json::from_slice(&fs::read(&path)?)?;
        assert!(value.get("main").is_some());
        assert_eq!(
            fs::read_dir(temp.path())?.count(),
            1,
            "Concurrent saves must not leave json.tmp or other fragments"
        );
        Ok(())
    }

    #[test]
    fn stage73_corrupt_existing_settings_cannot_be_replaced_by_defaults() -> Result<()> {
        let temp = tempfile::tempdir()?;
        let path = temp.path().join("nsrp_config.json");
        let original = b"{incomplete settings";
        fs::write(&path, original)?;
        let defaults_after_bad_json = AppConfig::load(&path);
        assert!(
            defaults_after_bad_json.save(&path).is_err(),
            "A parse error must not destroy the user's saved settings"
        );
        assert_eq!(fs::read(&path)?, original);
        Ok(())
    }
}
