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
        let parent = path.parent().context("설정 파일 상위 경로가 없습니다")?;
        fs::create_dir_all(parent)?;
        let tmp = path.with_extension("json.tmp");
        let text = serde_json::to_string_pretty(self)?;
        fs::write(&tmp, format!("{text}\n"))?;
        if path.exists() {
            let _ = fs::remove_file(path);
        }
        fs::rename(&tmp, path).with_context(|| format!("설정 저장 실패: {}", path.display()))
    }
}
