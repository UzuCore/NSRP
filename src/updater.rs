//! GitHub Releases updater. Only the executable and its verified manifest are
//! allowed to replace files in the installation folder. Game data, keys and
//! app configuration are never included in an update transaction.
use anyhow::{Context, Result, bail, ensure};
use serde::Deserialize;
use sha2::{Digest, Sha256};
use std::{
    collections::{HashMap, HashSet},
    fs,
    io::{self, Read, Write},
    path::{Path, PathBuf},
    process::{Command, Stdio},
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

const API_URL: &str = "https://api.github.com/repos/UzuCore/NSRP/releases/latest";
const COMPARE_URL: &str = "https://api.github.com/repos/UzuCore/NSRP/compare";
const RELEASE_ASSET: &str = "nsrp-win64.zip";
const MAX_ZIP_BYTES: u64 = 300 * 1024 * 1024;
const MAX_EXTRACTED_BYTES: u64 = 350 * 1024 * 1024;

pub fn build_commit() -> &'static str {
    env!("NSRP_BUILD_COMMIT")
}

pub fn short_commit(value: &str) -> &str {
    value.get(..7).unwrap_or(value)
}

pub fn current_version() -> String {
    short_commit(build_commit()).to_owned()
}

#[derive(Clone, Debug)]
pub struct UpdateInfo {
    pub latest: String,
    pub commit: String,
    pub url: String,
    pub notes: String,
}

#[derive(Debug)]
pub enum UpdateCheck {
    NoPublishedRelease,
    Current,
    Available(UpdateInfo),
}

#[derive(Deserialize)]
struct ReleaseInfo {
    tag_name: String,
    target_commitish: String,
    #[serde(default)]
    body: String,
    #[serde(default)]
    assets: Vec<ReleaseAsset>,
}

#[derive(Deserialize)]
struct ReleaseAsset {
    name: String,
    browser_download_url: String,
}

#[derive(Deserialize)]
struct CommitComparison {
    status: String,
}

#[derive(Deserialize)]
struct PackageManifest {
    application: String,
    version: String,
    commit: String,
    platform: String,
    sha256: HashMap<String, String>,
}

fn valid_commit(value: &str) -> bool {
    value.len() == 40 && value.bytes().all(|b| b.is_ascii_hexdigit())
}

// Matches the opt-in, KST-dated Actions build tags used by NSL and NSRP.
fn dated_release_tag(tag: &str) -> bool {
    let Some(rest) = tag.strip_prefix("build-") else {
        return false;
    };
    let parts = rest.split('-').collect::<Vec<_>>();
    parts.len() == 4
        && parts[0].len() == 8
        && parts[0].bytes().all(|b| b.is_ascii_digit())
        && parts[1].len() == 6
        && parts[1].bytes().all(|b| b.is_ascii_digit())
        && parts[2] == "KST"
        && parts[3]
            .strip_prefix('r')
            .is_some_and(|v| !v.is_empty() && v.bytes().all(|b| b.is_ascii_digit()))
}

fn trusted_release_url(url: &str, tag: &str) -> bool {
    dated_release_tag(tag)
        && url == format!("https://github.com/UzuCore/NSRP/releases/download/{tag}/{RELEASE_ASSET}")
}

#[cfg(windows)]
fn hidden_curl(args: &[&str]) -> Result<std::process::Output> {
    use std::os::windows::process::CommandExt;
    let output = Command::new("curl.exe")
        .args(args)
        .creation_flags(0x0800_0000)
        .output()
        .context("Windows curl.exe 실행 실패")?;
    ensure!(
        output.status.success(),
        "GitHub 연결 오류: {}",
        String::from_utf8_lossy(&output.stderr).trim()
    );
    Ok(output)
}

#[cfg(not(windows))]
fn hidden_curl(_args: &[&str]) -> Result<std::process::Output> {
    bail!("NSRP 자동 업데이트는 Windows에서만 지원합니다")
}

fn get_github_json(url: &str) -> Result<Option<serde_json::Value>> {
    let response = hidden_curl(&[
        "--location",
        "--silent",
        "--show-error",
        "--proto",
        "=https",
        "--proto-redir",
        "=https",
        "--connect-timeout",
        "10",
        "--max-time",
        "20",
        "--max-filesize",
        "1048576",
        "--header",
        "User-Agent: NSRP",
        "--header",
        "Accept: application/vnd.github+json",
        "--write-out",
        "\nNSRP_STATUS:%{http_code}",
        url,
    ])?;
    let body = String::from_utf8(response.stdout).context("GitHub 응답 인코딩 오류")?;
    let (json, status) = body
        .rsplit_once("\nNSRP_STATUS:")
        .context("GitHub HTTP 상태를 확인하지 못했습니다")?;
    match status.trim() {
        "404" => Ok(None),
        "200" => serde_json::from_str(json)
            .context("GitHub 릴리스 정보 JSON 형식 오류")
            .map(Some),
        other => bail!("GitHub 서버가 HTTP {other}를 반환했습니다"),
    }
}

pub fn check_latest() -> Result<UpdateCheck> {
    let Some(raw) = get_github_json(API_URL)? else {
        return Ok(UpdateCheck::NoPublishedRelease);
    };
    let release: ReleaseInfo =
        serde_json::from_value(raw).context("GitHub 릴리스 메타데이터 오류")?;
    if !dated_release_tag(&release.tag_name) || !valid_commit(&release.target_commitish) {
        // An old or manually uploaded asset must not be installed by this
        // verifier. It is safer to show an informative error than downgrade.
        bail!("공식 빌드 태그 또는 40자리 커밋이 아닌 릴리스입니다");
    }
    let commit = release.target_commitish.to_ascii_lowercase();
    if commit.eq_ignore_ascii_case(build_commit()) {
        return Ok(UpdateCheck::Current);
    }
    ensure!(
        valid_commit(build_commit()),
        "현재 개발 빌드의 커밋을 확인할 수 없어 자동 업데이트하지 않습니다"
    );
    // The comparison, rather than a version string or an upload timestamp,
    // prevents installing an older manual Actions build over local changes.
    let compare_url = format!("{COMPARE_URL}/{}...{commit}", build_commit());
    let Some(compare_json) = get_github_json(&compare_url)? else {
        bail!("로컬 커밋이 공개 GitHub 이력에 없어 자동 업데이트할 수 없습니다");
    };
    let comparison: CommitComparison =
        serde_json::from_value(compare_json).context("GitHub 커밋 비교 오류")?;
    if comparison.status != "ahead" {
        return Ok(UpdateCheck::Current);
    }
    let url = release
        .assets
        .iter()
        .find(|asset| asset.name == RELEASE_ASSET)
        .map(|asset| asset.browser_download_url.clone())
        .context("새 릴리스에 nsrp-win64.zip 파일이 없습니다")?;
    ensure!(
        trusted_release_url(&url, &release.tag_name),
        "신뢰할 수 없는 릴리스 파일 URL입니다"
    );
    Ok(UpdateCheck::Available(UpdateInfo {
        latest: short_commit(&commit).to_owned(),
        commit,
        url,
        notes: release.body,
    }))
}

fn hash_file(path: &Path) -> Result<String> {
    let mut file = io::BufReader::new(fs::File::open(path)?);
    let mut digest = Sha256::new();
    let mut buf = [0u8; 64 * 1024];
    loop {
        let read = file.read(&mut buf)?;
        if read == 0 {
            break;
        }
        digest.update(&buf[..read]);
    }
    Ok(format!("{:x}", digest.finalize()))
}

fn verify_manifest(dir: &Path, expected_commit: &str) -> Result<()> {
    let manifest: PackageManifest =
        serde_json::from_slice(&fs::read(dir.join("nsrp-manifest.json"))?)
            .context("업데이트 매니페스트가 올바르지 않습니다")?;
    ensure!(manifest.application == "NSRP", "잘못된 업데이트 앱 이름");
    ensure!(
        manifest.platform == "windows-x86_64",
        "지원하지 않는 플랫폼"
    );
    ensure!(
        !manifest.version.trim().is_empty(),
        "업데이트 버전이 비어 있습니다"
    );
    ensure!(
        valid_commit(&manifest.commit) && manifest.commit.eq_ignore_ascii_case(expected_commit),
        "릴리스 커밋과 업데이트 패키지가 일치하지 않습니다"
    );
    let expected = manifest
        .sha256
        .get("nsrp.exe")
        .context("실행파일 SHA-256 매니페스트 항목이 없습니다")?;
    ensure!(
        expected.len() == 64 && expected.bytes().all(|b| b.is_ascii_hexdigit()),
        "매니페스트 SHA-256 형식 오류"
    );
    ensure!(
        hash_file(&dir.join("nsrp.exe"))?.eq_ignore_ascii_case(expected),
        "업데이트 실행파일 SHA-256 불일치"
    );
    Ok(())
}

fn allowed_archive_file(name: &str) -> bool {
    matches!(
        name,
        "nsrp.exe"
            | "nsrp-manifest.json"
            | "LICENSE"
            | "THIRD_PARTY_NOTICES.md"
            | "licenses/hacbuild-MIT.txt"
            | "licenses/hactool-ISC.txt"
            | "licenses/LibHac-MIT.txt"
            | "licenses/Slint-Royalty-free-2.0.md"
            | "licenses/mbedtls-Apache-2.0.txt"
            | "licenses/sevenz-rust2-Apache-2.0.txt"
    )
}

fn extract_verified_zip(archive: &Path, output: &Path, expected_commit: &str) -> Result<()> {
    let file = fs::File::open(archive)?;
    ensure!(
        file.metadata()?.len() <= MAX_ZIP_BYTES,
        "ZIP 다운로드 용량 제한 초과"
    );
    let mut zip = zip::ZipArchive::new(file).context("업데이트 ZIP 형식 오류")?;
    ensure!(zip.len() <= 15, "예상하지 못한 ZIP 항목 수");
    fs::create_dir_all(output)?;
    let mut total = 0u64;
    let mut seen = HashSet::<String>::new();
    for index in 0..zip.len() {
        let mut item = zip.by_index(index)?;
        let name = item.name().replace('\\', "/");
        if item.is_dir() && name == "licenses/" {
            continue;
        }
        ensure!(
            !item.is_dir() && item.enclosed_name().is_some() && allowed_archive_file(&name),
            "업데이트 ZIP에 허용되지 않은 경로가 있습니다: {name}"
        );
        ensure!(
            item.unix_mode()
                .is_none_or(|mode| mode & 0o170000 != 0o120000),
            "업데이트 ZIP에는 심볼릭 링크를 포함할 수 없습니다"
        );
        ensure!(seen.insert(name.to_ascii_lowercase()), "중복 ZIP 파일 항목");
        total = total
            .checked_add(item.size())
            .context("ZIP 크기 오버플로")?;
        ensure!(total <= MAX_EXTRACTED_BYTES, "ZIP 해제 용량 제한 초과");
        if name == "nsrp.exe" || name == "nsrp-manifest.json" {
            if name == "nsrp-manifest.json" {
                ensure!(item.size() <= 64 * 1024, "매니페스트 크기 초과");
            } else {
                ensure!(item.size() <= 256 * 1024 * 1024, "실행파일 크기 초과");
            }
            let mut target = fs::File::create(output.join(&name))?;
            io::copy(&mut item, &mut target).context("업데이트 ZIP 해제 오류")?;
            target.flush()?;
        }
    }
    ensure!(
        seen.contains("nsrp.exe") && seen.contains("nsrp-manifest.json"),
        "업데이트 ZIP에 필수 실행파일 또는 매니페스트가 없습니다"
    );
    verify_manifest(output, expected_commit)
}

pub fn download_and_prepare(info: &UpdateInfo, workspace_root: &Path) -> Result<PathBuf> {
    ensure!(
        valid_commit(&info.commit),
        "업데이트 커밋이 올바르지 않습니다"
    );
    let tag = info
        .url
        .strip_prefix("https://github.com/UzuCore/NSRP/releases/download/")
        .and_then(|rest| rest.strip_suffix("/nsrp-win64.zip"))
        .context("업데이트 URL 형식이 올바르지 않습니다")?;
    ensure!(
        trusted_release_url(&info.url, tag),
        "허용되지 않은 다운로드 주소"
    );
    let micros = SystemTime::now().duration_since(UNIX_EPOCH)?.as_micros();
    let updates = workspace_root.join("updates");
    fs::create_dir_all(&updates)?;
    let task = updates.join(format!("nsrp_update_{}_{}", std::process::id(), micros));
    fs::create_dir(&task).context("업데이트 작업 폴더 생성 실패")?;
    let archive = task.join("update.zip");
    let response = hidden_curl(&[
        "--location",
        "--fail",
        "--silent",
        "--show-error",
        "--proto",
        "=https",
        "--proto-redir",
        "=https",
        "--connect-timeout",
        "10",
        "--max-time",
        "120",
        "--max-filesize",
        "314572800",
        "--header",
        "User-Agent: NSRP",
        "--output",
        archive
            .to_str()
            .context("업데이트 ZIP 파일 경로 인코딩 오류")?,
        &info.url,
    ])?;
    ensure!(response.status.success(), "GitHub 업데이트 다운로드 실패");
    extract_verified_zip(&archive, &task.join("package"), &info.commit)?;
    Ok(task)
}

#[cfg(windows)]
fn powershell_compatible_path(path: &Path) -> Result<PathBuf> {
    use std::ffi::OsString;
    use std::os::windows::ffi::{OsStrExt, OsStringExt};
    let wide: Vec<u16> = path.as_os_str().encode_wide().collect();
    let verbatim = [b'\\' as u16, b'\\' as u16, b'?' as u16, b'\\' as u16];
    let unc = [b'U' as u16, b'N' as u16, b'C' as u16, b'\\' as u16];
    let normal = if wide.starts_with(&verbatim) {
        let suffix = &wide[verbatim.len()..];
        if suffix.starts_with(&unc) {
            let mut result = vec![b'\\' as u16, b'\\' as u16];
            result.extend_from_slice(&suffix[unc.len()..]);
            result
        } else {
            suffix.to_vec()
        }
    } else {
        wide
    };
    let output = PathBuf::from(OsString::from_wide(&normal));
    ensure!(
        output.is_absolute(),
        "PowerShell 설치 경로가 절대경로가 아닙니다"
    );
    Ok(output)
}

pub fn launch_apply_and_exit(task: &Path, workspace_root: &Path) -> Result<()> {
    #[cfg(not(windows))]
    {
        let _ = (task, workspace_root);
        bail!("Windows에서만 업데이트할 수 있습니다")
    }
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        let exe = std::env::current_exe()?.canonicalize()?;
        ensure!(
            exe.file_name().and_then(|n| n.to_str()) == Some("nsrp.exe"),
            "실행 중인 프로그램이 nsrp.exe가 아닙니다"
        );
        let install = exe.parent().context("현재 실행 폴더 오류")?;
        let root = workspace_root.join("updates").canonicalize()?;
        let task = task.canonicalize()?;
        ensure!(
            task.parent() == Some(root.as_path())
                && task
                    .file_name()
                    .and_then(|n| n.to_str())
                    .is_some_and(|n| n.starts_with("nsrp_update_")),
            "업데이트 작업 폴더가 허용된 위치에 있지 않습니다"
        );
        let manifest: PackageManifest =
            serde_json::from_slice(&fs::read(task.join("package/nsrp-manifest.json"))?)?;
        verify_manifest(&task.join("package"), &manifest.commit)?;
        let helper_path = task.join("apply.ps1");
        fs::write(&helper_path, include_str!("../scripts/apply-update.ps1"))?;
        ensure!(
            !task.join("apply-ready.flag").exists(),
            "이미 시작한 업데이트입니다"
        );
        let stdout = fs::File::create(task.join("apply-stdout.log"))?;
        let stderr_log = task.join("apply-stderr.log");
        let stderr = fs::File::create(&stderr_log)?;
        let mut child = Command::new("powershell.exe")
            .args([
                "-NoProfile",
                "-NonInteractive",
                "-ExecutionPolicy",
                "Bypass",
                "-File",
            ])
            .arg(powershell_compatible_path(&helper_path)?)
            .arg("-BaseDir")
            .arg(powershell_compatible_path(install)?)
            .arg("-TaskDir")
            .arg(powershell_compatible_path(&task)?)
            .arg("-WaitForPid")
            .arg(std::process::id().to_string())
            .creation_flags(0x0800_0000)
            .stdout(Stdio::from(stdout))
            .stderr(Stdio::from(stderr))
            .spawn()
            .context("업데이트 적용 프로세스 실행 실패")?;
        let started = Instant::now();
        loop {
            if let Some(status) = child.try_wait()? {
                bail!(
                    "업데이트 적용 프로세스가 조기 종료되었습니다 ({status}): {}",
                    fs::read_to_string(&stderr_log).unwrap_or_default()
                );
            }
            if task.join("apply-ready.flag").is_file() {
                // Only after the helper validates and stages the replacement
                // may the GUI exit. The helper waits for this exact PID.
                std::process::exit(0);
            }
            if started.elapsed() > Duration::from_secs(30) {
                let _ = child.kill();
                let _ = child.wait();
                bail!("업데이트 적용 프로세스 준비 시간이 초과됐습니다");
            }
            std::thread::sleep(Duration::from_millis(100));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn trusted_release_requires_exact_repository_asset_and_tag() {
        let tag = "build-20261122-143500-KST-r12";
        assert!(dated_release_tag(tag));
        assert!(!dated_release_tag("1.1.0"));
        assert!(!dated_release_tag("build-20261122-KST-r12"));
        assert!(!dated_release_tag("build-20261122-143500-KST-r12/foo"));
        assert!(trusted_release_url(
            &format!("https://github.com/UzuCore/NSRP/releases/download/{tag}/nsrp-win64.zip"),
            tag
        ));
        assert!(!trusted_release_url(
            &format!("https://evil.example/UzuCore/NSRP/releases/download/{tag}/nsrp-win64.zip"),
            tag
        ));
        assert!(!trusted_release_url(
            &format!("https://github.com/UzuCore/NSRP/releases/download/{tag}/nsrp.exe"),
            tag
        ));
        assert!(!trusted_release_url(
            &format!("https://github.com/UzuCore/NSRP/releases/download/{tag}/nsrp-win64.zip?x=1"),
            tag
        ));
        assert!(valid_commit(&"a".repeat(40)));
        assert!(!valid_commit("1.1.0"));
    }

    #[test]
    fn stage79_build_revision_is_the_only_displayed_version() {
        assert!(!env!("CARGO_PKG_VERSION").is_empty());
        assert!(valid_commit(build_commit()));
        assert_eq!(short_commit(build_commit()).len(), 7);
        assert_eq!(current_version(), short_commit(build_commit()));
        assert!(!current_version().contains('.'));
        assert!(!current_version().contains('v'));
    }

    #[test]
    fn untrusted_files_cannot_enter_the_update_zip() {
        assert!(allowed_archive_file("licenses/mbedtls-Apache-2.0.txt"));
        for bad in [
            "prod.keys",
            "title.keys",
            "config.json",
            "nsrp_config.json",
            "sub/nsrp.exe",
            "../nsrp.exe",
            "update.bat",
            "anything.exe",
            "LICENSE/../../nsrp.exe",
            "licenses/extra.txt",
            "licenses/hacpack-GPL-2.0.txt",
            "bin/hacpack.exe",
        ] {
            assert!(!allowed_archive_file(bad), "Unexpectedly allowed: {bad}");
        }
    }

    #[test]
    fn staged_zip_sha_and_archive_allowlist_are_enforced() -> Result<()> {
        let test = tempfile::tempdir()?;
        let commit = "a".repeat(40);
        let exe_data = b"safe test executable, not a real program";
        let digest = format!("{:x}", Sha256::digest(exe_data));
        let manifest = serde_json::json!({
            "application": "NSRP", "version": "1.1.0", "platform": "windows-x86_64",
            "commit": commit, "sha256": {"nsrp.exe": digest}
        })
        .to_string();
        let make_zip = |name: &str, exe: &[u8], extra: Option<&str>| -> Result<PathBuf> {
            let path = test.path().join(name);
            let mut writer = zip::ZipWriter::new(fs::File::create(&path)?);
            let options = zip::write::SimpleFileOptions::default();
            writer.start_file("nsrp.exe", options)?;
            writer.write_all(exe)?;
            writer.start_file("nsrp-manifest.json", options)?;
            writer.write_all(manifest.as_bytes())?;
            if let Some(unwanted) = extra {
                writer.start_file(unwanted, options)?;
                writer.write_all(b"private user data must never be installed")?;
            }
            writer.finish()?;
            Ok(path)
        };
        let good = make_zip("good.zip", exe_data, None)?;
        let valid = test.path().join("verified");
        extract_verified_zip(&good, &valid, &commit)?;
        assert_eq!(fs::read(valid.join("nsrp.exe"))?, exe_data);
        assert!(!valid.join("prod.keys").exists());

        let corrupted = make_zip("tampered.zip", b"modified executable bytes", None)?;
        assert!(extract_verified_zip(&corrupted, &test.path().join("bad_sha"), &commit).is_err());
        let sneaky = make_zip("with_keys.zip", exe_data, Some("prod.keys"))?;
        assert!(extract_verified_zip(&sneaky, &test.path().join("bad_file"), &commit).is_err());
        let traversal = make_zip("traversal.zip", exe_data, Some("../nsrp.exe"))?;
        assert!(extract_verified_zip(&traversal, &test.path().join("bad_path"), &commit).is_err());
        assert!(
            extract_verified_zip(&good, &test.path().join("wrong_commit"), &"b".repeat(40))
                .is_err()
        );
        Ok(())
    }
}
