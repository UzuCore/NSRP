use anyhow::{Context, Result, bail};
use std::{
    ffi::OsString,
    io::Read,
    path::{Path, PathBuf},
    process::{Command, Stdio},
    sync::atomic::{AtomicBool, Ordering},
    thread,
    time::Duration,
};

// Tool output can be arbitrarily large or malformed. Preserve the useful
// trailing diagnostics while always draining pipes to prevent deadlocks.
const MAX_TOOL_OUTPUT_BYTES: usize = 256 * 1024;

fn read_tool_output_tail(mut stream: impl Read) -> Vec<u8> {
    let mut output = Vec::new();
    let mut chunk = [0u8; 16 * 1024];
    loop {
        let count = match stream.read(&mut chunk) {
            Ok(0) | Err(_) => break,
            Ok(count) => count,
        };
        let overflow = output
            .len()
            .saturating_add(count)
            .saturating_sub(MAX_TOOL_OUTPUT_BYTES);
        if overflow > 0 {
            output.drain(..overflow);
        }
        output.extend_from_slice(&chunk[..count]);
    }
    output
}

#[derive(Debug, Clone)]
pub struct ToolOutput {
    pub code: i32,
    pub stdout: String,
    pub stderr: String,
}

impl ToolOutput {
    pub fn success(&self) -> bool {
        self.code == 0
    }

    pub fn combined(&self) -> String {
        match (self.stdout.is_empty(), self.stderr.is_empty()) {
            (false, false) => format!("{}\n{}", self.stdout, self.stderr),
            (false, true) => self.stdout.clone(),
            (true, false) => self.stderr.clone(),
            (true, true) => String::new(),
        }
    }
}

pub fn run_tool<I, S>(
    program: &Path,
    args: I,
    cwd: Option<&Path>,
    cancel: &AtomicBool,
) -> Result<ToolOutput>
where
    I: IntoIterator<Item = S>,
    S: Into<OsString>,
{
    if !program.is_file() {
        bail!("필수 도구가 없습니다: {}", program.display());
    }
    if cancel.load(Ordering::Relaxed) {
        bail!("작업이 중단되었습니다");
    }
    let mut command = Command::new(program);
    let args: Vec<OsString> = args.into_iter().map(Into::into).collect();
    command.args(&args);
    if let Some(cwd) = cwd {
        command.current_dir(cwd);
    }
    command
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        const CREATE_NO_WINDOW: u32 = 0x0800_0000;
        command.creation_flags(CREATE_NO_WINDOW);
    }
    let mut child = command
        .spawn()
        .with_context(|| format!("도구 실행 실패: {}", program.display()))?;
    let stdout = child.stdout.take().context("stdout pipe 생성 실패")?;
    let stderr = child.stderr.take().context("stderr pipe 생성 실패")?;
    let out_thread = thread::spawn(move || read_tool_output_tail(stdout));
    let err_thread = thread::spawn(move || read_tool_output_tail(stderr));

    let status = loop {
        if cancel.load(Ordering::Relaxed) {
            let _ = child.kill();
            let _ = child.wait();
            let _ = out_thread.join();
            let _ = err_thread.join();
            bail!("작업이 중단되었습니다");
        }
        if let Some(status) = child.try_wait()? {
            break status;
        }
        thread::sleep(Duration::from_millis(40));
    };
    let stdout = out_thread.join().unwrap_or_default();
    let stderr = err_thread.join().unwrap_or_default();
    Ok(ToolOutput {
        code: status.code().unwrap_or(-1),
        stdout: String::from_utf8_lossy(&stdout).into_owned(),
        stderr: String::from_utf8_lossy(&stderr).into_owned(),
    })
}

pub fn require_tools(base: &Path, names: &[&str]) -> Result<Vec<PathBuf>> {
    names
        .iter()
        .map(|name| {
            let p = base.join("bin").join(name);
            if p.is_file() {
                Ok(p)
            } else {
                bail!("필수 도구가 없습니다: {}", p.display())
            }
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tool_output_capture_keeps_tail_with_bounded_memory() {
        let mut bytes = vec![b'x'; 1024 * 1024];
        bytes.extend_from_slice(b"\nFATAL: final error message\n");
        let output = read_tool_output_tail(std::io::Cursor::new(bytes));
        assert_eq!(output.len(), MAX_TOOL_OUTPUT_BYTES);
        assert!(output.ends_with(b"FATAL: final error message\n"));
    }

    #[test]
    fn tool_launch_rejects_missing_file_and_pre_cancelled_operations() {
        let temp = tempfile::tempdir().unwrap();
        let cancelled = AtomicBool::new(true);
        let missing = temp.path().join("not-a-tool.exe");
        assert!(run_tool(&missing, Vec::<OsString>::new(), None, &cancelled).is_err());
        assert!(require_tools(temp.path(), &["hactool.exe"]).is_err());
    }
}
