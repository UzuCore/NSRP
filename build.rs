use std::{env, process::Command};

fn git(args: &[&str]) -> Option<String> {
    let result = Command::new("git").args(args).output().ok()?;
    result.status.success().then(|| {
        String::from_utf8(result.stdout)
            .ok()
            .map(|s| s.trim().to_owned())
    })?
}

fn main() {
    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-changed=.git/HEAD");
    println!("cargo:rerun-if-changed=.git/logs/HEAD");
    println!("cargo:rerun-if-changed=.git/refs/heads/master");
    println!("cargo:rerun-if-changed=.git/refs/heads/main");
    println!("cargo:rerun-if-env-changed=GITHUB_SHA");
    let valid = |v: &str| v.len() == 40 && v.bytes().all(|byte| byte.is_ascii_hexdigit());
    let commit = env::var("GITHUB_SHA")
        .ok()
        .filter(|sha| valid(sha))
        .or_else(|| git(&["rev-parse", "HEAD"]).filter(|sha| valid(sha)))
        .unwrap_or_else(|| "unknown".to_owned());
    let commit_time = git(&["log", "-1", "--format=%ct"])
        .and_then(|text| text.parse::<u64>().ok())
        .unwrap_or(0);
    println!("cargo:rustc-env=NSRP_BUILD_COMMIT={commit}");
    println!("cargo:rustc-env=NSRP_BUILD_COMMIT_TIME={commit_time}");
    slint_build::compile("ui/main.slint").expect("failed to compile Slint UI");
    #[cfg(windows)]
    {
        let mut resource = winresource::WindowsResource::new();
        resource.set_icon("assets/icon.ico");
        let version = env::var("CARGO_PKG_VERSION").expect("Cargo package version missing");
        let components = version
            .split('.')
            .map(|part| part.parse::<u16>().expect("expected major.minor.patch"))
            .collect::<Vec<_>>();
        assert_eq!(components.len(), 3, "expected major.minor.patch");
        let packed = (u64::from(components[0]) << 48)
            | (u64::from(components[1]) << 32)
            | (u64::from(components[2]) << 16);
        resource.set_version_info(winresource::VersionInfo::FILEVERSION, packed);
        resource.set_version_info(winresource::VersionInfo::PRODUCTVERSION, packed);
        resource.set("FileVersion", &version);
        resource.set("ProductVersion", &version);
        resource.set("FileDescription", "NSRP Nintendo Switch ROM Processor");
        resource.set("ProductName", "NSRP");
        resource
            .compile()
            .expect("failed to compile Windows resources");
    }
}
