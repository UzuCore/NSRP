@echo off
setlocal
cd /d "%~dp0"

where cargo >nul 2>nul
if errorlevel 1 (
    echo [ERROR] Rust/Cargo was not found in PATH.
    exit /b 1
)

echo [NSRP] Verifying checked-in embedded inputs...
powershell.exe -NoProfile -NonInteractive -ExecutionPolicy Bypass -File "%~dp0scripts\verify_embedded_inputs.ps1"
if errorlevel 1 exit /b %errorlevel%

echo [NSRP] Verifying third-party license attribution...
powershell.exe -NoProfile -NonInteractive -ExecutionPolicy Bypass -File "%~dp0scripts\check-third-party-attribution.ps1"
if errorlevel 1 exit /b %errorlevel%

echo [NSRP] Building the locked Windows release...
if /I "%NSRP_BUILD_OFFLINE%"=="1" (
    cargo build --release --locked --offline
) else (
    cargo build --release --locked
)
if errorlevel 1 exit /b %errorlevel%

echo [NSRP] Packaging only allowlisted public release files...
powershell.exe -NoProfile -NonInteractive -ExecutionPolicy Bypass -File "%~dp0scripts\package.ps1"
if errorlevel 1 exit /b %errorlevel%

echo [OK] Release: target\release\nsrp.exe
echo [OK] Distribution: dist\nsrp-win64.zip
endlocal
