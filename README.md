# NSRP — Nintendo Switch 패키지 처리 도구

**NSRP**는 사용자가 제공한 Nintendo Switch 게임 패키지·컨테이너 파일을 검사하고 처리하는 **Windows GUI 프로그램**입니다. Rust 처리 엔진과 Slint 기반의 화면을 사용하며, 자체 스트리밍 파서·생성기와 필요한 일부 호환성 도구로 작업을 수행합니다.

> **주의:** 저장소와 배포 파일에는 게임 이미지, 콘솔 키(`prod.keys`, `title.keys`), 티켓, 사용자 데이터베이스가 포함되지 않습니다. 사용 권한이 있는 콘텐츠만 처리해야 합니다.

[최신 빌드 다운로드](https://github.com/UzuCore/NSRP/releases/latest) · [빌드 및 배포 안내](BUILD_RELEASE.md) · [모듈 구조](docs/architecture/NSRP_MODULES.md)

## 주요 기능

- **파일 분석:** NSP·NSZ·XCI·XCZ 등 지원 컨테이너의 구성과 메타데이터 확인
- **변환·압축·해제:** 지원하는 형식 간 변환과 압축·압축 해제
- **병합·분할:** 본편·업데이트·DLC를 CNMT 기반으로 판별해 병합하거나 구성별로 분할
- **타이틀 수정·패치:** 지원되는 NCA 구조에서 제목·아이콘 변경과 패치
- **한글패치 입력:** RomFS·ExeFS 폴더와 ZIP·7z 압축파일(암호화 7z 포함)을 파일 교체 패치로 적용합니다. xdelta·IPS는 지원하지 않습니다.
- **작업 안전성:** 취소 처리, 출력 검증, 원본 보호, 충돌 방지와 실패 시 복구
- **자동업데이트:** GitHub 공식 Release의 Git 커밋·매니페스트·SHA-256을 검증한 뒤 업데이트

파일 종류에 따라 지원 범위가 다를 수 있습니다. 알 수 없는 NCA/BKTR 구조는 기존 파일을 보호하기 위해 중단하며, 모든 게임이나 실기와의 호환성을 보장하지는 않습니다.

## 다운로드 및 실행

1. [GitHub Releases](https://github.com/UzuCore/NSRP/releases/latest)에서 `nsrp-win64.zip`을 다운로드한 뒤 원하는 폴더에 압축을 풉니다.
2. `nsrp.exe`를 실행합니다.
3. 처리할 파일을 추가하고 기능과 출력 형식을 선택하면 됩니다.

NSL과 동일하게 프로그램 제목 표시줄에는 **`NSRP  <커밋 앞 7자리>`**만 표시됩니다. 정보창과 업데이트 확인창에도 커밋을 사용하며, GitHub Release 제목 역시 **`NSRP <커밋 앞 7자리> (날짜 KST)`** 형식입니다. 전체 40자리 커밋은 정보창과 배포 매니페스트에 보존합니다. `Cargo.toml`의 숫자 버전은 Rust 내부 패키지·기존 자동업데이트 호환성용으로만 유지하며 사용자에게 버전으로 표시하지 않습니다.

업데이트는 **도움말 → 업데이트**에서 확인할 수 있습니다. 공식 GitHub 자산과 해시가 맞지 않으면 설치하지 않으며, 사용자의 설정·키·게임 파일은 업데이트 대상이 아닙니다.

## 소스 구성

```text
NSRP/
├── .github/workflows/windows-build.yml  # GitHub Actions 수동 Windows 빌드
├── src/                                # Rust GUI 및 처리 엔진
│   ├── formats/                        # PFS0, HFS0, NCA, NCZ, BKTR
│   ├── ops/                            # 변환, 병합, 패치, 복구
│   ├── updater.rs                       # GitHub 자산 및 SHA-256 검증
│   ├── update_ui.rs                      # 업데이트 UI
│   └── workspace.rs                      # 사용자별 작업 공간
├── ui/                                 # Slint 인터페이스·이미지 리소스
├── bin/                                # 체크섬을 검증하는 호환성 도구
├── assets/                             # 프로그램 아이콘
├── licenses/                           # 외부 구성 요소 라이선스
├── scripts/                            # 빌드·패키징·검증·롤백 테스트
├── docs/architecture/                  # 구조 설명
├── Cargo.toml / Cargo.lock              # 내부 패키지 메타데이터·고정 의존성
├── rust-toolchain.toml                  # Rust 툴체인
├── build.bat                            # Windows Release 빌드
├── LICENSE / THIRD_PARTY_NOTICES.md     # 라이선스 고지
└── README.md
```

로컬 개발 환경에는 개인 키, 테스트 게임, 출력물, QA 로그가 별도로 존재할 수 있지만 **공개 Git 저장소에는 등록하지 않습니다**. 공개 소스만으로 빌드할 수 있으며 상위 폴더의 `bin` 또는 `assets`를 요구하지 않습니다.

일반 Program/Control 추출, CNMT 검사, 기본 XCI 스트리밍 생성에는 Rust 네이티브 경로를 우선 사용합니다. 선택한 RomFS·ExeFS만 추출하며, 기본 XCI의 소규모 secure 파티션도 지원합니다. 특수 저장 구조, 일부 CNMT 수정 및 검증되지 않은 XCI 레이아웃에는 호환성 도구 3종을 유지합니다. Program/Control NCA 재패키징은 기존 GPL 패커 없이 네이티브 코드로 처리합니다. 각 구성 요소의 라이선스는 [외부 라이선스 고지](THIRD_PARTY_NOTICES.md)를 참고하세요.

## 소스에서 빌드

**Windows** 환경에서 Rust/Cargo와 PowerShell이 필요합니다. 소스 루트에서 실행하면 됩니다.

```cmd
build.bat
```

스크립트는 내장 입력 7개의 SHA-256을 검증하고, 고정된 의존성으로 Release를 빌드한 뒤 허용된 파일만 `dist/nsrp-win64.zip`으로 패키징합니다.

개별 검수 명령:

```cmd
cargo fmt --all -- --check
cargo clippy --locked --all-targets -- -D warnings
cargo test --locked --lib
cargo test --locked --bin nsrp
cargo test --locked --bin nsrp stage60_drop_output_state_and_tab_epoch_are_preserved -- --ignored --test-threads=1
cargo test --locked --bin nsrp stage63_help_about_opens_slint_attribution_dialog -- --ignored --test-threads=1
cargo test --locked --bin nsrp stage74_title_logo_original_and_replacement_top_edge_clicks_align -- --ignored --test-threads=1
powershell.exe -NoProfile -ExecutionPolicy Bypass -File scripts\test-auto-update.ps1 -RunDelayedFailure
powershell.exe -NoProfile -ExecutionPolicy Bypass -File scripts\check-third-party-attribution.ps1
```

Slint/Winit은 프로세스당 GUI 이벤트 루프 하나만 지원하므로, 위에 표시한 격리 GUI 테스트는 일반 GUI 회귀 테스트와 **분리해서 실행**합니다.

## 커밋 버전, GitHub Actions 및 업데이트

- 표시용 버전은 **Git 커밋 앞 7자리**입니다. 실행파일에는 전체 40자리 소스 커밋이 포함됩니다.
- GitHub Actions는 `workflow_dispatch`로 **수동 실행**합니다. `git push`만으로 Release가 게시되지는 않습니다.
- Windows CI는 코드 포맷·테스트·정적 검사, 실행파일 빌드, ZIP 무결성 확인, 격리된 자동업데이트·롤백 시험을 수행합니다.
- 공개 Release는 외부 라이선스를 검토한 뒤 `publish_release`를 명시적으로 선택해야 생성됩니다.
- GitHub Release **제목과 본문은 커밋 기준**이며 숫자 버전을 표시하지 않습니다. NSL과 동일하게 고유 다운로드 식별자로 `build-YYYYMMDD-HHMMSS-KST-rN` 태그를 유지합니다. ZIP에는 `nsrp.exe`, 내부 호환성 메타데이터·전체 커밋·SHA-256을 기록한 `nsrp-manifest.json`, 필수 라이선스 고지가 들어 있습니다.

업데이트는 공식 UzuCore/NSRP Release의 커밋을 비교해 다운그레이드를 방지하고, ZIP 안의 허용된 파일과 SHA-256을 검증합니다. NSRP 프로세스가 종료되면 **해당 실행파일 폴더의 `nsrp.exe`와 `nsrp-manifest.json`만** 교체하고, 실패하면 이전 파일을 복원합니다. 사용자 키·설정·게임·샘플 및 알 수 없는 파일은 변경하지 않습니다. ZIP 안의 임의 실행파일이나 설치 스크립트를 실행하지도 않습니다.

## 지원 범위와 안전성

Program NCA 패치와 Control NCA의 제목·아이콘 변경은 지원하는 IVFC/PFS0 구조를 네이티브 코드로 재생성합니다. 크기 변경과 검증된 BKTR 평탄화도 처리하지만, 알 수 없는 희소·압축·특수 저장 구조는 **안전하게 실패**하도록 설계했습니다. 모든 NCA 구조를 지원한다는 뜻은 아닙니다.

본 도구는 **사용 권한을 가진 콘텐츠**를 처리하기 위한 소프트웨어입니다. 실제 `prod.keys`, `title.keys`, 개인 티켓이나 ROM 샘플을 저장소·이슈에 게시하지 마세요. 실기 설치를 위한 서명·권한 검사를 우회하지 않으며, 합성 파일·에뮬레이터 GUI 테스트가 실기 호환성을 입증하지는 않습니다.

## 라이선스

NSRP 자체 소스는 [MIT 라이선스](LICENSE)를 사용하고, 외부 도구와 UI 구성 요소에는 각각 별도의 라이선스가 적용됩니다.

- **Slint 1.17.1:** Royalty-free Desktop License 2.0을 사용합니다. **도움말 → 정보**에 원본 `AboutSlint` 고지 위젯을 표시하며, [라이선스 원문](licenses/Slint-Royalty-free-2.0.md)을 배포에 포함합니다. `scripts/check-third-party-attribution.ps1`에서 고지 연결과 라이선스 SHA를 검수합니다. Slint 프레임워크 자체를 별도로 배포하지 않습니다.
- **hactool / hacbuild / LibHac:** [외부 라이선스 고지](THIRD_PARTY_NOTICES.md)에서 출처와 적용 라이선스를 확인할 수 있습니다.
- **Mbed TLS:** hactool의 암호화 구성 요소에 필요한 [Apache-2.0 고지 원문](licenses/mbedtls-Apache-2.0.txt)을 변경 없이 보관합니다.
- **sevenz-rust2 0.25.0:** 외부 7z 실행파일 없이 7z를 처리하는 Apache-2.0 라이브러리입니다. [라이선스 원문](licenses/sevenz-rust2-Apache-2.0.txt)을 배포에 포함합니다.

더 자세한 내용은 [빌드·배포 문서](BUILD_RELEASE.md)와 [NSRP 모듈 구성](docs/architecture/NSRP_MODULES.md)을 참고하세요.