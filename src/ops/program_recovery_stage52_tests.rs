//! Stage52: read-only recovery messages must never imply an automatic restore.
use super::*;

fn event(phase: ProgramRecoveryPhase) -> ProgramRecoveryEvent {
    ProgramRecoveryEvent {
        sequence: 0,
        timestamp_unix_seconds: 1,
        phase,
        output_index: Some(0),
    }
}

#[test]
fn stage52_all_inflight_rename_and_cleanup_boundaries_report_uncertainty() {
    for phase in [
        ProgramRecoveryPhase::BackupRenameStarted,
        ProgramRecoveryPhase::PublishRenameStarted,
        ProgramRecoveryPhase::BackupCleanupStarted,
        ProgramRecoveryPhase::RollbackPublishStarted,
        ProgramRecoveryPhase::RollbackBackupStarted,
        ProgramRecoveryPhase::RollbackEmptyCreateStarted,
    ] {
        let history = vec![event(phase)];
        assert!(recovery_has_ambiguous_mutation(&history), "{phase:?}");
        assert!(
            recovery_manual_review_hint_ko(&history).contains("완료 여부를 추측하지"),
            "{phase:?}"
        );
    }
}

#[test]
fn stage52_success_event_and_rollback_failure_give_distinct_safe_guidance() {
    let failed = vec![event(ProgramRecoveryPhase::RollbackFailed)];
    let published = vec![event(ProgramRecoveryPhase::PublicationCompleted)];
    assert!(!recovery_has_ambiguous_mutation(&failed));
    assert!(!recovery_has_ambiguous_mutation(&published));
    assert!(recovery_manual_review_hint_ko(&failed).contains("롤백 실패"));
    assert!(recovery_manual_review_hint_ko(&published).contains("게시 완료"));
    assert!(recovery_manual_review_hint_ko(&failed).contains("수동"));
}

#[test]
fn stage52_legacy_empty_events_require_inspection_not_automatic_restore() {
    assert!(!recovery_has_ambiguous_mutation(&[]));
    let hint = recovery_manual_review_hint_ko(&[]);
    assert!(hint.contains("이전 버전"));
    assert!(hint.contains("자동 복원하지"));
}
