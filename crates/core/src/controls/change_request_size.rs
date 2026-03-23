use crate::control::{builtin, Control, ControlFinding, ControlId};
use crate::evidence::{EvidenceBundle, EvidenceState};
use crate::size::{classify_pr_size, is_generated_file};
use crate::verdict::Severity;

const WARN_LINES: usize = 500;
const WARN_FILES: usize = 15;
const ERROR_LINES: usize = 1000;
const ERROR_FILES: usize = 30;

/// Verifies that change request size is within acceptable limits.
pub struct ChangeRequestSizeControl;

impl Control for ChangeRequestSizeControl {
    fn id(&self) -> ControlId {
        builtin::id(builtin::CHANGE_REQUEST_SIZE)
    }

    fn evaluate(&self, evidence: &EvidenceBundle) -> Vec<ControlFinding> {
        if evidence.change_requests.is_empty() {
            return vec![ControlFinding::not_applicable(
                self.id(),
                "No change requests found",
            )];
        }

        evidence
            .change_requests
            .iter()
            .map(|cr| evaluate_change(self.id(), cr))
            .collect()
    }
}

fn evaluate_change(id: ControlId, cr: &crate::evidence::GovernedChange) -> ControlFinding {
    let assets = match &cr.changed_assets {
        EvidenceState::NotApplicable => {
            return ControlFinding::not_applicable(id, "Changed assets not applicable");
        }
        EvidenceState::Missing { gaps } => {
            return ControlFinding::indeterminate(
                id,
                "Changed assets evidence could not be collected",
                Vec::new(),
                gaps.clone(),
            );
        }
        EvidenceState::Complete { value } | EvidenceState::Partial { value, .. } => value,
    };

    let filtered: Vec<_> = assets
        .iter()
        .filter(|a| !is_generated_file(&a.path))
        .collect();

    let total_lines: usize = filtered
        .iter()
        .map(|a| (a.additions + a.deletions) as usize)
        .sum();
    let total_files = filtered.len();

    let subjects: Vec<String> = filtered.iter().map(|a| a.path.clone()).collect();

    let severity = classify_pr_size(
        total_lines,
        total_files,
        WARN_LINES,
        WARN_FILES,
        ERROR_LINES,
        ERROR_FILES,
    );

    match severity {
        Severity::Pass => ControlFinding::satisfied(
            id,
            format!("Change request size is acceptable ({total_lines} lines across {total_files} files)"),
            subjects,
        ),
        Severity::Warning => ControlFinding::violated(
            id,
            format!(
                "Change request touches {total_lines} lines across {total_files} files \
                 (warning: >{WARN_LINES} lines or >{WARN_FILES} files)"
            ),
            subjects,
        ),
        Severity::Error => ControlFinding::violated(
            id,
            format!(
                "Change request touches {total_lines} lines across {total_files} files \
                 (exceeds: >{ERROR_LINES} lines or >{ERROR_FILES} files)"
            ),
            subjects,
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::control::ControlStatus;
    use crate::evidence::{ChangeRequestId, ChangedAsset, EvidenceGap, GovernedChange};

    fn asset(path: &str, additions: u32, deletions: u32) -> ChangedAsset {
        ChangedAsset {
            path: path.to_string(),
            diff_available: true,
            additions,
            deletions,
            status: "modified".to_string(),
            diff: None,
        }
    }

    fn bundle_with(assets: EvidenceState<Vec<ChangedAsset>>) -> EvidenceBundle {
        EvidenceBundle {
            change_requests: vec![GovernedChange {
                id: ChangeRequestId::new("github_pr", "owner/repo#1"),
                title: "test".to_string(),
                summary: None,
                submitted_by: None,
                changed_assets: assets,
                approval_decisions: EvidenceState::not_applicable(),
                source_revisions: EvidenceState::not_applicable(),
                work_item_refs: EvidenceState::not_applicable(),
            }],
            ..Default::default()
        }
    }

    #[test]
    fn not_applicable_when_no_changes() {
        let findings = ChangeRequestSizeControl.evaluate(&EvidenceBundle::default());
        assert_eq!(findings[0].status, ControlStatus::NotApplicable);
    }

    #[test]
    fn satisfied_for_small_pr() {
        let bundle = bundle_with(EvidenceState::complete(vec![
            asset("src/foo.rs", 50, 10),
            asset("src/bar.rs", 30, 5),
        ]));
        let findings = ChangeRequestSizeControl.evaluate(&bundle);
        assert_eq!(findings[0].status, ControlStatus::Satisfied);
    }

    #[test]
    fn violated_for_large_pr() {
        let bundle = bundle_with(EvidenceState::complete(vec![asset(
            "src/huge.rs",
            800,
            300,
        )]));
        let findings = ChangeRequestSizeControl.evaluate(&bundle);
        assert_eq!(findings[0].status, ControlStatus::Violated);
    }

    #[test]
    fn generated_files_excluded() {
        let bundle = bundle_with(EvidenceState::complete(vec![
            asset("package-lock.json", 5000, 2000),
            asset("src/main.rs", 10, 5),
        ]));
        let findings = ChangeRequestSizeControl.evaluate(&bundle);
        assert_eq!(findings[0].status, ControlStatus::Satisfied);
        assert!(
            !findings[0]
                .subjects
                .contains(&"package-lock.json".to_string())
        );
    }

    #[test]
    fn indeterminate_when_evidence_missing() {
        let bundle = bundle_with(EvidenceState::missing(vec![
            EvidenceGap::CollectionFailed {
                source: "github".to_string(),
                subject: "files".to_string(),
                detail: "API error".to_string(),
            },
        ]));
        let findings = ChangeRequestSizeControl.evaluate(&bundle);
        assert_eq!(findings[0].status, ControlStatus::Indeterminate);
    }
}
