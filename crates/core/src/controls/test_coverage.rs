use crate::control::{Control, ControlFinding, ControlId, builtin};
use crate::evidence::{EvidenceBundle, EvidenceState, GovernedChange};
use crate::scope::{FileRole, classify_file_role, is_non_code_file};
use crate::test_coverage::has_test_coverage;

/// Verifies that source file changes include corresponding test updates.
pub struct TestCoverageControl;

impl Control for TestCoverageControl {
    fn id(&self) -> ControlId {
        builtin::id(builtin::TEST_COVERAGE)
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

fn evaluate_change(id: ControlId, cr: &GovernedChange) -> ControlFinding {
    let cr_subject = cr.id.to_string();

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

    // Filter to code files that are not removed
    let code_files: Vec<&str> = assets
        .iter()
        .filter(|a| a.status != "removed" && !is_non_code_file(&a.path))
        .map(|a| a.path.as_str())
        .collect();

    let source_files: Vec<&str> = code_files
        .iter()
        .copied()
        .filter(|p| classify_file_role(p) == FileRole::Source)
        .collect();

    let test_files: Vec<&str> = code_files
        .iter()
        .copied()
        .filter(|p| classify_file_role(p) == FileRole::Test)
        .collect();

    if source_files.is_empty() {
        return ControlFinding::satisfied(
            id,
            format!("{cr_subject}: no source files changed; test coverage not required"),
            Vec::new(),
        );
    }

    let uncovered = has_test_coverage(&source_files, &test_files);

    if uncovered.is_empty() {
        ControlFinding::satisfied(
            id,
            format!(
                "{cr_subject}: all {} source file(s) have matching test updates",
                source_files.len()
            ),
            source_files.iter().map(|s| s.to_string()).collect(),
        )
    } else {
        let uncovered_paths: Vec<String> =
            uncovered.iter().map(|u| u.source_path.clone()).collect();
        ControlFinding::violated(
            id,
            format!(
                "{cr_subject}: {} source file(s) changed without matching test updates: {}",
                uncovered.len(),
                uncovered_paths.join(", ")
            ),
            uncovered_paths,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::control::ControlStatus;
    use crate::evidence::{ChangeRequestId, ChangedAsset, EvidenceGap};

    fn asset(path: &str) -> ChangedAsset {
        ChangedAsset {
            path: path.to_string(),
            diff_available: true,
            additions: 1,
            deletions: 0,
            status: "modified".to_string(),
            diff: None,
        }
    }

    fn bundle_with(assets: Vec<ChangedAsset>) -> EvidenceBundle {
        EvidenceBundle {
            change_requests: vec![GovernedChange {
                id: ChangeRequestId::new("test", "owner/repo#1"),
                title: "test".to_string(),
                summary: None,
                submitted_by: None,
                changed_assets: EvidenceState::complete(assets),
                approval_decisions: EvidenceState::not_applicable(),
                source_revisions: EvidenceState::not_applicable(),
                work_item_refs: EvidenceState::not_applicable(),
            }],
            ..Default::default()
        }
    }

    #[test]
    fn not_applicable_when_no_changes() {
        let findings = TestCoverageControl.evaluate(&EvidenceBundle::default());
        assert_eq!(findings[0].status, ControlStatus::NotApplicable);
    }

    #[test]
    fn satisfied_when_test_pair_exists() {
        let bundle = bundle_with(vec![asset("src/foo.rs"), asset("tests/foo_test.rs")]);
        let findings = TestCoverageControl.evaluate(&bundle);
        assert_eq!(findings[0].status, ControlStatus::Satisfied);
    }

    #[test]
    fn violated_when_source_has_no_test() {
        let bundle = bundle_with(vec![asset("src/bar.rs")]);
        let findings = TestCoverageControl.evaluate(&bundle);
        assert_eq!(findings[0].status, ControlStatus::Violated);
        assert!(findings[0].subjects.contains(&"src/bar.rs".to_string()));
    }

    #[test]
    fn satisfied_for_test_only_pr() {
        let bundle = bundle_with(vec![asset("tests/foo_test.rs")]);
        let findings = TestCoverageControl.evaluate(&bundle);
        assert_eq!(findings[0].status, ControlStatus::Satisfied);
    }

    #[test]
    fn satisfied_for_non_code_only_pr() {
        let bundle = bundle_with(vec![asset("README.md"), asset("docs/guide.md")]);
        let findings = TestCoverageControl.evaluate(&bundle);
        assert_eq!(findings[0].status, ControlStatus::Satisfied);
    }

    #[test]
    fn indeterminate_when_evidence_missing() {
        let bundle = EvidenceBundle {
            change_requests: vec![GovernedChange {
                id: ChangeRequestId::new("test", "owner/repo#1"),
                title: "test".to_string(),
                summary: None,
                submitted_by: None,
                changed_assets: EvidenceState::missing(vec![EvidenceGap::CollectionFailed {
                    source: "github".to_string(),
                    subject: "files".to_string(),
                    detail: "API error".to_string(),
                }]),
                approval_decisions: EvidenceState::not_applicable(),
                source_revisions: EvidenceState::not_applicable(),
                work_item_refs: EvidenceState::not_applicable(),
            }],
            ..Default::default()
        };
        let findings = TestCoverageControl.evaluate(&bundle);
        assert_eq!(findings[0].status, ControlStatus::Indeterminate);
    }
}
