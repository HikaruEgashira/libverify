use crate::control::{Control, ControlFinding, ControlId, builtin};
use crate::evidence::{CheckConclusion, EvidenceBundle, EvidenceState};

/// Verifies that CI check runs on the change request HEAD commit all passed.
pub struct RequiredStatusChecksControl;

impl Control for RequiredStatusChecksControl {
    fn id(&self) -> ControlId {
        builtin::id(builtin::REQUIRED_STATUS_CHECKS)
    }

    fn evaluate(&self, evidence: &EvidenceBundle) -> Vec<ControlFinding> {
        let id = self.id();

        let runs = match &evidence.check_runs {
            EvidenceState::NotApplicable => {
                return vec![ControlFinding::not_applicable(
                    id,
                    "Check runs evidence is not applicable",
                )];
            }
            EvidenceState::Missing { gaps } => {
                return vec![ControlFinding::indeterminate(
                    id,
                    "Check runs evidence is unavailable",
                    vec!["commit".to_string()],
                    gaps.clone(),
                )];
            }
            EvidenceState::Complete { value } => value,
            EvidenceState::Partial { value, .. } => value,
        };

        if runs.is_empty() {
            return vec![ControlFinding::indeterminate(
                id,
                "No check runs found on the HEAD commit",
                vec!["commit".to_string()],
                vec![],
            )];
        }

        let failed: Vec<&str> = runs
            .iter()
            .filter(|r| is_failing_conclusion(&r.conclusion))
            .map(|r| r.name.as_str())
            .collect();

        if failed.is_empty() {
            vec![ControlFinding::satisfied(
                id,
                format!("{} check run(s) passed", runs.len()),
                vec!["commit".to_string()],
            )]
        } else {
            vec![ControlFinding::violated(
                id,
                format!(
                    "{} check run(s) failed: {}",
                    failed.len(),
                    failed.join(", ")
                ),
                vec!["commit".to_string()],
            )]
        }
    }
}

/// Returns true if the conclusion represents a failing state.
fn is_failing_conclusion(conclusion: &CheckConclusion) -> bool {
    matches!(
        conclusion,
        CheckConclusion::Failure
            | CheckConclusion::Cancelled
            | CheckConclusion::TimedOut
            | CheckConclusion::ActionRequired
            | CheckConclusion::Pending
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::control::ControlStatus;
    use crate::evidence::{CheckConclusion, CheckRunEvidence, EvidenceGap};

    fn make_bundle(runs: Vec<CheckRunEvidence>) -> EvidenceBundle {
        EvidenceBundle {
            check_runs: EvidenceState::complete(runs),
            ..Default::default()
        }
    }

    fn run(name: &str, conclusion: CheckConclusion) -> CheckRunEvidence {
        CheckRunEvidence {
            name: name.to_string(),
            conclusion,
            app_slug: None,
        }
    }

    // --- Satisfied ---

    #[test]
    fn all_checks_success_is_satisfied() {
        let findings = RequiredStatusChecksControl.evaluate(&make_bundle(vec![run(
            "ci/build",
            CheckConclusion::Success,
        )]));
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].status, ControlStatus::Satisfied);
        assert_eq!(findings[0].subjects, vec!["commit"]);
        assert!(findings[0].rationale.contains("1 check run(s) passed"));
    }

    #[test]
    fn multiple_checks_all_pass_is_satisfied() {
        let findings = RequiredStatusChecksControl.evaluate(&make_bundle(vec![
            run("ci/build", CheckConclusion::Success),
            run("ci/test", CheckConclusion::Success),
            run("ci/lint", CheckConclusion::Neutral),
        ]));
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].status, ControlStatus::Satisfied);
        assert!(findings[0].rationale.contains("3 check run(s) passed"));
    }

    #[test]
    fn skipped_check_is_satisfied() {
        let findings = RequiredStatusChecksControl.evaluate(&make_bundle(vec![
            run("ci/build", CheckConclusion::Success),
            run("ci/optional", CheckConclusion::Skipped),
        ]));
        assert_eq!(findings[0].status, ControlStatus::Satisfied);
    }

    // --- Violated ---

    #[test]
    fn one_check_failed_is_violated() {
        let findings = RequiredStatusChecksControl.evaluate(&make_bundle(vec![
            run("ci/build", CheckConclusion::Success),
            run("ci/test", CheckConclusion::Failure),
        ]));
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].status, ControlStatus::Violated);
        assert!(findings[0].rationale.contains("ci/test"));
    }

    #[test]
    fn cancelled_check_is_violated() {
        let findings = RequiredStatusChecksControl.evaluate(&make_bundle(vec![run(
            "ci/build",
            CheckConclusion::Cancelled,
        )]));
        assert_eq!(findings[0].status, ControlStatus::Violated);
    }

    #[test]
    fn timed_out_check_is_violated() {
        let findings = RequiredStatusChecksControl.evaluate(&make_bundle(vec![run(
            "ci/build",
            CheckConclusion::TimedOut,
        )]));
        assert_eq!(findings[0].status, ControlStatus::Violated);
    }

    #[test]
    fn pending_check_is_violated() {
        let findings = RequiredStatusChecksControl.evaluate(&make_bundle(vec![run(
            "ci/deploy",
            CheckConclusion::Pending,
        )]));
        assert_eq!(findings[0].status, ControlStatus::Violated);
    }

    // --- Indeterminate ---

    #[test]
    fn no_check_runs_is_indeterminate() {
        let findings = RequiredStatusChecksControl.evaluate(&make_bundle(vec![]));
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].status, ControlStatus::Indeterminate);
        assert!(findings[0].rationale.contains("No check runs found"));
    }

    #[test]
    fn indeterminate_when_evidence_missing() {
        let bundle = EvidenceBundle {
            check_runs: EvidenceState::missing(vec![EvidenceGap::CollectionFailed {
                source: "github".to_string(),
                subject: "commit".to_string(),
                detail: "403 Forbidden".to_string(),
            }]),
            ..Default::default()
        };
        let findings = RequiredStatusChecksControl.evaluate(&bundle);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].status, ControlStatus::Indeterminate);
        assert_eq!(findings[0].evidence_gaps.len(), 1);
    }

    // --- NotApplicable ---

    #[test]
    fn not_applicable_when_evidence_not_applicable() {
        let bundle = EvidenceBundle {
            check_runs: EvidenceState::not_applicable(),
            ..Default::default()
        };
        let findings = RequiredStatusChecksControl.evaluate(&bundle);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].status, ControlStatus::NotApplicable);
    }

    // --- Edge cases ---

    #[test]
    fn partial_evidence_still_evaluates() {
        let bundle = EvidenceBundle {
            check_runs: EvidenceState::partial(
                vec![run("ci/test", CheckConclusion::Success)],
                vec![EvidenceGap::Truncated {
                    source: "github".to_string(),
                    subject: "check_runs".to_string(),
                }],
            ),
            ..Default::default()
        };
        let findings = RequiredStatusChecksControl.evaluate(&bundle);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].status, ControlStatus::Satisfied);
    }

    #[test]
    fn control_id_is_required_status_checks() {
        assert_eq!(
            RequiredStatusChecksControl.id(),
            builtin::id(builtin::REQUIRED_STATUS_CHECKS)
        );
    }
}
