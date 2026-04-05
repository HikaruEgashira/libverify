use crate::control::{Control, ControlFinding, ControlId, builtin};
use crate::evidence::{CheckConclusion, EvidenceBundle, EvidenceState};

/// Required CI harness categories that must each have at least one passing run.
const REQUIRED_CATEGORIES: &[&str] = &["build", "test", "lint", "typecheck"];

/// Verifies that all required CI harnesses (build, test, lint, typecheck) passed.
pub struct HarnessResultControl;

impl Control for HarnessResultControl {
    fn id(&self) -> ControlId {
        builtin::id(builtin::HARNESS_RESULT)
    }

    fn description(&self) -> &'static str {
        "All required CI harnesses (build, test, lint, typecheck) must pass"
    }

    fn evaluate(&self, evidence: &EvidenceBundle) -> Vec<ControlFinding> {
        let id = self.id();

        let (runs, gaps) = match &evidence.check_runs {
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
            EvidenceState::Complete { value } => (value, vec![]),
            EvidenceState::Partial { value, gaps } => (value, gaps.clone()),
        };

        let missing_categories: Vec<&str> = REQUIRED_CATEGORIES
            .iter()
            .filter(|category| {
                !runs.iter().any(|run| {
                    run.name.to_lowercase().contains(*category)
                        && run.conclusion == CheckConclusion::Success
                })
            })
            .copied()
            .collect();

        if missing_categories.is_empty() {
            let mut rationale = format!(
                "All {} required harness categories covered",
                REQUIRED_CATEGORIES.len()
            );
            if !gaps.is_empty() {
                rationale.push_str(" (partial evidence — some gaps exist)");
            }
            vec![ControlFinding::satisfied(
                id,
                rationale,
                vec!["commit".to_string()],
            )]
        } else {
            vec![ControlFinding::violated(
                id,
                format!(
                    "Missing passing harness for: {}",
                    missing_categories.join(", ")
                ),
                vec!["commit".to_string()],
            )]
        }
    }
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
    fn all_categories_passing_is_satisfied() {
        let findings = HarnessResultControl.evaluate(&make_bundle(vec![
            run("ci/build", CheckConclusion::Success),
            run("ci/test", CheckConclusion::Success),
            run("ci/lint", CheckConclusion::Success),
            run("ci/typecheck", CheckConclusion::Success),
        ]));
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].status, ControlStatus::Satisfied);
        assert!(
            findings[0]
                .rationale
                .contains("4 required harness categories covered")
        );
    }

    // --- Violated: missing category ---

    #[test]
    fn missing_lint_category_is_violated() {
        let findings = HarnessResultControl.evaluate(&make_bundle(vec![
            run("ci/build", CheckConclusion::Success),
            run("ci/test", CheckConclusion::Success),
            run("ci/typecheck", CheckConclusion::Success),
        ]));
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].status, ControlStatus::Violated);
        assert!(findings[0].rationale.contains("lint"));
    }

    // --- Violated: failed build (only run for that category) ---

    #[test]
    fn failed_build_only_run_is_violated() {
        let findings = HarnessResultControl.evaluate(&make_bundle(vec![
            run("ci/build", CheckConclusion::Failure),
            run("ci/test", CheckConclusion::Success),
            run("ci/lint", CheckConclusion::Success),
            run("ci/typecheck", CheckConclusion::Success),
        ]));
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].status, ControlStatus::Violated);
        assert!(findings[0].rationale.contains("build"));
    }

    // --- Indeterminate: missing evidence ---

    #[test]
    fn missing_evidence_is_indeterminate() {
        let bundle = EvidenceBundle {
            check_runs: EvidenceState::missing(vec![EvidenceGap::CollectionFailed {
                source: "github".to_string(),
                subject: "commit".to_string(),
                detail: "403 Forbidden".to_string(),
            }]),
            ..Default::default()
        };
        let findings = HarnessResultControl.evaluate(&bundle);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].status, ControlStatus::Indeterminate);
        assert_eq!(findings[0].evidence_gaps.len(), 1);
    }

    // --- NotApplicable ---

    #[test]
    fn not_applicable_evidence_is_not_applicable() {
        let bundle = EvidenceBundle {
            check_runs: EvidenceState::not_applicable(),
            ..Default::default()
        };
        let findings = HarnessResultControl.evaluate(&bundle);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].status, ControlStatus::NotApplicable);
    }

    // --- Violated: mixed pass/fail across categories ---

    #[test]
    fn mixed_some_categories_only_failed_is_violated() {
        let findings = HarnessResultControl.evaluate(&make_bundle(vec![
            run("ci/build", CheckConclusion::Success),
            run("ci/test", CheckConclusion::Failure),
            run("ci/lint", CheckConclusion::Success),
            run("ci/typecheck", CheckConclusion::Cancelled),
        ]));
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].status, ControlStatus::Violated);
        assert!(findings[0].rationale.contains("test"));
        assert!(findings[0].rationale.contains("typecheck"));
    }

    // --- Case-insensitive matching ---

    #[test]
    fn case_insensitive_matching_works() {
        let findings = HarnessResultControl.evaluate(&make_bundle(vec![
            run("CI Build", CheckConclusion::Success),
            run("Unit Test Suite", CheckConclusion::Success),
            run("ESLint Check", CheckConclusion::Success),
            run("TypeCheck", CheckConclusion::Success),
        ]));
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].status, ControlStatus::Satisfied);
    }

    // --- Partial evidence with gaps ---

    #[test]
    fn partial_evidence_evaluates_available_runs() {
        let bundle = EvidenceBundle {
            check_runs: EvidenceState::partial(
                vec![
                    run("ci/build", CheckConclusion::Success),
                    run("ci/test", CheckConclusion::Success),
                    run("ci/lint", CheckConclusion::Success),
                    run("ci/typecheck", CheckConclusion::Success),
                ],
                vec![EvidenceGap::Truncated {
                    source: "github".to_string(),
                    subject: "check_runs".to_string(),
                }],
            ),
            ..Default::default()
        };
        let findings = HarnessResultControl.evaluate(&bundle);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].status, ControlStatus::Satisfied);
        assert!(findings[0].rationale.contains("partial evidence"));
    }

    #[test]
    fn control_id_is_harness_result() {
        assert_eq!(
            HarnessResultControl.id(),
            builtin::id(builtin::HARNESS_RESULT)
        );
    }
}
