use crate::control::{Control, ControlFinding, ControlId, builtin};
use crate::evidence::{EvidenceBundle, EvidenceState};

/// Verifies that all deterministic gates (tests, lint, typecheck) passed.
pub struct HarnessGateControl;

impl Control for HarnessGateControl {
    fn id(&self) -> ControlId {
        builtin::id(builtin::HARNESS_GATE)
    }

    fn description(&self) -> &'static str {
        "All deterministic gates (tests, lint, typecheck) must pass"
    }

    fn evaluate(&self, evidence: &EvidenceBundle) -> Vec<ControlFinding> {
        let id = self.id();

        let results = match &evidence.harness_results {
            EvidenceState::NotApplicable => {
                return vec![ControlFinding::not_applicable(
                    id,
                    "Harness results evidence is not applicable",
                )];
            }
            EvidenceState::Missing { gaps } => {
                return vec![ControlFinding::indeterminate(
                    id,
                    "Harness results evidence is unavailable",
                    vec![],
                    gaps.clone(),
                )];
            }
            EvidenceState::Complete { value } | EvidenceState::Partial { value, .. } => value,
        };

        if results.is_empty() {
            return vec![ControlFinding::indeterminate(
                id,
                "No harness results found",
                vec![],
                vec![],
            )];
        }

        let failed: Vec<&str> = results
            .iter()
            .filter(|r| !r.passed)
            .map(|r| r.name.as_str())
            .collect();

        if failed.is_empty() {
            vec![ControlFinding::satisfied(
                id,
                format!("{} harness(es) passed", results.len()),
                results.iter().map(|r| r.name.clone()).collect(),
            )]
        } else {
            vec![ControlFinding::violated(
                id,
                format!("{} harness(es) failed: {}", failed.len(), failed.join(", ")),
                failed.iter().map(|s| s.to_string()).collect(),
            )]
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::control::ControlStatus;
    use crate::evidence::{EvidenceGap, HarnessResult};

    fn harness(name: &str, passed: bool) -> HarnessResult {
        HarnessResult {
            name: name.to_string(),
            passed,
            total: 10,
            passed_count: if passed { 10 } else { 8 },
            failed_count: if passed { 0 } else { 2 },
            skipped_count: 0,
            duration_secs: None,
            source_format: None,
        }
    }

    fn make_bundle(results: Vec<HarnessResult>) -> EvidenceBundle {
        EvidenceBundle {
            harness_results: EvidenceState::complete(results),
            ..Default::default()
        }
    }

    #[test]
    fn all_pass_is_satisfied() {
        let findings = HarnessGateControl.evaluate(&make_bundle(vec![
            harness("unit-tests", true),
            harness("lint", true),
        ]));
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].status, ControlStatus::Satisfied);
        assert!(findings[0].rationale.contains("2 harness(es) passed"));
    }

    #[test]
    fn one_fails_is_violated() {
        let findings = HarnessGateControl.evaluate(&make_bundle(vec![
            harness("unit-tests", true),
            harness("lint", false),
        ]));
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].status, ControlStatus::Violated);
        assert!(findings[0].rationale.contains("lint"));
        assert!(findings[0].subjects.contains(&"lint".to_string()));
    }

    #[test]
    fn empty_results_is_indeterminate() {
        let findings = HarnessGateControl.evaluate(&make_bundle(vec![]));
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].status, ControlStatus::Indeterminate);
    }

    #[test]
    fn missing_evidence_is_indeterminate() {
        let bundle = EvidenceBundle {
            harness_results: EvidenceState::missing(vec![EvidenceGap::CollectionFailed {
                source: "ci".to_string(),
                subject: "harness".to_string(),
                detail: "timeout".to_string(),
            }]),
            ..Default::default()
        };
        let findings = HarnessGateControl.evaluate(&bundle);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].status, ControlStatus::Indeterminate);
        assert_eq!(findings[0].evidence_gaps.len(), 1);
    }

    #[test]
    fn not_applicable_when_evidence_not_applicable() {
        let bundle = EvidenceBundle {
            harness_results: EvidenceState::not_applicable(),
            ..Default::default()
        };
        let findings = HarnessGateControl.evaluate(&bundle);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].status, ControlStatus::NotApplicable);
    }

    #[test]
    fn control_id_is_harness_gate() {
        assert_eq!(HarnessGateControl.id(), builtin::id(builtin::HARNESS_GATE));
    }

    #[test]
    fn partial_evidence_still_evaluates() {
        let bundle = EvidenceBundle {
            harness_results: EvidenceState::partial(
                vec![harness("unit-tests", true)],
                vec![EvidenceGap::Truncated {
                    source: "ci".to_string(),
                    subject: "harness_results".to_string(),
                }],
            ),
            ..Default::default()
        };
        let findings = HarnessGateControl.evaluate(&bundle);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].status, ControlStatus::Satisfied);
    }
}
