use crate::control::{Control, ControlFinding, ControlId, builtin};
use crate::evidence::{EvidenceBundle, EvidenceState};

/// Default minimum line coverage percentage.
const DEFAULT_THRESHOLD: f64 = 60.0;

/// Verifies that code coverage meets a minimum threshold.
pub struct CoverageThresholdControl;

impl Control for CoverageThresholdControl {
    fn id(&self) -> ControlId {
        builtin::id(builtin::COVERAGE_THRESHOLD)
    }

    fn description(&self) -> &'static str {
        "Code coverage must meet the minimum threshold"
    }

    fn evaluate(&self, evidence: &EvidenceBundle) -> Vec<ControlFinding> {
        let id = self.id();

        let report = match &evidence.coverage_report {
            EvidenceState::NotApplicable => {
                return vec![ControlFinding::not_applicable(
                    id,
                    "Coverage report evidence is not applicable",
                )];
            }
            EvidenceState::Missing { gaps } => {
                return vec![ControlFinding::indeterminate(
                    id,
                    "Coverage report evidence is unavailable",
                    vec![],
                    gaps.clone(),
                )];
            }
            EvidenceState::Complete { value } | EvidenceState::Partial { value, .. } => value,
        };

        let pct = report.line_coverage_pct;

        if pct >= DEFAULT_THRESHOLD {
            vec![ControlFinding::satisfied(
                id,
                format!("Line coverage {pct:.1}% meets threshold {DEFAULT_THRESHOLD:.0}%"),
                vec![format!("{pct:.1}%")],
            )]
        } else {
            vec![ControlFinding::violated(
                id,
                format!("Line coverage {pct:.1}% is below threshold {DEFAULT_THRESHOLD:.0}%"),
                vec![format!("{pct:.1}%")],
            )]
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::control::ControlStatus;
    use crate::evidence::{CoverageReport, EvidenceGap};

    fn make_bundle(pct: f64) -> EvidenceBundle {
        EvidenceBundle {
            coverage_report: EvidenceState::complete(CoverageReport {
                line_coverage_pct: pct,
                lines_total: 1000,
                lines_covered: (pct * 10.0) as u32,
                branch_coverage_pct: None,
                source_format: None,
            }),
            ..Default::default()
        }
    }

    #[test]
    fn above_threshold_is_satisfied() {
        let findings = CoverageThresholdControl.evaluate(&make_bundle(75.0));
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].status, ControlStatus::Satisfied);
        assert!(findings[0].rationale.contains("75.0%"));
    }

    #[test]
    fn at_threshold_is_satisfied() {
        let findings = CoverageThresholdControl.evaluate(&make_bundle(60.0));
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].status, ControlStatus::Satisfied);
    }

    #[test]
    fn below_threshold_is_violated() {
        let findings = CoverageThresholdControl.evaluate(&make_bundle(45.5));
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].status, ControlStatus::Violated);
        assert!(findings[0].rationale.contains("45.5%"));
        assert!(findings[0].rationale.contains("below"));
    }

    #[test]
    fn zero_coverage_is_violated() {
        let findings = CoverageThresholdControl.evaluate(&make_bundle(0.0));
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].status, ControlStatus::Violated);
    }

    #[test]
    fn missing_evidence_is_indeterminate() {
        let bundle = EvidenceBundle {
            coverage_report: EvidenceState::missing(vec![EvidenceGap::CollectionFailed {
                source: "ci".to_string(),
                subject: "coverage".to_string(),
                detail: "no report".to_string(),
            }]),
            ..Default::default()
        };
        let findings = CoverageThresholdControl.evaluate(&bundle);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].status, ControlStatus::Indeterminate);
        assert_eq!(findings[0].evidence_gaps.len(), 1);
    }

    #[test]
    fn not_applicable_when_evidence_not_applicable() {
        let bundle = EvidenceBundle {
            coverage_report: EvidenceState::not_applicable(),
            ..Default::default()
        };
        let findings = CoverageThresholdControl.evaluate(&bundle);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].status, ControlStatus::NotApplicable);
    }

    #[test]
    fn control_id_is_coverage_threshold() {
        assert_eq!(
            CoverageThresholdControl.id(),
            builtin::id(builtin::COVERAGE_THRESHOLD)
        );
    }

    #[test]
    fn partial_evidence_still_evaluates() {
        let bundle = EvidenceBundle {
            coverage_report: EvidenceState::partial(
                CoverageReport {
                    line_coverage_pct: 80.0,
                    lines_total: 100,
                    lines_covered: 80,
                    branch_coverage_pct: None,
                    source_format: None,
                },
                vec![EvidenceGap::Truncated {
                    source: "ci".to_string(),
                    subject: "coverage".to_string(),
                }],
            ),
            ..Default::default()
        };
        let findings = CoverageThresholdControl.evaluate(&bundle);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].status, ControlStatus::Satisfied);
    }
}
