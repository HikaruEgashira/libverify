//! Drata-compatible JSON output format.
//!
//! Delegates to [`libverify_drata::adapter`] for the actual conversion.

use anyhow::Result;
use libverify_core::assessment::{BatchReport, VerificationResult};

pub fn render(result: &VerificationResult, only_failures: bool) -> Result<String> {
    libverify_drata::render(result, only_failures)
}

pub fn render_batch(batch: &BatchReport, only_failures: bool) -> Result<String> {
    libverify_drata::render_batch(batch, only_failures)
}

#[cfg(test)]
mod tests {
    use super::*;
    use libverify_core::assessment::{AssessmentReport, BatchEntry};
    use libverify_core::control::builtin;
    use libverify_core::profile::{FindingSeverity, GateDecision, ProfileOutcome, SeverityLabels};

    fn result() -> VerificationResult {
        let outcome = |id: &str, decision| ProfileOutcome {
            control_id: builtin::id(id),
            severity: FindingSeverity::Info,
            decision,
            rationale: "test rationale".to_string(),
            annotations: Default::default(),
        };
        VerificationResult {
            report: AssessmentReport {
                profile_name: "test-profile".to_string(),
                findings: vec![],
                outcomes: vec![
                    outcome(builtin::REVIEW_INDEPENDENCE, GateDecision::Pass),
                    outcome(builtin::TWO_PARTY_REVIEW, GateDecision::Fail),
                ],
                severity_labels: SeverityLabels::default(),
            },
            evidence: None,
        }
    }

    #[test]
    fn render_delegates_to_adapter() {
        for only_failures in [false, true] {
            let output = render(&result(), only_failures).unwrap();
            assert_eq!(
                output,
                libverify_drata::render(&result(), only_failures).unwrap()
            );
            let json: serde_json::Value = serde_json::from_str(&output).unwrap();
            assert!(!json.is_null());
        }
    }

    #[test]
    fn render_batch_delegates_to_adapter() {
        let batch = BatchReport {
            reports: vec![BatchEntry {
                subject_id: "repo-a".to_string(),
                result: result(),
            }],
            total_pass: 1,
            total_review: 0,
            total_fail: 1,
            skipped: vec![],
        };
        for only_failures in [false, true] {
            let output = render_batch(&batch, only_failures).unwrap();
            assert_eq!(
                output,
                libverify_drata::render_batch(&batch, only_failures).unwrap()
            );
            let json: serde_json::Value = serde_json::from_str(&output).unwrap();
            assert!(!json.is_null());
        }
    }
}
