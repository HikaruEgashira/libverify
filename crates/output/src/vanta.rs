//! Vanta-compatible JSON output format.
//!
//! Delegates to [`libverify_vanta::adapter`] for the actual conversion.

use anyhow::Result;
use libverify_core::assessment::{BatchReport, VerificationResult};

pub fn render(result: &VerificationResult, only_failures: bool) -> Result<String> {
    libverify_vanta::render(result, only_failures)
}

pub fn render_batch(batch: &BatchReport, only_failures: bool) -> Result<String> {
    libverify_vanta::render_batch(batch, only_failures)
}

#[cfg(test)]
mod tests {
    use super::*;
    use libverify_core::assessment::{AssessmentReport, BatchEntry, SkippedEntry};
    use libverify_core::control::builtin;
    use libverify_core::profile::{FindingSeverity, GateDecision, ProfileOutcome};

    fn sample_result() -> VerificationResult {
        VerificationResult {
            report: AssessmentReport {
                profile_name: "test".to_string(),
                findings: vec![],
                outcomes: vec![
                    ProfileOutcome {
                        control_id: builtin::id(builtin::REVIEW_INDEPENDENCE),
                        severity: FindingSeverity::Info,
                        decision: GateDecision::Pass,
                        rationale: "approved".to_string(),
                        annotations: Default::default(),
                    },
                    ProfileOutcome {
                        control_id: builtin::id(builtin::SOURCE_AUTHENTICITY),
                        severity: FindingSeverity::Error,
                        decision: GateDecision::Fail,
                        rationale: "unsigned".to_string(),
                        annotations: Default::default(),
                    },
                ],
                severity_labels: Default::default(),
            },
            evidence: None,
        }
    }

    fn sample_batch() -> BatchReport {
        BatchReport {
            reports: vec![BatchEntry {
                subject_id: "repo-a".to_string(),
                result: sample_result(),
            }],
            total_pass: 1,
            total_review: 0,
            total_fail: 1,
            skipped: vec![SkippedEntry {
                subject_id: "repo-b".to_string(),
                reason: "not found".to_string(),
            }],
        }
    }

    #[test]
    fn render_matches_adapter() {
        let result = sample_result();
        for only_failures in [false, true] {
            let out = render(&result, only_failures).unwrap();
            assert_eq!(
                out,
                libverify_vanta::render(&result, only_failures).unwrap()
            );
            serde_json::from_str::<serde_json::Value>(&out).unwrap();
        }
    }

    #[test]
    fn render_batch_matches_adapter() {
        let batch = sample_batch();
        for only_failures in [false, true] {
            let out = render_batch(&batch, only_failures).unwrap();
            assert_eq!(
                out,
                libverify_vanta::render_batch(&batch, only_failures).unwrap()
            );
            serde_json::from_str::<serde_json::Value>(&out).unwrap();
        }
    }
}
