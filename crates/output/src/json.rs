use anyhow::Result;
use libverify_core::assessment::{AssessmentReport, BatchEntry, BatchReport, VerificationResult};
use libverify_core::profile::GateDecision;

pub fn render(result: &VerificationResult, only_failures: bool) -> Result<String> {
    if only_failures {
        let filtered = filter_result(result);
        Ok(serde_json::to_string_pretty(&filtered)?)
    } else {
        Ok(serde_json::to_string_pretty(result)?)
    }
}

pub fn render_batch(batch: &BatchReport, only_failures: bool) -> Result<String> {
    if only_failures {
        let filtered = filter_batch(batch);
        Ok(serde_json::to_string_pretty(&filtered)?)
    } else {
        Ok(serde_json::to_string_pretty(batch)?)
    }
}

fn filter_result(result: &VerificationResult) -> VerificationResult {
    let report = &result.report;
    let mut filtered_findings = Vec::new();
    let mut filtered_outcomes = Vec::new();

    for (finding, outcome) in report.findings.iter().zip(report.outcomes.iter()) {
        if outcome.decision == GateDecision::Fail {
            filtered_findings.push(finding.clone());
            filtered_outcomes.push(outcome.clone());
        }
    }

    VerificationResult {
        report: AssessmentReport {
            profile_name: report.profile_name.clone(),
            findings: filtered_findings,
            outcomes: filtered_outcomes,
            severity_labels: report.severity_labels.clone(),
        },
        evidence: result.evidence.clone(),
    }
}

fn filter_batch(batch: &BatchReport) -> BatchReport {
    BatchReport {
        reports: batch
            .reports
            .iter()
            .map(|entry| BatchEntry {
                subject_id: entry.subject_id.clone(),
                result: filter_result(&entry.result),
            })
            .collect(),
        total_pass: batch.total_pass,
        total_review: batch.total_review,
        total_fail: batch.total_fail,
        skipped: batch.skipped.clone(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use libverify_core::assessment::AssessmentReport;
    use libverify_core::control::{ControlFinding, builtin};
    use libverify_core::profile::{FindingSeverity, ProfileOutcome};

    fn sample_result() -> VerificationResult {
        VerificationResult {
            report: AssessmentReport {
                profile_name: "test".to_string(),
                findings: vec![
                    ControlFinding::satisfied(
                        builtin::id(builtin::REVIEW_INDEPENDENCE),
                        "approved",
                        vec!["pr:1".to_string()],
                    ),
                    ControlFinding::violated(
                        builtin::id(builtin::SOURCE_AUTHENTICITY),
                        "unsigned",
                        vec!["pr:1".to_string()],
                    ),
                ],
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

    #[test]
    fn render_produces_valid_json() {
        let output = render(&sample_result(), false).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&output).unwrap();
        assert_eq!(parsed["profile_name"], "test");
        assert_eq!(parsed["findings"].as_array().unwrap().len(), 2);
    }

    #[test]
    fn render_with_only_failures_filters_to_fail_only() {
        let output = render(&sample_result(), true).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&output).unwrap();
        let findings = parsed["findings"].as_array().unwrap();
        assert_eq!(findings.len(), 1);
        let outcomes = parsed["outcomes"].as_array().unwrap();
        assert_eq!(outcomes.len(), 1);
        assert_eq!(outcomes[0]["decision"], "fail");
    }

    #[test]
    fn render_batch_produces_valid_json() {
        let batch = BatchReport {
            reports: vec![BatchEntry {
                subject_id: "owner/repo".to_string(),
                result: sample_result(),
            }],
            total_pass: 1,
            total_review: 0,
            total_fail: 1,
            skipped: vec![],
        };
        let output = render_batch(&batch, false).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&output).unwrap();
        assert_eq!(parsed["reports"].as_array().unwrap().len(), 1);
    }

    #[test]
    fn render_batch_with_only_failures_filters() {
        let batch = BatchReport {
            reports: vec![BatchEntry {
                subject_id: "owner/repo".to_string(),
                result: sample_result(),
            }],
            total_pass: 1,
            total_review: 0,
            total_fail: 1,
            skipped: vec![],
        };
        let output = render_batch(&batch, true).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&output).unwrap();
        let outcomes = parsed["reports"][0]["outcomes"].as_array().unwrap();
        assert_eq!(outcomes.len(), 1);
        assert_eq!(outcomes[0]["decision"], "fail");
    }

    #[test]
    fn filter_result_keeps_only_fail_decisions() {
        let filtered = filter_result(&sample_result());
        assert_eq!(filtered.report.findings.len(), 1);
        assert_eq!(filtered.report.outcomes.len(), 1);
        assert_eq!(filtered.report.outcomes[0].decision, GateDecision::Fail);
    }

    #[test]
    fn filter_result_excludes_pass_and_review() {
        let filtered = filter_result(&sample_result());
        for outcome in &filtered.report.outcomes {
            assert_eq!(outcome.decision, GateDecision::Fail);
        }
    }

    #[test]
    fn filter_batch_applies_filter_to_all_entries() {
        let batch = BatchReport {
            reports: vec![
                BatchEntry {
                    subject_id: "repo1".to_string(),
                    result: sample_result(),
                },
                BatchEntry {
                    subject_id: "repo2".to_string(),
                    result: sample_result(),
                },
            ],
            total_pass: 2,
            total_review: 0,
            total_fail: 2,
            skipped: vec![],
        };
        let filtered = filter_batch(&batch);
        assert_eq!(filtered.reports.len(), 2);
        for entry in &filtered.reports {
            assert_eq!(entry.result.report.outcomes.len(), 1);
            assert_eq!(entry.result.report.outcomes[0].decision, GateDecision::Fail);
        }
    }
}
