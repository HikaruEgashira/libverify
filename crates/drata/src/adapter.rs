//! Converts libverify assessment results into Drata API test results.

use libverify_core::assessment::{BatchReport, VerificationResult};
use libverify_core::control::ControlFinding;
use libverify_core::profile::{FindingSeverity, GateDecision, ProfileOutcome};

use crate::model::{DrataMetadata, DrataSummary, DrataTestResult, DrataTestResultBatch};

fn severity_str(s: FindingSeverity) -> &'static str {
    match s {
        FindingSeverity::Info => "info",
        FindingSeverity::Warning => "warning",
        FindingSeverity::Error => "error",
    }
}

fn utc_now_rfc3339() -> String {
    libverify_output_timestamp()
}

fn libverify_output_timestamp() -> String {
    use std::time::SystemTime;
    let now = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap_or_default();
    let secs = now.as_secs();
    let days = secs / 86400;
    let day_secs = secs % 86400;
    let hours = day_secs / 3600;
    let minutes = (day_secs % 3600) / 60;
    let seconds = day_secs % 60;

    // Simple epoch-to-date (good enough for ISO 8601)
    let mut y = 1970i64;
    let mut remaining_days = days as i64;
    loop {
        let year_days = if is_leap(y) { 366 } else { 365 };
        if remaining_days < year_days {
            break;
        }
        remaining_days -= year_days;
        y += 1;
    }
    let leap = is_leap(y);
    let month_days: [i64; 12] = [
        31,
        if leap { 29 } else { 28 },
        31,
        30,
        31,
        30,
        31,
        31,
        30,
        31,
        30,
        31,
    ];
    let mut m = 0usize;
    for md in &month_days {
        if remaining_days < *md {
            break;
        }
        remaining_days -= md;
        m += 1;
    }
    let d = remaining_days + 1;
    format!(
        "{y:04}-{:02}-{d:02}T{hours:02}:{minutes:02}:{seconds:02}Z",
        m + 1
    )
}

fn is_leap(y: i64) -> bool {
    (y % 4 == 0 && y % 100 != 0) || y % 400 == 0
}

fn to_test_result(
    finding: &ControlFinding,
    outcome: &ProfileOutcome,
    profile_name: &str,
    tested_at: &str,
) -> DrataTestResult {
    let subjects: Vec<String> = finding.subjects.clone();
    let external_id = format!(
        "{}:{}:{}",
        profile_name,
        outcome.control_id,
        subjects.first().map(|s| s.as_str()).unwrap_or("unknown")
    );

    DrataTestResult {
        external_id,
        control_id: outcome.control_id.to_string(),
        passed: outcome.decision == GateDecision::Pass,
        description: format!("Control {} verification", outcome.control_id),
        evidence: outcome.rationale.clone(),
        tested_at: tested_at.to_string(),
        metadata: DrataMetadata {
            profile: profile_name.to_string(),
            severity: severity_str(outcome.severity).to_string(),
            decision: outcome.decision.as_str().to_string(),
            subjects,
            framework_ref: outcome.annotations.get("framework_ref").cloned(),
        },
    }
}

/// Convert a single [`VerificationResult`] into a list of [`DrataTestResult`]s.
///
/// When `only_failures` is true, only controls with `GateDecision::Fail` are included.
pub fn to_test_results(result: &VerificationResult, only_failures: bool) -> Vec<DrataTestResult> {
    let report = &result.report;
    let tested_at = utc_now_rfc3339();

    report
        .findings
        .iter()
        .zip(report.outcomes.iter())
        .filter(|(_, outcome)| !only_failures || outcome.decision == GateDecision::Fail)
        .map(|(finding, outcome)| {
            to_test_result(finding, outcome, &report.profile_name, &tested_at)
        })
        .collect()
}

/// Convert a [`BatchReport`] into a [`DrataTestResultBatch`].
pub fn to_batch(batch: &BatchReport, only_failures: bool) -> DrataTestResultBatch {
    let results: Vec<DrataTestResult> = batch
        .reports
        .iter()
        .flat_map(|entry| to_test_results(&entry.result, only_failures))
        .collect();

    let passed = results.iter().filter(|r| r.passed).count();
    let failed = results.iter().filter(|r| !r.passed).count();
    let review = results
        .iter()
        .filter(|r| r.metadata.decision == "review")
        .count();

    DrataTestResultBatch {
        source: "libverify".to_string(),
        source_version: env!("CARGO_PKG_VERSION").to_string(),
        summary: DrataSummary {
            total: results.len(),
            passed,
            failed,
            review,
        },
        results,
    }
}

/// Render a single result as Drata-compatible JSON (array of test results).
pub fn render(result: &VerificationResult, only_failures: bool) -> anyhow::Result<String> {
    let results = to_test_results(result, only_failures);
    Ok(serde_json::to_string_pretty(&results)?)
}

/// Render a batch as a Drata batch payload.
pub fn render_batch(batch: &BatchReport, only_failures: bool) -> anyhow::Result<String> {
    let payload = to_batch(batch, only_failures);
    Ok(serde_json::to_string_pretty(&payload)?)
}

#[cfg(test)]
mod tests {
    use super::*;
    use libverify_core::assessment::{AssessmentReport, BatchEntry};
    use libverify_core::control::{ControlFinding, builtin};
    use libverify_core::profile::{FindingSeverity, ProfileOutcome, SeverityLabels};
    use std::collections::BTreeMap;

    fn make_outcome(
        id: &str,
        severity: FindingSeverity,
        decision: GateDecision,
        rationale: &str,
        framework_ref: Option<&str>,
    ) -> ProfileOutcome {
        let mut annotations = BTreeMap::new();
        if let Some(r) = framework_ref {
            annotations.insert("framework_ref".to_string(), r.to_string());
        }
        ProfileOutcome {
            control_id: builtin::id(id),
            severity,
            decision,
            rationale: rationale.to_string(),
            annotations,
        }
    }

    fn mixed_result() -> VerificationResult {
        VerificationResult {
            report: AssessmentReport {
                profile_name: "soc2".to_string(),
                findings: vec![
                    ControlFinding::satisfied(
                        builtin::id(builtin::REVIEW_INDEPENDENCE),
                        "approved",
                        vec!["owner/repo#1".to_string()],
                    ),
                    ControlFinding::violated(
                        builtin::id(builtin::SOURCE_AUTHENTICITY),
                        "unsigned",
                        vec!["owner/repo#1".to_string()],
                    ),
                    ControlFinding::satisfied(
                        builtin::id(builtin::TWO_PARTY_REVIEW),
                        "two reviewers",
                        vec!["owner/repo#1".to_string()],
                    ),
                ],
                outcomes: vec![
                    make_outcome(
                        builtin::REVIEW_INDEPENDENCE,
                        FindingSeverity::Info,
                        GateDecision::Pass,
                        "approved",
                        Some("CC8.1"),
                    ),
                    make_outcome(
                        builtin::SOURCE_AUTHENTICITY,
                        FindingSeverity::Error,
                        GateDecision::Fail,
                        "unsigned",
                        None,
                    ),
                    make_outcome(
                        builtin::TWO_PARTY_REVIEW,
                        FindingSeverity::Warning,
                        GateDecision::Review,
                        "two reviewers",
                        None,
                    ),
                ],
                severity_labels: SeverityLabels::default(),
            },
            evidence: None,
        }
    }

    fn all_pass_result() -> VerificationResult {
        VerificationResult {
            report: AssessmentReport {
                profile_name: "soc2".to_string(),
                findings: vec![ControlFinding::satisfied(
                    builtin::id(builtin::REVIEW_INDEPENDENCE),
                    "ok",
                    vec![],
                )],
                outcomes: vec![make_outcome(
                    builtin::REVIEW_INDEPENDENCE,
                    FindingSeverity::Info,
                    GateDecision::Pass,
                    "ok",
                    None,
                )],
                severity_labels: SeverityLabels::default(),
            },
            evidence: None,
        }
    }

    #[test]
    fn mixed_produces_correct_count() {
        let results = to_test_results(&mixed_result(), false);
        assert_eq!(results.len(), 3);
        assert!(results[0].passed);
        assert!(!results[1].passed);
        assert!(!results[2].passed); // review is not "passed"
    }

    #[test]
    fn only_failures_filters() {
        let results = to_test_results(&mixed_result(), true);
        assert_eq!(results.len(), 1);
        assert!(!results[0].passed);
        assert_eq!(results[0].metadata.decision, "fail");
    }

    #[test]
    fn framework_ref_included() {
        let results = to_test_results(&mixed_result(), false);
        assert_eq!(results[0].metadata.framework_ref.as_deref(), Some("CC8.1"));
        assert_eq!(results[1].metadata.framework_ref, None);
    }

    #[test]
    fn external_id_format() {
        let results = to_test_results(&mixed_result(), false);
        assert!(results[0].external_id.starts_with("soc2:"));
        assert!(results[0].external_id.contains("owner/repo#1"));
    }

    #[test]
    fn batch_aggregates_all_entries() {
        let batch = BatchReport {
            reports: vec![
                BatchEntry {
                    subject_id: "owner/repo#1".to_string(),
                    result: mixed_result(),
                },
                BatchEntry {
                    subject_id: "owner/repo#2".to_string(),
                    result: all_pass_result(),
                },
            ],
            total_pass: 3,
            total_review: 1,
            total_fail: 1,
            skipped: vec![],
        };
        let payload = to_batch(&batch, false);
        assert_eq!(payload.results.len(), 4); // 3 + 1
        assert_eq!(payload.summary.total, 4);
        assert_eq!(payload.source, "libverify");
    }

    #[test]
    fn render_produces_valid_json() {
        let output = render(&mixed_result(), false).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&output).unwrap();
        assert!(parsed.is_array());
        assert_eq!(parsed.as_array().unwrap().len(), 3);
    }

    #[test]
    fn render_batch_produces_object() {
        let batch = BatchReport {
            reports: vec![BatchEntry {
                subject_id: "r1".to_string(),
                result: mixed_result(),
            }],
            total_pass: 1,
            total_review: 1,
            total_fail: 1,
            skipped: vec![],
        };
        let output = render_batch(&batch, false).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&output).unwrap();
        assert!(parsed.is_object());
        assert_eq!(parsed["source"], "libverify");
        assert!(parsed["results"].is_array());
    }

    #[test]
    fn json_keys_are_camel_case() {
        let results = to_test_results(&mixed_result(), false);
        let json = serde_json::to_string(&results[0]).unwrap();
        assert!(json.contains("externalId"));
        assert!(json.contains("controlId"));
        assert!(json.contains("testedAt"));
        assert!(json.contains("frameworkRef"));
        assert!(!json.contains("external_id"));
        assert!(!json.contains("control_id"));
        assert!(!json.contains("tested_at"));
    }
}
