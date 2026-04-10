//! Converts libverify assessment results into Vanta API resources.

use libverify_core::assessment::{BatchReport, VerificationResult};
use libverify_core::control::ControlFinding;
use libverify_core::profile::{FindingSeverity, GateDecision, ProfileOutcome};

use crate::model::{VantaControl, VantaProperties, VantaResource};

fn severity_str(s: FindingSeverity) -> &'static str {
    match s {
        FindingSeverity::Info => "info",
        FindingSeverity::Warning => "warning",
        FindingSeverity::Error => "error",
    }
}

fn to_vanta_control(finding: &ControlFinding, outcome: &ProfileOutcome) -> VantaControl {
    VantaControl {
        control_id: outcome.control_id.to_string(),
        status: finding.status.as_str().to_string(),
        decision: outcome.decision.as_str().to_string(),
        severity: severity_str(outcome.severity).to_string(),
        rationale: outcome.rationale.clone(),
        framework_ref: outcome.annotations.get("framework_ref").cloned(),
    }
}

struct OutcomeCounts {
    pass: usize,
    review: usize,
    fail: usize,
}

impl OutcomeCounts {
    fn tally(outcomes: &[ProfileOutcome]) -> Self {
        let mut counts = Self {
            pass: 0,
            review: 0,
            fail: 0,
        };
        for o in outcomes {
            match o.decision {
                GateDecision::Pass => counts.pass += 1,
                GateDecision::Review => counts.review += 1,
                GateDecision::Fail => counts.fail += 1,
            }
        }
        counts
    }

    fn overall_status(&self) -> &'static str {
        if self.fail > 0 {
            "FAIL"
        } else if self.review > 0 {
            "WARN"
        } else {
            "PASS"
        }
    }
}

/// Convert a single [`VerificationResult`] into a [`VantaResource`].
///
/// When `only_failures` is true, only controls with `GateDecision::Fail` are
/// included in the `controls` array.
pub fn to_resource(result: &VerificationResult, only_failures: bool) -> VantaResource {
    let report = &result.report;

    let first_subject: Option<&str> = report
        .findings
        .iter()
        .flat_map(|f| f.subjects.first().map(|s| s.as_str()))
        .next();

    let resource_id = first_subject.unwrap_or(&report.profile_name).to_string();
    let display_name = first_subject
        .map(|s| s.to_string())
        .unwrap_or_else(|| "SDLC Verification".to_string());
    let description = format!(
        "SDLC verification result for {}",
        first_subject.unwrap_or(&report.profile_name)
    );

    let counts = OutcomeCounts::tally(&report.outcomes);
    let status = counts.overall_status().to_string();
    let status_description = format!(
        "{} pass, {} review, {} fail",
        counts.pass, counts.review, counts.fail
    );

    let controls: Vec<VantaControl> = report
        .findings
        .iter()
        .zip(report.outcomes.iter())
        .filter(|(_, outcome)| !only_failures || outcome.decision == GateDecision::Fail)
        .map(|(finding, outcome)| to_vanta_control(finding, outcome))
        .collect();

    VantaResource {
        resource_id,
        resource_type: "sdlc_verification".to_string(),
        display_name,
        description,
        status,
        status_description,
        properties: VantaProperties {
            profile: report.profile_name.clone(),
            controls,
        },
    }
}

/// Convert a [`BatchReport`] into a list of [`VantaResource`]s (one per subject).
pub fn to_resources(batch: &BatchReport, only_failures: bool) -> Vec<VantaResource> {
    batch
        .reports
        .iter()
        .map(|entry| to_resource(&entry.result, only_failures))
        .collect()
}

/// Render a single result as Vanta-compatible JSON.
pub fn render(result: &VerificationResult, only_failures: bool) -> anyhow::Result<String> {
    let resource = to_resource(result, only_failures);
    Ok(serde_json::to_string_pretty(&resource)?)
}

/// Render a batch as a JSON array of Vanta resources.
pub fn render_batch(batch: &BatchReport, only_failures: bool) -> anyhow::Result<String> {
    let resources = to_resources(batch, only_failures);
    Ok(serde_json::to_string_pretty(&resources)?)
}

#[cfg(test)]
mod tests {
    use super::*;
    use libverify_core::assessment::AssessmentReport;
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
                severity_labels: Default::default(),
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
                severity_labels: Default::default(),
            },
            evidence: None,
        }
    }

    fn review_only_result() -> VerificationResult {
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
                    FindingSeverity::Warning,
                    GateDecision::Review,
                    "needs review",
                    None,
                )],
                severity_labels: Default::default(),
            },
            evidence: None,
        }
    }

    // ── Status mapping ──────────────────────────────────────────────

    #[test]
    fn mixed_outcomes_produce_fail_status() {
        let resource = to_resource(&mixed_result(), false);
        assert_eq!(resource.status, "FAIL");
        assert_eq!(resource.status_description, "1 pass, 1 review, 1 fail");
        assert_eq!(resource.resource_type, "sdlc_verification");
        assert_eq!(resource.properties.profile, "soc2");
        assert_eq!(resource.properties.controls.len(), 3);
    }

    #[test]
    fn all_pass_produces_pass_status() {
        let resource = to_resource(&all_pass_result(), false);
        assert_eq!(resource.status, "PASS");
    }

    #[test]
    fn review_only_produces_warn_status() {
        let resource = to_resource(&review_only_result(), false);
        assert_eq!(resource.status, "WARN");
    }

    // ── Filtering ───────────────────────────────────────────────────

    #[test]
    fn only_failures_filters_controls() {
        let resource = to_resource(&mixed_result(), true);
        assert_eq!(resource.properties.controls.len(), 1);
        assert_eq!(resource.properties.controls[0].decision, "fail");
    }

    // ── Framework ref ───────────────────────────────────────────────

    #[test]
    fn framework_ref_from_annotations_is_included() {
        let resource = to_resource(&mixed_result(), false);
        let controls = &resource.properties.controls;
        assert_eq!(controls[0].framework_ref.as_deref(), Some("CC8.1"));
        assert_eq!(controls[1].framework_ref, None);
    }

    // ── Resource ID ─────────────────────────────────────────────────

    #[test]
    fn resource_id_uses_first_subject() {
        let resource = to_resource(&mixed_result(), false);
        assert_eq!(resource.resource_id, "owner/repo#1");
        assert_eq!(resource.display_name, "owner/repo#1");
    }

    #[test]
    fn resource_id_falls_back_to_profile_when_no_subjects() {
        let resource = to_resource(&all_pass_result(), false);
        assert_eq!(resource.resource_id, "soc2");
        assert_eq!(resource.display_name, "SDLC Verification");
    }

    // ── Batch ───────────────────────────────────────────────────────

    #[test]
    fn batch_produces_one_resource_per_entry() {
        let batch = BatchReport {
            reports: vec![
                libverify_core::assessment::BatchEntry {
                    subject_id: "owner/repo#1".to_string(),
                    result: mixed_result(),
                },
                libverify_core::assessment::BatchEntry {
                    subject_id: "owner/repo#2".to_string(),
                    result: all_pass_result(),
                },
            ],
            total_pass: 3,
            total_review: 1,
            total_fail: 1,
            skipped: vec![],
        };
        let resources = to_resources(&batch, false);
        assert_eq!(resources.len(), 2);
        assert_eq!(resources[0].status, "FAIL");
        assert_eq!(resources[1].status, "PASS");
    }

    // ── JSON round-trip ─────────────────────────────────────────────

    #[test]
    fn json_round_trip_preserves_structure() {
        let resource = to_resource(&mixed_result(), false);
        let json = serde_json::to_string(&resource).unwrap();
        let parsed: VantaResource = serde_json::from_str(&json).unwrap();
        assert_eq!(resource, parsed);
    }

    #[test]
    fn render_produces_valid_json() {
        let output = render(&mixed_result(), false).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&output).unwrap();
        assert_eq!(parsed["status"], "FAIL");
        assert_eq!(parsed["resourceType"], "sdlc_verification");
    }

    #[test]
    fn render_batch_produces_array() {
        let batch = BatchReport {
            reports: vec![libverify_core::assessment::BatchEntry {
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
        assert!(parsed.is_array());
    }

    // ── camelCase serialization ─────────────────────────────────────

    #[test]
    fn json_keys_are_camel_case() {
        let resource = to_resource(&mixed_result(), false);
        let json = serde_json::to_string(&resource).unwrap();
        assert!(json.contains("resourceId"));
        assert!(json.contains("resourceType"));
        assert!(json.contains("displayName"));
        assert!(json.contains("statusDescription"));
        assert!(json.contains("controlId"));
        assert!(json.contains("frameworkRef"));
        // Ensure snake_case is NOT present
        assert!(!json.contains("resource_id"));
        assert!(!json.contains("resource_type"));
        assert!(!json.contains("control_id"));
    }
}
