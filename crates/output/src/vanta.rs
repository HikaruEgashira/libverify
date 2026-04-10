use anyhow::Result;
use libverify_core::assessment::{BatchReport, VerificationResult};
use libverify_core::control::ControlFinding;
use libverify_core::profile::{FindingSeverity, GateDecision, ProfileOutcome};
use serde::Serialize;

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct VantaResource {
    resource_id: String,
    resource_type: String,
    display_name: String,
    description: String,
    status: String,
    status_description: String,
    properties: VantaProperties,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct VantaProperties {
    profile: String,
    controls: Vec<VantaControl>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct VantaControl {
    control_id: String,
    status: String,
    decision: String,
    severity: String,
    rationale: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    framework_ref: Option<String>,
}

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
        let mut counts = Self { pass: 0, review: 0, fail: 0 };
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

fn build_resource(result: &VerificationResult, only_failures: bool) -> VantaResource {
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
    let status_description = format!("{} pass, {} review, {} fail", counts.pass, counts.review, counts.fail);

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

pub fn render(result: &VerificationResult, only_failures: bool) -> Result<String> {
    let resource = build_resource(result, only_failures);
    Ok(serde_json::to_string_pretty(&resource)?)
}

pub fn render_batch(batch: &BatchReport, only_failures: bool) -> Result<String> {
    let resources: Vec<VantaResource> = batch
        .reports
        .iter()
        .map(|entry| build_resource(&entry.result, only_failures))
        .collect();
    Ok(serde_json::to_string_pretty(&resources)?)
}

#[cfg(test)]
mod tests {
    use super::*;
    use libverify_core::assessment::{AssessmentReport, BatchEntry};
    use libverify_core::control::{ControlFinding, builtin};
    use libverify_core::profile::{FindingSeverity, ProfileOutcome};
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

    #[test]
    fn mixed_outcomes_produce_fail_status() {
        let output = render(&mixed_result(), false).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&output).unwrap();
        assert_eq!(parsed["status"], "FAIL");
        assert_eq!(parsed["statusDescription"], "1 pass, 1 review, 1 fail");
        assert_eq!(parsed["resourceType"], "sdlc_verification");
        assert_eq!(parsed["properties"]["profile"], "soc2");
        assert_eq!(parsed["properties"]["controls"].as_array().unwrap().len(), 3);
    }

    #[test]
    fn only_failures_filters_controls() {
        let output = render(&mixed_result(), true).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&output).unwrap();
        let controls = parsed["properties"]["controls"].as_array().unwrap();
        assert_eq!(controls.len(), 1);
        assert_eq!(controls[0]["decision"], "fail");
    }

    #[test]
    fn all_pass_produces_pass_status() {
        let result = VerificationResult {
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
        };
        let output = render(&result, false).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&output).unwrap();
        assert_eq!(parsed["status"], "PASS");
    }

    #[test]
    fn review_only_produces_warn_status() {
        let result = VerificationResult {
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
        };
        let output = render(&result, false).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&output).unwrap();
        assert_eq!(parsed["status"], "WARN");
    }

    #[test]
    fn framework_ref_from_annotations_is_included() {
        let output = render(&mixed_result(), false).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&output).unwrap();
        let controls = parsed["properties"]["controls"].as_array().unwrap();
        let first = &controls[0];
        assert_eq!(first["controlId"], builtin::REVIEW_INDEPENDENCE);
        assert_eq!(first["frameworkRef"], "CC8.1");
        let second = &controls[1];
        assert!(second.get("frameworkRef").is_none() || second["frameworkRef"].is_null());
    }

    #[test]
    fn batch_render_produces_array() {
        let batch = BatchReport {
            reports: vec![
                BatchEntry {
                    subject_id: "owner/repo#1".to_string(),
                    result: mixed_result(),
                },
                BatchEntry {
                    subject_id: "owner/repo#2".to_string(),
                    result: mixed_result(),
                },
            ],
            total_pass: 2,
            total_review: 2,
            total_fail: 2,
            skipped: vec![],
        };
        let output = render_batch(&batch, false).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&output).unwrap();
        assert!(parsed.is_array());
        assert_eq!(parsed.as_array().unwrap().len(), 2);
    }

    #[test]
    fn resource_id_uses_first_subject() {
        let output = render(&mixed_result(), false).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&output).unwrap();
        assert_eq!(parsed["resourceId"], "owner/repo#1");
        assert_eq!(parsed["displayName"], "owner/repo#1");
    }

    #[test]
    fn resource_id_falls_back_to_profile_when_no_subjects() {
        let result = VerificationResult {
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
        };
        let output = render(&result, false).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&output).unwrap();
        assert_eq!(parsed["resourceId"], "soc2");
        assert_eq!(parsed["displayName"], "SDLC Verification");
    }
}
