use anyhow::Result;
use libverify_core::assessment::{AssessmentReport, BatchReport, VerificationResult};
use libverify_core::control::ControlId;
use libverify_core::profile::FindingSeverity;

/// Built-in rule descriptions, keyed by control ID string.
fn builtin_rule_description(id: &str) -> &'static str {
    match id {
        "source-authenticity" => "All commits must carry verified signatures",
        "review-independence" => "Four-eyes: approver must differ from author",
        "branch-history-integrity" => {
            "Branch history must be continuous and protected from force-push"
        }
        "branch-protection-enforcement" => {
            "Branch protection rules must be continuously enforced"
        }
        "two-party-review" => "At least two independent reviewers must approve changes",
        "build-provenance" => "Artifacts must have verified SLSA provenance",
        "required-status-checks" => "At least one required status check must be configured",
        "hosted-build-platform" => {
            "Build must run on a hosted platform, not a developer workstation"
        }
        "provenance-authenticity" => "Provenance attestation must be cryptographically signed",
        "build-isolation" => "Build must run in an isolated, ephemeral environment",
        "change-request-size" => "Change request size must be within acceptable limits",
        "test-coverage" => "Source changes must include matching test updates",
        "scoped-change" => "Changes must be well-scoped (single logical unit)",
        "issue-linkage" => "Change request must reference at least one issue or ticket",
        "stale-review" => "Approvals must postdate the latest source revision",
        "description-quality" => "Change requests must include a meaningful description",
        "merge-commit-policy" => "Source revisions must follow linear history (no merge commits)",
        "conventional-title" => "Titles must follow Conventional Commits format",
        "security-file-change" => {
            "Changes to security-sensitive files require heightened scrutiny"
        }
        "release-traceability" => "Release batches must trace to governed change requests",
        _ => "Custom control",
    }
}

pub fn render(
    result: &VerificationResult,
    only_failures: bool,
    tool_name: &str,
    tool_version: &str,
) -> Result<String> {
    let mut sarif = build_sarif(&result.report, tool_name, tool_version);
    if only_failures {
        filter_sarif_runs(&mut sarif);
    }
    if let Some(evidence) = &result.evidence {
        if let Some(run) = sarif["runs"].as_array_mut().and_then(|a| a.first_mut()) {
            run["properties"]["evidence"] = serde_json::to_value(evidence)?;
        }
    }
    Ok(serde_json::to_string_pretty(&sarif)?)
}

pub fn render_batch(
    batch: &BatchReport,
    only_failures: bool,
    tool_name: &str,
    tool_version: &str,
) -> Result<String> {
    let mut runs = Vec::new();
    for entry in &batch.reports {
        let mut sarif = build_sarif(&entry.result.report, tool_name, tool_version);
        if only_failures {
            filter_sarif_runs(&mut sarif);
        }
        if let Some(run) = sarif["runs"].as_array().and_then(|a| a.first()) {
            let mut run = run.clone();
            let mut props = serde_json::json!({ "subjectId": entry.subject_id });
            if let Some(evidence) = &entry.result.evidence {
                props["evidence"] = serde_json::to_value(evidence)?;
            }
            run["properties"] = props;
            runs.push(run);
        }
    }
    let sarif = serde_json::json!({
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/sarif-2.1/schema/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": runs,
    });
    Ok(serde_json::to_string_pretty(&sarif)?)
}

fn build_sarif(
    report: &AssessmentReport,
    tool_name: &str,
    tool_version: &str,
) -> serde_json::Value {
    let mut seen_rules: Vec<ControlId> = Vec::new();
    let rules: Vec<serde_json::Value> = report
        .outcomes
        .iter()
        .filter_map(|o| {
            if seen_rules.contains(&o.control_id) {
                return None;
            }
            seen_rules.push(o.control_id.clone());
            Some(rule_descriptor(&o.control_id))
        })
        .collect();

    let results: Vec<serde_json::Value> = report
        .findings
        .iter()
        .zip(report.outcomes.iter())
        .map(|(finding, outcome)| {
            let mut result = serde_json::json!({
                "ruleId": outcome.control_id.as_str(),
                "level": severity_to_level(outcome.severity),
                "message": { "text": outcome.rationale },
                "properties": {
                    "decision": outcome.decision.as_str(),
                    "controlStatus": finding.status.as_str(),
                },
            });

            if !finding.subjects.is_empty() {
                let locations: Vec<serde_json::Value> = finding
                    .subjects
                    .iter()
                    .map(|s| {
                        serde_json::json!({
                            "logicalLocations": [{
                                "fullyQualifiedName": s,
                                "kind": "resource",
                            }]
                        })
                    })
                    .collect();
                result["locations"] = serde_json::Value::Array(locations);
            }

            if !finding.evidence_gaps.is_empty() {
                let gaps: Vec<String> = finding
                    .evidence_gaps
                    .iter()
                    .map(|g| format!("{g}"))
                    .collect();
                result["properties"]["evidenceGaps"] = serde_json::json!(gaps);
            }

            result
        })
        .collect();

    serde_json::json!({
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/sarif-2.1/schema/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {
                "driver": {
                    "name": tool_name,
                    "version": tool_version,
                    "rules": rules,
                }
            },
            "results": results,
        }]
    })
}

fn filter_sarif_runs(sarif: &mut serde_json::Value) {
    if let Some(runs) = sarif["runs"].as_array_mut() {
        for run in runs.iter_mut() {
            if let Some(results) = run["results"].as_array() {
                let filtered: Vec<serde_json::Value> = results
                    .iter()
                    .filter(|r| r["level"].as_str() == Some("error"))
                    .cloned()
                    .collect();
                run["results"] = serde_json::Value::Array(filtered);
            }
        }
    }
}

fn rule_descriptor(id: &ControlId) -> serde_json::Value {
    let desc = builtin_rule_description(id.as_str());
    serde_json::json!({
        "id": id.as_str(),
        "shortDescription": { "text": desc },
    })
}

fn severity_to_level(severity: FindingSeverity) -> &'static str {
    match severity {
        FindingSeverity::Info => "note",
        FindingSeverity::Warning => "warning",
        FindingSeverity::Error => "error",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use libverify_core::assessment::AssessmentReport;
    use libverify_core::control::{ControlFinding, builtin};
    use libverify_core::profile::{GateDecision, ProfileOutcome};

    fn sample_report() -> AssessmentReport {
        AssessmentReport {
            profile_name: "slsa-source-l1-build-l1".to_string(),
            findings: vec![
                ControlFinding::satisfied(
                    builtin::id(builtin::REVIEW_INDEPENDENCE),
                    "Independent reviewer approved",
                    vec!["pr:owner/repo#1".to_string()],
                ),
                ControlFinding::violated(
                    builtin::id(builtin::SOURCE_AUTHENTICITY),
                    "1 unsigned commit",
                    vec!["pr:owner/repo#1".to_string()],
                ),
            ],
            outcomes: vec![
                ProfileOutcome {
                    control_id: builtin::id(builtin::REVIEW_INDEPENDENCE),
                    severity: FindingSeverity::Info,
                    decision: GateDecision::Pass,
                    rationale: "Independent reviewer approved".to_string(),
                },
                ProfileOutcome {
                    control_id: builtin::id(builtin::SOURCE_AUTHENTICITY),
                    severity: FindingSeverity::Error,
                    decision: GateDecision::Fail,
                    rationale: "1 unsigned commit".to_string(),
                },
            ],
            severity_labels: Default::default(),
        }
    }

    #[test]
    fn sarif_version_is_2_1_0() {
        let sarif = build_sarif(&sample_report(), "test-verify", "0.1.0");
        assert_eq!(sarif["version"], "2.1.0");
    }

    #[test]
    fn sarif_results_length_matches_outcomes() {
        let sarif = build_sarif(&sample_report(), "test-verify", "0.1.0");
        let results = sarif["runs"][0]["results"].as_array().unwrap();
        assert_eq!(results.len(), 2);
    }

    #[test]
    fn sarif_tool_name_is_configurable() {
        let sarif = build_sarif(&sample_report(), "atlassian-verify", "1.0.0");
        assert_eq!(
            sarif["runs"][0]["tool"]["driver"]["name"],
            "atlassian-verify"
        );
    }
}
