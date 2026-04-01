use anyhow::Result;
use libverify_core::assessment::{AssessmentReport, BatchReport, VerificationResult};
use libverify_core::control::ControlId;
use libverify_core::profile::FindingSeverity;
use std::time::{SystemTime, UNIX_EPOCH};

/// Format a `SystemTime` as an RFC 3339 / ISO 8601 UTC timestamp
/// (e.g. `"2026-03-24T12:34:56Z"`). Uses only `std` — no external crates.
pub fn utc_now_rfc3339() -> String {
    let secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    let s = secs % 60;
    let total_min = secs / 60;
    let m = total_min % 60;
    let total_hour = total_min / 60;
    let h = total_hour % 24;
    let total_days = total_hour / 24;
    // Gregorian calendar reconstruction from epoch days
    let (year, month, day) = days_to_ymd(total_days);
    format!("{year:04}-{month:02}-{day:02}T{h:02}:{m:02}:{s:02}Z")
}

/// Convert days since 1970-01-01 (UTC) to (year, month, day).
pub fn days_to_ymd(days: u64) -> (u64, u64, u64) {
    // Algorithm: Civil date from days — Hatcher/Richards (no external deps)
    let z = days + 719468;
    let era = z / 146097;
    let doe = z % 146097;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if m <= 2 { y + 1 } else { y };
    (y, m, d)
}

fn builtin_rule_description(id: &str) -> &'static str {
    libverify_core::controls::control_description(id)
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
    if let Some(evidence) = &result.evidence
        && let Some(run) = sarif["runs"].as_array_mut().and_then(|a| a.first_mut())
    {
        run["properties"]["evidence"] = serde_json::to_value(evidence)?;
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
            let mut props = serde_json::json!({
                "decision": outcome.decision.as_str(),
                "controlStatus": finding.status.as_str(),
            });
            // Merge policy annotations into SARIF properties
            for (k, v) in &outcome.annotations {
                props[k] = serde_json::Value::String(v.clone());
            }

            let mut result = serde_json::json!({
                "ruleId": outcome.control_id.as_str(),
                "level": severity_to_level(outcome.severity),
                "message": { "text": outcome.rationale },
                "properties": props,
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

    let end_time = utc_now_rfc3339();
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
            "invocations": [{
                "endTimeUtc": end_time,
                "executionSuccessful": true,
            }],
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
                    annotations: Default::default(),
                },
                ProfileOutcome {
                    control_id: builtin::id(builtin::SOURCE_AUTHENTICITY),
                    severity: FindingSeverity::Error,
                    decision: GateDecision::Fail,
                    rationale: "1 unsigned commit".to_string(),
                    annotations: Default::default(),
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

    #[test]
    fn sarif_invocations_present_and_successful() {
        let sarif = build_sarif(&sample_report(), "test-verify", "0.1.0");
        let invocations = sarif["runs"][0]["invocations"].as_array().unwrap();
        assert_eq!(invocations.len(), 1);
        assert_eq!(invocations[0]["executionSuccessful"], true);
        let ts = invocations[0]["endTimeUtc"].as_str().unwrap();
        // Basic ISO 8601 UTC format check: YYYY-MM-DDTHH:MM:SSZ
        assert!(ts.ends_with('Z'), "timestamp must end with Z: {ts}");
        assert_eq!(ts.len(), 20, "unexpected timestamp length: {ts}");
    }

    #[test]
    fn utc_now_rfc3339_format() {
        let ts = utc_now_rfc3339();
        assert!(ts.ends_with('Z'));
        assert_eq!(ts.len(), 20);
        // Year sanity: must be >= 2026
        let year: u64 = ts[..4].parse().unwrap();
        assert!(year >= 2026, "unexpected year: {year}");
    }
}
