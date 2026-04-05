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
    use libverify_core::assessment::{
        AssessmentReport, BatchEntry, BatchReport, VerificationResult,
    };
    use libverify_core::control::{ControlFinding, builtin};
    use libverify_core::evidence::EvidenceGap;
    use libverify_core::profile::{GateDecision, ProfileOutcome};
    use std::collections::BTreeMap;

    fn sample_report() -> AssessmentReport {
        AssessmentReport {
            profile_name: "test-profile".to_string(),
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

    fn sample_verification_result() -> VerificationResult {
        VerificationResult {
            report: sample_report(),
            evidence: None,
        }
    }

    // ── days_to_ymd: known-date regression ──────────────────────────

    #[test]
    fn days_to_ymd_known_dates() {
        // Unix epoch
        assert_eq!(days_to_ymd(0), (1970, 1, 1));
        // Standard dates
        assert_eq!(days_to_ymd(59), (1970, 3, 1));
        assert_eq!(days_to_ymd(10957), (2000, 1, 1));
        assert_eq!(days_to_ymd(20453), (2025, 12, 31));
        assert_eq!(days_to_ymd(20454), (2026, 1, 1));
        assert_eq!(days_to_ymd(20536), (2026, 3, 24));
        // Leap years (4-year rule)
        assert_eq!(days_to_ymd(789), (1972, 2, 29));
        assert_eq!(days_to_ymd(19782), (2024, 2, 29));
        assert_eq!(days_to_ymd(19783), (2024, 3, 1));
        // 400-year leap: 2000 IS a leap year
        assert_eq!(days_to_ymd(11016), (2000, 2, 29));
        // Century boundaries: 2100 is NOT a leap year (100-year correction)
        assert_eq!(days_to_ymd(46080), (2096, 2, 29));
        assert_eq!(days_to_ymd(47540), (2100, 2, 28));
        assert_eq!(days_to_ymd(47541), (2100, 3, 1));
        assert_eq!(days_to_ymd(49001), (2104, 2, 29));
        // Additional century boundaries
        assert_eq!(days_to_ymd(84065), (2200, 3, 1));
        assert_eq!(days_to_ymd(120589), (2300, 3, 1));
        // 400-year leap: 2400 IS a leap year (400-year correction)
        assert_eq!(days_to_ymd(157113), (2400, 2, 29));
        assert_eq!(days_to_ymd(157114), (2400, 3, 1));
    }

    // ── utc_now_rfc3339 ─────────────────────────────────────────────

    #[test]
    fn utc_now_rfc3339_format() {
        let ts = utc_now_rfc3339();
        assert!(ts.ends_with('Z'));
        assert_eq!(ts.len(), 20);
        let year: u64 = ts[..4].parse().unwrap();
        assert!(year >= 2026, "unexpected year: {year}");
    }

    // ── builtin_rule_description ────────────────────────────────────

    #[test]
    fn builtin_rule_description_returns_known_description() {
        let desc = builtin_rule_description(builtin::REVIEW_INDEPENDENCE);
        assert!(!desc.is_empty());
        assert_ne!(desc, "xyzzy");
        assert_ne!(desc, "Custom control");
    }

    // ── severity_to_level ───────────────────────────────────────────

    #[test]
    fn severity_to_level_maps_all_variants() {
        assert_eq!(severity_to_level(FindingSeverity::Info), "note");
        assert_eq!(severity_to_level(FindingSeverity::Warning), "warning");
        assert_eq!(severity_to_level(FindingSeverity::Error), "error");
    }

    // ── rule_descriptor ─────────────────────────────────────────────

    #[test]
    fn rule_descriptor_contains_id_and_description() {
        let id = builtin::id(builtin::REVIEW_INDEPENDENCE);
        let desc = rule_descriptor(&id);
        assert_eq!(desc["id"].as_str().unwrap(), builtin::REVIEW_INDEPENDENCE);
        assert!(desc["shortDescription"]["text"].as_str().unwrap().len() > 0);
    }

    // ── build_sarif ─────────────────────────────────────────────────

    #[test]
    fn build_sarif_structure() {
        let sarif = build_sarif(&sample_report(), "test-verify", "0.1.0");
        assert_eq!(sarif["version"], "2.1.0");
        assert_eq!(sarif["runs"][0]["tool"]["driver"]["name"], "test-verify");
        assert_eq!(sarif["runs"][0]["tool"]["driver"]["version"], "0.1.0");
        let results = sarif["runs"][0]["results"].as_array().unwrap();
        assert_eq!(results.len(), 2);

        // First result: pass/note
        assert_eq!(results[0]["level"], "note");
        assert_eq!(results[0]["properties"]["decision"], "pass");

        // Second result: fail/error
        assert_eq!(results[1]["level"], "error");
        assert_eq!(results[1]["properties"]["decision"], "fail");
    }

    #[test]
    fn build_sarif_includes_subjects_as_locations() {
        let sarif = build_sarif(&sample_report(), "t", "0");
        let results = sarif["runs"][0]["results"].as_array().unwrap();
        // Both findings have subjects, so both should have locations
        let locs = results[0]["locations"].as_array().unwrap();
        assert_eq!(locs.len(), 1);
        assert_eq!(
            locs[0]["logicalLocations"][0]["fullyQualifiedName"],
            "pr:owner/repo#1"
        );
    }

    #[test]
    fn build_sarif_omits_locations_when_no_subjects() {
        let report = AssessmentReport {
            profile_name: "test".to_string(),
            findings: vec![ControlFinding::not_applicable(
                builtin::id(builtin::REVIEW_INDEPENDENCE),
                "N/A",
            )],
            outcomes: vec![ProfileOutcome {
                control_id: builtin::id(builtin::REVIEW_INDEPENDENCE),
                severity: FindingSeverity::Info,
                decision: GateDecision::Pass,
                rationale: "N/A".to_string(),
                annotations: Default::default(),
            }],
            severity_labels: Default::default(),
        };
        let sarif = build_sarif(&report, "t", "0");
        let result = &sarif["runs"][0]["results"][0];
        assert!(result["locations"].is_null());
    }

    #[test]
    fn build_sarif_includes_evidence_gaps() {
        let finding = ControlFinding::indeterminate(
            builtin::id(builtin::SOURCE_AUTHENTICITY),
            "missing data",
            vec!["pr:owner/repo#1".to_string()],
            vec![EvidenceGap::CollectionFailed {
                source: "api".to_string(),
                subject: "pr:owner/repo#1".to_string(),
                detail: "timeout".to_string(),
            }],
        );
        // Ensure evidence_gaps is populated
        assert!(!finding.evidence_gaps.is_empty());

        let report = AssessmentReport {
            profile_name: "test".to_string(),
            findings: vec![finding],
            outcomes: vec![ProfileOutcome {
                control_id: builtin::id(builtin::SOURCE_AUTHENTICITY),
                severity: FindingSeverity::Warning,
                decision: GateDecision::Review,
                rationale: "missing data".to_string(),
                annotations: Default::default(),
            }],
            severity_labels: Default::default(),
        };
        let sarif = build_sarif(&report, "t", "0");
        let result = &sarif["runs"][0]["results"][0];
        let gaps = result["properties"]["evidenceGaps"].as_array().unwrap();
        assert!(!gaps.is_empty());
    }

    #[test]
    fn build_sarif_invocations_timestamp() {
        let sarif = build_sarif(&sample_report(), "t", "0");
        let ts = sarif["runs"][0]["invocations"][0]["endTimeUtc"]
            .as_str()
            .unwrap();
        assert!(ts.ends_with('Z'));
        assert_eq!(ts.len(), 20);
    }

    #[test]
    fn build_sarif_dedups_rules() {
        // Two findings for same control → one rule entry
        let report = AssessmentReport {
            profile_name: "test".to_string(),
            findings: vec![
                ControlFinding::satisfied(
                    builtin::id(builtin::REVIEW_INDEPENDENCE),
                    "pass1",
                    vec![],
                ),
                ControlFinding::violated(
                    builtin::id(builtin::REVIEW_INDEPENDENCE),
                    "fail1",
                    vec![],
                ),
            ],
            outcomes: vec![
                ProfileOutcome {
                    control_id: builtin::id(builtin::REVIEW_INDEPENDENCE),
                    severity: FindingSeverity::Info,
                    decision: GateDecision::Pass,
                    rationale: "pass1".to_string(),
                    annotations: Default::default(),
                },
                ProfileOutcome {
                    control_id: builtin::id(builtin::REVIEW_INDEPENDENCE),
                    severity: FindingSeverity::Error,
                    decision: GateDecision::Fail,
                    rationale: "fail1".to_string(),
                    annotations: Default::default(),
                },
            ],
            severity_labels: Default::default(),
        };
        let sarif = build_sarif(&report, "t", "0");
        let rules = sarif["runs"][0]["tool"]["driver"]["rules"]
            .as_array()
            .unwrap();
        assert_eq!(rules.len(), 1);
    }

    // ── filter_sarif_runs ───────────────────────────────────────────

    #[test]
    fn filter_sarif_runs_keeps_only_errors() {
        let mut sarif = build_sarif(&sample_report(), "t", "0");
        // Before filter: 2 results (note + error)
        assert_eq!(sarif["runs"][0]["results"].as_array().unwrap().len(), 2);
        filter_sarif_runs(&mut sarif);
        // After filter: only error level kept
        let results = sarif["runs"][0]["results"].as_array().unwrap();
        assert_eq!(results.len(), 1);
        assert_eq!(results[0]["level"], "error");
    }

    // ── render / render_batch ───────────────────────────────────────

    #[test]
    fn render_produces_valid_sarif_json() {
        let result = sample_verification_result();
        let output = render(&result, false, "test", "0.1").unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&output).unwrap();
        assert_eq!(parsed["version"], "2.1.0");
        assert_eq!(parsed["runs"][0]["results"].as_array().unwrap().len(), 2);
    }

    #[test]
    fn render_with_only_failures_filters() {
        let result = sample_verification_result();
        let output = render(&result, true, "test", "0.1").unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&output).unwrap();
        let results = parsed["runs"][0]["results"].as_array().unwrap();
        assert_eq!(results.len(), 1);
        assert_eq!(results[0]["level"], "error");
    }

    #[test]
    fn render_batch_produces_valid_sarif_json() {
        let batch = BatchReport {
            reports: vec![BatchEntry {
                subject_id: "owner/repo".to_string(),
                result: sample_verification_result(),
            }],
            total_pass: 1,
            total_review: 0,
            total_fail: 1,
            skipped: vec![],
        };
        let output = render_batch(&batch, false, "test", "0.1").unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&output).unwrap();
        assert_eq!(parsed["version"], "2.1.0");
        let runs = parsed["runs"].as_array().unwrap();
        assert_eq!(runs.len(), 1);
        assert_eq!(runs[0]["properties"]["subjectId"], "owner/repo");
    }

    #[test]
    fn render_batch_with_only_failures_filters() {
        let batch = BatchReport {
            reports: vec![BatchEntry {
                subject_id: "owner/repo".to_string(),
                result: sample_verification_result(),
            }],
            total_pass: 1,
            total_review: 0,
            total_fail: 1,
            skipped: vec![],
        };
        let output = render_batch(&batch, true, "test", "0.1").unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&output).unwrap();
        let results = parsed["runs"][0]["results"].as_array().unwrap();
        assert_eq!(results.len(), 1);
        assert_eq!(results[0]["level"], "error");
    }

    // ── annotations in SARIF properties ─────────────────────────────

    #[test]
    fn build_sarif_merges_annotations_into_properties() {
        let mut annotations = BTreeMap::new();
        annotations.insert("framework_ref".to_string(), "SOC2-CC6.1".to_string());
        let report = AssessmentReport {
            profile_name: "test".to_string(),
            findings: vec![ControlFinding::violated(
                builtin::id(builtin::REVIEW_INDEPENDENCE),
                "failed",
                vec![],
            )],
            outcomes: vec![ProfileOutcome {
                control_id: builtin::id(builtin::REVIEW_INDEPENDENCE),
                severity: FindingSeverity::Error,
                decision: GateDecision::Fail,
                rationale: "failed".to_string(),
                annotations,
            }],
            severity_labels: Default::default(),
        };
        let sarif = build_sarif(&report, "t", "0");
        let props = &sarif["runs"][0]["results"][0]["properties"];
        assert_eq!(props["framework_ref"], "SOC2-CC6.1");
    }
}
