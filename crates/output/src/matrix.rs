use std::collections::BTreeMap;

use anyhow::Result;
use libverify_core::assessment::{BatchReport, VerificationResult};
use libverify_core::profile::GateDecision;

fn decision_icon(decision: GateDecision) -> &'static str {
    match decision {
        GateDecision::Pass => "✅",
        GateDecision::Review => "⚠️",
        GateDecision::Fail => "❌",
    }
}

fn sort_key(decision: GateDecision) -> u8 {
    match decision {
        GateDecision::Fail => 0,
        GateDecision::Review => 1,
        GateDecision::Pass => 2,
    }
}

pub fn render(result: &VerificationResult, only_failures: bool) -> Result<String> {
    let report = &result.report;

    let (mut pass, mut review, mut fail) = (0usize, 0usize, 0usize);
    for o in &report.outcomes {
        match o.decision {
            GateDecision::Pass => pass += 1,
            GateDecision::Review => review += 1,
            GateDecision::Fail => fail += 1,
        }
    }

    let mut outcomes: Vec<_> = report
        .outcomes
        .iter()
        .filter(|o| !only_failures || o.decision == GateDecision::Fail)
        .collect();
    outcomes.sort_by_key(|o| sort_key(o.decision));

    let mut out = String::new();
    out.push_str(&format!(
        "# Compliance Matrix — {}\n\n",
        report.profile_name
    ));
    out.push_str(&format!(
        "**Summary:** ✅ {} pass, ⚠️ {} review, ❌ {} fail\n\n",
        pass, review, fail
    ));

    out.push_str("| Control | Status | Decision | Framework Ref | Rationale |\n");
    out.push_str("|---------|--------|----------|---------------|-----------|\n");

    for outcome in outcomes {
        let status = report.severity_labels.label_for(outcome.severity);
        let icon = decision_icon(outcome.decision);
        let framework_ref = outcome
            .annotations
            .get("framework_ref")
            .map(|s| s.as_str())
            .unwrap_or("");
        let rationale = outcome.rationale.replace('|', "\\|");
        out.push_str(&format!(
            "| {} | {} | {} {} | {} | {} |\n",
            outcome.control_id, status, icon, outcome.decision, framework_ref, rationale,
        ));
    }

    Ok(out)
}

pub fn render_batch(batch: &BatchReport, only_failures: bool) -> Result<String> {
    let mut out = String::new();
    out.push_str("# Compliance Matrix — Batch Report\n\n");
    out.push_str(&format!(
        "**Summary:** {} subjects, ✅ {} pass, ⚠️ {} review, ❌ {} fail\n\n",
        batch.reports.len(),
        batch.total_pass,
        batch.total_review,
        batch.total_fail
    ));

    // Track worst decision per control across all subjects in one pass.
    let mut worst: BTreeMap<String, GateDecision> = BTreeMap::new();
    for entry in &batch.reports {
        for outcome in &entry.result.report.outcomes {
            let id = outcome.control_id.to_string();
            worst
                .entry(id)
                .and_modify(|d| {
                    if sort_key(outcome.decision) < sort_key(*d) {
                        *d = outcome.decision;
                    }
                })
                .or_insert(outcome.decision);
        }
    }
    // Filter by worst decision, then sort: Fail first, Review, Pass last.
    let mut control_ids: Vec<String> = worst
        .iter()
        .filter(|(_, d)| !only_failures || **d == GateDecision::Fail)
        .map(|(id, _)| id.clone())
        .collect();
    control_ids.sort_by_key(|id| sort_key(*worst.get(id).unwrap()));

    let subject_ids: Vec<&str> = batch
        .reports
        .iter()
        .map(|e| e.subject_id.as_str())
        .collect();

    out.push_str("| Control");
    for sid in &subject_ids {
        out.push_str(" | ");
        out.push_str(sid);
    }
    out.push_str(" |\n");

    out.push_str("|--------");
    for _ in &subject_ids {
        out.push_str("|--------");
    }
    out.push_str("|\n");

    for control_id in &control_ids {
        out.push_str(&format!("| {}", control_id));
        for entry in &batch.reports {
            let icon = entry
                .result
                .report
                .outcomes
                .iter()
                .find(|o| o.control_id.as_str() == control_id)
                .map(|o| decision_icon(o.decision))
                .unwrap_or("—");
            out.push_str(&format!(" | {}", icon));
        }
        out.push_str(" |\n");
    }

    if !batch.skipped.is_empty() {
        out.push('\n');
        out.push_str("## Skipped\n\n");
        out.push_str("| Subject | Reason |\n");
        out.push_str("|---------|--------|\n");
        for s in &batch.skipped {
            out.push_str(&format!("| {} | {} |\n", s.subject_id, s.reason));
        }
    }

    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use libverify_core::assessment::{AssessmentReport, BatchReport};
    use libverify_core::control::builtin;
    use libverify_core::profile::{FindingSeverity, GateDecision, ProfileOutcome, SeverityLabels};

    fn outcome(id: &str, decision: GateDecision) -> ProfileOutcome {
        ProfileOutcome {
            control_id: builtin::id(id),
            severity: FindingSeverity::Info,
            decision,
            rationale: "test rationale".to_string(),
            annotations: Default::default(),
        }
    }

    fn result_with_outcomes(outcomes: Vec<ProfileOutcome>) -> VerificationResult {
        VerificationResult {
            report: AssessmentReport {
                profile_name: "test-profile".to_string(),
                findings: vec![],
                outcomes,
                severity_labels: SeverityLabels::default(),
            },
            evidence: None,
        }
    }

    #[test]
    fn renders_header_and_summary() {
        let result = result_with_outcomes(vec![
            outcome(builtin::REVIEW_INDEPENDENCE, GateDecision::Pass),
            outcome(builtin::TWO_PARTY_REVIEW, GateDecision::Fail),
        ]);
        let output = render(&result, false).unwrap();
        assert!(output.contains("# Compliance Matrix — test-profile"));
        assert!(output.contains("1 pass"));
        assert!(output.contains("1 fail"));
    }

    #[test]
    fn only_failures_filters_rows() {
        let result = result_with_outcomes(vec![
            outcome(builtin::REVIEW_INDEPENDENCE, GateDecision::Pass),
            outcome(builtin::TWO_PARTY_REVIEW, GateDecision::Fail),
        ]);
        let output = render(&result, true).unwrap();
        assert!(output.contains(builtin::TWO_PARTY_REVIEW));
        assert!(!output.contains(builtin::REVIEW_INDEPENDENCE));
    }

    #[test]
    fn fail_rows_sorted_first() {
        let result = result_with_outcomes(vec![
            outcome(builtin::REVIEW_INDEPENDENCE, GateDecision::Pass),
            outcome(builtin::TWO_PARTY_REVIEW, GateDecision::Fail),
        ]);
        let output = render(&result, false).unwrap();
        let fail_pos = output.find(builtin::TWO_PARTY_REVIEW).unwrap();
        let pass_pos = output.find(builtin::REVIEW_INDEPENDENCE).unwrap();
        assert!(fail_pos < pass_pos);
    }

    #[test]
    fn batch_render_cross_subject_matrix() {
        let entry1 = libverify_core::assessment::BatchEntry {
            subject_id: "repo-a".to_string(),
            result: result_with_outcomes(vec![outcome(
                builtin::REVIEW_INDEPENDENCE,
                GateDecision::Pass,
            )]),
        };
        let entry2 = libverify_core::assessment::BatchEntry {
            subject_id: "repo-b".to_string(),
            result: result_with_outcomes(vec![outcome(
                builtin::REVIEW_INDEPENDENCE,
                GateDecision::Fail,
            )]),
        };
        let batch = BatchReport {
            reports: vec![entry1, entry2],
            total_pass: 1,
            total_review: 0,
            total_fail: 1,
            skipped: vec![],
        };
        let output = render_batch(&batch, false).unwrap();
        assert!(output.contains("repo-a"));
        assert!(output.contains("repo-b"));
        assert!(output.contains(builtin::REVIEW_INDEPENDENCE));
    }

    fn entry(
        subject: &str,
        outcomes: Vec<ProfileOutcome>,
    ) -> libverify_core::assessment::BatchEntry {
        libverify_core::assessment::BatchEntry {
            subject_id: subject.to_string(),
            result: result_with_outcomes(outcomes),
        }
    }

    #[test]
    fn decision_icon_values() {
        assert_eq!(decision_icon(GateDecision::Pass), "✅");
        assert_eq!(decision_icon(GateDecision::Review), "⚠️");
        assert_eq!(decision_icon(GateDecision::Fail), "❌");
    }

    #[test]
    fn render_exact_output() {
        let mut annotated = outcome(builtin::REVIEW_INDEPENDENCE, GateDecision::Pass);
        annotated
            .annotations
            .insert("framework_ref".to_string(), "CC8.1".to_string());
        annotated.rationale = "a|b".to_string();
        let result = result_with_outcomes(vec![
            annotated,
            outcome(builtin::TWO_PARTY_REVIEW, GateDecision::Fail),
            outcome(builtin::SOURCE_AUTHENTICITY, GateDecision::Review),
            outcome(builtin::BRANCH_HISTORY_INTEGRITY, GateDecision::Pass),
        ]);
        let header = "# Compliance Matrix — test-profile\n\n\
            **Summary:** ✅ 2 pass, ⚠️ 1 review, ❌ 1 fail\n\n\
            | Control | Status | Decision | Framework Ref | Rationale |\n\
            |---------|--------|----------|---------------|-----------|\n";
        let fail_row = "| two-party-review | compliant | ❌ fail |  | test rationale |\n";
        let expected = format!(
            "{header}{fail_row}\
            | source-authenticity | compliant | ⚠️ review |  | test rationale |\n\
            | review-independence | compliant | ✅ pass | CC8.1 | a\\|b |\n\
            | branch-history-integrity | compliant | ✅ pass |  | test rationale |\n"
        );
        assert_eq!(render(&result, false).unwrap(), expected);
        assert_eq!(
            render(&result, true).unwrap(),
            format!("{header}{fail_row}")
        );
    }

    #[test]
    fn render_counts_multiple_reviews_and_fails() {
        let result = result_with_outcomes(vec![
            outcome(builtin::REVIEW_INDEPENDENCE, GateDecision::Review),
            outcome(builtin::TWO_PARTY_REVIEW, GateDecision::Review),
            outcome(builtin::SOURCE_AUTHENTICITY, GateDecision::Fail),
            outcome(builtin::BRANCH_HISTORY_INTEGRITY, GateDecision::Fail),
        ]);
        let output = render(&result, false).unwrap();
        assert!(output.contains("**Summary:** ✅ 0 pass, ⚠️ 2 review, ❌ 2 fail\n"));
    }

    fn sample_batch(skipped: Vec<libverify_core::assessment::SkippedEntry>) -> BatchReport {
        BatchReport {
            reports: vec![
                entry(
                    "repo-a",
                    vec![
                        outcome(builtin::TWO_PARTY_REVIEW, GateDecision::Fail),
                        outcome(builtin::BRANCH_HISTORY_INTEGRITY, GateDecision::Pass),
                        outcome(builtin::REVIEW_INDEPENDENCE, GateDecision::Review),
                        outcome(builtin::SOURCE_AUTHENTICITY, GateDecision::Pass),
                    ],
                ),
                entry(
                    "repo-b",
                    vec![
                        outcome(builtin::TWO_PARTY_REVIEW, GateDecision::Pass),
                        outcome(builtin::SOURCE_AUTHENTICITY, GateDecision::Fail),
                        outcome(builtin::BRANCH_PROTECTION_ENFORCEMENT, GateDecision::Review),
                        outcome(builtin::BRANCH_HISTORY_INTEGRITY, GateDecision::Pass),
                    ],
                ),
            ],
            total_pass: 4,
            total_review: 2,
            total_fail: 2,
            skipped,
        }
    }

    const BATCH_HEADER: &str = "# Compliance Matrix — Batch Report\n\n\
        **Summary:** 2 subjects, ✅ 4 pass, ⚠️ 2 review, ❌ 2 fail\n\n\
        | Control | repo-a | repo-b |\n\
        |--------|--------|--------|\n";
    const BATCH_FAIL_ROWS: &str = "| source-authenticity | ✅ | ❌ |\n\
        | two-party-review | ❌ | ✅ |\n";

    #[test]
    fn render_batch_exact_output() {
        let batch = sample_batch(vec![]);
        let expected = format!(
            "{BATCH_HEADER}{BATCH_FAIL_ROWS}\
            | branch-protection-enforcement | — | ⚠️ |\n\
            | review-independence | ⚠️ | — |\n\
            | branch-history-integrity | ✅ | ✅ |\n"
        );
        assert_eq!(render_batch(&batch, false).unwrap(), expected);
    }

    #[test]
    fn render_batch_only_failures_with_skipped() {
        let batch = sample_batch(vec![libverify_core::assessment::SkippedEntry {
            subject_id: "repo-c".to_string(),
            reason: "not found".to_string(),
        }]);
        let expected = format!(
            "{BATCH_HEADER}{BATCH_FAIL_ROWS}\n\
            ## Skipped\n\n\
            | Subject | Reason |\n\
            |---------|--------|\n\
            | repo-c | not found |\n"
        );
        assert_eq!(render_batch(&batch, true).unwrap(), expected);
    }
}
