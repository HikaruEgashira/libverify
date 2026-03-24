use serde::{Deserialize, Serialize};

use crate::control::{Control, ControlFinding, ControlStatus, evaluate_all};
use crate::evidence::EvidenceBundle;
use crate::profile::{ControlProfile, ProfileOutcome, SeverityLabels, apply_profile};
use crate::registry::ControlRegistry;

/// Complete assessment result combining raw control findings with profile-mapped outcomes.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AssessmentReport {
    pub profile_name: String,
    pub findings: Vec<ControlFinding>,
    pub outcomes: Vec<ProfileOutcome>,
    pub severity_labels: SeverityLabels,
}

/// Assessment report with optional raw evidence bundle for audit trails.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VerificationResult {
    #[serde(flatten)]
    pub report: AssessmentReport,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub evidence: Option<EvidenceBundle>,
}

impl VerificationResult {
    pub fn new(report: AssessmentReport, evidence: Option<EvidenceBundle>) -> Self {
        Self { report, evidence }
    }
}

/// Batch verification report for multiple change requests.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BatchReport {
    pub reports: Vec<BatchEntry>,
    pub total_pass: usize,
    pub total_review: usize,
    pub total_fail: usize,
    pub skipped: Vec<SkippedEntry>,
}

/// A single entry in a batch report.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BatchEntry {
    pub subject_id: String,
    #[serde(flatten)]
    pub result: VerificationResult,
}

/// A skipped entry in a batch report.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SkippedEntry {
    pub subject_id: String,
    pub reason: String,
}

/// Evaluates all controls against evidence and maps findings through a profile.
pub fn assess(
    evidence: &EvidenceBundle,
    controls: &[Box<dyn Control>],
    profile: &dyn ControlProfile,
) -> AssessmentReport {
    let findings: Vec<ControlFinding> = evaluate_all(controls, evidence)
        .into_iter()
        .filter(|f| f.status != ControlStatus::NotApplicable)
        .collect();
    let outcomes = apply_profile(profile, &findings);

    AssessmentReport {
        profile_name: profile.name().to_string(),
        findings,
        outcomes,
        severity_labels: profile.severity_labels(),
    }
}

/// Assess using a control registry and profile.
pub fn assess_with_registry(
    evidence: &EvidenceBundle,
    registry: &ControlRegistry,
    profile: &dyn ControlProfile,
) -> AssessmentReport {
    assess(evidence, registry.controls(), profile)
}

// ---------------------------------------------------------------------------
// Fleet-level aggregation
// ---------------------------------------------------------------------------

use crate::profile::GateDecision;
use std::collections::HashMap;

/// Fleet-level aggregation of verification results across multiple repositories.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FleetReport {
    /// Per-repo summaries, sorted by fail count descending (worst first).
    pub repos: Vec<RepoSummary>,
    /// Control-level statistics across the fleet.
    pub control_stats: Vec<ControlFleetStat>,
    /// Fleet-wide totals.
    pub total_pass: usize,
    pub total_review: usize,
    pub total_fail: usize,
}

/// Summary of a single repository's verification results.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RepoSummary {
    pub repo_id: String,
    pub pass: usize,
    pub review: usize,
    pub fail: usize,
    /// Failing control IDs for quick triage.
    pub failing_controls: Vec<String>,
}

/// Fleet-wide statistics for a single control.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ControlFleetStat {
    pub control_id: String,
    /// Number of repos where this control failed.
    pub fail_count: usize,
    /// Number of repos where this control was reviewed.
    pub review_count: usize,
    /// Number of repos where this control passed.
    pub pass_count: usize,
    /// SOC2 TSC criteria mapping.
    pub tsc_criteria: Vec<String>,
}

impl FleetReport {
    /// Build a fleet report from a set of (repo_id, assessment_report) pairs.
    pub fn from_assessments(entries: Vec<(String, &AssessmentReport)>) -> Self {
        let mut repos = Vec::new();
        let mut control_map: HashMap<String, (usize, usize, usize)> = HashMap::new();
        let mut total_pass = 0;
        let mut total_review = 0;
        let mut total_fail = 0;

        for (repo_id, report) in &entries {
            let mut pass = 0;
            let mut review = 0;
            let mut fail = 0;
            let mut failing_controls = Vec::new();

            for outcome in &report.outcomes {
                let key = outcome.control_id.as_str().to_string();
                let entry = control_map.entry(key.clone()).or_insert((0, 0, 0));

                match outcome.decision {
                    GateDecision::Pass => {
                        pass += 1;
                        entry.2 += 1;
                    }
                    GateDecision::Review => {
                        review += 1;
                        entry.1 += 1;
                    }
                    GateDecision::Fail => {
                        fail += 1;
                        entry.0 += 1;
                        failing_controls.push(key);
                    }
                }
            }

            total_pass += pass;
            total_review += review;
            total_fail += fail;

            repos.push(RepoSummary {
                repo_id: repo_id.clone(),
                pass,
                review,
                fail,
                failing_controls,
            });
        }

        // Sort repos by fail count descending (worst first)
        repos.sort_by(|a, b| b.fail.cmp(&a.fail));

        // Build control stats sorted by fail count descending
        let mut control_stats: Vec<ControlFleetStat> = control_map
            .into_iter()
            .map(|(id, (fail, review, pass))| ControlFleetStat {
                tsc_criteria: crate::control::builtin_tsc_mapping(&id)
                    .iter()
                    .map(|s| s.to_string())
                    .collect(),
                control_id: id,
                fail_count: fail,
                review_count: review,
                pass_count: pass,
            })
            .collect();
        control_stats.sort_by(|a, b| b.fail_count.cmp(&a.fail_count));

        FleetReport {
            repos,
            control_stats,
            total_pass,
            total_review,
            total_fail,
        }
    }
}
