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

