use std::fmt;

use serde::{Deserialize, Serialize};

use crate::evidence::{EvidenceBundle, EvidenceGap};

/// A string-based control identifier, enabling open extensibility.
///
/// Built-in controls use kebab-case IDs (e.g. "review-independence").
/// Platform-specific verifiers can register controls with their own IDs
/// (e.g. "jira-linkage", "bitbucket-pipeline-status").
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct ControlId(String);

impl ControlId {
    pub fn new(id: impl Into<String>) -> Self {
        Self(id.into())
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for ControlId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl From<&str> for ControlId {
    fn from(s: &str) -> Self {
        Self(s.to_string())
    }
}

impl From<String> for ControlId {
    fn from(s: String) -> Self {
        Self(s)
    }
}

// --- Built-in control IDs (constants for compile-time safety) ---

pub mod builtin {
    use super::ControlId;

    // Source Track
    pub const SOURCE_AUTHENTICITY: &str = "source-authenticity";
    pub const REVIEW_INDEPENDENCE: &str = "review-independence";
    pub const BRANCH_HISTORY_INTEGRITY: &str = "branch-history-integrity";
    pub const BRANCH_PROTECTION_ENFORCEMENT: &str = "branch-protection-enforcement";
    pub const TWO_PARTY_REVIEW: &str = "two-party-review";

    // Build Track
    pub const BUILD_PROVENANCE: &str = "build-provenance";
    pub const REQUIRED_STATUS_CHECKS: &str = "required-status-checks";
    pub const HOSTED_BUILD_PLATFORM: &str = "hosted-build-platform";
    pub const PROVENANCE_AUTHENTICITY: &str = "provenance-authenticity";
    pub const BUILD_ISOLATION: &str = "build-isolation";

    // Compliance (platform-neutral naming)
    pub const CHANGE_REQUEST_SIZE: &str = "change-request-size";
    pub const TEST_COVERAGE: &str = "test-coverage";
    pub const SCOPED_CHANGE: &str = "scoped-change";
    pub const ISSUE_LINKAGE: &str = "issue-linkage";
    pub const STALE_REVIEW: &str = "stale-review";
    pub const DESCRIPTION_QUALITY: &str = "description-quality";
    pub const MERGE_COMMIT_POLICY: &str = "merge-commit-policy";
    pub const CONVENTIONAL_TITLE: &str = "conventional-title";
    pub const SECURITY_FILE_CHANGE: &str = "security-file-change";
    pub const RELEASE_TRACEABILITY: &str = "release-traceability";

    /// All 20 built-in control IDs.
    pub const ALL: &[&str] = &[
        SOURCE_AUTHENTICITY,
        REVIEW_INDEPENDENCE,
        BRANCH_HISTORY_INTEGRITY,
        BRANCH_PROTECTION_ENFORCEMENT,
        TWO_PARTY_REVIEW,
        BUILD_PROVENANCE,
        REQUIRED_STATUS_CHECKS,
        HOSTED_BUILD_PLATFORM,
        PROVENANCE_AUTHENTICITY,
        BUILD_ISOLATION,
        CHANGE_REQUEST_SIZE,
        TEST_COVERAGE,
        SCOPED_CHANGE,
        ISSUE_LINKAGE,
        STALE_REVIEW,
        DESCRIPTION_QUALITY,
        MERGE_COMMIT_POLICY,
        CONVENTIONAL_TITLE,
        SECURITY_FILE_CHANGE,
        RELEASE_TRACEABILITY,
    ];

    /// Returns a ControlId for a built-in constant.
    pub fn id(s: &str) -> ControlId {
        ControlId::new(s)
    }
}

/// Outcome of evaluating a single control against evidence.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ControlStatus {
    Satisfied,
    Violated,
    Indeterminate,
    NotApplicable,
}

impl ControlStatus {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Satisfied => "satisfied",
            Self::Violated => "violated",
            Self::Indeterminate => "indeterminate",
            Self::NotApplicable => "not_applicable",
        }
    }
}

impl fmt::Display for ControlStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Result of a single control evaluation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ControlFinding {
    pub control_id: ControlId,
    pub status: ControlStatus,
    pub rationale: String,
    pub subjects: Vec<String>,
    pub evidence_gaps: Vec<EvidenceGap>,
}

impl ControlFinding {
    pub fn satisfied(
        control_id: ControlId,
        rationale: impl Into<String>,
        subjects: Vec<String>,
    ) -> Self {
        Self {
            control_id,
            status: ControlStatus::Satisfied,
            rationale: rationale.into(),
            subjects,
            evidence_gaps: Vec::new(),
        }
    }

    pub fn violated(
        control_id: ControlId,
        rationale: impl Into<String>,
        subjects: Vec<String>,
    ) -> Self {
        Self {
            control_id,
            status: ControlStatus::Violated,
            rationale: rationale.into(),
            subjects,
            evidence_gaps: Vec::new(),
        }
    }

    pub fn indeterminate(
        control_id: ControlId,
        rationale: impl Into<String>,
        subjects: Vec<String>,
        evidence_gaps: Vec<EvidenceGap>,
    ) -> Self {
        Self {
            control_id,
            status: ControlStatus::Indeterminate,
            rationale: rationale.into(),
            subjects,
            evidence_gaps,
        }
    }

    pub fn not_applicable(control_id: ControlId, rationale: impl Into<String>) -> Self {
        Self {
            control_id,
            status: ControlStatus::NotApplicable,
            rationale: rationale.into(),
            subjects: Vec::new(),
            evidence_gaps: Vec::new(),
        }
    }
}

/// A verifiable SDLC control that produces findings from evidence.
pub trait Control: Send + Sync {
    /// Returns the unique identifier for this control.
    fn id(&self) -> ControlId;

    /// Evaluates the evidence bundle and returns one finding per subject.
    fn evaluate(&self, evidence: &EvidenceBundle) -> Vec<ControlFinding>;
}

/// Runs every control against the evidence bundle and collects all findings.
pub fn evaluate_all(
    controls: &[Box<dyn Control>],
    evidence: &EvidenceBundle,
) -> Vec<ControlFinding> {
    let mut findings = Vec::new();
    for control in controls {
        findings.extend(control.evaluate(evidence));
    }
    findings
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn control_id_display() {
        let id = ControlId::new("review-independence");
        assert_eq!(id.to_string(), "review-independence");
        assert_eq!(id.as_str(), "review-independence");
    }

    #[test]
    fn control_id_from_str() {
        let id: ControlId = "source-authenticity".into();
        assert_eq!(id.as_str(), "source-authenticity");
    }

    #[test]
    fn builtin_ids_are_20() {
        assert_eq!(builtin::ALL.len(), 20);
    }

    #[test]
    fn builtin_ids_are_unique() {
        let mut seen = std::collections::HashSet::new();
        for id in builtin::ALL {
            assert!(seen.insert(id), "duplicate built-in ID: {id}");
        }
    }
}
