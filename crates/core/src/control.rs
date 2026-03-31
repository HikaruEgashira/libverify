use std::fmt;

use serde::{Deserialize, Serialize};

use crate::evidence::{EvidenceBundle, EvidenceGap, EvidenceState, RepositoryPosture};

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

    // Dependencies Track
    pub const DEPENDENCY_SIGNATURE: &str = "dependency-signature";
    pub const DEPENDENCY_PROVENANCE_CHECK: &str = "dependency-provenance";
    pub const DEPENDENCY_SIGNER_VERIFIED: &str = "dependency-signer-verified";
    pub const DEPENDENCY_COMPLETENESS: &str = "dependency-completeness";

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

    // ASPM / Repository Posture
    pub const CODEOWNERS_COVERAGE: &str = "codeowners-coverage";
    pub const SECRET_SCANNING: &str = "secret-scanning";
    pub const VULNERABILITY_SCANNING: &str = "vulnerability-scanning";
    pub const SECURITY_POLICY: &str = "security-policy";

    // Enterprise Posture
    pub const SECRET_SCANNING_PUSH_PROTECTION: &str = "secret-scanning-push-protection";
    pub const BRANCH_PROTECTION_ADMIN_ENFORCEMENT: &str = "branch-protection-admin-enforcement";
    pub const DISMISS_STALE_REVIEWS_ON_PUSH: &str = "dismiss-stale-reviews-on-push";
    pub const ACTIONS_PINNED_DEPENDENCIES: &str = "actions-pinned-dependencies";
    pub const ENVIRONMENT_PROTECTION_RULES: &str = "environment-protection-rules";
    pub const CODE_SCANNING_ALERTS_RESOLVED: &str = "code-scanning-alerts-resolved";
    pub const DEPENDENCY_LICENSE_COMPLIANCE: &str = "dependency-license-compliance";
    pub const SBOM_ATTESTATION: &str = "sbom-attestation";
    pub const RELEASE_ASSET_ATTESTATION: &str = "release-asset-attestation";
    pub const PRIVILEGED_WORKFLOW_DETECTION: &str = "privileged-workflow-detection";
    pub const WORKFLOW_PERMISSIONS_RESTRICTED: &str = "workflow-permissions-restricted";
    pub const DEPENDENCY_UPDATE_TOOL: &str = "dependency-update-tool";
    pub const REPOSITORY_PERMISSIONS_AUDIT: &str = "repository-permissions-audit";

    /// All 41 built-in control IDs.
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
        DEPENDENCY_SIGNATURE,
        DEPENDENCY_PROVENANCE_CHECK,
        DEPENDENCY_SIGNER_VERIFIED,
        DEPENDENCY_COMPLETENESS,
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
        CODEOWNERS_COVERAGE,
        SECRET_SCANNING,
        VULNERABILITY_SCANNING,
        SECURITY_POLICY,
        SECRET_SCANNING_PUSH_PROTECTION,
        BRANCH_PROTECTION_ADMIN_ENFORCEMENT,
        DISMISS_STALE_REVIEWS_ON_PUSH,
        ACTIONS_PINNED_DEPENDENCIES,
        ENVIRONMENT_PROTECTION_RULES,
        CODE_SCANNING_ALERTS_RESOLVED,
        DEPENDENCY_LICENSE_COMPLIANCE,
        SBOM_ATTESTATION,
        RELEASE_ASSET_ATTESTATION,
        PRIVILEGED_WORKFLOW_DETECTION,
        WORKFLOW_PERMISSIONS_RESTRICTED,
        DEPENDENCY_UPDATE_TOOL,
        REPOSITORY_PERMISSIONS_AUDIT,
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

    /// Extracts `RepositoryPosture` from evidence, returning appropriate
    /// `Indeterminate` or `NotApplicable` findings for non-complete states.
    ///
    /// Use in posture controls to eliminate repeated `match` boilerplate:
    /// ```ignore
    /// let posture = match ControlFinding::extract_posture(self.id(), evidence) {
    ///     Ok(p) => p,
    ///     Err(findings) => return findings,
    /// };
    /// ```
    pub fn extract_posture(
        id: ControlId,
        evidence: &EvidenceBundle,
    ) -> Result<&RepositoryPosture, Vec<ControlFinding>> {
        match &evidence.repository_posture {
            EvidenceState::Complete { value } | EvidenceState::Partial { value, .. } => Ok(value),
            EvidenceState::Missing { gaps } => Err(vec![ControlFinding::indeterminate(
                id,
                "Repository posture evidence could not be collected",
                vec![],
                gaps.clone(),
            )]),
            EvidenceState::NotApplicable => Err(vec![ControlFinding::not_applicable(
                id,
                "Repository posture not applicable",
            )]),
        }
    }
}

/// A verifiable SDLC control that produces findings from evidence.
pub trait Control: Send + Sync {
    /// Returns the unique identifier for this control.
    fn id(&self) -> ControlId;

    /// Human-readable description for SARIF rule output.
    fn description(&self) -> &'static str {
        "Custom control"
    }

    /// SOC2 Trust Services Criteria this control maps to (e.g., &["CC6.1", "CC8.1"]).
    /// Returns empty slice for controls not mapped to SOC2.
    fn tsc_criteria(&self) -> &'static [&'static str] {
        builtin_tsc_mapping(self.id().as_str())
    }

    /// Evaluates the evidence bundle and returns one finding per subject.
    fn evaluate(&self, evidence: &EvidenceBundle) -> Vec<ControlFinding>;
}

/// Returns SOC2 Trust Services Criteria for a built-in control ID.
pub fn builtin_tsc_mapping(id: &str) -> &'static [&'static str] {
    match id {
        // CC6: Logical and Physical Access Controls
        builtin::SOURCE_AUTHENTICITY => &["CC6.1"],
        builtin::BRANCH_PROTECTION_ENFORCEMENT => &["CC6.1", "CC8.1"],
        builtin::CODEOWNERS_COVERAGE => &["CC6.1"],
        builtin::SECRET_SCANNING => &["CC6.1", "CC6.6"],
        // CC7: System Operations
        builtin::ISSUE_LINKAGE => &["CC7.2"],
        builtin::STALE_REVIEW => &["CC7.2"],
        builtin::SECURITY_FILE_CHANGE => &["CC7.2"],
        builtin::RELEASE_TRACEABILITY => &["CC7.2"],
        builtin::REQUIRED_STATUS_CHECKS => &["CC7.1"],
        builtin::VULNERABILITY_SCANNING => &["CC7.1"],
        builtin::SECURITY_POLICY => &["CC7.3", "CC7.4"],
        // CC8: Change Management
        builtin::REVIEW_INDEPENDENCE => &["CC8.1"],
        builtin::TWO_PARTY_REVIEW => &["CC8.1"],
        builtin::CHANGE_REQUEST_SIZE => &["CC8.1"],
        builtin::TEST_COVERAGE => &["CC8.1"],
        builtin::SCOPED_CHANGE => &["CC8.1"],
        builtin::DESCRIPTION_QUALITY => &["CC8.1"],
        builtin::MERGE_COMMIT_POLICY => &["CC8.1"],
        builtin::CONVENTIONAL_TITLE => &["CC8.1"],
        builtin::BRANCH_HISTORY_INTEGRITY => &["CC8.1"],
        // PI: Processing Integrity
        builtin::BUILD_PROVENANCE => &["PI1.4"],
        builtin::HOSTED_BUILD_PLATFORM => &["PI1.4"],
        builtin::PROVENANCE_AUTHENTICITY => &["PI1.4"],
        builtin::BUILD_ISOLATION => &["PI1.4"],
        // Dependencies (CC7.1 + PI)
        builtin::DEPENDENCY_SIGNATURE => &["CC7.1", "PI1.4"],
        builtin::DEPENDENCY_PROVENANCE_CHECK => &["CC7.1", "PI1.4"],
        builtin::DEPENDENCY_SIGNER_VERIFIED => &["CC7.1", "PI1.4"],
        builtin::DEPENDENCY_COMPLETENESS => &["CC7.1", "PI1.4"],
        // Enterprise Posture
        builtin::SECRET_SCANNING_PUSH_PROTECTION => &["CC6.1", "CC6.6"],
        builtin::BRANCH_PROTECTION_ADMIN_ENFORCEMENT => &["CC6.1", "CC8.1"],
        builtin::DISMISS_STALE_REVIEWS_ON_PUSH => &["CC8.1"],
        builtin::ACTIONS_PINNED_DEPENDENCIES => &["CC7.1", "PI1.4"],
        builtin::ENVIRONMENT_PROTECTION_RULES => &["CC6.1", "CC8.1"],
        builtin::CODE_SCANNING_ALERTS_RESOLVED => &["CC7.1"],
        builtin::DEPENDENCY_LICENSE_COMPLIANCE => &["CC7.1"],
        builtin::SBOM_ATTESTATION => &["CC7.1"],
        builtin::RELEASE_ASSET_ATTESTATION => &["PI1.4"],
        builtin::PRIVILEGED_WORKFLOW_DETECTION => &["CC6.1", "CC8.1"],
        _ => &[],
    }
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
    fn builtin_ids_are_unique() {
        let mut seen = std::collections::HashSet::new();
        for id in builtin::ALL {
            assert!(seen.insert(id), "duplicate built-in ID: {id}");
        }
    }
}
