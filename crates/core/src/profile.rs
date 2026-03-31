use std::collections::BTreeMap;
use std::fmt;

use serde::{Deserialize, Serialize};

use crate::control::{ControlFinding, ControlId};

/// Policy-specific display labels for severity levels.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SeverityLabels {
    pub info: String,
    pub warning: String,
    pub error: String,
}

impl Default for SeverityLabels {
    fn default() -> Self {
        Self {
            info: "compliant".to_string(),
            warning: "observation".to_string(),
            error: "exception".to_string(),
        }
    }
}

impl SeverityLabels {
    pub fn label_for(&self, severity: FindingSeverity) -> &str {
        match severity {
            FindingSeverity::Info => &self.info,
            FindingSeverity::Warning => &self.warning,
            FindingSeverity::Error => &self.error,
        }
    }
}

/// Severity level assigned to a control finding by a profile.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FindingSeverity {
    Info,
    Warning,
    Error,
}

/// Gate outcome that determines whether a pipeline stage may proceed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GateDecision {
    Pass,
    Review,
    Fail,
}

impl GateDecision {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Pass => "pass",
            Self::Review => "review",
            Self::Fail => "fail",
        }
    }
}

impl fmt::Display for GateDecision {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// The profile-mapped result for a single control finding.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProfileOutcome {
    pub control_id: ControlId,
    pub severity: FindingSeverity,
    pub decision: GateDecision,
    pub rationale: String,
    /// Policy-supplied key-value annotations (e.g. framework_ref, recommendation).
    /// Empty by default for backward compatibility with existing Rego presets.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub annotations: BTreeMap<String, String>,
}

/// Maps raw control findings to severity and gate decisions for a given policy.
pub trait ControlProfile {
    fn name(&self) -> &str;
    fn map(&self, finding: &ControlFinding) -> ProfileOutcome;
    fn severity_labels(&self) -> SeverityLabels {
        SeverityLabels::default()
    }
}

/// Applies a profile to all findings and returns the mapped outcomes.
pub fn apply_profile(
    profile: &dyn ControlProfile,
    findings: &[ControlFinding],
) -> Vec<ProfileOutcome> {
    findings
        .iter()
        .map(|finding| profile.map(finding))
        .collect()
}
