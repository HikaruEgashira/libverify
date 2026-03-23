use std::fmt;

use serde::{Deserialize, Serialize};

use crate::control::{ControlFinding, ControlId, ControlStatus};
use crate::slsa::{SlsaLevel, SlsaTrack, control_slsa_mapping};

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
}

/// Maps raw control findings to severity and gate decisions for a given policy.
pub trait ControlProfile {
    fn name(&self) -> &str;
    fn map(&self, finding: &ControlFinding) -> ProfileOutcome;
    fn severity_labels(&self) -> SeverityLabels {
        SeverityLabels::default()
    }
}

/// SLSA level-aware profile.
pub struct SlsaLevelProfile {
    pub source_level: SlsaLevel,
    pub build_level: SlsaLevel,
    profile_name: String,
}

impl SlsaLevelProfile {
    pub fn new(source_level: SlsaLevel, build_level: SlsaLevel) -> Self {
        let profile_name =
            format!("slsa-source-{source_level}-build-{build_level}").to_ascii_lowercase();
        Self {
            source_level,
            build_level,
            profile_name,
        }
    }

    fn is_required(&self, control_id: &ControlId) -> bool {
        match control_slsa_mapping(control_id) {
            Some(mapping) => {
                let target_level = match mapping.track {
                    SlsaTrack::Source => self.source_level,
                    SlsaTrack::Build => self.build_level,
                };
                mapping.level <= target_level
            }
            None => false,
        }
    }
}

impl ControlProfile for SlsaLevelProfile {
    fn name(&self) -> &str {
        &self.profile_name
    }

    fn map(&self, finding: &ControlFinding) -> ProfileOutcome {
        let required = self.is_required(&finding.control_id);

        let (severity, decision) = match finding.status {
            ControlStatus::Satisfied | ControlStatus::NotApplicable => {
                (FindingSeverity::Info, GateDecision::Pass)
            }
            ControlStatus::Indeterminate => {
                if required {
                    (FindingSeverity::Error, GateDecision::Fail)
                } else {
                    (FindingSeverity::Warning, GateDecision::Review)
                }
            }
            ControlStatus::Violated => (FindingSeverity::Error, GateDecision::Fail),
        };

        ProfileOutcome {
            control_id: finding.control_id.clone(),
            severity,
            decision,
            rationale: finding.rationale.clone(),
        }
    }
}

/// Parses a profile name into the corresponding profile instance.
pub fn parse_profile(name: &str) -> Option<Box<dyn ControlProfile>> {
    if name.starts_with("slsa-source-l") && name.contains("-build-l") {
        parse_level_profile(name).map(|p| Box::new(p) as Box<dyn ControlProfile>)
    } else {
        None
    }
}

fn parse_level_profile(name: &str) -> Option<SlsaLevelProfile> {
    let rest = name.strip_prefix("slsa-source-l")?;
    let dash_pos = rest.find("-build-l")?;
    let source_str = &rest[..dash_pos];
    let build_str = &rest[dash_pos + 8..];

    let source_level = parse_level_num(source_str)?;
    let build_level = parse_level_num(build_str)?;

    if !build_level.is_valid_for_track(SlsaTrack::Build) {
        return None;
    }

    Some(SlsaLevelProfile::new(source_level, build_level))
}

fn parse_level_num(s: &str) -> Option<SlsaLevel> {
    match s {
        "0" => Some(SlsaLevel::L0),
        "1" => Some(SlsaLevel::L1),
        "2" => Some(SlsaLevel::L2),
        "3" => Some(SlsaLevel::L3),
        "4" => Some(SlsaLevel::L4),
        _ => None,
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::control::builtin;

    fn l1_profile() -> SlsaLevelProfile {
        SlsaLevelProfile::new(SlsaLevel::L1, SlsaLevel::L1)
    }

    #[test]
    fn l1_indeterminate_required_control_fails() {
        let profile = l1_profile();
        let outcome = profile.map(&ControlFinding::indeterminate(
            builtin::id(builtin::REVIEW_INDEPENDENCE),
            "Evidence is partial",
            vec!["pr:owner/repo#10".to_string()],
            vec![],
        ));
        assert_eq!(outcome.severity, FindingSeverity::Error);
        assert_eq!(outcome.decision, GateDecision::Fail);
    }

    #[test]
    fn l1_satisfied_maps_to_pass() {
        let profile = l1_profile();
        let outcome = profile.map(&ControlFinding::satisfied(
            builtin::id(builtin::REVIEW_INDEPENDENCE),
            "Independent reviewer approved",
            vec!["pr:owner/repo#10".to_string()],
        ));
        assert_eq!(outcome.severity, FindingSeverity::Info);
        assert_eq!(outcome.decision, GateDecision::Pass);
    }

    #[test]
    fn violated_always_fails() {
        let profile = l1_profile();
        let outcome = profile.map(&ControlFinding::violated(
            builtin::id(builtin::SOURCE_AUTHENTICITY),
            "No valid signature found",
            vec!["release:owner/repo@v1.0".to_string()],
        ));
        assert_eq!(outcome.severity, FindingSeverity::Error);
        assert_eq!(outcome.decision, GateDecision::Fail);
    }

    #[test]
    fn compliance_indeterminate_reviews() {
        let profile = SlsaLevelProfile::new(SlsaLevel::L4, SlsaLevel::L3);
        let outcome = profile.map(&ControlFinding::indeterminate(
            builtin::id(builtin::CHANGE_REQUEST_SIZE),
            "Cannot determine CR size",
            vec!["pr:owner/repo#5".to_string()],
            vec![],
        ));
        assert_eq!(outcome.decision, GateDecision::Review);
        assert_eq!(outcome.severity, FindingSeverity::Warning);
    }

    #[test]
    fn parse_profile_level_based() {
        assert!(parse_profile("slsa-source-l1-build-l1").is_some());
        assert!(parse_profile("slsa-source-l4-build-l3").is_some());
        assert!(parse_profile("slsa-source-l4-build-l4").is_none());
        assert!(parse_profile("unknown").is_none());
    }
}
