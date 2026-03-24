//! SLSA v1.2 track and level definitions.

use std::fmt;

use serde::{Deserialize, Serialize};

use crate::control::{ControlId, builtin};

/// SLSA specification tracks per v1.2.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SlsaTrack {
    Source,
    Build,
    /// SLSA Dependencies Track: verifies integrity and provenance of dependencies.
    Dependencies,
}

impl fmt::Display for SlsaTrack {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Source => f.write_str("source"),
            Self::Build => f.write_str("build"),
            Self::Dependencies => f.write_str("dependencies"),
        }
    }
}

/// SLSA levels within a track (v1.2).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SlsaLevel {
    L0,
    L1,
    L2,
    L3,
    L4,
}

impl SlsaLevel {
    pub fn is_valid_for_track(self, track: SlsaTrack) -> bool {
        match track {
            SlsaTrack::Source => true,
            SlsaTrack::Build => self <= SlsaLevel::L3,
            SlsaTrack::Dependencies => self <= SlsaLevel::L1,
        }
    }
}

impl fmt::Display for SlsaLevel {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::L0 => f.write_str("L0"),
            Self::L1 => f.write_str("L1"),
            Self::L2 => f.write_str("L2"),
            Self::L3 => f.write_str("L3"),
            Self::L4 => f.write_str("L4"),
        }
    }
}

/// Mapping of a control to its SLSA track and minimum level.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SlsaMapping {
    pub track: SlsaTrack,
    pub level: SlsaLevel,
}

/// Returns the SLSA track and minimum level for a built-in control.
///
/// Platform-specific controls not in the SLSA framework return `None`.
pub fn control_slsa_mapping(id: &ControlId) -> Option<SlsaMapping> {
    match id.as_str() {
        // Source Track
        builtin::SOURCE_AUTHENTICITY => Some(SlsaMapping {
            track: SlsaTrack::Source,
            level: SlsaLevel::L1,
        }),
        builtin::REVIEW_INDEPENDENCE => Some(SlsaMapping {
            track: SlsaTrack::Source,
            level: SlsaLevel::L1,
        }),
        builtin::BRANCH_HISTORY_INTEGRITY => Some(SlsaMapping {
            track: SlsaTrack::Source,
            level: SlsaLevel::L2,
        }),
        builtin::BRANCH_PROTECTION_ENFORCEMENT => Some(SlsaMapping {
            track: SlsaTrack::Source,
            level: SlsaLevel::L3,
        }),
        builtin::TWO_PARTY_REVIEW => Some(SlsaMapping {
            track: SlsaTrack::Source,
            level: SlsaLevel::L4,
        }),

        // Build Track
        builtin::BUILD_PROVENANCE => Some(SlsaMapping {
            track: SlsaTrack::Build,
            level: SlsaLevel::L1,
        }),
        builtin::REQUIRED_STATUS_CHECKS => Some(SlsaMapping {
            track: SlsaTrack::Build,
            level: SlsaLevel::L1,
        }),
        builtin::HOSTED_BUILD_PLATFORM => Some(SlsaMapping {
            track: SlsaTrack::Build,
            level: SlsaLevel::L2,
        }),
        builtin::PROVENANCE_AUTHENTICITY => Some(SlsaMapping {
            track: SlsaTrack::Build,
            level: SlsaLevel::L2,
        }),
        builtin::BUILD_ISOLATION => Some(SlsaMapping {
            track: SlsaTrack::Build,
            level: SlsaLevel::L3,
        }),

        // Dependencies Track
        builtin::DEPENDENCY_SIGNATURE => Some(SlsaMapping {
            track: SlsaTrack::Dependencies,
            level: SlsaLevel::L1,
        }),

        // Compliance and platform-specific controls have no SLSA mapping
        _ => None,
    }
}

/// Returns all built-in SLSA control IDs at or below the given level for a track.
pub fn controls_for_level(track: SlsaTrack, level: SlsaLevel) -> Vec<ControlId> {
    ALL_SLSA_CONTROLS
        .iter()
        .map(|&s| ControlId::new(s))
        .filter(|id| control_slsa_mapping(id).is_some_and(|m| m.track == track && m.level <= level))
        .collect()
}

const ALL_SLSA_CONTROLS: &[&str] = &[
    builtin::SOURCE_AUTHENTICITY,
    builtin::REVIEW_INDEPENDENCE,
    builtin::BRANCH_HISTORY_INTEGRITY,
    builtin::BRANCH_PROTECTION_ENFORCEMENT,
    builtin::TWO_PARTY_REVIEW,
    builtin::BUILD_PROVENANCE,
    builtin::REQUIRED_STATUS_CHECKS,
    builtin::HOSTED_BUILD_PLATFORM,
    builtin::PROVENANCE_AUTHENTICITY,
    builtin::BUILD_ISOLATION,
    builtin::DEPENDENCY_SIGNATURE,
];

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn source_l1_controls() {
        let controls = controls_for_level(SlsaTrack::Source, SlsaLevel::L1);
        let ids: Vec<&str> = controls.iter().map(|c| c.as_str()).collect();
        assert!(ids.contains(&builtin::SOURCE_AUTHENTICITY));
        assert!(ids.contains(&builtin::REVIEW_INDEPENDENCE));
        assert!(!ids.contains(&builtin::BRANCH_HISTORY_INTEGRITY));
    }

    #[test]
    fn source_l4_includes_all_source_controls() {
        let controls = controls_for_level(SlsaTrack::Source, SlsaLevel::L4);
        assert_eq!(controls.len(), 5);
    }

    #[test]
    fn build_l3_includes_all_build_controls() {
        let controls = controls_for_level(SlsaTrack::Build, SlsaLevel::L3);
        assert_eq!(controls.len(), 5);
    }

    #[test]
    fn compliance_controls_have_no_slsa_mapping() {
        assert!(control_slsa_mapping(&ControlId::new(builtin::CHANGE_REQUEST_SIZE)).is_none());
        assert!(control_slsa_mapping(&ControlId::new(builtin::TEST_COVERAGE)).is_none());
    }

    #[test]
    fn l4_not_valid_for_build_track() {
        assert!(!SlsaLevel::L4.is_valid_for_track(SlsaTrack::Build));
        assert!(SlsaLevel::L4.is_valid_for_track(SlsaTrack::Source));
    }

    #[test]
    fn dependencies_track_l1_includes_dependency_signature() {
        let controls = controls_for_level(SlsaTrack::Dependencies, SlsaLevel::L1);
        let ids: Vec<&str> = controls.iter().map(|c| c.as_str()).collect();
        assert!(ids.contains(&builtin::DEPENDENCY_SIGNATURE));
        assert_eq!(controls.len(), 1);
    }

    #[test]
    fn dependency_signature_has_slsa_mapping() {
        let mapping =
            control_slsa_mapping(&ControlId::new(builtin::DEPENDENCY_SIGNATURE)).unwrap();
        assert_eq!(mapping.track, SlsaTrack::Dependencies);
        assert_eq!(mapping.level, SlsaLevel::L1);
    }

    #[test]
    fn l2_not_valid_for_dependencies_track() {
        assert!(SlsaLevel::L1.is_valid_for_track(SlsaTrack::Dependencies));
        assert!(!SlsaLevel::L2.is_valid_for_track(SlsaTrack::Dependencies));
    }
}
