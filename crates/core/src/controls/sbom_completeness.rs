use crate::control::{Control, ControlFinding, ControlId, builtin};
use crate::evidence::EvidenceBundle;

/// Validates that releases include a Software Bill of Materials (SBOM).
///
/// Maps to SOC2 CC7.1 / PI1.4: monitor system components and maintain
/// processing integrity. SBOMs enable vulnerability tracking and supply
/// chain transparency for released artifacts.
///
/// Evaluation:
/// - **Satisfied**: release includes an SBOM
/// - **Violated**: release does not include an SBOM
pub struct SbomCompletenessControl;

impl Control for SbomCompletenessControl {
    fn id(&self) -> ControlId {
        builtin::id(builtin::SBOM_COMPLETENESS)
    }

    fn description(&self) -> &'static str {
        "Releases must include a Software Bill of Materials (SBOM)"
    }

    fn evaluate(&self, evidence: &EvidenceBundle) -> Vec<ControlFinding> {
        let posture = match ControlFinding::extract_posture(self.id(), evidence) {
            Ok(p) => p,
            Err(findings) => return findings,
        };

        if posture.release_has_sbom {
            vec![ControlFinding::satisfied(
                self.id(),
                "Release includes an SBOM",
                vec!["repository:sbom".to_string()],
            )]
        } else {
            vec![ControlFinding::violated(
                self.id(),
                "Release does not include an SBOM — supply chain transparency is incomplete",
                vec!["repository:sbom".to_string()],
            )]
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::control::ControlStatus;
    use crate::evidence::{EvidenceGap, EvidenceState, RepositoryPosture};

    fn bundle(state: EvidenceState<RepositoryPosture>) -> EvidenceBundle {
        EvidenceBundle {
            repository_posture: state,
            ..Default::default()
        }
    }

    #[test]
    fn satisfied_when_sbom_present() {
        let posture = RepositoryPosture {
            release_has_sbom: true,
            ..Default::default()
        };
        let findings = SbomCompletenessControl.evaluate(&bundle(EvidenceState::complete(posture)));
        assert_eq!(findings[0].status, ControlStatus::Satisfied);
        assert!(findings[0].rationale.contains("includes an SBOM"));
    }

    #[test]
    fn violated_when_sbom_absent() {
        let posture = RepositoryPosture {
            release_has_sbom: false,
            ..Default::default()
        };
        let findings = SbomCompletenessControl.evaluate(&bundle(EvidenceState::complete(posture)));
        assert_eq!(findings[0].status, ControlStatus::Violated);
        assert!(findings[0].rationale.contains("does not include"));
    }

    #[test]
    fn indeterminate_when_posture_missing() {
        let findings = SbomCompletenessControl.evaluate(&bundle(EvidenceState::missing(vec![
            EvidenceGap::CollectionFailed {
                source: "github".to_string(),
                subject: "posture".to_string(),
                detail: "API error".to_string(),
            },
        ])));
        assert_eq!(findings[0].status, ControlStatus::Indeterminate);
    }

    #[test]
    fn not_applicable_when_posture_not_applicable() {
        let findings = SbomCompletenessControl.evaluate(&bundle(EvidenceState::not_applicable()));
        assert_eq!(findings[0].status, ControlStatus::NotApplicable);
    }
}
