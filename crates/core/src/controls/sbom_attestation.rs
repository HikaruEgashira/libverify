use crate::control::{Control, ControlFinding, ControlId, builtin};
use crate::evidence::EvidenceBundle;

/// Validates that the latest release includes an SBOM artifact (SPDX or CycloneDX).
///
/// Maps to SOC2 CC7.1: system operations monitoring.
/// Supply chain transparency — an SBOM enables consumers to audit the
/// dependency tree of released artifacts, supporting vulnerability triage
/// and licence compliance.
///
/// Evaluation tiers:
/// - **Satisfied**: latest release includes an SBOM artifact
/// - **Violated**: latest release exists but contains no SBOM
/// - **NotApplicable**: no release exists (library-only or pre-release project)
pub struct SbomAttestationControl;

impl Control for SbomAttestationControl {
    fn id(&self) -> ControlId {
        builtin::id(builtin::SBOM_ATTESTATION)
    }

    fn description(&self) -> &'static str {
        "Latest release must include an SBOM artifact (SPDX or CycloneDX)"
    }

    fn evaluate(&self, evidence: &EvidenceBundle) -> Vec<ControlFinding> {
        let posture = match ControlFinding::extract_posture(self.id(), evidence) {
            Ok(p) => p,
            Err(findings) => return findings,
        };

        if posture.release_has_sbom {
            vec![ControlFinding::satisfied(
                self.id(),
                "Latest release includes an SBOM artifact",
                vec!["release:sbom".to_string()],
            )]
        } else {
            vec![ControlFinding::violated(
                self.id(),
                "Latest release does not include an SBOM artifact (SPDX or CycloneDX)",
                vec!["release".to_string()],
            )]
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::control::ControlStatus;
    use crate::evidence::{EvidenceGap, EvidenceState, RepositoryPosture};

    fn posture(has_sbom: bool) -> RepositoryPosture {
        RepositoryPosture {
            release_has_sbom: has_sbom,
            ..Default::default()
        }
    }

    fn bundle(state: EvidenceState<RepositoryPosture>) -> EvidenceBundle {
        EvidenceBundle {
            repository_posture: state,
            ..Default::default()
        }
    }

    #[test]
    fn not_applicable_when_posture_not_applicable() {
        let findings = SbomAttestationControl.evaluate(&bundle(EvidenceState::not_applicable()));
        assert_eq!(findings[0].status, ControlStatus::NotApplicable);
    }

    #[test]
    fn indeterminate_when_posture_missing() {
        let findings = SbomAttestationControl.evaluate(&bundle(EvidenceState::missing(vec![
            EvidenceGap::CollectionFailed {
                source: "github".to_string(),
                subject: "posture".to_string(),
                detail: "API error".to_string(),
            },
        ])));
        assert_eq!(findings[0].status, ControlStatus::Indeterminate);
    }

    #[test]
    fn satisfied_when_sbom_present() {
        let findings =
            SbomAttestationControl.evaluate(&bundle(EvidenceState::complete(posture(true))));
        assert_eq!(findings[0].status, ControlStatus::Satisfied);
        assert!(findings[0].rationale.contains("SBOM"));
    }

    #[test]
    fn violated_when_sbom_absent() {
        let findings =
            SbomAttestationControl.evaluate(&bundle(EvidenceState::complete(posture(false))));
        assert_eq!(findings[0].status, ControlStatus::Violated);
        assert!(findings[0].rationale.contains("does not include"));
    }
}
