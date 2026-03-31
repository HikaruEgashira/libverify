use crate::control::{Control, ControlFinding, ControlId, builtin};
use crate::evidence::EvidenceBundle;

/// Validates that the latest release assets have build provenance attestations
/// (GitHub Attestations / Sigstore).
///
/// Maps to SOC2 PI1.4: processing integrity through artifact provenance.
/// Build provenance attestations bind release binaries to the source commit
/// and CI workflow that produced them, enabling consumers to verify that
/// artifacts were not tampered with after build.
///
/// Evaluation tiers:
/// - **Satisfied**: release assets have attestations
/// - **Violated**: release assets exist but lack attestations
/// - **NotApplicable**: no release exists
pub struct ReleaseAssetAttestationControl;

impl Control for ReleaseAssetAttestationControl {
    fn id(&self) -> ControlId {
        builtin::id(builtin::RELEASE_ASSET_ATTESTATION)
    }

    fn description(&self) -> &'static str {
        "Latest release assets must have build provenance attestations (Sigstore)"
    }

    fn evaluate(&self, evidence: &EvidenceBundle) -> Vec<ControlFinding> {
        let posture = match ControlFinding::extract_posture(self.id(), evidence) {
            Ok(p) => p,
            Err(findings) => return findings,
        };

        if posture.release_assets_attested {
            vec![ControlFinding::satisfied(
                self.id(),
                "Latest release assets have build provenance attestations",
                vec!["release:attestation".to_string()],
            )]
        } else {
            vec![ControlFinding::violated(
                self.id(),
                "Latest release assets lack build provenance attestations — \
                 consumers cannot verify artifact integrity",
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

    fn posture(attested: bool) -> RepositoryPosture {
        RepositoryPosture {
            release_assets_attested: attested,
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
        let findings =
            ReleaseAssetAttestationControl.evaluate(&bundle(EvidenceState::not_applicable()));
        assert_eq!(findings[0].status, ControlStatus::NotApplicable);
    }

    #[test]
    fn indeterminate_when_posture_missing() {
        let findings =
            ReleaseAssetAttestationControl.evaluate(&bundle(EvidenceState::missing(vec![
                EvidenceGap::CollectionFailed {
                    source: "github".to_string(),
                    subject: "posture".to_string(),
                    detail: "API error".to_string(),
                },
            ])));
        assert_eq!(findings[0].status, ControlStatus::Indeterminate);
    }

    #[test]
    fn satisfied_when_attested() {
        let findings = ReleaseAssetAttestationControl
            .evaluate(&bundle(EvidenceState::complete(posture(true))));
        assert_eq!(findings[0].status, ControlStatus::Satisfied);
        assert!(findings[0].rationale.contains("attestations"));
    }

    #[test]
    fn violated_when_not_attested() {
        let findings = ReleaseAssetAttestationControl
            .evaluate(&bundle(EvidenceState::complete(posture(false))));
        assert_eq!(findings[0].status, ControlStatus::Violated);
        assert!(findings[0].rationale.contains("lack"));
    }
}
