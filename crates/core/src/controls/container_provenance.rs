use crate::control::{Control, ControlFinding, ControlId, builtin};
use crate::evidence::{EvidenceBundle, EvidenceState};

/// Verifies that container images have SLSA provenance attestations.
///
/// Maps to SOC2 PI1.4: processing integrity through artifact provenance.
/// SLSA provenance attestations bind container images to the source commit
/// and build workflow that produced them, enabling consumers to verify the
/// build origin and integrity of the image.
///
/// Evaluation tiers:
/// - **Satisfied**: all container images have provenance attestations
/// - **Violated**: some container images lack provenance attestations
/// - **NotApplicable**: no container images in evidence
pub struct ContainerProvenanceControl;

impl Control for ContainerProvenanceControl {
    fn id(&self) -> ControlId {
        builtin::id(builtin::CONTAINER_PROVENANCE)
    }

    fn description(&self) -> &'static str {
        "Container images must include SLSA provenance attestation (requires external evidence)"
    }

    fn evaluate(&self, evidence: &EvidenceBundle) -> Vec<ControlFinding> {
        let id = self.id();

        match &evidence.container_images {
            EvidenceState::NotApplicable => {
                vec![ControlFinding::not_applicable(
                    id,
                    "Container image evidence is not applicable",
                )]
            }
            EvidenceState::Missing { gaps } => {
                vec![ControlFinding::indeterminate(
                    id,
                    "Container image evidence could not be collected",
                    Vec::new(),
                    gaps.clone(),
                )]
            }
            EvidenceState::Complete { value } | EvidenceState::Partial { value, .. } => {
                if value.is_empty() {
                    return vec![ControlFinding::not_applicable(
                        id,
                        "No container images were present",
                    )];
                }

                let gaps = match &evidence.container_images {
                    EvidenceState::Partial { gaps, .. } => gaps.as_slice(),
                    _ => &[],
                };

                let missing_provenance: Vec<&str> = value
                    .iter()
                    .filter(|img| !img.provenance_present)
                    .map(|img| img.reference.as_str())
                    .collect();

                let gap_suffix = if gaps.is_empty() {
                    String::new()
                } else {
                    format!(
                        " (WARNING: {} evidence gap(s) — images without provenance may be hidden)",
                        gaps.len()
                    )
                };

                let mut finding = if missing_provenance.is_empty() {
                    ControlFinding::satisfied(
                        id,
                        format!(
                            "All {} container image(s) have SLSA provenance attestations{}",
                            value.len(),
                            gap_suffix,
                        ),
                        value.iter().map(|img| img.reference.clone()).collect(),
                    )
                } else {
                    ControlFinding::violated(
                        id,
                        format!(
                            "Container image(s) missing SLSA provenance: {}{}",
                            missing_provenance.join("; "),
                            gap_suffix,
                        ),
                        value.iter().map(|img| img.reference.clone()).collect(),
                    )
                };

                if !gaps.is_empty() {
                    finding.evidence_gaps = gaps.to_vec();
                }

                vec![finding]
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::control::ControlStatus;
    use crate::evidence::{ContainerImageEvidence, EvidenceGap, VerificationOutcome};

    fn make_image(reference: &str, has_provenance: bool) -> ContainerImageEvidence {
        ContainerImageEvidence {
            reference: reference.to_string(),
            digest: Some("sha256:abcdef1234567890".to_string()),
            signature_verified: true,
            provenance_present: has_provenance,
            sbom_present: false,
            signer_identity: None,
            source_repo: if has_provenance {
                Some("owner/repo".to_string())
            } else {
                None
            },
            verification: VerificationOutcome::Verified,
        }
    }

    fn make_bundle(images: Vec<ContainerImageEvidence>) -> EvidenceBundle {
        EvidenceBundle {
            container_images: EvidenceState::complete(images),
            ..Default::default()
        }
    }

    #[test]
    fn not_applicable_when_evidence_not_applicable() {
        let evidence = EvidenceBundle::default();
        let findings = ContainerProvenanceControl.evaluate(&evidence);
        assert_eq!(findings[0].status, ControlStatus::NotApplicable);
    }

    #[test]
    fn not_applicable_when_empty_list() {
        let findings = ContainerProvenanceControl.evaluate(&make_bundle(vec![]));
        assert_eq!(findings[0].status, ControlStatus::NotApplicable);
    }

    #[test]
    fn indeterminate_when_missing() {
        let evidence = EvidenceBundle {
            container_images: EvidenceState::missing(vec![EvidenceGap::CollectionFailed {
                source: "container-registry".to_string(),
                subject: "images".to_string(),
                detail: "registry unreachable".to_string(),
            }]),
            ..Default::default()
        };
        let findings = ContainerProvenanceControl.evaluate(&evidence);
        assert_eq!(findings[0].status, ControlStatus::Indeterminate);
        assert_eq!(findings[0].evidence_gaps.len(), 1);
    }

    #[test]
    fn satisfied_when_all_have_provenance() {
        let findings = ContainerProvenanceControl.evaluate(&make_bundle(vec![
            make_image("ghcr.io/owner/repo:v1.0.0", true),
            make_image("ghcr.io/owner/repo:v1.0.1", true),
        ]));
        assert_eq!(findings[0].status, ControlStatus::Satisfied);
        assert!(
            findings[0]
                .rationale
                .contains("2 container image(s) have SLSA provenance")
        );
    }

    #[test]
    fn violated_when_missing_provenance() {
        let findings = ContainerProvenanceControl.evaluate(&make_bundle(vec![
            make_image("ghcr.io/owner/repo:v1.0.0", true),
            make_image("ghcr.io/owner/repo:latest", false),
        ]));
        assert_eq!(findings[0].status, ControlStatus::Violated);
        assert!(findings[0].rationale.contains("ghcr.io/owner/repo:latest"));
    }

    #[test]
    fn violated_when_all_missing_provenance() {
        let findings = ContainerProvenanceControl.evaluate(&make_bundle(vec![make_image(
            "ghcr.io/owner/repo:v1",
            false,
        )]));
        assert_eq!(findings[0].status, ControlStatus::Violated);
    }

    #[test]
    fn partial_evidence_with_gaps() {
        let evidence = EvidenceBundle {
            container_images: EvidenceState::partial(
                vec![make_image("ghcr.io/owner/repo:v1.0.0", true)],
                vec![EvidenceGap::Truncated {
                    source: "container-registry".to_string(),
                    subject: "image-list".to_string(),
                }],
            ),
            ..Default::default()
        };
        let findings = ContainerProvenanceControl.evaluate(&evidence);
        assert_eq!(findings[0].status, ControlStatus::Satisfied);
        assert!(findings[0].rationale.contains("evidence gap"));
        assert_eq!(findings[0].evidence_gaps.len(), 1);
    }

    #[test]
    fn correct_control_id() {
        assert_eq!(
            ContainerProvenanceControl.id(),
            builtin::id(builtin::CONTAINER_PROVENANCE)
        );
    }
}
