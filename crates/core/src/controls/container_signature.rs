use crate::control::{Control, ControlFinding, ControlId, builtin};
use crate::evidence::{EvidenceBundle, EvidenceState};

/// Verifies that container images have valid signatures (cosign/Sigstore).
///
/// Maps to SOC2 PI1.4: processing integrity through artifact provenance.
/// Container image signatures bind images to the identity that produced them,
/// enabling consumers to verify that images were not tampered with after build.
///
/// Evaluation tiers:
/// - **Satisfied**: all container images have verified signatures
/// - **Violated**: some container images lack verified signatures
/// - **NotApplicable**: no container images in evidence
pub struct ContainerSignatureControl;

impl Control for ContainerSignatureControl {
    fn id(&self) -> ControlId {
        builtin::id(builtin::CONTAINER_SIGNATURE)
    }

    fn description(&self) -> &'static str {
        "Container images must have verified signatures (cosign/Sigstore)"
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

                let unverified: Vec<&str> = value
                    .iter()
                    .filter(|img| !img.signature_verified || !img.verification.is_verified())
                    .map(|img| img.reference.as_str())
                    .collect();

                let gap_suffix = if gaps.is_empty() {
                    String::new()
                } else {
                    format!(
                        " (WARNING: {} evidence gap(s) — unverified images may be hidden)",
                        gaps.len()
                    )
                };

                let mut finding = if unverified.is_empty() {
                    ControlFinding::satisfied(
                        id,
                        format!(
                            "All {} container image(s) have verified signatures{}",
                            value.len(),
                            gap_suffix,
                        ),
                        value.iter().map(|img| img.reference.clone()).collect(),
                    )
                } else {
                    ControlFinding::violated(
                        id,
                        format!(
                            "Unverified container image signature(s): {}{}",
                            unverified.join("; "),
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

    fn make_image(reference: &str, signed: bool) -> ContainerImageEvidence {
        ContainerImageEvidence {
            reference: reference.to_string(),
            digest: Some("sha256:abcdef1234567890".to_string()),
            signature_verified: signed,
            provenance_present: false,
            sbom_present: false,
            signer_identity: if signed {
                Some("https://github.com/login/oauth".to_string())
            } else {
                None
            },
            source_repo: None,
            verification: if signed {
                VerificationOutcome::Verified
            } else {
                VerificationOutcome::AttestationAbsent {
                    detail: "no cosign signature found".to_string(),
                }
            },
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
        let findings = ContainerSignatureControl.evaluate(&evidence);
        assert_eq!(findings[0].status, ControlStatus::NotApplicable);
    }

    #[test]
    fn not_applicable_when_empty_list() {
        let findings = ContainerSignatureControl.evaluate(&make_bundle(vec![]));
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
        let findings = ContainerSignatureControl.evaluate(&evidence);
        assert_eq!(findings[0].status, ControlStatus::Indeterminate);
        assert_eq!(findings[0].evidence_gaps.len(), 1);
    }

    #[test]
    fn satisfied_when_all_signed() {
        let findings = ContainerSignatureControl.evaluate(&make_bundle(vec![
            make_image("ghcr.io/owner/repo:v1.0.0", true),
            make_image("ghcr.io/owner/repo:v1.0.1", true),
        ]));
        assert_eq!(findings[0].status, ControlStatus::Satisfied);
        assert!(findings[0].rationale.contains("2 container image(s)"));
    }

    #[test]
    fn violated_when_unsigned() {
        let findings = ContainerSignatureControl.evaluate(&make_bundle(vec![
            make_image("ghcr.io/owner/repo:v1.0.0", true),
            make_image("ghcr.io/owner/repo:latest", false),
        ]));
        assert_eq!(findings[0].status, ControlStatus::Violated);
        assert!(findings[0].rationale.contains("ghcr.io/owner/repo:latest"));
    }

    #[test]
    fn violated_when_all_unsigned() {
        let findings = ContainerSignatureControl.evaluate(&make_bundle(vec![make_image(
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
        let findings = ContainerSignatureControl.evaluate(&evidence);
        assert_eq!(findings[0].status, ControlStatus::Satisfied);
        assert!(findings[0].rationale.contains("evidence gap"));
        assert_eq!(findings[0].evidence_gaps.len(), 1);
    }

    #[test]
    fn correct_control_id() {
        assert_eq!(
            ContainerSignatureControl.id(),
            builtin::id(builtin::CONTAINER_SIGNATURE)
        );
    }
}
