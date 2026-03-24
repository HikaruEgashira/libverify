use crate::control::{Control, ControlFinding, ControlId, builtin};
use crate::evidence::{EvidenceBundle, EvidenceState};
use crate::integrity::provenance_authenticity_severity;
use crate::verdict::Severity;

/// Verifies that provenance attestations are cryptographically signed and authenticated
/// with traceable signer information.
pub struct ProvenanceAuthenticityControl;

impl Control for ProvenanceAuthenticityControl {
    fn id(&self) -> ControlId {
        builtin::id(builtin::PROVENANCE_AUTHENTICITY)
    }

    fn description(&self) -> &'static str {
        "Provenance attestation must be cryptographically signed"
    }

    fn evaluate(&self, evidence: &EvidenceBundle) -> Vec<ControlFinding> {
        let id = self.id();

        match &evidence.artifact_attestations {
            EvidenceState::NotApplicable => {
                vec![ControlFinding::not_applicable(
                    id,
                    "Artifact attestation evidence is not applicable",
                )]
            }
            EvidenceState::Missing { gaps } => {
                vec![ControlFinding::indeterminate(
                    id,
                    "Artifact attestation evidence could not be collected",
                    Vec::new(),
                    gaps.clone(),
                )]
            }
            EvidenceState::Complete { value } | EvidenceState::Partial { value, .. } => {
                if value.is_empty() {
                    return vec![ControlFinding::not_applicable(
                        id,
                        "No artifact attestations were present",
                    )];
                }

                let subjects: Vec<String> = value.iter().map(|a| a.subject.clone()).collect();

                let unauthenticated: Vec<String> = value
                    .iter()
                    .filter(|a| !a.verification.is_verified() || a.signer_workflow.is_none())
                    .map(|a| {
                        let mut reasons = Vec::new();
                        if !a.verification.is_verified() {
                            if let Some(kind) = a.verification.failure_kind() {
                                reasons.push(kind);
                            } else {
                                reasons.push("unverified");
                            }
                        }
                        if a.signer_workflow.is_none() {
                            reasons.push("no signer info");
                        }
                        format!("{} ({})", a.subject, reasons.join(", "))
                    })
                    .collect();

                let finding = match provenance_authenticity_severity(unauthenticated.len()) {
                    Severity::Pass => ControlFinding::satisfied(
                        id,
                        format!(
                            "All {} attestation(s) are verified with traceable signer",
                            value.len()
                        ),
                        subjects,
                    ),
                    _ => ControlFinding::violated(
                        id,
                        format!(
                            "Unauthenticated attestation(s): {}",
                            unauthenticated.join("; ")
                        ),
                        subjects,
                    ),
                };
                vec![finding]
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::control::ControlStatus;
    use crate::evidence::{ArtifactAttestation, EvidenceGap, VerificationOutcome};

    fn make_attestation(
        subject: &str,
        verified: bool,
        signer_workflow: Option<&str>,
    ) -> ArtifactAttestation {
        ArtifactAttestation {
            subject: subject.to_string(),
            subject_digest: None,
            predicate_type: "https://slsa.dev/provenance/v1".to_string(),
            signer_workflow: signer_workflow.map(|s| s.to_string()),
            source_repo: Some("owner/repo".to_string()),
            verification: if verified {
                VerificationOutcome::Verified
            } else {
                VerificationOutcome::SignatureInvalid {
                    detail: "signature mismatch".to_string(),
                }
            },
        }
    }

    fn make_bundle(attestations: Vec<ArtifactAttestation>) -> EvidenceBundle {
        EvidenceBundle {
            artifact_attestations: EvidenceState::complete(attestations),
            ..Default::default()
        }
    }

    // --- NotApplicable ---

    #[test]
    fn not_applicable_when_evidence_state_is_not_applicable() {
        let evidence = EvidenceBundle {
            artifact_attestations: EvidenceState::not_applicable(),
            ..Default::default()
        };
        let findings = ProvenanceAuthenticityControl.evaluate(&evidence);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].status, ControlStatus::NotApplicable);
        assert_eq!(
            findings[0].control_id,
            builtin::id(builtin::PROVENANCE_AUTHENTICITY)
        );
    }

    #[test]
    fn not_applicable_when_attestation_list_empty() {
        let findings = ProvenanceAuthenticityControl.evaluate(&make_bundle(vec![]));
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].status, ControlStatus::NotApplicable);
    }

    // --- Indeterminate ---

    #[test]
    fn indeterminate_when_evidence_missing() {
        let evidence = EvidenceBundle {
            artifact_attestations: EvidenceState::missing(vec![EvidenceGap::CollectionFailed {
                source: "gh-attestation".to_string(),
                subject: "binary".to_string(),
                detail: "API returned 403".to_string(),
            }]),
            ..Default::default()
        };
        let findings = ProvenanceAuthenticityControl.evaluate(&evidence);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].status, ControlStatus::Indeterminate);
        assert_eq!(findings[0].evidence_gaps.len(), 1);
    }

    // --- Satisfied ---

    #[test]
    fn satisfied_when_all_verified_with_signer() {
        let findings = ProvenanceAuthenticityControl.evaluate(&make_bundle(vec![
            make_attestation("app:v1.0", true, Some(".github/workflows/release.yml")),
            make_attestation("app:v1.1", true, Some(".github/workflows/ci.yml")),
        ]));
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].status, ControlStatus::Satisfied);
        assert_eq!(findings[0].subjects.len(), 2);
        assert!(
            findings[0]
                .rationale
                .contains("2 attestation(s) are verified")
        );
    }

    #[test]
    fn satisfied_single_attestation() {
        let findings =
            ProvenanceAuthenticityControl.evaluate(&make_bundle(vec![make_attestation(
                "binary",
                true,
                Some(".github/workflows/release.yml"),
            )]));
        assert_eq!(findings[0].status, ControlStatus::Satisfied);
        assert_eq!(findings[0].subjects, vec!["binary"]);
    }

    // --- Violated ---

    #[test]
    fn violated_when_attestation_not_verified() {
        let findings = ProvenanceAuthenticityControl.evaluate(&make_bundle(vec![
            make_attestation("app:v1.0", true, Some(".github/workflows/release.yml")),
            make_attestation("app:v1.1", false, Some(".github/workflows/ci.yml")),
        ]));
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].status, ControlStatus::Violated);
        assert!(findings[0].rationale.contains("app:v1.1"));
        assert!(findings[0].rationale.contains("signature_invalid"));
    }

    #[test]
    fn violated_when_signer_workflow_missing() {
        let findings = ProvenanceAuthenticityControl
            .evaluate(&make_bundle(vec![make_attestation("app:v1.0", true, None)]));
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].status, ControlStatus::Violated);
        assert!(findings[0].rationale.contains("app:v1.0"));
        assert!(findings[0].rationale.contains("no signer info"));
    }

    #[test]
    fn violated_when_both_unverified_and_no_signer() {
        let findings =
            ProvenanceAuthenticityControl.evaluate(&make_bundle(vec![make_attestation(
                "app:v1.0", false, None,
            )]));
        assert_eq!(findings[0].status, ControlStatus::Violated);
        assert!(findings[0].rationale.contains("signature_invalid"));
        assert!(findings[0].rationale.contains("no signer info"));
    }

    // --- Edge cases ---

    #[test]
    fn partial_evidence_with_authenticated_attestations_satisfied() {
        let evidence = EvidenceBundle {
            artifact_attestations: EvidenceState::partial(
                vec![make_attestation(
                    "partial-binary",
                    true,
                    Some(".github/workflows/release.yml"),
                )],
                vec![EvidenceGap::Truncated {
                    source: "gh-attestation".to_string(),
                    subject: "attestation-list".to_string(),
                }],
            ),
            ..Default::default()
        };
        let findings = ProvenanceAuthenticityControl.evaluate(&evidence);
        assert_eq!(findings[0].status, ControlStatus::Satisfied);
    }

    #[test]
    fn partial_evidence_with_unauthenticated_attestation_violated() {
        let evidence = EvidenceBundle {
            artifact_attestations: EvidenceState::partial(
                vec![make_attestation("partial-binary", false, None)],
                vec![EvidenceGap::Truncated {
                    source: "gh-attestation".to_string(),
                    subject: "attestation-list".to_string(),
                }],
            ),
            ..Default::default()
        };
        let findings = ProvenanceAuthenticityControl.evaluate(&evidence);
        assert_eq!(findings[0].status, ControlStatus::Violated);
    }

    #[test]
    fn correct_control_id() {
        assert_eq!(
            ProvenanceAuthenticityControl.id(),
            builtin::id(builtin::PROVENANCE_AUTHENTICITY)
        );
    }
}
