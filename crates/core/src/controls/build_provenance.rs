use crate::control::{Control, ControlFinding, ControlId, builtin};
use crate::evidence::{EvidenceBundle, EvidenceState};
use crate::integrity::build_provenance_severity;
use crate::verdict::Severity;

/// Verifies that all artifact attestations carry valid cryptographic provenance.
pub struct BuildProvenanceControl;

impl Control for BuildProvenanceControl {
    fn id(&self) -> ControlId {
        builtin::id(builtin::BUILD_PROVENANCE)
    }

    fn evaluate(&self, evidence: &EvidenceBundle) -> Vec<ControlFinding> {
        let id = self.id();

        match &evidence.artifact_attestations {
            EvidenceState::NotApplicable => {
                vec![ControlFinding::not_applicable(
                    id,
                    "No artifact attestations apply to this context",
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

                let unverified: Vec<&str> = value
                    .iter()
                    .filter(|a| !a.verification.is_verified())
                    .map(|a| a.subject.as_str())
                    .collect();

                let finding = match build_provenance_severity(unverified.len()) {
                    Severity::Pass => ControlFinding::satisfied(
                        id,
                        format!(
                            "All {} artifact attestation(s) are cryptographically verified",
                            value.len()
                        ),
                        subjects,
                    ),
                    _ => ControlFinding::violated(
                        id,
                        format!(
                            "Unverified artifact attestation(s): {}",
                            unverified.join(", ")
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

    fn make_attestation(subject: &str, verified: bool) -> ArtifactAttestation {
        ArtifactAttestation {
            subject: subject.to_string(),
            subject_digest: None,
            predicate_type: "https://slsa.dev/provenance/v1".to_string(),
            signer_workflow: Some(".github/workflows/release.yml".to_string()),
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

    #[test]
    fn not_applicable_when_evidence_state_is_not_applicable() {
        let evidence = EvidenceBundle {
            artifact_attestations: EvidenceState::not_applicable(),
            ..Default::default()
        };
        let findings = BuildProvenanceControl.evaluate(&evidence);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].status, ControlStatus::NotApplicable);
        assert_eq!(
            findings[0].control_id,
            builtin::id(builtin::BUILD_PROVENANCE)
        );
    }

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
        let findings = BuildProvenanceControl.evaluate(&evidence);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].status, ControlStatus::Indeterminate);
        assert_eq!(findings[0].evidence_gaps.len(), 1);
    }

    #[test]
    fn not_applicable_when_attestation_list_empty() {
        let evidence = EvidenceBundle {
            artifact_attestations: EvidenceState::complete(vec![]),
            ..Default::default()
        };
        let findings = BuildProvenanceControl.evaluate(&evidence);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].status, ControlStatus::NotApplicable);
    }

    #[test]
    fn satisfied_when_all_verified() {
        let evidence = EvidenceBundle {
            artifact_attestations: EvidenceState::complete(vec![
                make_attestation("ghcr.io/owner/app:v1.0.0", true),
                make_attestation("gh-verify-linux-amd64", true),
            ]),
            ..Default::default()
        };
        let findings = BuildProvenanceControl.evaluate(&evidence);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].status, ControlStatus::Satisfied);
        assert_eq!(findings[0].subjects.len(), 2);
    }

    #[test]
    fn violated_when_any_unverified() {
        let evidence = EvidenceBundle {
            artifact_attestations: EvidenceState::complete(vec![
                make_attestation("ghcr.io/owner/app:v1.0.0", true),
                make_attestation("gh-verify-linux-amd64", false),
            ]),
            ..Default::default()
        };
        let findings = BuildProvenanceControl.evaluate(&evidence);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].status, ControlStatus::Violated);
        assert!(findings[0].rationale.contains("gh-verify-linux-amd64"));
        // subjects should list all artifacts, not just unverified ones
        assert_eq!(findings[0].subjects.len(), 2);
    }

    #[test]
    fn violated_when_all_unverified() {
        let evidence = EvidenceBundle {
            artifact_attestations: EvidenceState::complete(vec![
                make_attestation("artifact-a", false),
                make_attestation("artifact-b", false),
            ]),
            ..Default::default()
        };
        let findings = BuildProvenanceControl.evaluate(&evidence);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].status, ControlStatus::Violated);
        assert!(findings[0].rationale.contains("artifact-a"));
        assert!(findings[0].rationale.contains("artifact-b"));
    }

    #[test]
    fn single_verified_attestation_satisfied() {
        let evidence = EvidenceBundle {
            artifact_attestations: EvidenceState::complete(vec![make_attestation(
                "single-binary",
                true,
            )]),
            ..Default::default()
        };
        let findings = BuildProvenanceControl.evaluate(&evidence);
        assert_eq!(findings[0].status, ControlStatus::Satisfied);
        assert_eq!(findings[0].subjects, vec!["single-binary"]);
    }

    #[test]
    fn partial_evidence_with_verified_attestations_satisfied() {
        let evidence = EvidenceBundle {
            artifact_attestations: EvidenceState::partial(
                vec![make_attestation("partial-binary", true)],
                vec![EvidenceGap::Truncated {
                    source: "gh-attestation".to_string(),
                    subject: "attestation-list".to_string(),
                }],
            ),
            ..Default::default()
        };
        let findings = BuildProvenanceControl.evaluate(&evidence);
        assert_eq!(findings[0].status, ControlStatus::Satisfied);
    }

    #[test]
    fn partial_evidence_with_unverified_attestation_violated() {
        let evidence = EvidenceBundle {
            artifact_attestations: EvidenceState::partial(
                vec![make_attestation("partial-binary", false)],
                vec![EvidenceGap::Truncated {
                    source: "gh-attestation".to_string(),
                    subject: "attestation-list".to_string(),
                }],
            ),
            ..Default::default()
        };
        let findings = BuildProvenanceControl.evaluate(&evidence);
        assert_eq!(findings[0].status, ControlStatus::Violated);
    }

    #[test]
    fn partial_evidence_with_empty_list_not_applicable() {
        let evidence = EvidenceBundle {
            artifact_attestations: EvidenceState::partial(
                vec![],
                vec![EvidenceGap::Truncated {
                    source: "gh-attestation".to_string(),
                    subject: "attestation-list".to_string(),
                }],
            ),
            ..Default::default()
        };
        let findings = BuildProvenanceControl.evaluate(&evidence);
        assert_eq!(findings[0].status, ControlStatus::NotApplicable);
    }

    #[test]
    fn correct_control_id() {
        assert_eq!(
            BuildProvenanceControl.id(),
            builtin::id(builtin::BUILD_PROVENANCE)
        );
    }
}
