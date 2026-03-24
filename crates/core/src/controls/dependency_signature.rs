use crate::control::{Control, ControlFinding, ControlId, builtin};
use crate::evidence::{EvidenceBundle, EvidenceState};
use crate::integrity::dependency_signature_severity;
use crate::verdict::Severity;

/// Verifies that all dependencies have valid cryptographic signatures.
pub struct DependencySignatureControl;

impl Control for DependencySignatureControl {
    fn id(&self) -> ControlId {
        builtin::id(builtin::DEPENDENCY_SIGNATURE)
    }

    fn evaluate(&self, evidence: &EvidenceBundle) -> Vec<ControlFinding> {
        let id = self.id();

        match &evidence.dependency_signatures {
            EvidenceState::NotApplicable => {
                vec![ControlFinding::not_applicable(
                    id,
                    "Dependency signature evidence is not applicable",
                )]
            }
            EvidenceState::Missing { gaps } => {
                vec![ControlFinding::indeterminate(
                    id,
                    "Dependency signature evidence could not be collected",
                    Vec::new(),
                    gaps.clone(),
                )]
            }
            EvidenceState::Complete { value } | EvidenceState::Partial { value, .. } => {
                if value.is_empty() {
                    return vec![ControlFinding::not_applicable(
                        id,
                        "No dependencies were present",
                    )];
                }

                let subjects: Vec<String> = value
                    .iter()
                    .map(|d| format!("{}@{}", d.name, d.version))
                    .collect();

                let unsigned: Vec<String> = value
                    .iter()
                    .filter(|d| !d.signature_verified)
                    .map(|d| format!("{}@{}", d.name, d.version))
                    .collect();

                let finding = match dependency_signature_severity(unsigned.len()) {
                    Severity::Pass => ControlFinding::satisfied(
                        id,
                        format!(
                            "All {} dependency signature(s) verified",
                            value.len()
                        ),
                        subjects,
                    ),
                    _ => ControlFinding::violated(
                        id,
                        format!(
                            "Unsigned dependency(ies): {}",
                            unsigned.join("; ")
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
    use crate::evidence::{DependencySignatureEvidence, EvidenceGap};

    fn make_dep(name: &str, version: &str, verified: bool) -> DependencySignatureEvidence {
        DependencySignatureEvidence {
            name: name.to_string(),
            version: version.to_string(),
            registry: Some("crates.io".to_string()),
            signature_verified: verified,
            signature_mechanism: if verified {
                Some("sigstore".to_string())
            } else {
                None
            },
        }
    }

    fn make_bundle(deps: Vec<DependencySignatureEvidence>) -> EvidenceBundle {
        EvidenceBundle {
            dependency_signatures: EvidenceState::complete(deps),
            ..Default::default()
        }
    }

    // --- NotApplicable ---

    #[test]
    fn not_applicable_when_evidence_state_is_not_applicable() {
        let evidence = EvidenceBundle::default();
        let findings = DependencySignatureControl.evaluate(&evidence);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].status, ControlStatus::NotApplicable);
        assert_eq!(
            findings[0].control_id,
            builtin::id(builtin::DEPENDENCY_SIGNATURE)
        );
    }

    #[test]
    fn not_applicable_when_dependency_list_empty() {
        let findings = DependencySignatureControl.evaluate(&make_bundle(vec![]));
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].status, ControlStatus::NotApplicable);
    }

    // --- Indeterminate ---

    #[test]
    fn indeterminate_when_evidence_missing() {
        let evidence = EvidenceBundle {
            dependency_signatures: EvidenceState::missing(vec![
                EvidenceGap::CollectionFailed {
                    source: "package-registry".to_string(),
                    subject: "dependencies".to_string(),
                    detail: "registry unreachable".to_string(),
                },
            ]),
            ..Default::default()
        };
        let findings = DependencySignatureControl.evaluate(&evidence);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].status, ControlStatus::Indeterminate);
        assert_eq!(findings[0].evidence_gaps.len(), 1);
    }

    // --- Satisfied ---

    #[test]
    fn satisfied_when_all_signed() {
        let findings = DependencySignatureControl.evaluate(&make_bundle(vec![
            make_dep("serde", "1.0.204", true),
            make_dep("tokio", "1.38.0", true),
        ]));
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].status, ControlStatus::Satisfied);
        assert_eq!(findings[0].subjects.len(), 2);
        assert!(findings[0].rationale.contains("2 dependency signature(s) verified"));
    }

    #[test]
    fn satisfied_single_dependency() {
        let findings =
            DependencySignatureControl.evaluate(&make_bundle(vec![make_dep("serde", "1.0.204", true)]));
        assert_eq!(findings[0].status, ControlStatus::Satisfied);
        assert_eq!(findings[0].subjects, vec!["serde@1.0.204"]);
    }

    // --- Violated ---

    #[test]
    fn violated_when_dependency_unsigned() {
        let findings = DependencySignatureControl.evaluate(&make_bundle(vec![
            make_dep("serde", "1.0.204", true),
            make_dep("sketchy-lib", "0.1.0", false),
        ]));
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].status, ControlStatus::Violated);
        assert!(findings[0].rationale.contains("sketchy-lib@0.1.0"));
    }

    #[test]
    fn violated_when_all_unsigned() {
        let findings = DependencySignatureControl.evaluate(&make_bundle(vec![
            make_dep("foo", "1.0.0", false),
            make_dep("bar", "2.0.0", false),
        ]));
        assert_eq!(findings[0].status, ControlStatus::Violated);
        assert!(findings[0].rationale.contains("foo@1.0.0"));
        assert!(findings[0].rationale.contains("bar@2.0.0"));
    }

    // --- Edge cases ---

    #[test]
    fn partial_evidence_with_signed_deps_satisfied() {
        let evidence = EvidenceBundle {
            dependency_signatures: EvidenceState::partial(
                vec![make_dep("serde", "1.0.204", true)],
                vec![EvidenceGap::Truncated {
                    source: "package-registry".to_string(),
                    subject: "dependency-list".to_string(),
                }],
            ),
            ..Default::default()
        };
        let findings = DependencySignatureControl.evaluate(&evidence);
        assert_eq!(findings[0].status, ControlStatus::Satisfied);
    }

    #[test]
    fn partial_evidence_with_unsigned_dep_violated() {
        let evidence = EvidenceBundle {
            dependency_signatures: EvidenceState::partial(
                vec![make_dep("sketchy", "0.1.0", false)],
                vec![EvidenceGap::Truncated {
                    source: "package-registry".to_string(),
                    subject: "dependency-list".to_string(),
                }],
            ),
            ..Default::default()
        };
        let findings = DependencySignatureControl.evaluate(&evidence);
        assert_eq!(findings[0].status, ControlStatus::Violated);
    }

    #[test]
    fn correct_control_id() {
        assert_eq!(
            DependencySignatureControl.id(),
            builtin::id(builtin::DEPENDENCY_SIGNATURE)
        );
    }
}
