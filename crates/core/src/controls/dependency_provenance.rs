use crate::control::{Control, ControlFinding, ControlId, builtin};
use crate::evidence::{EvidenceBundle, EvidenceState, RegistryProvenanceCapability};

/// Verifies that all dependencies have cryptographic provenance (Dependencies L2).
///
/// Requires every dependency to have:
/// - `VerificationOutcome::Verified` (not just `ChecksumMatch`)
/// - `source_repo` present (provenance links to source)
///
/// This is stricter than L1 (`dependency-signature`) which accepts checksum-only verification.
///
/// **Registry scoping**: Only evaluates dependencies from registries that support
/// cryptographic provenance (L2+). Dependencies from checksum-only registries
/// (e.g. crates.io) are excluded to avoid false positives. If all dependencies
/// are from checksum-only registries, the control returns `NotApplicable`.
pub struct DependencyProvenanceControl;

impl Control for DependencyProvenanceControl {
    fn id(&self) -> ControlId {
        builtin::id(builtin::DEPENDENCY_PROVENANCE_CHECK)
    }

    fn description(&self) -> &'static str {
        "All dependencies must have cryptographic signatures with source provenance"
    }

    fn evaluate(&self, evidence: &EvidenceBundle) -> Vec<ControlFinding> {
        let id = self.id();

        match &evidence.dependency_signatures {
            EvidenceState::NotApplicable => {
                vec![ControlFinding::not_applicable(
                    id,
                    "Dependency evidence is not applicable",
                )]
            }
            EvidenceState::Missing { gaps } => {
                vec![ControlFinding::indeterminate(
                    id,
                    "Dependency evidence could not be collected",
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

                // Filter to registries that support L2+ provenance
                let in_scope: Vec<_> = value
                    .iter()
                    .filter(|d| {
                        d.registry_provenance_capability()
                            >= RegistryProvenanceCapability::CryptographicProvenance
                    })
                    .collect();

                let skipped = value.len() - in_scope.len();

                if in_scope.is_empty() {
                    return vec![ControlFinding::not_applicable(
                        id,
                        format!(
                            "No dependencies from provenance-capable registries \
                             ({skipped} dependenc(ies) from checksum-only registries skipped)",
                        ),
                    )];
                }

                let subjects: Vec<String> = in_scope
                    .iter()
                    .map(|d| format!("{}@{}", d.name, d.version))
                    .collect();

                let lacking: Vec<String> = in_scope
                    .iter()
                    .filter(|d| {
                        !d.verification.is_cryptographically_signed() || d.source_repo.is_none()
                    })
                    .map(|d| {
                        let mut reasons = Vec::new();
                        if !d.verification.is_cryptographically_signed() {
                            reasons.push("no cryptographic signature");
                        }
                        if d.source_repo.is_none() {
                            reasons.push("no source_repo");
                        }
                        format!("{}@{} ({})", d.name, d.version, reasons.join(", "))
                    })
                    .collect();

                let gaps = evidence.dependency_signatures.gaps();
                let gap_suffix = if gaps.is_empty() {
                    String::new()
                } else {
                    format!(" (WARNING: {} evidence gap(s))", gaps.len())
                };

                let skip_note = if skipped > 0 {
                    format!(" [{skipped} checksum-only registr(ies) skipped]")
                } else {
                    String::new()
                };

                if lacking.is_empty() {
                    let mut finding = ControlFinding::satisfied(
                        id,
                        format!(
                            "All {} dependenc(ies) have cryptographic provenance{}{}",
                            in_scope.len(),
                            skip_note,
                            gap_suffix,
                        ),
                        subjects,
                    );
                    if !gaps.is_empty() {
                        finding.evidence_gaps = gaps.to_vec();
                    }
                    vec![finding]
                } else {
                    let mut finding = ControlFinding::violated(
                        id,
                        format!(
                            "Dependenc(ies) lacking provenance: {}{}{}",
                            lacking.join("; "),
                            skip_note,
                            gap_suffix,
                        ),
                        subjects,
                    );
                    if !gaps.is_empty() {
                        finding.evidence_gaps = gaps.to_vec();
                    }
                    vec![finding]
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::control::ControlStatus;
    use crate::evidence::{DependencySignatureEvidence, VerificationOutcome};

    fn npm_dep_signed(name: &str, source_repo: Option<&str>) -> DependencySignatureEvidence {
        DependencySignatureEvidence {
            name: name.to_string(),
            version: "1.0.0".to_string(),
            registry: Some("registry.npmjs.org".to_string()),
            verification: VerificationOutcome::Verified,
            signature_mechanism: Some("sigstore".to_string()),
            signer_identity: Some("https://github.com/login/oauth".to_string()),
            source_repo: source_repo.map(str::to_string),
            source_commit: None,
            pinned_digest: None,
            actual_digest: None,
            transparency_log_uri: Some(
                "https://rekor.sigstore.dev/api/v1/log/entries/abc".to_string(),
            ),
            is_direct: true,
        }
    }

    fn npm_dep_no_provenance(name: &str) -> DependencySignatureEvidence {
        DependencySignatureEvidence {
            name: name.to_string(),
            version: "1.0.0".to_string(),
            registry: Some("registry.npmjs.org".to_string()),
            verification: VerificationOutcome::ChecksumMatch,
            signature_mechanism: Some("checksum".to_string()),
            signer_identity: None,
            source_repo: None,
            source_commit: None,
            pinned_digest: Some("sha512-abc".to_string()),
            actual_digest: None,
            transparency_log_uri: None,
            is_direct: true,
        }
    }

    fn cargo_dep(name: &str) -> DependencySignatureEvidence {
        DependencySignatureEvidence {
            name: name.to_string(),
            version: "1.0.0".to_string(),
            registry: Some("crates.io".to_string()),
            verification: VerificationOutcome::ChecksumMatch,
            signature_mechanism: Some("checksum".to_string()),
            signer_identity: None,
            source_repo: None,
            source_commit: None,
            pinned_digest: Some("sha256:abc".to_string()),
            actual_digest: None,
            transparency_log_uri: None,
            is_direct: true,
        }
    }

    fn bundle(deps: Vec<DependencySignatureEvidence>) -> EvidenceBundle {
        EvidenceBundle {
            dependency_signatures: EvidenceState::complete(deps),
            ..Default::default()
        }
    }

    #[test]
    fn satisfied_when_all_npm_signed_with_source_repo() {
        let evidence = bundle(vec![
            npm_dep_signed("react", Some("facebook/react")),
            npm_dep_signed("express", Some("expressjs/express")),
        ]);
        let findings = DependencyProvenanceControl.evaluate(&evidence);
        assert_eq!(findings[0].status, ControlStatus::Satisfied);
    }

    #[test]
    fn violated_when_npm_checksum_only() {
        let evidence = bundle(vec![npm_dep_no_provenance("lodash")]);
        let findings = DependencyProvenanceControl.evaluate(&evidence);
        assert_eq!(findings[0].status, ControlStatus::Violated);
        assert!(findings[0].rationale.contains("no cryptographic signature"));
    }

    #[test]
    fn violated_when_npm_signed_but_no_source_repo() {
        let evidence = bundle(vec![npm_dep_signed("react", None)]);
        let findings = DependencyProvenanceControl.evaluate(&evidence);
        assert_eq!(findings[0].status, ControlStatus::Violated);
        assert!(findings[0].rationale.contains("no source_repo"));
    }

    #[test]
    fn not_applicable_when_only_cargo_deps() {
        let evidence = bundle(vec![cargo_dep("serde"), cargo_dep("tokio")]);
        let findings = DependencyProvenanceControl.evaluate(&evidence);
        assert_eq!(findings[0].status, ControlStatus::NotApplicable);
        assert!(findings[0].rationale.contains("checksum-only registries"));
    }

    #[test]
    fn mixed_registries_only_evaluates_npm() {
        let evidence = bundle(vec![
            cargo_dep("serde"),
            npm_dep_signed("react", Some("facebook/react")),
        ]);
        let findings = DependencyProvenanceControl.evaluate(&evidence);
        assert_eq!(findings[0].status, ControlStatus::Satisfied);
        assert!(findings[0].rationale.contains("1 dependenc(ies)"));
        assert!(findings[0].rationale.contains("skipped"));
    }

    #[test]
    fn not_applicable_when_empty() {
        let evidence = bundle(vec![]);
        let findings = DependencyProvenanceControl.evaluate(&evidence);
        assert_eq!(findings[0].status, ControlStatus::NotApplicable);
    }

    #[test]
    fn indeterminate_when_evidence_missing() {
        let evidence = EvidenceBundle {
            dependency_signatures: EvidenceState::missing(vec![
                crate::evidence::EvidenceGap::CollectionFailed {
                    source: "registry".to_string(),
                    subject: "deps".to_string(),
                    detail: "timeout".to_string(),
                },
            ]),
            ..Default::default()
        };
        let findings = DependencyProvenanceControl.evaluate(&evidence);
        assert_eq!(findings[0].status, ControlStatus::Indeterminate);
        assert_eq!(findings[0].evidence_gaps.len(), 1);
    }

    #[test]
    fn partial_evidence_propagates_gaps_in_rationale() {
        let evidence = EvidenceBundle {
            dependency_signatures: EvidenceState::partial(
                vec![npm_dep_signed("react", Some("facebook/react"))],
                vec![crate::evidence::EvidenceGap::Truncated {
                    source: "tree-api".to_string(),
                    subject: "repo-tree".to_string(),
                }],
            ),
            ..Default::default()
        };
        let findings = DependencyProvenanceControl.evaluate(&evidence);
        assert!(
            findings[0].rationale.contains("evidence gap"),
            "rationale should warn about gaps: {}",
            findings[0].rationale
        );
        assert_eq!(findings[0].evidence_gaps.len(), 1);
    }
}
