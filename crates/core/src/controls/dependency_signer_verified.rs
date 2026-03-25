use crate::control::{Control, ControlFinding, ControlId, builtin};
use crate::evidence::{EvidenceBundle, EvidenceState, RegistryProvenanceCapability};

/// Verifies that all dependencies have bound signer identity and transparency log (Dependencies L3).
///
/// Requires every dependency to have:
/// - `VerificationOutcome::Verified` (cryptographic signature)
/// - `signer_identity` present (who signed it)
/// - `transparency_log_uri` present (publicly auditable)
///
/// This extends L2 (`dependency-provenance`) by requiring the full trust chain
/// to be inspectable: not just "signed by someone" but "signed by whom, verifiable where".
///
/// **Registry scoping**: Only evaluates dependencies from registries that support
/// the full trust chain (L3: signature + signer identity + transparency log).
/// Currently only npm (Sigstore + Rekor) qualifies. Dependencies from L2-only
/// or checksum-only registries are excluded.
pub struct DependencySignerVerifiedControl;

impl Control for DependencySignerVerifiedControl {
    fn id(&self) -> ControlId {
        builtin::id(builtin::DEPENDENCY_SIGNER_VERIFIED)
    }

    fn description(&self) -> &'static str {
        "All dependencies must have verified signer identity and transparency log"
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

                // Filter to registries that support L3 (full trust chain)
                let in_scope: Vec<_> = value
                    .iter()
                    .filter(|d| {
                        d.registry_provenance_capability()
                            >= RegistryProvenanceCapability::FullTrustChain
                    })
                    .collect();

                let skipped = value.len() - in_scope.len();

                if in_scope.is_empty() {
                    return vec![ControlFinding::not_applicable(
                        id,
                        format!(
                            "No dependencies from registries with full trust chain support \
                             ({skipped} dependenc(ies) from other registries skipped)",
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
                        !d.verification.is_cryptographically_signed()
                            || d.signer_identity.is_none()
                            || d.transparency_log_uri.is_none()
                    })
                    .map(|d| {
                        let mut reasons = Vec::new();
                        if !d.verification.is_cryptographically_signed() {
                            reasons.push("no signature");
                        }
                        if d.signer_identity.is_none() {
                            reasons.push("no signer_identity");
                        }
                        if d.transparency_log_uri.is_none() {
                            reasons.push("no transparency_log");
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
                    format!(" [{skipped} non-L3 registr(ies) skipped]")
                } else {
                    String::new()
                };

                if lacking.is_empty() {
                    let mut finding = ControlFinding::satisfied(
                        id,
                        format!(
                            "All {} dependenc(ies) have verified signer identity with transparency log{}{}",
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
                            "Dependenc(ies) lacking signer verification: {}{}{}",
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

    fn npm_dep_full(name: &str) -> DependencySignatureEvidence {
        DependencySignatureEvidence {
            name: name.to_string(),
            version: "1.0.0".to_string(),
            registry: Some("registry.npmjs.org".to_string()),
            verification: VerificationOutcome::Verified,
            signature_mechanism: Some("sigstore".to_string()),
            signer_identity: Some("https://github.com/login/oauth".to_string()),
            source_repo: Some("owner/repo".to_string()),
            source_commit: Some("abc123".to_string()),
            pinned_digest: None,
            actual_digest: None,
            transparency_log_uri: Some(
                "https://rekor.sigstore.dev/api/v1/log/entries/abc".to_string(),
            ),
            is_direct: true,
        }
    }

    fn npm_dep_no_signer(name: &str) -> DependencySignatureEvidence {
        let mut d = npm_dep_full(name);
        d.signer_identity = None;
        d
    }

    fn npm_dep_no_tlog(name: &str) -> DependencySignatureEvidence {
        let mut d = npm_dep_full(name);
        d.transparency_log_uri = None;
        d
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
    fn satisfied_with_full_trust_chain() {
        let findings = DependencySignerVerifiedControl.evaluate(&bundle(vec![
            npm_dep_full("react"),
            npm_dep_full("express"),
        ]));
        assert_eq!(findings[0].status, ControlStatus::Satisfied);
    }

    #[test]
    fn violated_when_signer_identity_missing() {
        let findings =
            DependencySignerVerifiedControl.evaluate(&bundle(vec![npm_dep_no_signer("lodash")]));
        assert_eq!(findings[0].status, ControlStatus::Violated);
        assert!(findings[0].rationale.contains("no signer_identity"));
    }

    #[test]
    fn violated_when_transparency_log_missing() {
        let findings =
            DependencySignerVerifiedControl.evaluate(&bundle(vec![npm_dep_no_tlog("lodash")]));
        assert_eq!(findings[0].status, ControlStatus::Violated);
        assert!(findings[0].rationale.contains("no transparency_log"));
    }

    #[test]
    fn not_applicable_when_only_cargo_deps() {
        let findings = DependencySignerVerifiedControl.evaluate(&bundle(vec![cargo_dep("serde")]));
        assert_eq!(findings[0].status, ControlStatus::NotApplicable);
        assert!(findings[0].rationale.contains("skipped"));
    }

    #[test]
    fn mixed_registries_only_evaluates_npm() {
        let evidence = bundle(vec![cargo_dep("serde"), npm_dep_full("react")]);
        let findings = DependencySignerVerifiedControl.evaluate(&evidence);
        assert_eq!(findings[0].status, ControlStatus::Satisfied);
        assert!(findings[0].rationale.contains("1 dependenc(ies)"));
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
        let findings = DependencySignerVerifiedControl.evaluate(&evidence);
        assert_eq!(findings[0].status, ControlStatus::Indeterminate);
        assert_eq!(findings[0].evidence_gaps.len(), 1);
    }

    #[test]
    fn partial_evidence_propagates_gaps_in_rationale() {
        let evidence = EvidenceBundle {
            dependency_signatures: EvidenceState::partial(
                vec![npm_dep_full("react")],
                vec![crate::evidence::EvidenceGap::Truncated {
                    source: "tree-api".to_string(),
                    subject: "repo-tree".to_string(),
                }],
            ),
            ..Default::default()
        };
        let findings = DependencySignerVerifiedControl.evaluate(&evidence);
        assert!(
            findings[0].rationale.contains("evidence gap"),
            "rationale should warn about gaps: {}",
            findings[0].rationale
        );
        assert_eq!(findings[0].evidence_gaps.len(), 1);
    }

    #[test]
    fn violated_when_both_signer_and_tlog_missing() {
        let mut d = npm_dep_full("pkg");
        d.signer_identity = None;
        d.transparency_log_uri = None;
        let findings = DependencySignerVerifiedControl.evaluate(&bundle(vec![d]));
        assert_eq!(findings[0].status, ControlStatus::Violated);
        assert!(findings[0].rationale.contains("no signer_identity"));
        assert!(findings[0].rationale.contains("no transparency_log"));
    }
}
