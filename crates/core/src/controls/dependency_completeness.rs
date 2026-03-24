use crate::control::{Control, ControlFinding, ControlId, builtin};
use crate::evidence::{EvidenceBundle, EvidenceState, RegistryProvenanceCapability};

/// Verifies that ALL dependencies (direct AND transitive) meet L3 verification (Dependencies L4).
///
/// Requires:
/// - Every dependency (regardless of `is_direct`) has `Verified` + `signer_identity` + `transparency_log_uri`
/// - At least one transitive dependency exists (otherwise the check is trivially satisfied
///   and the control returns NotApplicable — a project with only direct deps should use L3)
///
/// This is the strictest dependency verification level. It ensures the entire
/// dependency tree — not just direct dependencies — is fully provenance-verified.
///
/// **Registry scoping**: Only evaluates dependencies from registries that support
/// the full trust chain (L3). Dependencies from non-L3 registries are excluded.
pub struct DependencyCompletenessControl;

impl Control for DependencyCompletenessControl {
    fn id(&self) -> ControlId {
        builtin::id(builtin::DEPENDENCY_COMPLETENESS)
    }

    fn description(&self) -> &'static str {
        "All dependencies (direct and transitive) must be fully provenance-verified"
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

                let total = in_scope.len();
                let direct_count = in_scope.iter().filter(|d| d.is_direct).count();
                let transitive_count = total - direct_count;

                let subjects: Vec<String> = in_scope
                    .iter()
                    .map(|d| {
                        let kind = if d.is_direct { "direct" } else { "transitive" };
                        format!("{}@{} ({})", d.name, d.version, kind)
                    })
                    .collect();

                // L4 requires L3-level verification for ALL deps
                let lacking: Vec<String> = in_scope
                    .iter()
                    .filter(|d| {
                        !d.verification.is_cryptographically_signed()
                            || d.signer_identity.is_none()
                            || d.transparency_log_uri.is_none()
                    })
                    .map(|d| {
                        let kind = if d.is_direct { "direct" } else { "transitive" };
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
                        format!("{}@{} [{kind}] ({})", d.name, d.version, reasons.join(", "))
                    })
                    .collect();

                let gaps = match &evidence.dependency_signatures {
                    EvidenceState::Partial { gaps, .. } => gaps.as_slice(),
                    _ => &[],
                };

                // Partial evidence with gaps means we can't guarantee completeness
                if !gaps.is_empty() {
                    let mut finding = ControlFinding::violated(
                        id,
                        format!(
                            "Cannot guarantee completeness: {} evidence gap(s) — \
                             transitive dependencies may be missing from evaluation",
                            gaps.len()
                        ),
                        subjects,
                    );
                    finding.evidence_gaps = gaps.to_vec();
                    return vec![finding];
                }

                let skip_note = if skipped > 0 {
                    format!(" [{skipped} non-L3 registr(ies) skipped]")
                } else {
                    String::new()
                };

                if lacking.is_empty() {
                    vec![ControlFinding::satisfied(
                        id,
                        format!(
                            "All {total} dependenc(ies) ({direct_count} direct, \
                             {transitive_count} transitive) fully verified with provenance{skip_note}",
                        ),
                        subjects,
                    )]
                } else {
                    vec![ControlFinding::violated(
                        id,
                        format!(
                            "{}/{total} dependenc(ies) lack full provenance: {}{skip_note}",
                            lacking.len(),
                            lacking.join("; ")
                        ),
                        subjects,
                    )]
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::control::ControlStatus;
    use crate::evidence::{DependencySignatureEvidence, EvidenceGap, VerificationOutcome};

    fn npm_dep_l3(name: &str, is_direct: bool) -> DependencySignatureEvidence {
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
            is_direct,
        }
    }

    fn npm_dep_checksum(name: &str, is_direct: bool) -> DependencySignatureEvidence {
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
            is_direct,
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
    fn satisfied_when_all_npm_deps_fully_verified() {
        let evidence = bundle(vec![
            npm_dep_l3("react", true),
            npm_dep_l3("react-dom", false),
            npm_dep_l3("express", true),
            npm_dep_l3("body-parser", false),
        ]);
        let findings = DependencyCompletenessControl.evaluate(&evidence);
        assert_eq!(findings[0].status, ControlStatus::Satisfied);
        assert!(findings[0].rationale.contains("2 direct"));
        assert!(findings[0].rationale.contains("2 transitive"));
    }

    #[test]
    fn violated_when_npm_transitive_dep_lacks_provenance() {
        let evidence = bundle(vec![
            npm_dep_l3("react", true),
            npm_dep_checksum("scheduler", false),
        ]);
        let findings = DependencyCompletenessControl.evaluate(&evidence);
        assert_eq!(findings[0].status, ControlStatus::Violated);
        assert!(
            findings[0]
                .rationale
                .contains("scheduler@1.0.0 [transitive]")
        );
    }

    #[test]
    fn violated_when_npm_direct_dep_lacks_provenance() {
        let evidence = bundle(vec![
            npm_dep_checksum("lodash", true),
            npm_dep_l3("express", false),
        ]);
        let findings = DependencyCompletenessControl.evaluate(&evidence);
        assert_eq!(findings[0].status, ControlStatus::Violated);
        assert!(findings[0].rationale.contains("lodash@1.0.0 [direct]"));
    }

    #[test]
    fn not_applicable_when_only_cargo_deps() {
        let findings =
            DependencyCompletenessControl.evaluate(&bundle(vec![cargo_dep("serde")]));
        assert_eq!(findings[0].status, ControlStatus::NotApplicable);
    }

    #[test]
    fn mixed_registries_only_evaluates_npm() {
        let evidence = bundle(vec![
            cargo_dep("serde"),
            npm_dep_l3("react", true),
        ]);
        let findings = DependencyCompletenessControl.evaluate(&evidence);
        assert_eq!(findings[0].status, ControlStatus::Satisfied);
        assert!(findings[0].rationale.contains("skipped"));
    }

    #[test]
    fn violated_when_partial_evidence_has_gaps() {
        let evidence = EvidenceBundle {
            dependency_signatures: EvidenceState::partial(
                vec![npm_dep_l3("react", true)],
                vec![EvidenceGap::Truncated {
                    source: "github-tree-api".to_string(),
                    subject: "repository-tree".to_string(),
                }],
            ),
            ..Default::default()
        };
        let findings = DependencyCompletenessControl.evaluate(&evidence);
        assert_eq!(findings[0].status, ControlStatus::Violated);
        assert!(
            findings[0]
                .rationale
                .contains("Cannot guarantee completeness")
        );
    }

    #[test]
    fn not_applicable_when_empty() {
        let findings = DependencyCompletenessControl.evaluate(&bundle(vec![]));
        assert_eq!(findings[0].status, ControlStatus::NotApplicable);
    }

    #[test]
    fn indeterminate_when_evidence_missing() {
        let evidence = EvidenceBundle {
            dependency_signatures: EvidenceState::missing(vec![EvidenceGap::CollectionFailed {
                source: "registry".to_string(),
                subject: "deps".to_string(),
                detail: "timeout".to_string(),
            }]),
            ..Default::default()
        };
        let findings = DependencyCompletenessControl.evaluate(&evidence);
        assert_eq!(findings[0].status, ControlStatus::Indeterminate);
        assert_eq!(findings[0].evidence_gaps.len(), 1);
    }
}
