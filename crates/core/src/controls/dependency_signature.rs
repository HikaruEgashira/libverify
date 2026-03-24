use crate::control::{Control, ControlFinding, ControlId, builtin};
use crate::evidence::{EvidenceBundle, EvidenceState};
use crate::integrity::dependency_signature_severity;
use crate::verdict::Severity;

/// Verifies that all dependencies have valid cryptographic signatures or provenance.
///
/// Supports multiple verification mechanisms including npm provenance (Sigstore/SLSA),
/// PGP signatures, and lock-file checksum pinning. Uses `VerificationOutcome` for
/// structured failure reasons, distinguishing between absent signatures, invalid
/// signatures, signer mismatches, and missing transparency log entries.
///
/// When evidence is `Partial` (some dependencies could not be checked), the control
/// propagates the evidence gaps into the finding and appends a warning to the rationale.
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
            EvidenceState::Complete { value } => {
                if value.is_empty() {
                    return vec![ControlFinding::not_applicable(
                        id,
                        "No dependencies were present",
                    )];
                }
                evaluate_deps(&id, value, &[])
            }
            EvidenceState::Partial { value, gaps } => {
                if value.is_empty() {
                    return vec![ControlFinding::indeterminate(
                        id,
                        format!(
                            "No verified dependencies available; {} evidence gap(s) reported",
                            gaps.len()
                        ),
                        Vec::new(),
                        gaps.clone(),
                    )];
                }
                evaluate_deps(&id, value, gaps)
            }
        }
    }
}

fn evaluate_deps(
    id: &ControlId,
    deps: &[crate::evidence::DependencySignatureEvidence],
    gaps: &[crate::evidence::EvidenceGap],
) -> Vec<ControlFinding> {
    let subjects: Vec<String> = deps
        .iter()
        .map(|d| format!("{}@{}", d.name, d.version))
        .collect();

    let unverified: Vec<String> = deps
        .iter()
        .filter(|d| !d.verification.is_verified())
        .map(|d| {
            let reason = d
                .verification
                .failure_kind()
                .unwrap_or("unverified");
            format!("{}@{} ({})", d.name, d.version, reason)
        })
        .collect();

    let gap_suffix = if gaps.is_empty() {
        String::new()
    } else {
        format!(
            " (WARNING: {} evidence gap(s) — unverified dependencies may be hidden)",
            gaps.len()
        )
    };

    let mut finding = match dependency_signature_severity(unverified.len()) {
        Severity::Pass => ControlFinding::satisfied(
            id.clone(),
            format!(
                "All {} dependency signature(s) verified{}",
                deps.len(),
                gap_suffix,
            ),
            subjects,
        ),
        _ => ControlFinding::violated(
            id.clone(),
            format!(
                "Unverified dependency(ies): {}{}",
                unverified.join("; "),
                gap_suffix,
            ),
            subjects,
        ),
    };

    if !gaps.is_empty() {
        finding.evidence_gaps = gaps.to_vec();
    }

    vec![finding]
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::control::ControlStatus;
    use crate::evidence::{
        DependencySignatureEvidence, EvidenceGap, VerificationOutcome,
    };

    fn make_dep(name: &str, version: &str, verified: bool) -> DependencySignatureEvidence {
        DependencySignatureEvidence {
            name: name.to_string(),
            version: version.to_string(),
            registry: Some("crates.io".to_string()),
            verification: if verified {
                VerificationOutcome::Verified
            } else {
                VerificationOutcome::AttestationAbsent {
                    detail: "no signature found".to_string(),
                }
            },
            signature_mechanism: if verified {
                Some("sigstore".to_string())
            } else {
                None
            },
            signer_identity: None,
            source_repo: None,
            source_commit: None,
            subject_digest: None,
            transparency_log_uri: None,
        }
    }

    fn make_npm_dep(
        name: &str,
        version: &str,
        verified: bool,
        source_repo: Option<&str>,
    ) -> DependencySignatureEvidence {
        DependencySignatureEvidence {
            name: name.to_string(),
            version: version.to_string(),
            registry: Some("registry.npmjs.org".to_string()),
            verification: if verified {
                VerificationOutcome::Verified
            } else {
                VerificationOutcome::AttestationAbsent {
                    detail: "npm provenance not found".to_string(),
                }
            },
            signature_mechanism: if verified {
                Some("sigstore".to_string())
            } else {
                None
            },
            signer_identity: if verified {
                Some("https://github.com/login/oauth".to_string())
            } else {
                None
            },
            source_repo: source_repo.map(str::to_string),
            source_commit: None,
            subject_digest: None,
            transparency_log_uri: if verified {
                Some("https://rekor.sigstore.dev/api/v1/log/entries/...".to_string())
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
        assert!(findings[0]
            .rationale
            .contains("2 dependency signature(s) verified"));
    }

    #[test]
    fn satisfied_single_dependency() {
        let findings = DependencySignatureControl
            .evaluate(&make_bundle(vec![make_dep("serde", "1.0.204", true)]));
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
        assert!(findings[0].rationale.contains("attestation_absent"));
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

    #[test]
    fn violated_with_signature_invalid_reason() {
        let evidence = make_bundle(vec![DependencySignatureEvidence {
            name: "tampered-pkg".to_string(),
            version: "1.0.0".to_string(),
            registry: Some("registry.npmjs.org".to_string()),
            verification: VerificationOutcome::SignatureInvalid {
                detail: "ECDSA signature mismatch".to_string(),
            },
            signature_mechanism: Some("sigstore".to_string()),
            signer_identity: None,
            source_repo: None,
            source_commit: None,
            subject_digest: None,
            transparency_log_uri: None,
        }]);
        let findings = DependencySignatureControl.evaluate(&evidence);
        assert_eq!(findings[0].status, ControlStatus::Violated);
        assert!(findings[0].rationale.contains("signature_invalid"));
    }

    // --- Partial evidence handling ---

    #[test]
    fn partial_evidence_with_signed_deps_includes_gap_warning() {
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
        assert!(
            findings[0].rationale.contains("evidence gap"),
            "Partial evidence must warn about gaps in rationale: {}",
            findings[0].rationale
        );
        assert_eq!(
            findings[0].evidence_gaps.len(),
            1,
            "Partial evidence gaps must propagate to finding"
        );
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
        assert!(findings[0].rationale.contains("evidence gap"));
        assert_eq!(findings[0].evidence_gaps.len(), 1);
    }

    #[test]
    fn partial_evidence_empty_deps_is_indeterminate() {
        let evidence = EvidenceBundle {
            dependency_signatures: EvidenceState::partial(
                vec![],
                vec![EvidenceGap::CollectionFailed {
                    source: "npm-registry".to_string(),
                    subject: "audit-signatures".to_string(),
                    detail: "timeout".to_string(),
                }],
            ),
            ..Default::default()
        };
        let findings = DependencySignatureControl.evaluate(&evidence);
        assert_eq!(findings[0].status, ControlStatus::Indeterminate);
    }

    // --- npm provenance ---

    #[test]
    fn npm_provenance_satisfied_with_source_repo() {
        let findings = DependencySignatureControl.evaluate(&make_bundle(vec![
            make_npm_dep("react", "18.3.1", true, Some("facebook/react")),
            make_npm_dep("express", "4.18.2", true, Some("expressjs/express")),
        ]));
        assert_eq!(findings[0].status, ControlStatus::Satisfied);
    }

    #[test]
    fn npm_provenance_mixed_legacy_violated() {
        let findings = DependencySignatureControl.evaluate(&make_bundle(vec![
            make_npm_dep("react", "18.3.1", true, Some("facebook/react")),
            make_npm_dep("lodash", "4.17.21", false, None),
        ]));
        assert_eq!(findings[0].status, ControlStatus::Violated);
        assert!(findings[0].rationale.contains("lodash@4.17.21"));
    }

    #[test]
    fn correct_control_id() {
        assert_eq!(
            DependencySignatureControl.id(),
            builtin::id(builtin::DEPENDENCY_SIGNATURE)
        );
    }
}
