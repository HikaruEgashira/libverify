/// Integration tests for the dependency-signature control.
///
/// These tests exercise the control end-to-end through the public API surface:
/// `EvidenceBundle`, `ControlRegistry`, and `evaluate_all`.
use libverify_core::control::{ControlStatus, builtin, evaluate_all};
use libverify_core::evidence::{
    DependencySignatureEvidence, EvidenceBundle, EvidenceState, VerificationOutcome,
};
use libverify_core::registry::ControlRegistry;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn dep(name: &str, version: &str, verified: bool) -> DependencySignatureEvidence {
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
        pinned_digest: None,
        actual_digest: None,
        transparency_log_uri: None,
        is_direct: true,
    }
}

fn bundle_with(deps: Vec<DependencySignatureEvidence>) -> EvidenceBundle {
    EvidenceBundle {
        dependency_signatures: EvidenceState::complete(deps),
        ..Default::default()
    }
}

// ---------------------------------------------------------------------------
// Scenario A: All dependencies signed → Satisfied
// ---------------------------------------------------------------------------

#[test]
fn scenario_a_all_signed_is_satisfied() {
    let registry = ControlRegistry::builtin();

    let evidence = bundle_with(vec![
        dep("serde", "1.0.204", true),
        dep("tokio", "1.38.0", true),
        dep("anyhow", "1.0.86", true),
    ]);

    let findings = evaluate_all(registry.controls(), &evidence);

    let dep_sig_findings: Vec<_> = findings
        .iter()
        .filter(|f| f.control_id.as_str() == builtin::DEPENDENCY_SIGNATURE)
        .collect();

    assert_eq!(
        dep_sig_findings.len(),
        1,
        "dependency-signature should produce exactly one finding"
    );

    let finding = &dep_sig_findings[0];
    assert_eq!(
        finding.status,
        ControlStatus::Satisfied,
        "all signed deps must yield Satisfied; got rationale: {}",
        finding.rationale
    );
    assert!(
        finding.rationale.contains("3 dependency signature(s) verified"),
        "rationale should mention count; got: {}",
        finding.rationale
    );
}

// ---------------------------------------------------------------------------
// Scenario B: One unsigned dependency → Violated, rationale contains pkg name
// ---------------------------------------------------------------------------

#[test]
fn scenario_b_one_unsigned_is_violated_with_package_name_in_rationale() {
    let registry = ControlRegistry::builtin();

    let evidence = bundle_with(vec![
        dep("serde", "1.0.204", true),
        dep("sketchy-lib", "0.1.0", false),
        dep("tokio", "1.38.0", true),
    ]);

    let findings = evaluate_all(registry.controls(), &evidence);

    let dep_sig_findings: Vec<_> = findings
        .iter()
        .filter(|f| f.control_id.as_str() == builtin::DEPENDENCY_SIGNATURE)
        .collect();

    assert_eq!(dep_sig_findings.len(), 1);

    let finding = &dep_sig_findings[0];
    assert_eq!(
        finding.status,
        ControlStatus::Violated,
        "one unsigned dep must yield Violated; got rationale: {}",
        finding.rationale
    );
    assert!(
        finding.rationale.contains("sketchy-lib@0.1.0"),
        "rationale must contain the unsigned package name; got: {}",
        finding.rationale
    );
    // Signed deps must not appear in the violation rationale.
    assert!(
        !finding.rationale.contains("serde@"),
        "signed deps should not be listed in violation; got: {}",
        finding.rationale
    );
}

// ---------------------------------------------------------------------------
// Scenario C: ControlRegistry::builtin() contains dependency-signature
// ---------------------------------------------------------------------------

#[test]
fn scenario_c_builtin_registry_contains_dependency_signature() {
    let registry = ControlRegistry::builtin();

    let id_strings: Vec<String> = registry
        .control_ids()
        .into_iter()
        .map(|id| id.as_str().to_string())
        .collect();

    assert!(
        id_strings
            .iter()
            .any(|id| id == builtin::DEPENDENCY_SIGNATURE),
        "ControlRegistry::builtin() must include '{}'; found: {:?}",
        builtin::DEPENDENCY_SIGNATURE,
        id_strings
    );

    // Also verify the total count matches the documented 21.
    assert_eq!(
        registry.len(),
        21,
        "builtin registry should have 21 controls"
    );
}

// ---------------------------------------------------------------------------
// Scenario D: evaluate_all with multiple controls includes dependency-signature
// ---------------------------------------------------------------------------

#[test]
fn scenario_d_evaluate_all_includes_dependency_signature_finding() {
    let registry = ControlRegistry::builtin();

    // Mix of signed and unsigned to get a non-trivial finding.
    let evidence = bundle_with(vec![
        dep("reqwest", "0.12.0", true),
        dep("malware-pkg", "9.9.9", false),
    ]);

    let all_findings = evaluate_all(registry.controls(), &evidence);

    // There must be findings from many controls (registry has 21).
    assert!(
        all_findings.len() > 1,
        "evaluate_all should produce findings from multiple controls"
    );

    // The dependency-signature finding must be present and Violated.
    let dep_finding = all_findings
        .iter()
        .find(|f| f.control_id.as_str() == builtin::DEPENDENCY_SIGNATURE)
        .expect("dependency-signature finding must be present in evaluate_all output");

    assert_eq!(dep_finding.status, ControlStatus::Violated);
    assert!(
        dep_finding.rationale.contains("malware-pkg@9.9.9"),
        "finding rationale must name the unsigned package; got: {}",
        dep_finding.rationale
    );

    // subjects must list all deps (signed + unsigned).
    assert_eq!(
        dep_finding.subjects.len(),
        2,
        "subjects should enumerate all dependencies; got: {:?}",
        dep_finding.subjects
    );
}
