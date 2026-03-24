//! Enterprise SRE scenario: SOC2 Type II evaluation of a realistic PR.
//!
//! Simulates a 2000-person company with:
//! - 2 independent reviewers (both different from author)
//! - All commits GPG-signed
//! - CODEOWNERS with catch-all and specific paths
//! - Secret scanning + push protection
//! - Dependabot + CodeQL (SAST) enabled
//! - SECURITY.md present but disclosure process is in internal portal
//! - Branch protection on
//! - PR changes a Dockerfile (security-sensitive file)
//!
//! Run: cargo run --example enterprise_scenario -p libverify-policy

use libverify_core::assessment::{VerificationResult, assess_with_registry};
use libverify_core::control::builtin;
use libverify_core::evidence::{
    ApprovalDecision, ApprovalDisposition, AuthenticityEvidence, ChangeRequestId, ChangedAsset,
    CodeownersEntry, EvidenceBundle, EvidenceState, GovernedChange, RepositoryPosture,
    SourceRevision, WorkItemRef,
};
use libverify_core::profile::GateDecision;
use libverify_core::registry::ControlRegistry;
use libverify_policy::OpaProfile;

fn build_evidence() -> EvidenceBundle {
    // --- Change Request: PR #4217 updating Dockerfile + app code ---
    let cr = GovernedChange {
        id: ChangeRequestId::new("github", "acme-corp/platform#4217"),
        title: "fix: harden production Dockerfile and update auth middleware".to_string(),
        summary: Some(
            "Pins base image to digest, drops root user, and updates JWT validation \
             in auth middleware to reject expired tokens earlier."
                .to_string(),
        ),
        submitted_by: Some("alice".to_string()),

        changed_assets: EvidenceState::complete(vec![
            ChangedAsset {
                path: "Dockerfile".to_string(),
                diff_available: true,
                additions: 12,
                deletions: 4,
                status: "modified".to_string(),
                diff: Some(
                    "@@ -1,4 +1,12 @@\n-FROM node:20\n+FROM node:20@sha256:abc123...".to_string(),
                ),
            },
            ChangedAsset {
                path: "src/auth/middleware.ts".to_string(),
                diff_available: true,
                additions: 8,
                deletions: 3,
                status: "modified".to_string(),
                diff: None,
            },
            ChangedAsset {
                path: "src/auth/jwt.ts".to_string(),
                diff_available: true,
                additions: 15,
                deletions: 7,
                status: "modified".to_string(),
                diff: None,
            },
        ]),

        // 2 independent reviewers, both different from author "alice"
        approval_decisions: EvidenceState::complete(vec![
            ApprovalDecision {
                actor: "bob".to_string(),
                disposition: ApprovalDisposition::Approved,
                submitted_at: Some("2026-03-24T10:00:00Z".to_string()),
            },
            ApprovalDecision {
                actor: "carol".to_string(),
                disposition: ApprovalDisposition::Approved,
                submitted_at: Some("2026-03-24T11:30:00Z".to_string()),
            },
        ]),

        // All 3 commits GPG-signed
        source_revisions: EvidenceState::complete(vec![
            SourceRevision {
                id: "a1b2c3d".to_string(),
                authored_by: Some("alice".to_string()),
                committed_at: Some("2026-03-23T14:00:00Z".to_string()),
                merge: false,
                authenticity: EvidenceState::complete(AuthenticityEvidence::new(
                    true,
                    Some("gpg".to_string()),
                )),
            },
            SourceRevision {
                id: "e4f5g6h".to_string(),
                authored_by: Some("alice".to_string()),
                committed_at: Some("2026-03-23T16:00:00Z".to_string()),
                merge: false,
                authenticity: EvidenceState::complete(AuthenticityEvidence::new(
                    true,
                    Some("gpg".to_string()),
                )),
            },
            SourceRevision {
                id: "i7j8k9l".to_string(),
                authored_by: Some("alice".to_string()),
                committed_at: Some("2026-03-24T09:00:00Z".to_string()),
                merge: false,
                authenticity: EvidenceState::complete(AuthenticityEvidence::new(
                    true,
                    Some("gpg".to_string()),
                )),
            },
        ]),

        // Linked to Jira ticket
        work_item_refs: EvidenceState::complete(vec![WorkItemRef {
            system: "jira".to_string(),
            value: "SEC-1042".to_string(),
        }]),
    };

    // --- Repository Posture: enterprise-grade settings ---
    let posture = RepositoryPosture {
        codeowners_entries: vec![
            CodeownersEntry {
                pattern: "*".to_string(),
                owners: vec!["@acme-corp/platform-eng".to_string()],
            },
            CodeownersEntry {
                pattern: "/infra/".to_string(),
                owners: vec![
                    "@acme-corp/sre-team".to_string(),
                    "@acme-corp/security".to_string(),
                ],
            },
            CodeownersEntry {
                pattern: "/src/auth/".to_string(),
                owners: vec!["@acme-corp/security".to_string()],
            },
        ],
        secret_scanning_enabled: true,
        secret_push_protection_enabled: true,
        vulnerability_scanning_enabled: true, // Dependabot
        code_scanning_enabled: true,          // CodeQL / SAST
        security_policy_present: true,
        security_policy_has_disclosure: false, // disclosure in internal portal, not SECURITY.md
        default_branch_protected: true,
    };

    EvidenceBundle {
        change_requests: vec![cr],
        promotion_batches: vec![],
        // No artifact attestations (pre-merge check, no release yet)
        artifact_attestations: EvidenceState::NotApplicable,
        // No CI check run evidence provided (would need adapter)
        check_runs: EvidenceState::NotApplicable,
        // No build platform evidence (pre-merge)
        build_platform: EvidenceState::NotApplicable,
        // No dependency signature evidence (would need lock-file parser)
        dependency_signatures: EvidenceState::NotApplicable,
        repository_posture: EvidenceState::complete(posture),
    }
}

fn main() {
    let evidence = build_evidence();

    // All 28 built-in controls
    let registry = ControlRegistry::builtin();
    println!(
        "=== Enterprise SRE Scenario: SOC2 Type II Evaluation ===\n\
         Controls registered: {}\n",
        registry.len()
    );

    // SOC2 policy preset
    let profile = OpaProfile::soc2_preset().expect("SOC2 preset should load");
    let report = assess_with_registry(&evidence, &registry, &profile);

    // --- Print each finding ---
    println!(
        "{:<35} {:<15} {:<10} {:<8}",
        "CONTROL", "STATUS", "SEVERITY", "DECISION"
    );
    println!("{}", "-".repeat(70));

    let mut pass_count = 0usize;
    let mut review_count = 0usize;
    let mut fail_count = 0usize;

    for (finding, outcome) in report.findings.iter().zip(report.outcomes.iter()) {
        let severity_label = report.severity_labels.label_for(outcome.severity);
        let decision_str = outcome.decision.as_str();

        println!(
            "{:<35} {:<15} {:<10} {:<8}",
            finding.control_id.as_str(),
            finding.status.as_str(),
            severity_label,
            decision_str,
        );

        match outcome.decision {
            GateDecision::Pass => pass_count += 1,
            GateDecision::Review => review_count += 1,
            GateDecision::Fail => fail_count += 1,
        }
    }

    println!("{}", "-".repeat(70));
    println!(
        "TOTALS: {} pass, {} review, {} fail  (out of {} evaluated findings)\n",
        pass_count,
        review_count,
        fail_count,
        report.findings.len()
    );

    // --- Specific assertions the SRE cares about ---
    // 1. security-file-change should flag the Dockerfile
    let sfc = report
        .findings
        .iter()
        .find(|f| f.control_id.as_str() == builtin::SECURITY_FILE_CHANGE)
        .expect("security-file-change finding must exist");
    println!(
        "[CHECK] security-file-change status: {} | rationale: {}",
        sfc.status, sfc.rationale
    );
    assert_eq!(
        sfc.status,
        libverify_core::control::ControlStatus::Violated,
        "Dockerfile change must be flagged as violated"
    );

    // 2. security-policy should be "review" not "fail" under SOC2
    let sp_outcome = report
        .outcomes
        .iter()
        .find(|o| o.control_id.as_str() == builtin::SECURITY_POLICY)
        .expect("security-policy outcome must exist");
    println!(
        "[CHECK] security-policy decision: {} (expected: review)",
        sp_outcome.decision
    );
    assert_eq!(
        sp_outcome.decision,
        GateDecision::Review,
        "SOC2 preset must treat security-policy violation as review, not fail"
    );

    // --- SARIF output ---
    let vr = VerificationResult::new(report, Some(evidence));
    let sarif_opts = libverify_output::OutputOptions {
        format: libverify_output::Format::Sarif,
        only_failures: false,
        tool_name: "enterprise-scenario".to_string(),
        tool_version: "0.1.0".to_string(),
    };
    let sarif_output =
        libverify_output::render(&sarif_opts, &vr).expect("SARIF rendering must succeed");

    // Validate SARIF structure
    let sarif: serde_json::Value =
        serde_json::from_str(&sarif_output).expect("SARIF must be valid JSON");
    assert_eq!(sarif["version"], "2.1.0");
    let results = sarif["runs"][0]["results"]
        .as_array()
        .expect("SARIF results must be an array");
    println!(
        "\n[CHECK] SARIF output: valid, version 2.1.0, {} results",
        results.len()
    );

    // Write SARIF to stdout (truncated for readability)
    println!("\n=== SARIF Output (first 80 lines) ===");
    for (i, line) in sarif_output.lines().enumerate() {
        if i >= 80 {
            println!("... ({} more lines)", sarif_output.lines().count() - 80);
            break;
        }
        println!("{line}");
    }

    println!("\n=== All checks passed. ===");
}
