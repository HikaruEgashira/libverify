//! Real-world OSS maintainer scenario: a contributor PR on a 500-star GitHub Free repo.
//!
//! Evidence setup:
//!   - PR from a contributor (not the maintainer), with one approval from the maintainer
//!   - No CODEOWNERS file
//!   - Secret scanning NOT available (GitHub Free plan)
//!   - Dependabot enabled (vulnerability scanning = true)
//!   - SECURITY.md exists but only says "email me" (no disclosure process)
//!   - PR changes src/lib.rs and adds tests/integration.rs
//!   - One unsigned commit (contributor doesn't sign commits)
//!   - CI passes (one check run: "ci" with success)
//!   - Conventional commit title, linked issue, description present
//!   - No build provenance, no artifact attestations, no dependency signatures
//!   - Branch protection enabled on default branch

use libverify_core::assessment::{VerificationResult, assess};
use libverify_core::control::evaluate_all;
use libverify_core::controls::all_controls;
use libverify_core::evidence::*;
use libverify_core::profile::GateDecision;
use libverify_output::sarif;
use libverify_policy::OpaProfile;

fn build_evidence() -> EvidenceBundle {
    let change = GovernedChange {
        id: ChangeRequestId::new("github", "myorg/mylib#42"),
        title: "feat: add streaming parser for large inputs".to_string(),
        summary: Some(
            "Adds a streaming parser that handles inputs larger than available memory. \
             Includes integration tests for 1GB+ payloads."
                .to_string(),
        ),
        submitted_by: Some("contributor-alice".to_string()),
        changed_assets: EvidenceState::complete(vec![
            ChangedAsset {
                path: "src/lib.rs".to_string(),
                diff_available: true,
                additions: 85,
                deletions: 12,
                status: "modified".to_string(),
                diff: Some(
                    "@@ -10,12 +10,85 @@\n+pub mod streaming;\n+// ... streaming parser impl"
                        .to_string(),
                ),
            },
            ChangedAsset {
                path: "tests/integration.rs".to_string(),
                diff_available: true,
                additions: 45,
                deletions: 0,
                status: "added".to_string(),
                diff: Some(
                    "@@ -0,0 +1,45 @@\n+#[test]\n+fn streaming_large_input() { ... }".to_string(),
                ),
            },
        ]),
        approval_decisions: EvidenceState::complete(vec![ApprovalDecision {
            actor: "maintainer-bob".to_string(),
            disposition: ApprovalDisposition::Approved,
            submitted_at: Some("2026-03-25T10:00:00Z".to_string()),
        }]),
        source_revisions: EvidenceState::complete(vec![SourceRevision {
            id: "abc123def456".to_string(),
            authored_by: Some("contributor-alice".to_string()),
            committed_at: Some("2026-03-25T09:30:00Z".to_string()),
            merge: false,
            authenticity: EvidenceState::complete(AuthenticityEvidence::new(false, None)),
        }]),
        work_item_refs: EvidenceState::complete(vec![WorkItemRef {
            system: "github".to_string(),
            value: "myorg/mylib#38".to_string(),
        }]),
    };

    let posture = RepositoryPosture {
        codeowners_entries: vec![], // no CODEOWNERS
        secret_scanning_enabled: false,
        secret_push_protection_enabled: false,
        vulnerability_scanning_enabled: true, // Dependabot
        code_scanning_enabled: false,
        security_policy_present: true,
        security_policy_has_disclosure: false, // just "email me"
        default_branch_protected: true,
    };

    EvidenceBundle {
        change_requests: vec![change],
        promotion_batches: vec![],
        artifact_attestations: EvidenceState::not_applicable(),
        check_runs: EvidenceState::complete(vec![CheckRunEvidence {
            name: "ci".to_string(),
            conclusion: CheckConclusion::Success,
            app_slug: Some("github-actions".to_string()),
        }]),
        build_platform: EvidenceState::not_applicable(),
        dependency_signatures: EvidenceState::not_applicable(),
        repository_posture: EvidenceState::complete(posture),
    }
}

fn main() {
    let evidence = build_evidence();
    let controls = all_controls();
    let profile = OpaProfile::from_preset_or_file("oss").expect("failed to load OSS policy preset");

    // Step 1: raw control findings
    let findings = evaluate_all(&controls, &evidence);

    // Step 2: assess through the OSS policy
    let report = assess(&evidence, &controls, &profile);

    // Print per-finding results
    println!("=== OSS Scenario: Contributor PR on GitHub Free (500-star repo) ===\n");
    println!(
        "{:<35} {:<15} {:<10} {:<8}",
        "CONTROL", "STATUS", "SEVERITY", "DECISION"
    );
    println!("{}", "-".repeat(70));

    let mut pass_count = 0usize;
    let mut review_count = 0usize;
    let mut fail_count = 0usize;

    for (finding, outcome) in report.findings.iter().zip(report.outcomes.iter()) {
        let severity_str = format!("{:?}", outcome.severity);
        let decision_str = outcome.decision.as_str();
        println!(
            "{:<35} {:<15} {:<10} {:<8}",
            finding.control_id.as_str(),
            finding.status.as_str(),
            severity_str.to_lowercase(),
            decision_str,
        );

        match outcome.decision {
            GateDecision::Pass => pass_count += 1,
            GateDecision::Review => review_count += 1,
            GateDecision::Fail => fail_count += 1,
        }
    }

    let not_applicable_count = findings.len() - report.findings.len();

    println!("\n=== Summary ===");
    println!("Total controls evaluated: {}", findings.len());
    println!("  Not applicable (filtered): {not_applicable_count}");
    println!("  Pass:   {pass_count}");
    println!("  Review: {review_count}");
    println!("  Fail:   {fail_count}");

    let gate = if fail_count > 0 {
        "BLOCKED"
    } else if review_count > 0 {
        "REVIEW REQUIRED"
    } else {
        "CLEAR"
    };
    println!("\nOverall gate: {gate}");

    // Step 3: SARIF output
    let verification = VerificationResult::new(report, Some(evidence));
    let sarif_output =
        sarif::render(&verification, false, "oss-scenario", "0.1.0").expect("SARIF render failed");

    println!("\n=== SARIF Output ===");
    println!("{sarif_output}");

    // Exit with appropriate code for CI
    if fail_count > 0 {
        std::process::exit(1);
    }
}
