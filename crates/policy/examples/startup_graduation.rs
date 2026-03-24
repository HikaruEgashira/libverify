//! OSS -> SOC2 graduation path demo for a 15-person startup.
//!
//! Simulates a realistic startup posture:
//!   - No CODEOWNERS file
//!   - Dependabot enabled, no secret scanning
//!   - Basic SECURITY.md (present, no disclosure process)
//!   - Self-reviewed PRs (author == reviewer)
//!   - No branch protection, no signed commits
//!   - CI running but no build provenance/attestations
//!
//! Run: cargo run -p libverify-policy --example startup_graduation

use libverify_core::control::evaluate_all;
use libverify_core::controls::all_controls;
use libverify_core::evidence::*;
use libverify_core::profile::{GateDecision, apply_profile};
use libverify_policy::OpaProfile;

/// Build an EvidenceBundle representing a typical early-stage startup.
fn startup_evidence() -> EvidenceBundle {
    // A self-reviewed PR: alice authored, alice approved
    let pr = GovernedChange {
        id: ChangeRequestId::new("github", "42"),
        title: "feat: add user auth".to_string(),
        summary: Some("Adds JWT-based authentication flow for the API.".to_string()),
        submitted_by: Some("alice".to_string()),
        changed_assets: EvidenceState::complete(vec![
            ChangedAsset {
                path: "src/auth/mod.rs".to_string(),
                diff_available: true,
                additions: 120,
                deletions: 5,
                status: "added".to_string(),
                diff: None,
            },
            ChangedAsset {
                path: "src/auth/jwt.rs".to_string(),
                diff_available: true,
                additions: 85,
                deletions: 0,
                status: "added".to_string(),
                diff: None,
            },
            ChangedAsset {
                path: "tests/auth_test.rs".to_string(),
                diff_available: true,
                additions: 40,
                deletions: 0,
                status: "added".to_string(),
                diff: None,
            },
        ]),
        approval_decisions: EvidenceState::complete(vec![ApprovalDecision {
            actor: "alice".to_string(), // same as submitter = self-review
            disposition: ApprovalDisposition::Approved,
            submitted_at: Some("2026-03-25T10:00:00Z".to_string()),
        }]),
        source_revisions: EvidenceState::complete(vec![SourceRevision {
            id: "abc1234".to_string(),
            authored_by: Some("alice".to_string()),
            committed_at: Some("2026-03-25T09:30:00Z".to_string()),
            merge: false,
            authenticity: EvidenceState::complete(AuthenticityEvidence {
                verified: false, // unsigned commits
                mechanism: None,
            }),
        }]),
        work_item_refs: EvidenceState::complete(vec![]), // no linked issues
    };

    // Repository posture: typical early startup
    let posture = RepositoryPosture {
        codeowners_entries: vec![],            // no CODEOWNERS
        secret_scanning_enabled: false,        // not enabled
        secret_push_protection_enabled: false, // not enabled
        vulnerability_scanning_enabled: true,  // Dependabot on
        code_scanning_enabled: false,          // no CodeQL
        security_policy_present: true,         // basic SECURITY.md
        security_policy_has_disclosure: false, // no disclosure process
        default_branch_protected: false,       // no branch protection
    };

    EvidenceBundle {
        change_requests: vec![pr],
        promotion_batches: vec![],
        artifact_attestations: EvidenceState::NotApplicable,
        check_runs: EvidenceState::complete(vec![
            CheckRunEvidence {
                name: "ci / test".to_string(),
                conclusion: CheckConclusion::Success,
                app_slug: Some("github-actions".to_string()),
            },
            CheckRunEvidence {
                name: "ci / lint".to_string(),
                conclusion: CheckConclusion::Success,
                app_slug: Some("github-actions".to_string()),
            },
        ]),
        build_platform: EvidenceState::NotApplicable, // no SLSA build evidence
        dependency_signatures: EvidenceState::NotApplicable, // no dep signing
        repository_posture: EvidenceState::complete(posture),
    }
}

fn main() {
    println!("==========================================================");
    println!("  libverify: OSS -> SOC2 Graduation Path Demo");
    println!("  Startup: 15-person team preparing for SOC2 Type II");
    println!("==========================================================\n");

    // --- Describe the startup posture ---
    println!("STARTUP POSTURE:");
    println!("  - No CODEOWNERS file");
    println!("  - Dependabot enabled, no secret scanning");
    println!("  - Basic SECURITY.md (no disclosure process)");
    println!("  - Self-reviewed PRs (author == sole reviewer)");
    println!("  - Unsigned commits, no branch protection");
    println!("  - CI running (tests + lint pass), no build provenance");
    println!("  - No dependency signature verification");
    println!();

    // --- Run all 28 controls ---
    let evidence = startup_evidence();
    let controls = all_controls();
    println!("Running {} controls against evidence...\n", controls.len());
    let findings = evaluate_all(&controls, &evidence);

    // --- Evaluate through OSS preset ---
    let oss_profile = OpaProfile::oss_preset().expect("OSS preset should load");
    let oss_outcomes = apply_profile(&oss_profile, &findings);

    // --- Evaluate through SOC2 preset ---
    let soc2_profile = OpaProfile::soc2_preset().expect("SOC2 preset should load");
    let soc2_outcomes = apply_profile(&soc2_profile, &findings);

    // --- Print side-by-side comparison ---
    println!(
        "{:<40} {:<12} {:<12}  {}",
        "CONTROL", "OSS", "SOC2", "DELTA"
    );
    println!("{}", "-".repeat(90));

    let mut oss_pass = 0u32;
    let mut oss_review = 0u32;
    let mut oss_fail = 0u32;
    let mut soc2_pass = 0u32;
    let mut soc2_review = 0u32;
    let mut soc2_fail = 0u32;
    let mut graduation_blockers: Vec<(String, String)> = Vec::new();

    for (oss_out, soc2_out) in oss_outcomes.iter().zip(soc2_outcomes.iter()) {
        let oss_dec = oss_out.decision;
        let soc2_dec = soc2_out.decision;

        match oss_dec {
            GateDecision::Pass => oss_pass += 1,
            GateDecision::Review => oss_review += 1,
            GateDecision::Fail => oss_fail += 1,
        }
        match soc2_dec {
            GateDecision::Pass => soc2_pass += 1,
            GateDecision::Review => soc2_review += 1,
            GateDecision::Fail => soc2_fail += 1,
        }

        let delta = if oss_dec == soc2_dec {
            " ".to_string()
        } else {
            let arrow = format!("{} -> {}", oss_dec, soc2_dec);
            if soc2_dec == GateDecision::Fail {
                graduation_blockers.push((
                    oss_out.control_id.as_str().to_string(),
                    oss_out.rationale.clone(),
                ));
                format!("!! {arrow}")
            } else {
                format!("   {arrow}")
            }
        };

        println!(
            "{:<40} {:<12} {:<12}  {}",
            oss_out.control_id.as_str(),
            format!("{}", oss_dec),
            format!("{}", soc2_dec),
            delta,
        );
    }

    // --- Summary ---
    println!("\n{}", "=".repeat(90));
    println!("SUMMARY\n");
    println!(
        "  OSS  preset:  {} pass / {} review / {} fail",
        oss_pass, oss_review, oss_fail
    );
    println!(
        "  SOC2 preset:  {} pass / {} review / {} fail",
        soc2_pass, soc2_review, soc2_fail
    );

    println!("\n{}", "-".repeat(90));
    println!(
        "GRADUATION BLOCKERS (review in OSS, fail in SOC2): {}\n",
        graduation_blockers.len()
    );
    if graduation_blockers.is_empty() {
        println!("  None -- you are already SOC2-ready (unlikely for a startup!)");
    } else {
        for (id, rationale) in &graduation_blockers {
            println!("  [BLOCK] {id}");
            println!("          {rationale}\n");
        }
    }

    // Also show controls that fail in both (already broken)
    let both_fail: Vec<_> = oss_outcomes
        .iter()
        .zip(soc2_outcomes.iter())
        .filter(|(o, s)| o.decision == GateDecision::Fail && s.decision == GateDecision::Fail)
        .map(|(o, _)| o.control_id.as_str().to_string())
        .collect();

    if !both_fail.is_empty() {
        println!("{}", "-".repeat(90));
        println!(
            "FAIL IN BOTH presets (fix these regardless): {}\n",
            both_fail.len()
        );
        for id in &both_fail {
            println!("  [FAIL] {id}");
        }
    }

    // Controls that are review in SOC2 (needs attention but not blocking)
    let soc2_review_list: Vec<_> = soc2_outcomes
        .iter()
        .filter(|o| o.decision == GateDecision::Review)
        .map(|o| o.control_id.as_str().to_string())
        .collect();

    if !soc2_review_list.is_empty() {
        println!("\n{}", "-".repeat(90));
        println!(
            "SOC2 REVIEW items (auditor will ask questions): {}\n",
            soc2_review_list.len()
        );
        for id in &soc2_review_list {
            println!("  [REVIEW] {id}");
        }
    }

    println!("\n{}", "=".repeat(90));
    println!("GRADUATION ROADMAP:");
    println!("  1. Enable branch protection + require reviews  (unblocks review-independence,");
    println!("     two-party-review, branch-protection-enforcement, branch-history-integrity)");
    println!("  2. Enable secret scanning + push protection    (unblocks secret-scanning)");
    println!("  3. Add CODEOWNERS file                         (unblocks codeowners-coverage)");
    println!("  4. Sign commits (GPG/SSH)                      (unblocks source-authenticity)");
    println!("  5. Link issues to PRs                          (unblocks issue-linkage)");
    println!("  6. Add disclosure process to SECURITY.md       (unblocks security-policy)");
    println!("  7. Set up build provenance (SLSA)              (unblocks build-track controls)");
    println!("{}", "=".repeat(90));
}
