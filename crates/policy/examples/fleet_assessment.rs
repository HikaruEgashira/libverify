//! Fleet-wide ASPM assessment simulation.
//!
//! Evaluates 5 synthetic repo profiles against the 4 ASPM controls
//! (codeowners-coverage, secret-scanning, vulnerability-scanning, security-policy)
//! through the SOC2 policy preset, then prints a prioritized fleet summary.
//!
//! Run: cargo run -p libverify-policy --example fleet_assessment

use libverify_core::control::{Control, ControlFinding, builtin, evaluate_all};
use libverify_core::controls::codeowners_coverage::CodeownersCoverageControl;
use libverify_core::controls::secret_scanning::SecretScanningControl;
use libverify_core::controls::security_policy::SecurityPolicyControl;
use libverify_core::controls::vulnerability_scanning::VulnerabilityScanningControl;
use libverify_core::evidence::{CodeownersEntry, EvidenceBundle, EvidenceState, RepositoryPosture};
use libverify_core::profile::{GateDecision, apply_profile};
use libverify_policy::OpaProfile;

// ---------------------------------------------------------------------------
// Repo profile definitions
// ---------------------------------------------------------------------------

struct RepoProfile {
    name: &'static str,
    description: &'static str,
    posture: RepositoryPosture,
}

fn repo_profiles() -> Vec<RepoProfile> {
    vec![
        // 1. frontend-app: public, no CODEOWNERS, Dependabot only, no SECURITY.md
        RepoProfile {
            name: "frontend-app",
            description: "Public SPA, Dependabot only, no ownership or policy",
            posture: RepositoryPosture {
                codeowners_entries: vec![],
                secret_scanning_enabled: false,
                secret_push_protection_enabled: false,
                vulnerability_scanning_enabled: true, // Dependabot
                code_scanning_enabled: false,
                security_policy_present: false,
                security_policy_has_disclosure: false,
                default_branch_protected: false,
                enforce_admins: false,
                dismiss_stale_reviews: false,
                ..Default::default()
            },
        },
        // 2. core-api: private, CODEOWNERS with catch-all, secret scanning + push
        //    protection, CodeQL, SECURITY.md with disclosure
        RepoProfile {
            name: "core-api",
            description: "Private API, full GHAS, CODEOWNERS, SECURITY.md",
            posture: RepositoryPosture {
                codeowners_entries: vec![
                    CodeownersEntry {
                        pattern: "*".to_string(),
                        owners: vec!["@org/backend-team".to_string()],
                    },
                    CodeownersEntry {
                        pattern: "/src/auth/".to_string(),
                        owners: vec!["@org/security-team".to_string()],
                    },
                    CodeownersEntry {
                        pattern: "/infra/".to_string(),
                        owners: vec!["@org/platform-team".to_string()],
                    },
                ],
                secret_scanning_enabled: true,
                secret_push_protection_enabled: true,
                vulnerability_scanning_enabled: true, // Dependabot
                code_scanning_enabled: true,          // CodeQL
                security_policy_present: true,
                security_policy_has_disclosure: true,
                default_branch_protected: true,
                enforce_admins: true,
                dismiss_stale_reviews: true,
                ..Default::default()
            },
        },
        // 3. infra-terraform: private, CODEOWNERS (2 entries only), secret scanning
        //    (no push protection), no SECURITY.md
        RepoProfile {
            name: "infra-terraform",
            description: "Private IaC, partial CODEOWNERS, detection-only scanning",
            posture: RepositoryPosture {
                codeowners_entries: vec![
                    CodeownersEntry {
                        pattern: "/modules/".to_string(),
                        owners: vec!["@org/platform-team".to_string()],
                    },
                    CodeownersEntry {
                        pattern: "/environments/".to_string(),
                        owners: vec!["@org/sre-team".to_string()],
                    },
                ],
                secret_scanning_enabled: true,
                secret_push_protection_enabled: false,
                vulnerability_scanning_enabled: false,
                code_scanning_enabled: false,
                security_policy_present: false,
                security_policy_has_disclosure: false,
                default_branch_protected: false,
                enforce_admins: false,
                dismiss_stale_reviews: false,
                ..Default::default()
            },
        },
        // 4. archived-legacy: no scanning, no CODEOWNERS, no policy
        RepoProfile {
            name: "archived-legacy",
            description: "Unmaintained legacy service, no controls",
            posture: RepositoryPosture {
                codeowners_entries: vec![],
                secret_scanning_enabled: false,
                secret_push_protection_enabled: false,
                vulnerability_scanning_enabled: false,
                code_scanning_enabled: false,
                security_policy_present: false,
                security_policy_has_disclosure: false,
                default_branch_protected: false,
                enforce_admins: false,
                dismiss_stale_reviews: false,
                ..Default::default()
            },
        },
        // 5. new-microservice: Dependabot only, basic SECURITY.md, 3 CODEOWNERS entries
        RepoProfile {
            name: "new-microservice",
            description: "New service, Dependabot + ownership, basic policy",
            posture: RepositoryPosture {
                codeowners_entries: vec![
                    CodeownersEntry {
                        pattern: "/src/".to_string(),
                        owners: vec!["@org/backend-team".to_string()],
                    },
                    CodeownersEntry {
                        pattern: "/deploy/".to_string(),
                        owners: vec!["@org/platform-team".to_string()],
                    },
                    CodeownersEntry {
                        pattern: "/.github/".to_string(),
                        owners: vec!["@org/devops".to_string()],
                    },
                ],
                secret_scanning_enabled: false,
                secret_push_protection_enabled: false,
                vulnerability_scanning_enabled: true, // Dependabot
                code_scanning_enabled: false,
                security_policy_present: true,
                security_policy_has_disclosure: false, // basic, no disclosure process
                default_branch_protected: false,
                enforce_admins: false,
                dismiss_stale_reviews: false,
                ..Default::default()
            },
        },
    ]
}

// ---------------------------------------------------------------------------
// Assessment logic
// ---------------------------------------------------------------------------

fn aspm_controls() -> Vec<Box<dyn Control>> {
    vec![
        Box::new(CodeownersCoverageControl),
        Box::new(SecretScanningControl),
        Box::new(VulnerabilityScanningControl),
        Box::new(SecurityPolicyControl),
    ]
}

struct RepoAssessment {
    name: &'static str,
    description: &'static str,
    pass: u32,
    review: u32,
    fail: u32,
    details: Vec<(String, GateDecision, String)>, // (control_id, decision, rationale)
}

fn assess_repo(profile: &RepoProfile, soc2: &OpaProfile) -> RepoAssessment {
    let bundle = EvidenceBundle {
        repository_posture: EvidenceState::complete(profile.posture.clone()),
        ..Default::default()
    };

    let controls = aspm_controls();
    let findings: Vec<ControlFinding> = evaluate_all(&controls, &bundle);
    let outcomes = apply_profile(soc2, &findings);

    let mut pass = 0u32;
    let mut review = 0u32;
    let mut fail = 0u32;
    let mut details = Vec::new();

    for outcome in &outcomes {
        match outcome.decision {
            GateDecision::Pass => pass += 1,
            GateDecision::Review => review += 1,
            GateDecision::Fail => fail += 1,
        }
        details.push((
            outcome.control_id.to_string(),
            outcome.decision,
            outcome.rationale.clone(),
        ));
    }

    RepoAssessment {
        name: profile.name,
        description: profile.description,
        pass,
        review,
        fail,
        details,
    }
}

// ---------------------------------------------------------------------------
// Output formatting
// ---------------------------------------------------------------------------

fn risk_score(a: &RepoAssessment) -> u32 {
    // Fail=3, Review=1, Pass=0 — higher is worse
    a.fail * 3 + a.review
}

fn risk_tier(score: u32) -> &'static str {
    match score {
        0 => "COMPLIANT",
        1..=3 => "LOW",
        4..=6 => "MEDIUM",
        7..=9 => "HIGH",
        _ => "CRITICAL",
    }
}

fn decision_symbol(d: GateDecision) -> &'static str {
    match d {
        GateDecision::Pass => "PASS",
        GateDecision::Review => "REVIEW",
        GateDecision::Fail => "FAIL",
    }
}

fn main() {
    let soc2 = OpaProfile::from_preset_or_file("soc2").expect("SOC2 preset should load");
    let profiles = repo_profiles();

    let mut assessments: Vec<RepoAssessment> =
        profiles.iter().map(|p| assess_repo(p, &soc2)).collect();

    // Sort by risk score descending (worst first)
    assessments.sort_by(|a, b| risk_score(b).cmp(&risk_score(a)));

    // ---- Fleet Summary Table ----
    println!("==========================================================================");
    println!("  FLEET-WIDE ASPM ASSESSMENT — SOC2 Preset (4 ASPM Controls x 5 Repos)");
    println!("==========================================================================");
    println!();
    println!(
        "  {:<20} {:>4}  {:>6}  {:>4}  {:>5}  {:<10}",
        "Repository", "Pass", "Review", "Fail", "Score", "Risk Tier"
    );
    println!(
        "  {:-<20} {:->4}  {:->6}  {:->4}  {:->5}  {:-<10}",
        "", "", "", "", "", ""
    );

    for a in &assessments {
        let score = risk_score(a);
        println!(
            "  {:<20} {:>4}  {:>6}  {:>4}  {:>5}  {:<10}",
            a.name,
            a.pass,
            a.review,
            a.fail,
            score,
            risk_tier(score),
        );
    }

    // ---- Fleet Totals ----
    let total_pass: u32 = assessments.iter().map(|a| a.pass).sum();
    let total_review: u32 = assessments.iter().map(|a| a.review).sum();
    let total_fail: u32 = assessments.iter().map(|a| a.fail).sum();
    let total = total_pass + total_review + total_fail;

    println!();
    println!(
        "  Fleet totals: {} pass / {} review / {} fail out of {} checks",
        total_pass, total_review, total_fail, total
    );
    println!(
        "  Fleet pass rate: {:.0}%",
        if total > 0 {
            (total_pass as f64 / total as f64) * 100.0
        } else {
            0.0
        }
    );

    // ---- Per-Repo Detail ----
    println!();
    println!("==========================================================================");
    println!("  PER-REPO FINDINGS (ordered by risk, worst first)");
    println!("==========================================================================");

    for a in &assessments {
        let score = risk_score(a);
        println!();
        println!(
            "  [{:<10}] {} — {}",
            risk_tier(score),
            a.name,
            a.description
        );

        for (control_id, decision, rationale) in &a.details {
            let symbol = decision_symbol(*decision);
            println!("    {:<6}  {:<26}  {}", symbol, control_id, rationale);
        }
    }

    // ---- Actionable Remediation Priorities ----
    println!();
    println!("==========================================================================");
    println!("  REMEDIATION PRIORITIES");
    println!("==========================================================================");
    println!();

    // Collect all failures across fleet, grouped by control
    let control_ids = [
        builtin::CODEOWNERS_COVERAGE,
        builtin::SECRET_SCANNING,
        builtin::VULNERABILITY_SCANNING,
        builtin::SECURITY_POLICY,
    ];

    for cid in &control_ids {
        let failing_repos: Vec<&str> = assessments
            .iter()
            .filter(|a| {
                a.details
                    .iter()
                    .any(|(id, d, _)| id == *cid && *d == GateDecision::Fail)
            })
            .map(|a| a.name)
            .collect();

        let review_repos: Vec<&str> = assessments
            .iter()
            .filter(|a| {
                a.details
                    .iter()
                    .any(|(id, d, _)| id == *cid && *d == GateDecision::Review)
            })
            .map(|a| a.name)
            .collect();

        if !failing_repos.is_empty() || !review_repos.is_empty() {
            println!("  {}", cid);
            if !failing_repos.is_empty() {
                println!(
                    "    FAIL ({} repos):   {}",
                    failing_repos.len(),
                    failing_repos.join(", ")
                );
            }
            if !review_repos.is_empty() {
                println!(
                    "    REVIEW ({} repos): {}",
                    review_repos.len(),
                    review_repos.join(", ")
                );
            }
            println!();
        }
    }

    // ---- Worst Repo Call-out ----
    if let Some(worst) = assessments.first() {
        let score = risk_score(worst);
        println!(
            "  Worst-posture repo: {} (score={}, tier={})",
            worst.name,
            score,
            risk_tier(score)
        );
        println!("  Recommended: prioritize enabling secret scanning and CODEOWNERS");
        println!("  for repos in CRITICAL/HIGH tiers before next SOC2 audit window.");
    }

    println!();
}
