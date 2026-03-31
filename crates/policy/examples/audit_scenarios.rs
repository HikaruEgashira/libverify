//! SOC2 Type II audit edge-case scenarios.
//!
//! Tests five boundary conditions that a security auditor probes during
//! examination, then runs each finding through both the OSS and SOC2 policy
//! presets to verify differentiated gate decisions.
//!
//! Run: cargo run -p libverify-policy --example audit_scenarios

use libverify_core::control::{Control, ControlStatus};
use libverify_core::controls::codeowners_coverage::CodeownersCoverageControl;
use libverify_core::controls::secret_scanning::SecretScanningControl;
use libverify_core::controls::security_policy::SecurityPolicyControl;
use libverify_core::controls::vulnerability_scanning::VulnerabilityScanningControl;
use libverify_core::evidence::{CodeownersEntry, EvidenceBundle, EvidenceState, RepositoryPosture};
use libverify_core::profile::{ControlProfile, GateDecision};
use libverify_policy::OpaProfile;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn default_posture() -> RepositoryPosture {
    RepositoryPosture {
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
    }
}

fn bundle_from_posture(posture: RepositoryPosture) -> EvidenceBundle {
    EvidenceBundle {
        repository_posture: EvidenceState::complete(posture),
        ..Default::default()
    }
}

fn entry(pattern: &str, owners: &[&str]) -> CodeownersEntry {
    CodeownersEntry {
        pattern: pattern.to_string(),
        owners: owners.iter().map(|s| s.to_string()).collect(),
    }
}

// ---------------------------------------------------------------------------
// Scenario runner
// ---------------------------------------------------------------------------

struct ScenarioResult {
    name: &'static str,
    expected_status: ControlStatus,
    actual_status: ControlStatus,
    rationale: String,
    subjects: Vec<String>,
    oss_decision: GateDecision,
    soc2_decision: GateDecision,
}

fn run_scenario(
    name: &'static str,
    control: &dyn Control,
    bundle: &EvidenceBundle,
    expected_status: ControlStatus,
    oss: &dyn ControlProfile,
    soc2: &dyn ControlProfile,
) -> ScenarioResult {
    let findings = control.evaluate(bundle);
    let finding = &findings[0];
    let oss_outcome = oss.map(finding);
    let soc2_outcome = soc2.map(finding);

    ScenarioResult {
        name,
        expected_status,
        actual_status: finding.status,
        rationale: finding.rationale.clone(),
        subjects: finding.subjects.clone(),
        oss_decision: oss_outcome.decision,
        soc2_decision: soc2_outcome.decision,
    }
}

// ---------------------------------------------------------------------------
// Main
// ---------------------------------------------------------------------------

fn main() {
    let oss = OpaProfile::from_preset_or_file("oss").expect("oss preset");
    let soc2 = OpaProfile::from_preset_or_file("soc2").expect("soc2 preset");

    let secret_ctrl = SecretScanningControl;
    let codeowners_ctrl = CodeownersCoverageControl;
    let vuln_ctrl = VulnerabilityScanningControl;
    let secpol_ctrl = SecurityPolicyControl;

    // --- Scenario A: secret scanning ON, push protection OFF ---
    // Expected: Satisfied with "detection" tier (not "prevention")
    let mut posture_a = default_posture();
    posture_a.secret_scanning_enabled = true;
    posture_a.secret_push_protection_enabled = false;
    let bundle_a = bundle_from_posture(posture_a);

    // --- Scenario B: CODEOWNERS with exactly 2 entries (below threshold of 3) ---
    // Expected: Violated (insufficient targeted coverage)
    let mut posture_b = default_posture();
    posture_b.codeowners_entries = vec![
        entry("/src/auth/", &["@org/security"]),
        entry("/infra/", &["@org/platform"]),
    ];
    let bundle_b = bundle_from_posture(posture_b);

    // --- Scenario C: CODEOWNERS with exactly 3 targeted entries (at threshold) ---
    // Expected: Satisfied (intentional targeted coverage)
    let mut posture_c = default_posture();
    posture_c.codeowners_entries = vec![
        entry("/src/auth/", &["@org/security"]),
        entry("/infra/", &["@org/platform"]),
        entry("/.github/", &["@org/devops"]),
    ];
    let bundle_c = bundle_from_posture(posture_c);

    // --- Scenario D: vulnerability scanning ON, code scanning OFF ---
    // Expected: Satisfied with "sca-only" tier (not "sca+sast")
    let mut posture_d = default_posture();
    posture_d.vulnerability_scanning_enabled = true;
    posture_d.code_scanning_enabled = false;
    let bundle_d = bundle_from_posture(posture_d);

    // --- Scenario E: SECURITY.md present but no disclosure process ---
    // Expected: Violated (policy exists but incomplete)
    let mut posture_e = default_posture();
    posture_e.security_policy_present = true;
    posture_e.security_policy_has_disclosure = false;
    let bundle_e = bundle_from_posture(posture_e);

    let results = vec![
        run_scenario(
            "A: Secret scanning ON, push protection OFF",
            &secret_ctrl,
            &bundle_a,
            ControlStatus::Satisfied,
            &oss,
            &soc2,
        ),
        run_scenario(
            "B: CODEOWNERS 2 entries (below threshold)",
            &codeowners_ctrl,
            &bundle_b,
            ControlStatus::Violated,
            &oss,
            &soc2,
        ),
        run_scenario(
            "C: CODEOWNERS 3 entries (at threshold)",
            &codeowners_ctrl,
            &bundle_c,
            ControlStatus::Satisfied,
            &oss,
            &soc2,
        ),
        run_scenario(
            "D: Vuln scanning ON, code scanning OFF",
            &vuln_ctrl,
            &bundle_d,
            ControlStatus::Satisfied,
            &oss,
            &soc2,
        ),
        run_scenario(
            "E: SECURITY.md present, no disclosure",
            &secpol_ctrl,
            &bundle_e,
            ControlStatus::Violated,
            &oss,
            &soc2,
        ),
    ];

    // --- Report ---
    println!("=== SOC2 Type II Audit Edge-Case Scenarios ===\n");

    let mut all_pass = true;
    for r in &results {
        let status_ok = r.actual_status == r.expected_status;
        let marker = if status_ok { "PASS" } else { "FAIL" };
        if !status_ok {
            all_pass = false;
        }

        println!("--- {} ---", r.name);
        println!(
            "  Status:    {} (expected: {}) [{}]",
            r.actual_status, r.expected_status, marker
        );
        println!("  Rationale: {}", r.rationale);
        println!("  Subjects:  {:?}", r.subjects);
        println!(
            "  OSS decision:  {:?}   SOC2 decision: {:?}",
            r.oss_decision, r.soc2_decision
        );
        println!();
    }

    // --- Policy differentiation summary ---
    println!("=== Policy Differentiation Summary ===\n");
    for r in &results {
        let diff = if r.oss_decision != r.soc2_decision {
            format!(
                "DIFFER (OSS={:?}, SOC2={:?})",
                r.oss_decision, r.soc2_decision
            )
        } else {
            format!("SAME ({:?})", r.oss_decision)
        };
        println!("  {}: {}", r.name, diff);
    }

    // --- Tiered subject verification ---
    println!("\n=== Tiered Subject Verification ===\n");
    let tier_checks: &[(&str, &str, usize)] = &[
        ("A: detection tier", "detection", 0),
        ("D: sca-only tier", "sca-only", 3),
    ];
    for (label, needle, idx) in tier_checks {
        let found = results[*idx].subjects.iter().any(|s| s.contains(needle));
        let mark = if found { "PRESENT" } else { "MISSING" };
        println!("  {}: '{}' -> [{}]", label, needle, mark);
    }

    println!();
    if all_pass {
        println!("All scenarios produced the expected control status.");
    } else {
        println!("WARNING: Some scenarios did NOT match expected status.");
        std::process::exit(1);
    }
}
