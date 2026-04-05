//! Convenience API for AI-ops (agent-driven) verification.
//!
//! Provides a high-level function that builds evidence, selects controls,
//! and evaluates — reducing integration from ~40 lines to ~5.

use crate::assessment::AssessmentReport;
use crate::control::evaluate_all;
use crate::controls::aiops_controls;
use crate::evidence::*;
use crate::profile::{ControlProfile, apply_profile};

/// Input for a single agent action (simplified builder input).
pub struct ActionInput {
    pub tool: String,
    pub command: String,
}

/// High-level input for assessing an agent session.
pub struct SessionInput {
    pub agent_id: String,
    pub session_id: String,
    pub actions: Vec<ActionInput>,
    pub spec: AgentSpec,
    pub files_touched: Vec<String>,
    pub tools_used: Vec<String>,
    pub steps_taken: u32,
    pub cost_cents: u32,
    pub check_runs: Vec<CheckRunEvidence>,
    pub privileged_events: Vec<PrivilegedGitEvent>,
}

/// Build an `EvidenceBundle` from agent session input.
pub fn build_evidence(input: &SessionInput) -> EvidenceBundle {
    let actions: Vec<AgentAction> = input
        .actions
        .iter()
        .map(|a| AgentAction {
            tool: a.tool.clone(),
            command: a.command.clone(),
            timestamp: None,
        })
        .collect();

    let action_log = AgentActionLog {
        agent_id: input.agent_id.clone(),
        session_id: input.session_id.clone(),
        actions,
    };

    let execution = AgentExecution {
        agent_id: input.agent_id.clone(),
        session_id: input.session_id.clone(),
        files_touched: input.files_touched.clone(),
        tools_used: input.tools_used.clone(),
        steps_taken: input.steps_taken,
        cost_cents: input.cost_cents,
    };

    EvidenceBundle {
        check_runs: if input.check_runs.is_empty() {
            EvidenceState::not_applicable()
        } else {
            EvidenceState::complete(input.check_runs.clone())
        },
        agent_action_log: EvidenceState::complete(action_log),
        agent_spec: EvidenceState::complete(input.spec.clone()),
        agent_execution: EvidenceState::complete(execution),
        privileged_git_events: if input.privileged_events.is_empty() {
            EvidenceState::complete(vec![])
        } else {
            EvidenceState::complete(input.privileged_events.clone())
        },
        ..Default::default()
    }
}

/// Assess an agent session against AI-ops controls.
///
/// Returns findings from the 2 AI-ops controls
/// (agent-spec-conformance, privileged-operation-audit).
///
/// Use with an OPA profile for gate decisions:
/// ```ignore
/// let report = assess_session(&input, &profile);
/// ```
pub fn assess_session(input: &SessionInput, profile: &dyn ControlProfile) -> AssessmentReport {
    let evidence = build_evidence(input);
    let controls = aiops_controls();
    let findings = evaluate_all(&controls, &evidence);
    let outcomes = apply_profile(profile, &findings);
    let severity_labels = profile.severity_labels();

    AssessmentReport {
        profile_name: "aiops".to_string(),
        findings,
        outcomes,
        severity_labels,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::control::ControlStatus;
    use crate::profile::{FindingSeverity, GateDecision, ProfileOutcome, SeverityLabels};

    /// Minimal pass-through profile for testing.
    struct TestProfile;
    impl ControlProfile for TestProfile {
        fn name(&self) -> &str {
            "test"
        }
        fn map(&self, finding: &crate::control::ControlFinding) -> ProfileOutcome {
            let (severity, decision) = match finding.status {
                ControlStatus::Satisfied => (FindingSeverity::Info, GateDecision::Pass),
                ControlStatus::Violated => (FindingSeverity::Error, GateDecision::Fail),
                ControlStatus::Indeterminate => (FindingSeverity::Warning, GateDecision::Review),
                ControlStatus::NotApplicable => (FindingSeverity::Info, GateDecision::Pass),
            };
            ProfileOutcome {
                control_id: finding.control_id.clone(),
                severity,
                decision,
                rationale: finding.rationale.clone(),
                annotations: Default::default(),
            }
        }
        fn severity_labels(&self) -> SeverityLabels {
            SeverityLabels::default()
        }
    }

    #[test]
    fn happy_path_all_pass() {
        let input = SessionInput {
            agent_id: "agent-1".into(),
            session_id: "sess-1".into(),
            actions: vec![
                ActionInput {
                    tool: "cargo".into(),
                    command: "cargo build".into(),
                },
                ActionInput {
                    tool: "cargo".into(),
                    command: "cargo test".into(),
                },
            ],
            spec: AgentSpec {
                allowed_paths: vec!["src/*".into()],
                forbidden_paths: vec![".env".into()],
                allowed_tools: vec!["cargo".into()],
                max_steps: Some(100),
                budget_cents: Some(5000),
                ..Default::default()
            },
            files_touched: vec!["src/main.rs".into()],
            tools_used: vec!["cargo".into()],
            steps_taken: 10,
            cost_cents: 500,
            check_runs: vec![
                CheckRunEvidence {
                    name: "ci/build".into(),
                    conclusion: CheckConclusion::Success,
                    app_slug: None,
                },
                CheckRunEvidence {
                    name: "ci/test".into(),
                    conclusion: CheckConclusion::Success,
                    app_slug: None,
                },
                CheckRunEvidence {
                    name: "ci/lint".into(),
                    conclusion: CheckConclusion::Success,
                    app_slug: None,
                },
                CheckRunEvidence {
                    name: "ci/typecheck".into(),
                    conclusion: CheckConclusion::Success,
                    app_slug: None,
                },
            ],
            privileged_events: vec![],
        };

        let report = assess_session(&input, &TestProfile);
        let pass_count = report
            .outcomes
            .iter()
            .filter(|o| o.decision == GateDecision::Pass)
            .count();
        assert_eq!(pass_count, 2, "All 2 AI-ops controls should pass");
    }

    #[test]
    fn rogue_agent_all_fail() {
        let input = SessionInput {
            agent_id: "rogue".into(),
            session_id: "evil-sess".into(),
            actions: vec![ActionInput {
                tool: "shell".into(),
                command: "rm -rf /".into(),
            }],
            spec: AgentSpec {
                allowed_paths: vec!["src/*".into()],
                forbidden_paths: vec![".env".into()],
                allowed_tools: vec!["cargo".into()],
                max_steps: Some(10),
                budget_cents: Some(100),
                ..Default::default()
            },
            files_touched: vec![".env".into()],
            tools_used: vec!["shell".into()],
            steps_taken: 50,
            cost_cents: 500,
            check_runs: vec![],
            privileged_events: vec![],
        };

        let report = assess_session(&input, &TestProfile);
        let fail_count = report
            .outcomes
            .iter()
            .filter(|o| o.decision == GateDecision::Fail)
            .count();
        // spec-conformance should fail (forbidden paths, unauthorized tools, over budget/steps)
        // privileged-operation-audit: empty privileged_events + rm -rf in action log -> Violated
        assert!(
            fail_count >= 2,
            "Both AI-ops controls should fail, got {fail_count}"
        );
    }

    #[test]
    fn build_evidence_includes_check_runs() {
        let input = SessionInput {
            agent_id: "a".into(),
            session_id: "s".into(),
            actions: vec![],
            spec: AgentSpec::default(),
            files_touched: vec![],
            tools_used: vec![],
            steps_taken: 0,
            cost_cents: 0,
            check_runs: vec![CheckRunEvidence {
                name: "ci/build".into(),
                conclusion: CheckConclusion::Success,
                app_slug: None,
            }],
            privileged_events: vec![],
        };
        let evidence = build_evidence(&input);
        let runs = evidence
            .check_runs
            .value()
            .expect("check_runs should be Complete");
        assert_eq!(runs.len(), 1);
        assert_eq!(runs[0].name, "ci/build");
    }

    #[test]
    fn build_evidence_empty_check_runs_is_not_applicable() {
        let input = SessionInput {
            agent_id: "a".into(),
            session_id: "s".into(),
            actions: vec![],
            spec: AgentSpec::default(),
            files_touched: vec![],
            tools_used: vec![],
            steps_taken: 0,
            cost_cents: 0,
            check_runs: vec![],
            privileged_events: vec![],
        };
        let evidence = build_evidence(&input);
        assert!(
            evidence.check_runs.value().is_none(),
            "empty check_runs should be NotApplicable"
        );
    }

    #[test]
    fn build_evidence_includes_privileged_events() {
        use crate::evidence::{PrivilegedAction, PrivilegedGitEvent};
        let input = SessionInput {
            agent_id: "a".into(),
            session_id: "s".into(),
            actions: vec![],
            spec: AgentSpec::default(),
            files_touched: vec![],
            tools_used: vec![],
            steps_taken: 0,
            cost_cents: 0,
            check_runs: vec![],
            privileged_events: vec![PrivilegedGitEvent {
                actor: "bot".into(),
                action: PrivilegedAction::ForcePush,
                branch: Some("main".into()),
                tag: None,
                timestamp: None,
                commit_sha: None,
                detail: None,
            }],
        };
        let evidence = build_evidence(&input);
        let events = evidence
            .privileged_git_events
            .value()
            .expect("events should be Complete");
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].action, PrivilegedAction::ForcePush);
    }
}
