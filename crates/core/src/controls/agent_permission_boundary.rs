use crate::control::{Control, ControlFinding, ControlId, builtin};
use crate::evidence::{AgentActionLog, AgentSpec, EvidenceBundle, EvidenceState};

pub struct AgentPermissionBoundaryControl;

impl Control for AgentPermissionBoundaryControl {
    fn id(&self) -> ControlId {
        builtin::id(builtin::AGENT_PERMISSION_BOUNDARY)
    }

    fn description(&self) -> &'static str {
        "Agent must operate within granted permissions"
    }

    fn evaluate(&self, evidence: &EvidenceBundle) -> Vec<ControlFinding> {
        let id = self.id();

        let log = match &evidence.agent_action_log {
            EvidenceState::NotApplicable => return vec![ControlFinding::not_applicable(id, "Agent action log not applicable")],
            EvidenceState::Missing { gaps } => {
                return vec![ControlFinding::indeterminate(id, "Agent action log evidence is missing", vec![], gaps.clone())];
            }
            EvidenceState::Complete { value } | EvidenceState::Partial { value, .. } => value,
        };

        let spec = match &evidence.agent_spec {
            EvidenceState::NotApplicable => return vec![ControlFinding::not_applicable(id, "Agent spec not applicable")],
            EvidenceState::Missing { gaps } => {
                return vec![ControlFinding::indeterminate(id, "Agent spec evidence is missing", vec![], gaps.clone())];
            }
            EvidenceState::Complete { value } | EvidenceState::Partial { value, .. } => value,
        };

        let violations = find_permission_violations(log, spec);

        if violations.is_empty() {
            vec![ControlFinding::satisfied(
                id,
                "All agent actions operated within granted permissions",
                vec![],
            )]
        } else {
            let subjects: Vec<String> = violations
                .iter()
                .map(|(cmd, perm)| format!("action '{cmd}' requires '{perm}' but not granted"))
                .collect();
            vec![ControlFinding::violated(
                id,
                format!("{} permission violation(s) detected", violations.len()),
                subjects,
            )]
        }
    }
}

/// Returns (command, required_permission) pairs for actions that exceed granted permissions.
fn find_permission_violations<'a>(
    log: &'a AgentActionLog,
    spec: &'a AgentSpec,
) -> Vec<(&'a str, &'a str)> {
    log.actions
        .iter()
        .filter_map(|action| {
            action.required_permission.as_deref().and_then(|perm| {
                if spec.granted_permissions.iter().any(|g| g == perm) {
                    None
                } else {
                    Some((action.command.as_str(), perm))
                }
            })
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::control::ControlStatus;
    use crate::evidence::{AgentAction, EvidenceGap};

    fn action(command: &str, perm: Option<&str>) -> AgentAction {
        AgentAction {
            tool: "test-tool".to_string(),
            command: command.to_string(),
            timestamp: None,
            required_permission: perm.map(String::from),
        }
    }

    fn log_with(actions: Vec<AgentAction>) -> EvidenceState<AgentActionLog> {
        EvidenceState::complete(AgentActionLog {
            agent_id: "agent-1".to_string(),
            session_id: "session-1".to_string(),
            actions,
        })
    }

    fn spec_with(permissions: Vec<&str>) -> EvidenceState<AgentSpec> {
        EvidenceState::complete(AgentSpec {
            allowed_paths: vec![],
            forbidden_paths: vec![],
            allowed_tools: vec![],
            granted_permissions: permissions.into_iter().map(String::from).collect(),
            max_steps: None,
            budget_cents: None,
        })
    }

    #[test]
    fn satisfied_when_all_actions_within_permissions() {
        let evidence = EvidenceBundle {
            agent_action_log: log_with(vec![
                action("git pull", Some("read:repo")),
                action("cat file.rs", Some("read:file")),
            ]),
            agent_spec: spec_with(vec!["read:repo", "read:file"]),
            ..Default::default()
        };
        let findings = AgentPermissionBoundaryControl.evaluate(&evidence);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].status, ControlStatus::Satisfied);
    }

    #[test]
    fn violated_when_action_requires_ungranted_permission() {
        let evidence = EvidenceBundle {
            agent_action_log: log_with(vec![action("DROP TABLE", Some("write:db"))]),
            agent_spec: spec_with(vec!["read:repo"]),
            ..Default::default()
        };
        let findings = AgentPermissionBoundaryControl.evaluate(&evidence);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].status, ControlStatus::Violated);
        assert!(findings[0].subjects[0].contains("write:db"));
        assert!(findings[0].subjects[0].contains("DROP TABLE"));
    }

    #[test]
    fn violated_lists_all_violations() {
        let evidence = EvidenceBundle {
            agent_action_log: log_with(vec![
                action("DROP TABLE", Some("write:db")),
                action("rm -rf /", Some("execute:shell")),
                action("git pull", Some("read:repo")),
            ]),
            agent_spec: spec_with(vec!["read:repo"]),
            ..Default::default()
        };
        let findings = AgentPermissionBoundaryControl.evaluate(&evidence);
        assert_eq!(findings[0].status, ControlStatus::Violated);
        assert_eq!(findings[0].subjects.len(), 2);
        assert!(findings[0].subjects.iter().any(|s| s.contains("write:db")));
        assert!(findings[0].subjects.iter().any(|s| s.contains("execute:shell")));
    }

    #[test]
    fn actions_without_required_permission_always_pass() {
        let evidence = EvidenceBundle {
            agent_action_log: log_with(vec![
                action("echo hello", None),
                action("pwd", None),
            ]),
            agent_spec: spec_with(vec![]),
            ..Default::default()
        };
        let findings = AgentPermissionBoundaryControl.evaluate(&evidence);
        assert_eq!(findings[0].status, ControlStatus::Satisfied);
    }

    #[test]
    fn satisfied_when_empty_action_log() {
        let evidence = EvidenceBundle {
            agent_action_log: log_with(vec![]),
            agent_spec: spec_with(vec!["read:repo"]),
            ..Default::default()
        };
        let findings = AgentPermissionBoundaryControl.evaluate(&evidence);
        assert_eq!(findings[0].status, ControlStatus::Satisfied);
    }

    #[test]
    fn indeterminate_when_action_log_missing() {
        let evidence = EvidenceBundle {
            agent_action_log: EvidenceState::missing(vec![EvidenceGap::CollectionFailed {
                source: "agent".to_string(),
                subject: "action-log".to_string(),
                detail: "not collected".to_string(),
            }]),
            agent_spec: spec_with(vec!["read:repo"]),
            ..Default::default()
        };
        let findings = AgentPermissionBoundaryControl.evaluate(&evidence);
        assert_eq!(findings[0].status, ControlStatus::Indeterminate);
    }

    #[test]
    fn indeterminate_when_spec_missing() {
        let evidence = EvidenceBundle {
            agent_action_log: log_with(vec![action("git pull", Some("read:repo"))]),
            agent_spec: EvidenceState::missing(vec![EvidenceGap::CollectionFailed {
                source: "agent".to_string(),
                subject: "spec".to_string(),
                detail: "not collected".to_string(),
            }]),
            ..Default::default()
        };
        let findings = AgentPermissionBoundaryControl.evaluate(&evidence);
        assert_eq!(findings[0].status, ControlStatus::Indeterminate);
    }

    #[test]
    fn not_applicable_when_action_log_not_applicable() {
        let evidence = EvidenceBundle {
            agent_action_log: EvidenceState::NotApplicable,
            agent_spec: spec_with(vec!["read:repo"]),
            ..Default::default()
        };
        let findings = AgentPermissionBoundaryControl.evaluate(&evidence);
        assert_eq!(findings[0].status, ControlStatus::NotApplicable);
    }

    #[test]
    fn violated_with_mix_of_permitted_and_unpermitted() {
        let evidence = EvidenceBundle {
            agent_action_log: log_with(vec![
                action("git pull", Some("read:repo")),
                action("DROP TABLE", Some("write:db")),
                action("echo hello", None),
                action("rm -rf /", Some("execute:shell")),
            ]),
            agent_spec: spec_with(vec!["read:repo"]),
            ..Default::default()
        };
        let findings = AgentPermissionBoundaryControl.evaluate(&evidence);
        assert_eq!(findings[0].status, ControlStatus::Violated);
        assert_eq!(findings[0].subjects.len(), 2);
        // Only violations listed, not permitted actions
        assert!(findings[0].subjects.iter().all(|s| !s.contains("git pull")));
        assert!(findings[0].subjects.iter().all(|s| !s.contains("echo hello")));
    }
}
