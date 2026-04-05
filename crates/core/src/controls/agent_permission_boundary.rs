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
            EvidenceState::NotApplicable => {
                return vec![ControlFinding::not_applicable(
                    id,
                    "Agent action log not applicable",
                )];
            }
            EvidenceState::Missing { gaps } => {
                return vec![ControlFinding::indeterminate(
                    id,
                    "Agent action log evidence is missing",
                    vec![],
                    gaps.clone(),
                )];
            }
            EvidenceState::Complete { value } | EvidenceState::Partial { value, .. } => value,
        };

        let spec = match &evidence.agent_spec {
            EvidenceState::NotApplicable => {
                return vec![ControlFinding::not_applicable(
                    id,
                    "Agent spec not applicable",
                )];
            }
            EvidenceState::Missing { gaps } => {
                return vec![ControlFinding::indeterminate(
                    id,
                    "Agent spec evidence is missing",
                    vec![],
                    gaps.clone(),
                )];
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
                .map(|(cmd, reason)| format!("action '{cmd}': {reason}"))
                .collect();
            vec![ControlFinding::violated(
                id,
                format!("{} permission violation(s) detected", violations.len()),
                subjects,
            )]
        }
    }
}

/// Returns (command, violation_reason) pairs for actions that exceed granted permissions.
fn find_permission_violations<'a>(
    log: &'a AgentActionLog,
    spec: &'a AgentSpec,
) -> Vec<(&'a str, String)> {
    log.actions
        .iter()
        .filter_map(|action| match action.required_permission.as_deref() {
            Some(perm) => {
                if spec.granted_permissions.iter().any(|g| g == perm) {
                    None
                } else {
                    Some((
                        action.command.as_str(),
                        format!("requires '{perm}' but not granted"),
                    ))
                }
            }
            None => {
                if spec.deny_unpermissioned_actions {
                    Some((
                        action.command.as_str(),
                        "no permission declared (deny_unpermissioned_actions is enabled)"
                            .to_string(),
                    ))
                } else {
                    None
                }
            }
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

    fn spec_with(permissions: Vec<&str>) -> AgentSpec {
        AgentSpec {
            allowed_paths: vec![],
            forbidden_paths: vec![],
            allowed_tools: vec![],
            granted_permissions: permissions.into_iter().map(String::from).collect(),
            max_steps: None,
            budget_cents: None,
            custom_destructive_patterns: vec![],
            deny_unpermissioned_actions: false,
        }
    }

    fn bundle_with(log: EvidenceState<AgentActionLog>, spec: AgentSpec) -> EvidenceBundle {
        EvidenceBundle {
            agent_action_log: log,
            agent_spec: EvidenceState::complete(spec),
            ..Default::default()
        }
    }

    #[test]
    fn satisfied_when_all_actions_within_permissions() {
        let evidence = bundle_with(
            log_with(vec![
                action("git pull", Some("read:repo")),
                action("cat file.rs", Some("read:file")),
            ]),
            spec_with(vec!["read:repo", "read:file"]),
        );
        let findings = AgentPermissionBoundaryControl.evaluate(&evidence);
        assert_eq!(findings[0].status, ControlStatus::Satisfied);
    }

    #[test]
    fn violated_when_action_requires_ungranted_permission() {
        let evidence = bundle_with(
            log_with(vec![action("DROP TABLE", Some("write:db"))]),
            spec_with(vec!["read:repo"]),
        );
        let findings = AgentPermissionBoundaryControl.evaluate(&evidence);
        assert_eq!(findings[0].status, ControlStatus::Violated);
        assert!(findings[0].subjects[0].contains("write:db"));
    }

    #[test]
    fn violated_lists_all_violations() {
        let evidence = bundle_with(
            log_with(vec![
                action("DROP TABLE", Some("write:db")),
                action("rm -rf /", Some("execute:shell")),
                action("git pull", Some("read:repo")),
            ]),
            spec_with(vec!["read:repo"]),
        );
        let findings = AgentPermissionBoundaryControl.evaluate(&evidence);
        assert_eq!(findings[0].status, ControlStatus::Violated);
        assert_eq!(findings[0].subjects.len(), 2);
    }

    #[test]
    fn actions_without_required_permission_pass_by_default() {
        let evidence = bundle_with(
            log_with(vec![action("echo hello", None), action("pwd", None)]),
            spec_with(vec![]),
        );
        let findings = AgentPermissionBoundaryControl.evaluate(&evidence);
        assert_eq!(findings[0].status, ControlStatus::Satisfied);
    }

    #[test]
    fn deny_unpermissioned_actions_flag_rejects_unlabeled() {
        let mut spec = spec_with(vec!["read:repo"]);
        spec.deny_unpermissioned_actions = true;
        let evidence = bundle_with(
            log_with(vec![
                action("git pull", Some("read:repo")),
                action("echo hello", None),
            ]),
            spec,
        );
        let findings = AgentPermissionBoundaryControl.evaluate(&evidence);
        assert_eq!(findings[0].status, ControlStatus::Violated);
        assert!(findings[0].subjects[0].contains("deny_unpermissioned_actions"));
    }

    #[test]
    fn deny_unpermissioned_actions_all_labeled_passes() {
        let mut spec = spec_with(vec!["read:repo"]);
        spec.deny_unpermissioned_actions = true;
        let evidence = bundle_with(log_with(vec![action("git pull", Some("read:repo"))]), spec);
        let findings = AgentPermissionBoundaryControl.evaluate(&evidence);
        assert_eq!(findings[0].status, ControlStatus::Satisfied);
    }

    #[test]
    fn satisfied_when_empty_action_log() {
        let evidence = bundle_with(log_with(vec![]), spec_with(vec!["read:repo"]));
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
            agent_spec: EvidenceState::complete(spec_with(vec!["read:repo"])),
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
                source: "config".to_string(),
                subject: "agent-spec".to_string(),
                detail: "not found".to_string(),
            }]),
            ..Default::default()
        };
        let findings = AgentPermissionBoundaryControl.evaluate(&evidence);
        assert_eq!(findings[0].status, ControlStatus::Indeterminate);
    }

    #[test]
    fn not_applicable_when_action_log_not_applicable() {
        let evidence = EvidenceBundle {
            agent_action_log: EvidenceState::not_applicable(),
            agent_spec: EvidenceState::complete(spec_with(vec![])),
            ..Default::default()
        };
        let findings = AgentPermissionBoundaryControl.evaluate(&evidence);
        assert_eq!(findings[0].status, ControlStatus::NotApplicable);
    }
}
