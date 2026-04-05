use crate::control::{Control, ControlFinding, ControlId, builtin};
use crate::evidence::{EvidenceBundle, EvidenceState};

/// Patterns matched case-insensitively against agent action commands.
/// Users can extend via `AgentSpec.custom_destructive_patterns`.
pub const NOTABLE_COMMAND_PATTERNS: &[&str] = &[
    // Filesystem
    "rm -rf",
    "rm -r",
    "rm -fr",
    "shred ",
    "find / -delete",
    "find . -delete",
    // SQL
    "drop table",
    "drop database",
    "drop schema",
    "truncate table",
    "delete from",
    // Git history mutation
    "git push --force",
    "git push -f",
    "git reset --hard",
    "git push origin :",
    // Container/orchestration
    "kubectl delete",
    "kubectl drain",
    "helm uninstall",
    "helm delete",
    "docker rm",
    "docker system prune",
    "docker-compose down -v",
    // Infrastructure
    "terraform destroy",
    "pulumi destroy",
    // Cloud provider
    "aws s3 rm",
    "aws s3 rb",
    "aws ec2 terminate",
    "aws rds delete",
    "aws lambda delete",
    "gsutil rm",
    "gcloud compute instances delete",
    "az vm delete",
    "az storage blob delete",
    // System administration
    "chmod 000",
    "chmod -r 000",
    "iptables -f",
    "systemctl stop",
    "kill -9",
    "format c:",
];

/// Surfaces privileged operations from two evidence sources:
/// 1. Structured git events (force push, admin bypass, tag/branch deletion)
/// 2. Agent action log commands matched against notable patterns
///
/// This control does not enforce policy — it makes operations visible.
/// The OPA profile decides whether each finding is pass/review/fail.
pub struct PrivilegedOperationAuditControl;

impl Control for PrivilegedOperationAuditControl {
    fn id(&self) -> ControlId {
        builtin::id(builtin::PRIVILEGED_OPERATION_AUDIT)
    }

    fn description(&self) -> &'static str {
        "Privileged operations (force push, notable commands, admin bypass) must be audited"
    }

    fn evaluate(&self, evidence: &EvidenceBundle) -> Vec<ControlFinding> {
        let id = self.id();
        let mut subjects: Vec<String> = Vec::new();

        // --- Source 1: Structured git events ---
        let git_gaps = match &evidence.privileged_git_events {
            EvidenceState::Complete { value } => {
                for e in value {
                    let target = e
                        .branch
                        .as_deref()
                        .or(e.tag.as_deref())
                        .unwrap_or("unknown");
                    subjects.push(format!(
                        "{}: {} on {} by {}",
                        e.action.as_str(),
                        e.detail.as_deref().unwrap_or(""),
                        target,
                        e.actor
                    ));
                }
                false
            }
            EvidenceState::Partial { value, .. } => {
                for e in value {
                    let target = e
                        .branch
                        .as_deref()
                        .or(e.tag.as_deref())
                        .unwrap_or("unknown");
                    subjects.push(format!(
                        "{}: {} on {} by {}",
                        e.action.as_str(),
                        e.detail.as_deref().unwrap_or(""),
                        target,
                        e.actor
                    ));
                }
                true
            }
            EvidenceState::Missing { .. } | EvidenceState::NotApplicable => false,
        };

        // --- Source 2: Agent action log command patterns ---
        let action_gaps = match &evidence.agent_action_log {
            EvidenceState::Complete { value } | EvidenceState::Partial { value, .. } => {
                let custom_patterns: Vec<String> = match &evidence.agent_spec {
                    EvidenceState::Complete { value } | EvidenceState::Partial { value, .. } => {
                        value
                            .custom_destructive_patterns
                            .iter()
                            .map(|p| p.to_lowercase())
                            .collect()
                    }
                    _ => vec![],
                };

                for action in &value.actions {
                    let lower = action.command.to_lowercase();
                    let matched = NOTABLE_COMMAND_PATTERNS.iter().any(|p| lower.contains(p))
                        || custom_patterns.iter().any(|p| lower.contains(p.as_str()));
                    if matched {
                        subjects.push(format!("command: {}", action.command));
                    }
                }
                matches!(&evidence.agent_action_log, EvidenceState::Partial { .. })
            }
            EvidenceState::Missing { .. } | EvidenceState::NotApplicable => false,
        };

        // --- Both sources missing = Indeterminate ---
        let git_missing = matches!(
            evidence.privileged_git_events,
            EvidenceState::Missing { .. }
        );
        let log_missing = matches!(evidence.agent_action_log, EvidenceState::Missing { .. });
        let git_na = matches!(evidence.privileged_git_events, EvidenceState::NotApplicable);
        let log_na = matches!(evidence.agent_action_log, EvidenceState::NotApplicable);

        if git_na && log_na {
            return vec![ControlFinding::not_applicable(
                id,
                "No privileged operation evidence applicable",
            )];
        }

        if git_missing && log_missing {
            let mut gaps = vec![];
            if let EvidenceState::Missing { gaps: g } = &evidence.privileged_git_events {
                gaps.extend(g.clone());
            }
            if let EvidenceState::Missing { gaps: g } = &evidence.agent_action_log {
                gaps.extend(g.clone());
            }
            return vec![ControlFinding::indeterminate(
                id,
                "Privileged operation evidence is missing",
                vec![],
                gaps,
            )];
        }

        // --- Produce finding ---
        if subjects.is_empty() {
            let mut rationale = "No privileged operations detected".to_string();
            if git_gaps || action_gaps {
                rationale
                    .push_str(" (partial evidence — some operations may not have been captured)");
            }
            vec![ControlFinding::satisfied(id, rationale, vec![])]
        } else {
            let count = subjects.len();
            vec![ControlFinding::violated(
                id,
                format!("{count} privileged operation(s) detected"),
                subjects,
            )]
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::control::ControlStatus;
    use crate::evidence::*;

    fn git_event(
        actor: &str,
        action: PrivilegedAction,
        branch: Option<&str>,
        tag: Option<&str>,
    ) -> PrivilegedGitEvent {
        PrivilegedGitEvent {
            actor: actor.to_string(),
            action,
            branch: branch.map(String::from),
            tag: tag.map(String::from),
            timestamp: None,
            commit_sha: None,
            detail: Some("test event".to_string()),
        }
    }

    fn action(command: &str) -> AgentAction {
        AgentAction {
            tool: "shell".to_string(),
            command: command.to_string(),
            timestamp: None,
        }
    }

    fn log_with(actions: Vec<AgentAction>) -> AgentActionLog {
        AgentActionLog {
            agent_id: "test-agent".to_string(),
            session_id: "session-1".to_string(),
            actions,
        }
    }

    // --- Git events ---

    #[test]
    fn no_events_no_actions_satisfied() {
        let b = EvidenceBundle {
            privileged_git_events: EvidenceState::complete(vec![]),
            agent_action_log: EvidenceState::complete(log_with(vec![])),
            ..Default::default()
        };
        let findings = PrivilegedOperationAuditControl.evaluate(&b);
        assert_eq!(findings[0].status, ControlStatus::Satisfied);
    }

    #[test]
    fn force_push_from_git_events() {
        let b = EvidenceBundle {
            privileged_git_events: EvidenceState::complete(vec![git_event(
                "bot",
                PrivilegedAction::ForcePush,
                Some("main"),
                None,
            )]),
            ..Default::default()
        };
        let findings = PrivilegedOperationAuditControl.evaluate(&b);
        assert_eq!(findings[0].status, ControlStatus::Violated);
        assert!(findings[0].subjects[0].contains("force-push"));
    }

    #[test]
    fn admin_bypass_from_git_events() {
        let b = EvidenceBundle {
            privileged_git_events: EvidenceState::complete(vec![git_event(
                "admin",
                PrivilegedAction::AdminBypassProtection,
                Some("main"),
                None,
            )]),
            ..Default::default()
        };
        let findings = PrivilegedOperationAuditControl.evaluate(&b);
        assert_eq!(findings[0].status, ControlStatus::Violated);
    }

    #[test]
    fn tag_deletion_from_git_events() {
        let b = EvidenceBundle {
            privileged_git_events: EvidenceState::complete(vec![git_event(
                "bot",
                PrivilegedAction::TagDeletion,
                None,
                Some("v1.0.0"),
            )]),
            ..Default::default()
        };
        let findings = PrivilegedOperationAuditControl.evaluate(&b);
        assert_eq!(findings[0].status, ControlStatus::Violated);
        assert!(findings[0].subjects[0].contains("v1.0.0"));
    }

    // --- Action log command patterns ---

    #[test]
    fn rm_rf_from_action_log() {
        let b = EvidenceBundle {
            agent_action_log: EvidenceState::complete(log_with(vec![action("rm -rf /tmp")])),
            ..Default::default()
        };
        let findings = PrivilegedOperationAuditControl.evaluate(&b);
        assert_eq!(findings[0].status, ControlStatus::Violated);
        assert!(findings[0].subjects[0].contains("rm -rf /tmp"));
    }

    #[test]
    fn terraform_destroy_from_action_log() {
        let b = EvidenceBundle {
            agent_action_log: EvidenceState::complete(log_with(vec![action(
                "terraform destroy -auto-approve",
            )])),
            ..Default::default()
        };
        let findings = PrivilegedOperationAuditControl.evaluate(&b);
        assert_eq!(findings[0].status, ControlStatus::Violated);
    }

    #[test]
    fn safe_commands_satisfied() {
        let b = EvidenceBundle {
            agent_action_log: EvidenceState::complete(log_with(vec![
                action("cargo build"),
                action("git commit -m 'fix'"),
            ])),
            privileged_git_events: EvidenceState::complete(vec![]),
            ..Default::default()
        };
        let findings = PrivilegedOperationAuditControl.evaluate(&b);
        assert_eq!(findings[0].status, ControlStatus::Satisfied);
    }

    #[test]
    fn custom_patterns_from_spec() {
        let b = EvidenceBundle {
            agent_action_log: EvidenceState::complete(log_with(vec![action(
                "vault delete secret/prod",
            )])),
            agent_spec: EvidenceState::complete(AgentSpec {
                custom_destructive_patterns: vec!["vault delete".to_string()],
                ..Default::default()
            }),
            ..Default::default()
        };
        let findings = PrivilegedOperationAuditControl.evaluate(&b);
        assert_eq!(findings[0].status, ControlStatus::Violated);
    }

    // --- Combined sources ---

    #[test]
    fn git_events_and_action_log_combined() {
        let b = EvidenceBundle {
            privileged_git_events: EvidenceState::complete(vec![git_event(
                "bot",
                PrivilegedAction::ForcePush,
                Some("main"),
                None,
            )]),
            agent_action_log: EvidenceState::complete(log_with(vec![action("DROP TABLE users")])),
            ..Default::default()
        };
        let findings = PrivilegedOperationAuditControl.evaluate(&b);
        assert_eq!(findings[0].status, ControlStatus::Violated);
        assert_eq!(findings[0].subjects.len(), 2);
    }

    // --- Missing/NotApplicable ---

    #[test]
    fn both_missing_indeterminate() {
        let b = EvidenceBundle {
            privileged_git_events: EvidenceState::missing(vec![EvidenceGap::CollectionFailed {
                source: "webhook".into(),
                subject: "events".into(),
                detail: "down".into(),
            }]),
            agent_action_log: EvidenceState::missing(vec![EvidenceGap::CollectionFailed {
                source: "monitor".into(),
                subject: "log".into(),
                detail: "down".into(),
            }]),
            ..Default::default()
        };
        let findings = PrivilegedOperationAuditControl.evaluate(&b);
        assert_eq!(findings[0].status, ControlStatus::Indeterminate);
        assert_eq!(findings[0].evidence_gaps.len(), 2);
    }

    #[test]
    fn both_not_applicable() {
        let b = EvidenceBundle {
            privileged_git_events: EvidenceState::not_applicable(),
            agent_action_log: EvidenceState::not_applicable(),
            ..Default::default()
        };
        let findings = PrivilegedOperationAuditControl.evaluate(&b);
        assert_eq!(findings[0].status, ControlStatus::NotApplicable);
    }

    #[test]
    fn one_missing_one_present_still_evaluates() {
        let b = EvidenceBundle {
            privileged_git_events: EvidenceState::missing(vec![]),
            agent_action_log: EvidenceState::complete(log_with(vec![action("rm -rf /")])),
            ..Default::default()
        };
        let findings = PrivilegedOperationAuditControl.evaluate(&b);
        assert_eq!(findings[0].status, ControlStatus::Violated);
    }

    #[test]
    fn case_insensitive_matching() {
        let b = EvidenceBundle {
            agent_action_log: EvidenceState::complete(log_with(vec![action("DROP TABLE users")])),
            ..Default::default()
        };
        let findings = PrivilegedOperationAuditControl.evaluate(&b);
        assert_eq!(findings[0].status, ControlStatus::Violated);
    }

    #[test]
    fn partial_evidence_notes_gaps() {
        let b = EvidenceBundle {
            privileged_git_events: EvidenceState::partial(
                vec![],
                vec![EvidenceGap::Truncated {
                    source: "webhook".into(),
                    subject: "events".into(),
                }],
            ),
            agent_action_log: EvidenceState::complete(log_with(vec![])),
            ..Default::default()
        };
        let findings = PrivilegedOperationAuditControl.evaluate(&b);
        assert_eq!(findings[0].status, ControlStatus::Satisfied);
        assert!(findings[0].rationale.contains("partial evidence"));
    }
}
