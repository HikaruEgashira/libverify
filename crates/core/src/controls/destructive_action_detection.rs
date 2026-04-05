use crate::control::{Control, ControlFinding, ControlId, builtin};
use crate::evidence::{EvidenceBundle, EvidenceState};

/// Built-in destructive patterns matched case-insensitively against agent action commands.
/// Users can extend this via `AgentSpec.custom_destructive_patterns`.
pub const DEFAULT_DESTRUCTIVE_PATTERNS: &[&str] = &[
    // Filesystem destruction
    "rm -rf",
    "rm -r",
    "rm -fr",
    "shred ",
    "find / -delete",
    "find . -delete",
    // SQL destruction
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
    // Container/orchestration destruction
    "kubectl delete",
    "kubectl drain",
    "helm uninstall",
    "helm delete",
    "docker rm",
    "docker system prune",
    "docker-compose down -v",
    // Infrastructure destruction
    "terraform destroy",
    "pulumi destroy",
    // Cloud provider destruction
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

pub struct DestructiveActionDetectionControl;

impl Control for DestructiveActionDetectionControl {
    fn id(&self) -> ControlId {
        builtin::id(builtin::DESTRUCTIVE_ACTION_DETECTION)
    }

    fn description(&self) -> &'static str {
        "Agent action logs must not contain destructive operations"
    }

    fn evaluate(&self, evidence: &EvidenceBundle) -> Vec<ControlFinding> {
        let (log, has_gaps) = match &evidence.agent_action_log {
            EvidenceState::Complete { value } => (value, false),
            EvidenceState::Partial { value, .. } => (value, true),
            EvidenceState::Missing { gaps } => {
                return vec![ControlFinding::indeterminate(
                    self.id(),
                    "Agent action log evidence is missing",
                    vec![],
                    gaps.clone(),
                )];
            }
            EvidenceState::NotApplicable => {
                return vec![ControlFinding::not_applicable(
                    self.id(),
                    "Agent action log not applicable (non-agent workflow)",
                )];
            }
        };

        // Merge built-in patterns with custom patterns from agent spec
        let custom_patterns: Vec<String> = match &evidence.agent_spec {
            EvidenceState::Complete { value } | EvidenceState::Partial { value, .. } => {
                value.custom_destructive_patterns.iter().map(|p| p.to_lowercase()).collect()
            }
            _ => vec![],
        };

        let destructive_commands: Vec<String> = log
            .actions
            .iter()
            .filter(|action| {
                let lower = action.command.to_lowercase();
                DEFAULT_DESTRUCTIVE_PATTERNS
                    .iter()
                    .any(|pattern| lower.contains(pattern))
                    || custom_patterns.iter().any(|pattern| lower.contains(pattern.as_str()))
            })
            .map(|action| action.command.clone())
            .collect();

        if destructive_commands.is_empty() {
            let mut rationale =
                "No destructive actions detected in agent action log".to_string();
            if has_gaps {
                rationale.push_str(" (partial evidence — some actions may not have been captured)");
            }
            vec![ControlFinding::satisfied(
                self.id(),
                rationale,
                vec![format!(
                    "agent:{}:session:{}",
                    log.agent_id, log.session_id
                )],
            )]
        } else {
            let count = destructive_commands.len();
            vec![ControlFinding::violated(
                self.id(),
                format!(
                    "{count} destructive action(s) detected in agent action log"
                ),
                destructive_commands,
            )]
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::control::ControlStatus;
    use crate::evidence::{AgentAction, AgentActionLog, AgentSpec, EvidenceGap, EvidenceState};

    fn action(command: &str) -> AgentAction {
        AgentAction {
            tool: "shell".to_string(),
            command: command.to_string(),
            timestamp: None,
            required_permission: None,
        }
    }

    fn log_with(actions: Vec<AgentAction>) -> AgentActionLog {
        AgentActionLog {
            agent_id: "test-agent".to_string(),
            session_id: "session-1".to_string(),
            actions,
        }
    }

    fn bundle(state: EvidenceState<AgentActionLog>) -> EvidenceBundle {
        EvidenceBundle {
            agent_action_log: state,
            ..Default::default()
        }
    }

    #[test]
    fn empty_action_log_satisfied() {
        let findings = DestructiveActionDetectionControl
            .evaluate(&bundle(EvidenceState::complete(log_with(vec![]))));
        assert_eq!(findings[0].status, ControlStatus::Satisfied);
    }

    #[test]
    fn safe_actions_only_satisfied() {
        let findings = DestructiveActionDetectionControl.evaluate(&bundle(
            EvidenceState::complete(log_with(vec![
                action("cargo build"),
                action("git commit -m 'fix'"),
            ])),
        ));
        assert_eq!(findings[0].status, ControlStatus::Satisfied);
    }

    #[test]
    fn single_destructive_action_violated() {
        let findings = DestructiveActionDetectionControl.evaluate(&bundle(
            EvidenceState::complete(log_with(vec![action("rm -rf /tmp/data")])),
        ));
        assert_eq!(findings[0].status, ControlStatus::Violated);
        assert_eq!(findings[0].subjects, vec!["rm -rf /tmp/data"]);
    }

    #[test]
    fn multiple_destructive_actions_lists_all() {
        let findings = DestructiveActionDetectionControl.evaluate(&bundle(
            EvidenceState::complete(log_with(vec![
                action("rm -rf /"),
                action("DROP TABLE users"),
            ])),
        ));
        assert_eq!(findings[0].status, ControlStatus::Violated);
        assert_eq!(findings[0].subjects.len(), 2);
    }

    #[test]
    fn case_insensitive_drop_table() {
        let findings = DestructiveActionDetectionControl.evaluate(&bundle(
            EvidenceState::complete(log_with(vec![action("DROP table users")])),
        ));
        assert_eq!(findings[0].status, ControlStatus::Violated);
    }

    #[test]
    fn git_push_force_violated() {
        let findings = DestructiveActionDetectionControl.evaluate(&bundle(
            EvidenceState::complete(log_with(vec![action(
                "git push --force origin main",
            )])),
        ));
        assert_eq!(findings[0].status, ControlStatus::Violated);
    }

    #[test]
    fn terraform_destroy_violated() {
        let findings = DestructiveActionDetectionControl.evaluate(&bundle(
            EvidenceState::complete(log_with(vec![action("terraform destroy -auto-approve")])),
        ));
        assert_eq!(findings[0].status, ControlStatus::Violated);
    }

    #[test]
    fn missing_evidence_indeterminate() {
        let findings = DestructiveActionDetectionControl.evaluate(&bundle(
            EvidenceState::missing(vec![EvidenceGap::CollectionFailed {
                source: "agent".to_string(),
                subject: "action_log".to_string(),
                detail: "not collected".to_string(),
            }]),
        ));
        assert_eq!(findings[0].status, ControlStatus::Indeterminate);
    }

    #[test]
    fn not_applicable_evidence() {
        let findings =
            DestructiveActionDetectionControl.evaluate(&bundle(EvidenceState::not_applicable()));
        assert_eq!(findings[0].status, ControlStatus::NotApplicable);
    }

    #[test]
    fn partial_match_in_middle_of_command() {
        let findings = DestructiveActionDetectionControl.evaluate(&bundle(
            EvidenceState::complete(log_with(vec![action(
                "sudo rm -rf /var/log/old",
            )])),
        ));
        assert_eq!(findings[0].status, ControlStatus::Violated);
    }

    // --- New tests for expanded patterns ---

    #[test]
    fn cloud_provider_patterns_detected() {
        for cmd in &[
            "aws s3 rm s3://bucket/key",
            "aws ec2 terminate-instances --instance-ids i-1234",
            "gcloud compute instances delete my-vm",
            "az vm delete --name my-vm",
            "helm uninstall my-release",
            "docker rm -f container1",
            "kubectl delete pod my-pod",
        ] {
            let findings = DestructiveActionDetectionControl.evaluate(&bundle(
                EvidenceState::complete(log_with(vec![action(cmd)])),
            ));
            assert_eq!(
                findings[0].status,
                ControlStatus::Violated,
                "Expected Violated for: {cmd}"
            );
        }
    }

    #[test]
    fn delete_from_sql_detected() {
        let findings = DestructiveActionDetectionControl.evaluate(&bundle(
            EvidenceState::complete(log_with(vec![action("DELETE FROM users WHERE 1=1")])),
        ));
        assert_eq!(findings[0].status, ControlStatus::Violated);
    }

    #[test]
    fn custom_patterns_from_agent_spec() {
        let evidence = EvidenceBundle {
            agent_action_log: EvidenceState::complete(log_with(vec![
                action("vault delete secret/prod/api-key"),
            ])),
            agent_spec: EvidenceState::complete(AgentSpec {
                custom_destructive_patterns: vec!["vault delete".to_string()],
                ..Default::default()
            }),
            ..Default::default()
        };
        let findings = DestructiveActionDetectionControl.evaluate(&evidence);
        assert_eq!(findings[0].status, ControlStatus::Violated);
    }

    #[test]
    fn partial_evidence_notes_gaps() {
        let evidence = EvidenceBundle {
            agent_action_log: EvidenceState::partial(
                log_with(vec![action("cargo build")]),
                vec![EvidenceGap::Truncated {
                    source: "monitor".to_string(),
                    subject: "action_log".to_string(),
                }],
            ),
            ..Default::default()
        };
        let findings = DestructiveActionDetectionControl.evaluate(&evidence);
        assert_eq!(findings[0].status, ControlStatus::Satisfied);
        assert!(findings[0].rationale.contains("partial evidence"));
    }
}
