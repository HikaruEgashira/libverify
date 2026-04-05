use crate::control::{Control, ControlFinding, ControlId, builtin};
use crate::evidence::{EvidenceBundle, EvidenceState};

/// Destructive patterns matched case-insensitively against agent action commands.
const DESTRUCTIVE_PATTERNS: &[&str] = &[
    "rm -rf",
    "drop table",
    "drop database",
    "truncate table",
    "git push --force",
    "git push -f",
    "git reset --hard",
    "kubectl delete",
    "terraform destroy",
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
        let log = match &evidence.agent_action_log {
            EvidenceState::Complete { value } | EvidenceState::Partial { value, .. } => value,
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

        let destructive_commands: Vec<String> = log
            .actions
            .iter()
            .filter(|action| {
                let lower = action.command.to_lowercase();
                DESTRUCTIVE_PATTERNS
                    .iter()
                    .any(|pattern| lower.contains(pattern))
            })
            .map(|action| action.command.clone())
            .collect();

        if destructive_commands.is_empty() {
            vec![ControlFinding::satisfied(
                self.id(),
                "No destructive actions detected in agent action log",
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
    use crate::evidence::{AgentAction, AgentActionLog, EvidenceGap, EvidenceState};

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
        assert!(findings[0].subjects.contains(&"rm -rf /".to_string()));
        assert!(findings[0]
            .subjects
            .contains(&"DROP TABLE users".to_string()));
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
        assert_eq!(findings[0].subjects[0], "sudo rm -rf /var/log/old");
    }
}
