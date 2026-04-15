use crate::control::{Control, ControlFinding, ControlId, builtin};
use crate::evidence::{EvidenceBundle, EvidenceState};

/// Verifies that MCP tool calls stayed within the allowed scope defined in the
/// agent spec. Checks both positive allow-lists (with wildcard support) and
/// forbidden server deny-lists.
pub struct McpScopeCheckControl;

/// Returns true if `tool_ref` (format "mcp:{server}/{tool}") matches `pattern`.
///
/// Supported patterns:
///   - Exact match: "mcp:github/create_pull_request"
///   - Wildcard: "mcp:github/*" matches any tool on the github server
fn matches_allowed(tool_ref: &str, pattern: &str) -> bool {
    if pattern == tool_ref {
        return true;
    }
    if let Some(prefix) = pattern.strip_suffix('*') {
        tool_ref.starts_with(prefix)
    } else {
        false
    }
}

impl Control for McpScopeCheckControl {
    fn id(&self) -> ControlId {
        builtin::id(builtin::MCP_SCOPE_CHECK)
    }

    fn description(&self) -> &'static str {
        "MCP tool calls must stay within allowed scope (requires agent execution log)"
    }

    fn evaluate(&self, evidence: &EvidenceBundle) -> Vec<ControlFinding> {
        let id = self.id();

        // Extract MCP tool calls
        let calls = match &evidence.mcp_tool_calls {
            EvidenceState::NotApplicable => {
                return vec![ControlFinding::not_applicable(
                    id,
                    "No MCP tool call evidence applicable",
                )];
            }
            EvidenceState::Missing { gaps } => {
                return vec![ControlFinding::indeterminate(
                    id,
                    "MCP tool call evidence is missing",
                    vec![],
                    gaps.clone(),
                )];
            }
            EvidenceState::Complete { value } | EvidenceState::Partial { value, .. } => value,
        };

        if calls.is_empty() {
            return vec![ControlFinding::satisfied(
                id,
                "No MCP tool calls recorded",
                vec![],
            )];
        }

        // Extract agent spec for allowed_tools and forbidden_mcp_servers
        let (allowed_tools, forbidden_servers) = match &evidence.agent_spec {
            EvidenceState::Complete { value } | EvidenceState::Partial { value, .. } => {
                (&value.allowed_tools, &value.forbidden_mcp_servers)
            }
            _ => (&vec![] as &Vec<String>, &vec![] as &Vec<String>),
        };

        let mut violations: Vec<String> = Vec::new();

        for call in calls {
            let tool_ref = format!("mcp:{}/{}", call.server, call.tool);

            // Check forbidden servers
            if forbidden_servers
                .iter()
                .any(|s| s.eq_ignore_ascii_case(&call.server))
            {
                violations.push(format!(
                    "{tool_ref} — server '{}' is forbidden",
                    call.server
                ));
                continue;
            }

            // Check allowed tools (if non-empty, acts as an allow-list)
            if !allowed_tools.is_empty()
                && !allowed_tools.iter().any(|p| matches_allowed(&tool_ref, p))
            {
                violations.push(format!("{tool_ref} — not in allowed_tools"));
            }
        }

        if violations.is_empty() {
            vec![ControlFinding::satisfied(
                id,
                format!(
                    "All {} MCP tool call(s) are within allowed scope",
                    calls.len()
                ),
                vec![],
            )]
        } else {
            let count = violations.len();
            vec![ControlFinding::violated(
                id,
                format!("{count} MCP tool call(s) outside allowed scope"),
                violations,
            )]
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::control::ControlStatus;
    use crate::evidence::*;

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
    fn not_applicable_when_no_evidence() {
        let b = EvidenceBundle::default();
        let findings = McpScopeCheckControl.evaluate(&b);
        assert_eq!(findings[0].status, ControlStatus::NotApplicable);
    }

    #[test]
    fn missing_evidence_indeterminate() {
        let b = EvidenceBundle {
            mcp_tool_calls: EvidenceState::missing(vec![EvidenceGap::CollectionFailed {
                source: "mcp".into(),
                subject: "calls".into(),
                detail: "unavailable".into(),
            }]),
            ..Default::default()
        };
        let findings = McpScopeCheckControl.evaluate(&b);
        assert_eq!(findings[0].status, ControlStatus::Indeterminate);
    }

    #[test]
    fn empty_calls_satisfied() {
        let b = EvidenceBundle {
            mcp_tool_calls: EvidenceState::complete(vec![]),
            ..Default::default()
        };
        let findings = McpScopeCheckControl.evaluate(&b);
        assert_eq!(findings[0].status, ControlStatus::Satisfied);
    }

    #[test]
    fn no_restrictions_satisfied() {
        let b = EvidenceBundle {
            mcp_tool_calls: EvidenceState::complete(vec![
                mcp_call("github", "create_pull_request"),
                mcp_call("filesystem", "write_file"),
            ]),
            agent_spec: EvidenceState::complete(AgentSpec::default()),
            ..Default::default()
        };
        let findings = McpScopeCheckControl.evaluate(&b);
        assert_eq!(findings[0].status, ControlStatus::Satisfied);
    }

    #[test]
    fn allowed_tools_exact_match() {
        let b = EvidenceBundle {
            mcp_tool_calls: EvidenceState::complete(vec![mcp_call(
                "github",
                "create_pull_request",
            )]),
            agent_spec: EvidenceState::complete(AgentSpec {
                allowed_tools: vec!["mcp:github/create_pull_request".to_string()],
                ..Default::default()
            }),
            ..Default::default()
        };
        let findings = McpScopeCheckControl.evaluate(&b);
        assert_eq!(findings[0].status, ControlStatus::Satisfied);
    }

    #[test]
    fn allowed_tools_wildcard_match() {
        let b = EvidenceBundle {
            mcp_tool_calls: EvidenceState::complete(vec![
                mcp_call("github", "create_pull_request"),
                mcp_call("github", "list_issues"),
            ]),
            agent_spec: EvidenceState::complete(AgentSpec {
                allowed_tools: vec!["mcp:github/*".to_string()],
                ..Default::default()
            }),
            ..Default::default()
        };
        let findings = McpScopeCheckControl.evaluate(&b);
        assert_eq!(findings[0].status, ControlStatus::Satisfied);
    }

    #[test]
    fn tool_not_in_allowed_list_violated() {
        let b = EvidenceBundle {
            mcp_tool_calls: EvidenceState::complete(vec![mcp_call("database", "execute_query")]),
            agent_spec: EvidenceState::complete(AgentSpec {
                allowed_tools: vec!["mcp:github/*".to_string()],
                ..Default::default()
            }),
            ..Default::default()
        };
        let findings = McpScopeCheckControl.evaluate(&b);
        assert_eq!(findings[0].status, ControlStatus::Violated);
        assert!(findings[0].subjects[0].contains("not in allowed_tools"));
    }

    #[test]
    fn forbidden_server_violated() {
        let b = EvidenceBundle {
            mcp_tool_calls: EvidenceState::complete(vec![mcp_call("database", "execute_query")]),
            agent_spec: EvidenceState::complete(AgentSpec {
                forbidden_mcp_servers: vec!["database".to_string()],
                ..Default::default()
            }),
            ..Default::default()
        };
        let findings = McpScopeCheckControl.evaluate(&b);
        assert_eq!(findings[0].status, ControlStatus::Violated);
        assert!(findings[0].subjects[0].contains("forbidden"));
    }

    #[test]
    fn forbidden_takes_precedence_over_allowed() {
        let b = EvidenceBundle {
            mcp_tool_calls: EvidenceState::complete(vec![mcp_call("database", "read_only")]),
            agent_spec: EvidenceState::complete(AgentSpec {
                allowed_tools: vec!["mcp:database/*".to_string()],
                forbidden_mcp_servers: vec!["database".to_string()],
                ..Default::default()
            }),
            ..Default::default()
        };
        let findings = McpScopeCheckControl.evaluate(&b);
        assert_eq!(findings[0].status, ControlStatus::Violated);
        assert!(findings[0].subjects[0].contains("forbidden"));
    }

    #[test]
    fn mixed_allowed_and_forbidden() {
        let b = EvidenceBundle {
            mcp_tool_calls: EvidenceState::complete(vec![
                mcp_call("github", "create_pr"),
                mcp_call("admin", "delete_user"),
            ]),
            agent_spec: EvidenceState::complete(AgentSpec {
                allowed_tools: vec!["mcp:github/*".to_string()],
                forbidden_mcp_servers: vec!["admin".to_string()],
                ..Default::default()
            }),
            ..Default::default()
        };
        let findings = McpScopeCheckControl.evaluate(&b);
        assert_eq!(findings[0].status, ControlStatus::Violated);
        // Only the admin call should be in violations
        assert_eq!(findings[0].subjects.len(), 1);
        assert!(findings[0].subjects[0].contains("admin"));
    }
}
