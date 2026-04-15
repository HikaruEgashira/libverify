use crate::control::{Control, ControlFinding, ControlId, builtin};
use crate::evidence::{AgentExecution, AgentSpec, EvidenceBundle, EvidenceState};

pub struct AgentSpecConformanceControl;

/// Normalize a path by resolving `.` and `..` segments and collapsing separators.
/// Does not touch the filesystem — purely lexical.
fn normalize_path(path: &str) -> String {
    let mut parts: Vec<&str> = Vec::new();
    for segment in path.split('/') {
        match segment {
            "" | "." => {}
            ".." => {
                parts.pop();
            }
            s => parts.push(s),
        }
    }
    parts.join("/")
}

/// Pattern ends with `*` or `/` -> prefix match (trailing char stripped).
/// Otherwise -> exact match.
/// All paths are normalized before matching to prevent traversal attacks.
fn path_matches(path: &str, pattern: &str) -> bool {
    let normalized = normalize_path(path);
    if pattern.ends_with('*') || pattern.ends_with('/') {
        let prefix = normalize_path(&pattern[..pattern.len() - 1]);
        normalized.starts_with(&prefix)
    } else {
        normalized == normalize_path(pattern)
    }
}

fn check_conformance(id: ControlId, spec: &AgentSpec, exec: &AgentExecution) -> ControlFinding {
    let mut violations: Vec<String> = Vec::new();

    // a. Forbidden paths
    for file in &exec.files_touched {
        for pattern in &spec.forbidden_paths {
            if path_matches(file, pattern) {
                violations.push(format!("touched forbidden path: {file}"));
                break;
            }
        }
    }

    // b. Allowed paths (only enforced when non-empty)
    if !spec.allowed_paths.is_empty() {
        for file in &exec.files_touched {
            let allowed = spec.allowed_paths.iter().any(|p| path_matches(file, p));
            if !allowed {
                violations.push(format!("touched path not in allowed list: {file}"));
            }
        }
    }

    // c. Allowed tools (only enforced when non-empty)
    if !spec.allowed_tools.is_empty() {
        for tool in &exec.tools_used {
            if !spec.allowed_tools.contains(tool) {
                violations.push(format!("used unauthorized tool: {tool}"));
            }
        }
    }

    // d. Step limit
    if let Some(max) = spec.max_steps
        && exec.steps_taken > max
    {
        violations.push(format!("exceeded step limit: {}/{}", exec.steps_taken, max));
    }

    // e. Budget limit
    if let Some(max) = spec.budget_cents
        && exec.cost_cents > max
    {
        violations.push(format!(
            "exceeded budget: {}/{} cents",
            exec.cost_cents, max
        ));
    }

    if violations.is_empty() {
        ControlFinding::satisfied(
            id,
            "Agent conformed to all spec constraints",
            vec![exec.agent_id.clone()],
        )
    } else {
        ControlFinding::violated(
            id,
            format!("Agent {} violated spec constraints", exec.agent_id),
            violations,
        )
    }
}

impl Control for AgentSpecConformanceControl {
    fn id(&self) -> ControlId {
        builtin::id(builtin::AGENT_SPEC_CONFORMANCE)
    }

    fn description(&self) -> &'static str {
        "Agent must conform to its spec (allowed paths, tools, budget)"
    }

    fn evaluate(&self, evidence: &EvidenceBundle) -> Vec<ControlFinding> {
        let spec = match &evidence.agent_spec {
            EvidenceState::Complete { value } | EvidenceState::Partial { value, .. } => value,
            EvidenceState::Missing { gaps } => {
                return vec![ControlFinding::indeterminate(
                    self.id(),
                    "Agent spec evidence is missing",
                    Vec::new(),
                    gaps.clone(),
                )];
            }
            EvidenceState::NotApplicable => {
                return vec![ControlFinding::not_applicable(
                    self.id(),
                    "Agent spec evidence is not applicable",
                )];
            }
        };

        let exec = match &evidence.agent_execution {
            EvidenceState::Complete { value } | EvidenceState::Partial { value, .. } => value,
            EvidenceState::Missing { gaps } => {
                return vec![ControlFinding::indeterminate(
                    self.id(),
                    "Agent execution evidence is missing",
                    Vec::new(),
                    gaps.clone(),
                )];
            }
            EvidenceState::NotApplicable => {
                return vec![ControlFinding::not_applicable(
                    self.id(),
                    "Agent execution evidence is not applicable",
                )];
            }
        };

        vec![check_conformance(self.id(), spec, exec)]
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::control::ControlStatus;

    fn spec(
        allowed_paths: Vec<&str>,
        forbidden_paths: Vec<&str>,
        allowed_tools: Vec<&str>,
        max_steps: Option<u32>,
        budget_cents: Option<u32>,
    ) -> AgentSpec {
        AgentSpec {
            allowed_paths: allowed_paths.into_iter().map(String::from).collect(),
            forbidden_paths: forbidden_paths.into_iter().map(String::from).collect(),
            allowed_tools: allowed_tools.into_iter().map(String::from).collect(),
            max_steps,
            budget_cents,
            custom_destructive_patterns: Vec::new(),
            forbidden_mcp_servers: Vec::new(),
        }
    }

    fn exec(files: Vec<&str>, tools: Vec<&str>, steps: u32, cost: u32) -> AgentExecution {
        AgentExecution {
            agent_id: "agent-1".to_string(),
            session_id: "session-1".to_string(),
            files_touched: files.into_iter().map(String::from).collect(),
            tools_used: tools.into_iter().map(String::from).collect(),
            steps_taken: steps,
            cost_cents: cost,
        }
    }

    fn bundle(s: AgentSpec, e: AgentExecution) -> EvidenceBundle {
        EvidenceBundle {
            agent_spec: EvidenceState::complete(s),
            agent_execution: EvidenceState::complete(e),
            ..Default::default()
        }
    }

    // 1. All checks pass
    #[test]
    fn all_checks_pass() {
        let b = bundle(
            spec(
                vec!["src/*"],
                vec![".env"],
                vec!["cargo"],
                Some(100),
                Some(2000),
            ),
            exec(vec!["src/main.rs"], vec!["cargo"], 50, 1000),
        );
        let findings = AgentSpecConformanceControl.evaluate(&b);
        assert_eq!(findings[0].status, ControlStatus::Satisfied);
    }

    // 2. Touch forbidden path ".env"
    #[test]
    fn forbidden_path_exact() {
        let b = bundle(
            spec(vec![], vec![".env"], vec![], None, None),
            exec(vec![".env"], vec![], 0, 0),
        );
        let findings = AgentSpecConformanceControl.evaluate(&b);
        assert_eq!(findings[0].status, ControlStatus::Violated);
        assert!(findings[0].subjects.iter().any(|s| s.contains(".env")));
    }

    // 3. Touch file not in allowed_paths
    #[test]
    fn file_not_in_allowed_paths() {
        let b = bundle(
            spec(vec!["src/*"], vec![], vec![], None, None),
            exec(vec!["config/settings.toml"], vec![], 0, 0),
        );
        let findings = AgentSpecConformanceControl.evaluate(&b);
        assert_eq!(findings[0].status, ControlStatus::Violated);
        assert!(
            findings[0]
                .subjects
                .iter()
                .any(|s| s.contains("config/settings.toml"))
        );
    }

    // 4. Use unauthorized tool
    #[test]
    fn unauthorized_tool() {
        let b = bundle(
            spec(vec![], vec![], vec!["cargo"], None, None),
            exec(vec![], vec!["curl"], 0, 0),
        );
        let findings = AgentSpecConformanceControl.evaluate(&b);
        assert_eq!(findings[0].status, ControlStatus::Violated);
        assert!(findings[0].subjects.iter().any(|s| s.contains("curl")));
    }

    // 5. Exceed step limit
    #[test]
    fn exceed_step_limit() {
        let b = bundle(
            spec(vec![], vec![], vec![], Some(100), None),
            exec(vec![], vec![], 150, 0),
        );
        let findings = AgentSpecConformanceControl.evaluate(&b);
        assert_eq!(findings[0].status, ControlStatus::Violated);
        assert!(findings[0].subjects.iter().any(|s| s.contains("150/100")));
    }

    // 6. Exceed budget
    #[test]
    fn exceed_budget() {
        let b = bundle(
            spec(vec![], vec![], vec![], None, Some(2000)),
            exec(vec![], vec![], 0, 5000),
        );
        let findings = AgentSpecConformanceControl.evaluate(&b);
        assert_eq!(findings[0].status, ControlStatus::Violated);
        assert!(findings[0].subjects.iter().any(|s| s.contains("5000/2000")));
    }

    // 7. Multiple violations at once
    #[test]
    fn multiple_violations() {
        let b = bundle(
            spec(
                vec!["src/*"],
                vec![".env"],
                vec!["cargo"],
                Some(100),
                Some(2000),
            ),
            exec(vec![".env", "docs/readme.md"], vec!["curl"], 150, 5000),
        );
        let findings = AgentSpecConformanceControl.evaluate(&b);
        assert_eq!(findings[0].status, ControlStatus::Violated);
        let subjects = &findings[0].subjects;
        assert!(subjects.iter().any(|s| s.contains(".env")));
        assert!(subjects.iter().any(|s| s.contains("docs/readme.md")));
        assert!(subjects.iter().any(|s| s.contains("curl")));
        assert!(subjects.iter().any(|s| s.contains("150/100")));
        assert!(subjects.iter().any(|s| s.contains("5000/2000")));
    }

    // 8. Empty allowed_paths means no restriction
    #[test]
    fn empty_allowed_paths_no_restriction() {
        let b = bundle(
            spec(vec![], vec![], vec![], None, None),
            exec(vec!["anywhere/file.txt"], vec![], 0, 0),
        );
        let findings = AgentSpecConformanceControl.evaluate(&b);
        assert_eq!(findings[0].status, ControlStatus::Satisfied);
    }

    // 9. Empty allowed_tools means no restriction
    #[test]
    fn empty_allowed_tools_no_restriction() {
        let b = bundle(
            spec(vec![], vec![], vec![], None, None),
            exec(vec![], vec!["anything"], 0, 0),
        );
        let findings = AgentSpecConformanceControl.evaluate(&b);
        assert_eq!(findings[0].status, ControlStatus::Satisfied);
    }

    // 10. Prefix match: forbidden "secrets/" matches "secrets/api.key"
    #[test]
    fn forbidden_prefix_match_with_slash() {
        let b = bundle(
            spec(vec![], vec!["secrets/"], vec![], None, None),
            exec(vec!["secrets/api.key"], vec![], 0, 0),
        );
        let findings = AgentSpecConformanceControl.evaluate(&b);
        assert_eq!(findings[0].status, ControlStatus::Violated);
        assert!(
            findings[0]
                .subjects
                .iter()
                .any(|s| s.contains("secrets/api.key"))
        );
    }

    // 11. Wildcard match: allowed "src/*" matches "src/main.rs"
    #[test]
    fn allowed_wildcard_match() {
        let b = bundle(
            spec(vec!["src/*"], vec![], vec![], None, None),
            exec(vec!["src/main.rs"], vec![], 0, 0),
        );
        let findings = AgentSpecConformanceControl.evaluate(&b);
        assert_eq!(findings[0].status, ControlStatus::Satisfied);
    }

    // 12. Missing spec evidence -> Indeterminate
    #[test]
    fn missing_spec_indeterminate() {
        let b = EvidenceBundle {
            agent_spec: EvidenceState::missing(vec![]),
            agent_execution: EvidenceState::complete(exec(vec![], vec![], 0, 0)),
            ..Default::default()
        };
        let findings = AgentSpecConformanceControl.evaluate(&b);
        assert_eq!(findings[0].status, ControlStatus::Indeterminate);
    }

    // 13. NotApplicable execution -> NotApplicable
    #[test]
    fn not_applicable_execution() {
        let b = EvidenceBundle {
            agent_spec: EvidenceState::complete(spec(vec![], vec![], vec![], None, None)),
            agent_execution: EvidenceState::not_applicable(),
            ..Default::default()
        };
        let findings = AgentSpecConformanceControl.evaluate(&b);
        assert_eq!(findings[0].status, ControlStatus::NotApplicable);
    }

    // 14. Path traversal attack: src/../secrets/key.pem should NOT pass allowed "src/*"
    #[test]
    fn path_traversal_blocked() {
        let b = bundle(
            spec(vec!["src/*"], vec![], vec![], None, None),
            exec(vec!["src/../secrets/key.pem"], vec![], 0, 0),
        );
        let findings = AgentSpecConformanceControl.evaluate(&b);
        assert_eq!(findings[0].status, ControlStatus::Violated);
        assert!(
            findings[0]
                .subjects
                .iter()
                .any(|s| s.contains("secrets/key.pem"))
        );
    }

    // 15. Path traversal attack: src/../.env should match forbidden ".env"
    #[test]
    fn path_traversal_forbidden_detected() {
        let b = bundle(
            spec(vec![], vec![".env"], vec![], None, None),
            exec(vec!["src/../.env"], vec![], 0, 0),
        );
        let findings = AgentSpecConformanceControl.evaluate(&b);
        assert_eq!(findings[0].status, ControlStatus::Violated);
    }

    // 16. Normalized path: ./src/main.rs should match allowed "src/*"
    #[test]
    fn dot_prefix_normalized() {
        let b = bundle(
            spec(vec!["src/*"], vec![], vec![], None, None),
            exec(vec!["./src/main.rs"], vec![], 0, 0),
        );
        let findings = AgentSpecConformanceControl.evaluate(&b);
        assert_eq!(findings[0].status, ControlStatus::Satisfied);
    }

    // 17. normalize_path unit tests
    #[test]
    fn normalize_path_resolves_traversal() {
        assert_eq!(normalize_path("src/../secrets/key.pem"), "secrets/key.pem");
        assert_eq!(normalize_path("./src/main.rs"), "src/main.rs");
        assert_eq!(normalize_path("src/./deep/../main.rs"), "src/main.rs");
        assert_eq!(normalize_path("a/b/c/../../d"), "a/d");
    }

    // 18. Boundary: steps exactly at limit -> Satisfied
    #[test]
    fn steps_at_limit_satisfied() {
        let b = bundle(
            spec(vec![], vec![], vec![], Some(100), None),
            exec(vec![], vec![], 100, 0),
        );
        let findings = AgentSpecConformanceControl.evaluate(&b);
        assert_eq!(findings[0].status, ControlStatus::Satisfied);
    }

    // 19. Boundary: budget exactly at limit -> Satisfied
    #[test]
    fn budget_at_limit_satisfied() {
        let b = bundle(
            spec(vec![], vec![], vec![], None, Some(2000)),
            exec(vec![], vec![], 0, 2000),
        );
        let findings = AgentSpecConformanceControl.evaluate(&b);
        assert_eq!(findings[0].status, ControlStatus::Satisfied);
    }

    // 20. Boundary: steps one over limit -> Violated
    #[test]
    fn steps_one_over_limit_violated() {
        let b = bundle(
            spec(vec![], vec![], vec![], Some(100), None),
            exec(vec![], vec![], 101, 0),
        );
        let findings = AgentSpecConformanceControl.evaluate(&b);
        assert_eq!(findings[0].status, ControlStatus::Violated);
    }

    // 21. Boundary: budget one over limit -> Violated
    #[test]
    fn budget_one_over_limit_violated() {
        let b = bundle(
            spec(vec![], vec![], vec![], None, Some(2000)),
            exec(vec![], vec![], 0, 2001),
        );
        let findings = AgentSpecConformanceControl.evaluate(&b);
        assert_eq!(findings[0].status, ControlStatus::Violated);
    }
}
