use crate::control::{Control, ControlFinding, ControlId, builtin};
use crate::evidence::{EvidenceBundle, EvidenceState, PrivilegedAction};

/// Audits privileged git operations that bypass normal workflow controls.
///
/// This control does NOT prevent operations — it detects them for visibility
/// and policy enforcement. Operations detected:
/// - Force push to any branch (especially default)
/// - Direct push to default branch without PR
/// - Admin bypass of branch protections
/// - Branch/tag deletion
/// - Protection rule override
pub struct PrivilegedOperationAuditControl;

impl Control for PrivilegedOperationAuditControl {
    fn id(&self) -> ControlId {
        builtin::id(builtin::PRIVILEGED_OPERATION_AUDIT)
    }

    fn description(&self) -> &'static str {
        "Privileged git operations (force push, admin bypass, tag deletion) must be audited"
    }

    fn evaluate(&self, evidence: &EvidenceBundle) -> Vec<ControlFinding> {
        let id = self.id();

        let (events, has_gaps) = match &evidence.privileged_git_events {
            EvidenceState::Complete { value } => (value, false),
            EvidenceState::Partial { value, .. } => (value, true),
            EvidenceState::Missing { gaps } => {
                return vec![ControlFinding::indeterminate(
                    id,
                    "Privileged git event evidence is missing",
                    vec![],
                    gaps.clone(),
                )];
            }
            EvidenceState::NotApplicable => {
                return vec![ControlFinding::not_applicable(
                    id,
                    "Privileged git event auditing not applicable",
                )];
            }
        };

        if events.is_empty() {
            let mut rationale =
                "No privileged operations detected".to_string();
            if has_gaps {
                rationale.push_str(" (partial evidence — some events may not have been captured)");
            }
            return vec![ControlFinding::satisfied(id, rationale, vec![])];
        }

        let subjects: Vec<String> = events
            .iter()
            .map(|e| {
                let target = e.branch.as_deref()
                    .or(e.tag.as_deref())
                    .unwrap_or("unknown");
                format!(
                    "{}: {} on {} by {}",
                    e.action.as_str(),
                    e.detail.as_deref().unwrap_or(""),
                    target,
                    e.actor
                )
            })
            .collect();

        let mut rationale = format!(
            "{} privileged operation(s) detected",
            events.len()
        );

        // Categorize by severity for rationale
        let force_pushes = events.iter().filter(|e| e.action == PrivilegedAction::ForcePush).count();
        let admin_bypasses = events.iter().filter(|e| e.action == PrivilegedAction::AdminBypassProtection).count();
        let direct_pushes = events.iter().filter(|e| e.action == PrivilegedAction::DirectPushToDefault).count();
        let deletions = events.iter().filter(|e| matches!(e.action, PrivilegedAction::BranchDeletion | PrivilegedAction::TagDeletion)).count();

        let mut breakdown = vec![];
        if force_pushes > 0 { breakdown.push(format!("{force_pushes} force push(es)")); }
        if admin_bypasses > 0 { breakdown.push(format!("{admin_bypasses} admin bypass(es)")); }
        if direct_pushes > 0 { breakdown.push(format!("{direct_pushes} direct push(es) to default")); }
        if deletions > 0 { breakdown.push(format!("{deletions} deletion(s)")); }
        if !breakdown.is_empty() {
            rationale.push_str(": ");
            rationale.push_str(&breakdown.join(", "));
        }

        vec![ControlFinding::violated(id, rationale, subjects)]
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::control::ControlStatus;
    use crate::evidence::{EvidenceGap, PrivilegedAction, PrivilegedGitEvent};

    fn event(actor: &str, action: PrivilegedAction, branch: Option<&str>, tag: Option<&str>) -> PrivilegedGitEvent {
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

    fn bundle(events: EvidenceState<Vec<PrivilegedGitEvent>>) -> EvidenceBundle {
        EvidenceBundle {
            privileged_git_events: events,
            ..Default::default()
        }
    }

    #[test]
    fn no_events_satisfied() {
        let findings = PrivilegedOperationAuditControl.evaluate(
            &bundle(EvidenceState::complete(vec![])),
        );
        assert_eq!(findings[0].status, ControlStatus::Satisfied);
    }

    #[test]
    fn force_push_to_main_violated() {
        let findings = PrivilegedOperationAuditControl.evaluate(&bundle(
            EvidenceState::complete(vec![
                event("bot-agent", PrivilegedAction::ForcePush, Some("main"), None),
            ]),
        ));
        assert_eq!(findings[0].status, ControlStatus::Violated);
        assert!(findings[0].rationale.contains("1 privileged operation"));
        assert!(findings[0].rationale.contains("force push"));
        assert!(findings[0].subjects[0].contains("main"));
        assert!(findings[0].subjects[0].contains("bot-agent"));
    }

    #[test]
    fn admin_bypass_violated() {
        let findings = PrivilegedOperationAuditControl.evaluate(&bundle(
            EvidenceState::complete(vec![
                event("admin-user", PrivilegedAction::AdminBypassProtection, Some("main"), None),
            ]),
        ));
        assert_eq!(findings[0].status, ControlStatus::Violated);
        assert!(findings[0].rationale.contains("admin bypass"));
    }

    #[test]
    fn direct_push_to_default_violated() {
        let findings = PrivilegedOperationAuditControl.evaluate(&bundle(
            EvidenceState::complete(vec![
                event("agent-1", PrivilegedAction::DirectPushToDefault, Some("main"), None),
            ]),
        ));
        assert_eq!(findings[0].status, ControlStatus::Violated);
        assert!(findings[0].rationale.contains("1 direct push(es) to default"));
        // must NOT contain other categories
        assert!(!findings[0].rationale.contains("force push"));
        assert!(!findings[0].rationale.contains("deletion"));
    }

    #[test]
    fn tag_deletion_violated() {
        let findings = PrivilegedOperationAuditControl.evaluate(&bundle(
            EvidenceState::complete(vec![
                event("agent-1", PrivilegedAction::TagDeletion, None, Some("v1.0.0")),
            ]),
        ));
        assert_eq!(findings[0].status, ControlStatus::Violated);
        assert!(findings[0].rationale.contains("deletion"));
        assert!(findings[0].subjects[0].contains("v1.0.0"));
    }

    #[test]
    fn branch_deletion_violated() {
        let findings = PrivilegedOperationAuditControl.evaluate(&bundle(
            EvidenceState::complete(vec![
                event("agent-1", PrivilegedAction::BranchDeletion, Some("feature/old"), None),
            ]),
        ));
        assert_eq!(findings[0].status, ControlStatus::Violated);
        assert!(findings[0].subjects[0].contains("feature/old"));
    }

    #[test]
    fn multiple_events_all_listed() {
        let findings = PrivilegedOperationAuditControl.evaluate(&bundle(
            EvidenceState::complete(vec![
                event("agent-1", PrivilegedAction::ForcePush, Some("main"), None),
                event("agent-2", PrivilegedAction::AdminBypassProtection, Some("main"), None),
                event("agent-1", PrivilegedAction::TagDeletion, None, Some("v2.0.0")),
            ]),
        ));
        assert_eq!(findings[0].status, ControlStatus::Violated);
        assert!(findings[0].rationale.contains("3 privileged operation"));
        assert_eq!(findings[0].subjects.len(), 3);
    }

    #[test]
    fn missing_evidence_indeterminate() {
        let findings = PrivilegedOperationAuditControl.evaluate(&bundle(
            EvidenceState::missing(vec![EvidenceGap::CollectionFailed {
                source: "git-webhook".to_string(),
                subject: "events".to_string(),
                detail: "webhook not configured".to_string(),
            }]),
        ));
        assert_eq!(findings[0].status, ControlStatus::Indeterminate);
    }

    #[test]
    fn not_applicable_evidence() {
        let findings = PrivilegedOperationAuditControl.evaluate(
            &bundle(EvidenceState::not_applicable()),
        );
        assert_eq!(findings[0].status, ControlStatus::NotApplicable);
    }

    #[test]
    fn partial_evidence_notes_gaps() {
        let findings = PrivilegedOperationAuditControl.evaluate(&bundle(
            EvidenceState::partial(
                vec![],
                vec![EvidenceGap::Truncated {
                    source: "webhook".to_string(),
                    subject: "events".to_string(),
                }],
            ),
        ));
        assert_eq!(findings[0].status, ControlStatus::Satisfied);
        assert!(findings[0].rationale.contains("partial evidence"));
    }

    #[test]
    fn protection_rule_override_violated() {
        let findings = PrivilegedOperationAuditControl.evaluate(&bundle(
            EvidenceState::complete(vec![
                event("admin", PrivilegedAction::ProtectionRuleOverride, Some("main"), None),
            ]),
        ));
        assert_eq!(findings[0].status, ControlStatus::Violated);
    }

    #[test]
    fn rationale_only_includes_present_categories() {
        // Only force push — rationale should mention "force push" but NOT "direct push" or "deletion"
        let findings = PrivilegedOperationAuditControl.evaluate(&bundle(
            EvidenceState::complete(vec![
                event("bot", PrivilegedAction::ForcePush, Some("main"), None),
            ]),
        ));
        assert!(findings[0].rationale.contains("1 force push"));
        assert!(!findings[0].rationale.contains("direct push"));
        assert!(!findings[0].rationale.contains("deletion"));
        assert!(!findings[0].rationale.contains("admin bypass"));
    }

    #[test]
    fn rationale_breakdown_counts_each_category_exactly() {
        // 2 force pushes + 1 deletion = rationale should show "2 force push(es), 1 deletion(s)"
        let findings = PrivilegedOperationAuditControl.evaluate(&bundle(
            EvidenceState::complete(vec![
                event("bot", PrivilegedAction::ForcePush, Some("main"), None),
                event("bot", PrivilegedAction::ForcePush, Some("dev"), None),
                event("bot", PrivilegedAction::TagDeletion, None, Some("v1.0")),
            ]),
        ));
        assert!(findings[0].rationale.contains("2 force push(es)"));
        assert!(findings[0].rationale.contains("1 deletion(s)"));
        assert!(!findings[0].rationale.contains("0 "));
    }
}
