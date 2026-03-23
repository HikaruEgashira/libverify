use crate::control::{builtin, Control, ControlFinding, ControlId};
use crate::evidence::{EvidenceBundle, EvidenceState, GovernedChange};
use crate::integrity::branch_history_severity;
use crate::verdict::Severity;

/// Source L2: Verifies that branch history is continuous and linear
/// by checking actual commit history for merge commits (evidence of non-linear history).
///
/// Instead of checking branch protection API settings (which require admin permissions),
/// this control examines the factual commit history collected from the PR.
/// See ADR-0002 for rationale.
pub struct BranchHistoryIntegrityControl;

impl Control for BranchHistoryIntegrityControl {
    fn id(&self) -> ControlId {
        builtin::id(builtin::BRANCH_HISTORY_INTEGRITY)
    }

    fn evaluate(&self, evidence: &EvidenceBundle) -> Vec<ControlFinding> {
        let id = self.id();

        if evidence.change_requests.is_empty() {
            return vec![ControlFinding::not_applicable(
                id,
                "No governed changes were supplied",
            )];
        }

        evidence
            .change_requests
            .iter()
            .map(|cr| evaluate_change(id.clone(), cr))
            .collect()
    }
}

fn evaluate_change(id: ControlId, change: &GovernedChange) -> ControlFinding {
    let subject = change.id.to_string();

    let revisions = match &change.source_revisions {
        EvidenceState::NotApplicable => {
            return ControlFinding::not_applicable(
                id,
                "Source revision evidence does not apply to this context",
            );
        }
        EvidenceState::Missing { gaps } => {
            return ControlFinding::indeterminate(
                id,
                "Source revision evidence could not be collected",
                vec![subject],
                gaps.clone(),
            );
        }
        EvidenceState::Complete { value } | EvidenceState::Partial { value, .. } => value,
    };

    if revisions.is_empty() {
        return ControlFinding::indeterminate(
            id,
            "No source revisions found in the change request",
            vec![subject],
            vec![],
        );
    }

    let merge_commits: Vec<&str> = revisions
        .iter()
        .filter(|r| r.merge)
        .map(|r| r.id.as_str())
        .collect();

    match branch_history_severity(merge_commits.len()) {
        Severity::Pass => ControlFinding::satisfied(
            id,
            format!(
                "All {} commit(s) form a linear history (no merge commits)",
                revisions.len()
            ),
            vec![subject],
        ),
        _ => ControlFinding::violated(
            id,
            format!(
                "{} merge commit(s) found, indicating non-linear history: {}",
                merge_commits.len(),
                merge_commits.join(", ")
            ),
            vec![subject],
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::control::ControlStatus;
    use crate::evidence::{ChangeRequestId, EvidenceGap, SourceRevision};

    fn make_revision(sha: &str, merge: bool) -> SourceRevision {
        SourceRevision {
            id: sha.to_string(),
            authored_by: Some("author".to_string()),
            committed_at: Some("2026-03-15T00:00:00Z".to_string()),
            merge,
            authenticity: EvidenceState::not_applicable(),
        }
    }

    fn make_change(revisions: EvidenceState<Vec<SourceRevision>>) -> GovernedChange {
        GovernedChange {
            id: ChangeRequestId::new("github_pr", "owner/repo#1"),
            title: "feat: test".to_string(),
            summary: None,
            submitted_by: Some("author".to_string()),
            changed_assets: EvidenceState::complete(vec![]),
            approval_decisions: EvidenceState::complete(vec![]),
            source_revisions: revisions,
            work_item_refs: EvidenceState::complete(vec![]),
        }
    }

    fn make_bundle(change: GovernedChange) -> EvidenceBundle {
        EvidenceBundle {
            change_requests: vec![change],
            ..Default::default()
        }
    }

    #[test]
    fn not_applicable_when_no_changes() {
        let evidence = EvidenceBundle::default();
        let findings = BranchHistoryIntegrityControl.evaluate(&evidence);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].status, ControlStatus::NotApplicable);
        assert_eq!(findings[0].control_id, builtin::id(builtin::BRANCH_HISTORY_INTEGRITY));
    }

    #[test]
    fn not_applicable_when_revisions_not_applicable() {
        let bundle = make_bundle(make_change(EvidenceState::not_applicable()));
        let findings = BranchHistoryIntegrityControl.evaluate(&bundle);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].status, ControlStatus::NotApplicable);
    }

    #[test]
    fn indeterminate_when_revisions_missing() {
        let bundle = make_bundle(make_change(EvidenceState::missing(vec![
            EvidenceGap::CollectionFailed {
                source: "github".to_string(),
                subject: "commits".to_string(),
                detail: "API returned 403".to_string(),
            },
        ])));
        let findings = BranchHistoryIntegrityControl.evaluate(&bundle);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].status, ControlStatus::Indeterminate);
        assert_eq!(findings[0].evidence_gaps.len(), 1);
    }

    #[test]
    fn indeterminate_when_revisions_empty() {
        let bundle = make_bundle(make_change(EvidenceState::complete(vec![])));
        let findings = BranchHistoryIntegrityControl.evaluate(&bundle);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].status, ControlStatus::Indeterminate);
    }

    #[test]
    fn satisfied_when_all_commits_linear() {
        let bundle = make_bundle(make_change(EvidenceState::complete(vec![
            make_revision("abc123", false),
            make_revision("def456", false),
        ])));
        let findings = BranchHistoryIntegrityControl.evaluate(&bundle);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].status, ControlStatus::Satisfied);
        assert!(findings[0].rationale.contains("linear history"));
    }

    #[test]
    fn violated_when_merge_commits_present() {
        let bundle = make_bundle(make_change(EvidenceState::complete(vec![
            make_revision("abc123", false),
            make_revision("merge1", true),
        ])));
        let findings = BranchHistoryIntegrityControl.evaluate(&bundle);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].status, ControlStatus::Violated);
        assert!(findings[0].rationale.contains("merge commit"));
        assert!(findings[0].rationale.contains("merge1"));
    }

    #[test]
    fn correct_control_id() {
        assert_eq!(
            BranchHistoryIntegrityControl.id(),
            builtin::id(builtin::BRANCH_HISTORY_INTEGRITY)
        );
    }
}
