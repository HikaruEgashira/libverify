use crate::control::{Control, ControlFinding, ControlId, builtin};
use crate::evidence::{EvidenceBundle, EvidenceState, GovernedChange};

/// Verifies that source revisions follow a linear history policy (no merge commits).
///
/// Maps to SOC2 CC8.1: change management process integrity.
/// Merge commits in a change request indicate non-linear history (e.g. merging the base
/// branch into the feature branch), which can obscure the audit trail and
/// make it harder to review individual changes.
pub struct MergeCommitPolicyControl;

impl Control for MergeCommitPolicyControl {
    fn id(&self) -> ControlId {
        builtin::id(builtin::MERGE_COMMIT_POLICY)
    }

    fn description(&self) -> &'static str {
        "Source revisions must follow linear history (no merge commits)"
    }

    fn evaluate(&self, evidence: &EvidenceBundle) -> Vec<ControlFinding> {
        if evidence.change_requests.is_empty() {
            return vec![ControlFinding::not_applicable(
                self.id(),
                "No change requests found",
            )];
        }

        evidence
            .change_requests
            .iter()
            .map(|cr| evaluate_change(self.id(), cr))
            .collect()
    }
}

fn evaluate_change(id: ControlId, cr: &GovernedChange) -> ControlFinding {
    let cr_subject = cr.id.to_string();

    let revisions = match &cr.source_revisions {
        EvidenceState::Complete { value } | EvidenceState::Partial { value, .. } => value,
        EvidenceState::Missing { gaps } => {
            return ControlFinding::indeterminate(
                id,
                format!("{cr_subject}: source revision evidence could not be collected"),
                vec![cr_subject],
                gaps.clone(),
            );
        }
        EvidenceState::NotApplicable => {
            return ControlFinding::not_applicable(id, "Source revisions not applicable");
        }
    };

    if revisions.is_empty() {
        return ControlFinding::not_applicable(
            id,
            format!("{cr_subject}: no source revisions to evaluate"),
        );
    }

    let merge_commits: Vec<&str> = revisions
        .iter()
        .filter(|r| r.merge)
        .map(|r| r.id.as_str())
        .collect();

    if merge_commits.is_empty() {
        ControlFinding::satisfied(
            id,
            format!(
                "{cr_subject}: all {} revision(s) follow linear history",
                revisions.len()
            ),
            vec![cr_subject],
        )
    } else {
        ControlFinding::violated(
            id,
            format!(
                "{cr_subject}: {} merge commit(s) found: {}",
                merge_commits.len(),
                merge_commits.join(", ")
            ),
            merge_commits.into_iter().map(String::from).collect(),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::control::ControlStatus;
    use crate::evidence::{ChangeRequestId, SourceRevision};

    fn revision(id: &str, merge: bool) -> SourceRevision {
        SourceRevision {
            id: id.to_string(),
            authored_by: Some("dev".to_string()),
            committed_at: None,
            merge,
            authenticity: EvidenceState::not_applicable(),
        }
    }

    fn make_change(revisions: EvidenceState<Vec<SourceRevision>>) -> GovernedChange {
        GovernedChange {
            id: ChangeRequestId::new("test", "owner/repo#1"),
            title: "test".to_string(),
            summary: None,
            submitted_by: None,
            changed_assets: EvidenceState::not_applicable(),
            approval_decisions: EvidenceState::not_applicable(),
            source_revisions: revisions,
            work_item_refs: EvidenceState::not_applicable(),
        }
    }

    fn bundle(changes: Vec<GovernedChange>) -> EvidenceBundle {
        EvidenceBundle {
            change_requests: changes,
            ..Default::default()
        }
    }

    #[test]
    fn not_applicable_when_no_changes() {
        let findings = MergeCommitPolicyControl.evaluate(&EvidenceBundle::default());
        assert_eq!(findings[0].status, ControlStatus::NotApplicable);
    }

    #[test]
    fn satisfied_when_all_linear() {
        let cr = make_change(EvidenceState::complete(vec![
            revision("abc", false),
            revision("def", false),
        ]));
        let findings = MergeCommitPolicyControl.evaluate(&bundle(vec![cr]));
        assert_eq!(findings[0].status, ControlStatus::Satisfied);
    }

    #[test]
    fn violated_when_merge_commit_present() {
        let cr = make_change(EvidenceState::complete(vec![
            revision("abc", false),
            revision("merge123", true),
        ]));
        let findings = MergeCommitPolicyControl.evaluate(&bundle(vec![cr]));
        assert_eq!(findings[0].status, ControlStatus::Violated);
        assert!(findings[0].rationale.contains("merge123"));
    }

    #[test]
    fn not_applicable_when_no_revisions() {
        let cr = make_change(EvidenceState::complete(vec![]));
        let findings = MergeCommitPolicyControl.evaluate(&bundle(vec![cr]));
        assert_eq!(findings[0].status, ControlStatus::NotApplicable);
    }

    #[test]
    fn indeterminate_when_revisions_missing() {
        let cr = make_change(EvidenceState::missing(vec![
            crate::evidence::EvidenceGap::CollectionFailed {
                source: "github".to_string(),
                subject: "commits".to_string(),
                detail: "API error".to_string(),
            },
        ]));
        let findings = MergeCommitPolicyControl.evaluate(&bundle(vec![cr]));
        assert_eq!(findings[0].status, ControlStatus::Indeterminate);
    }
}
