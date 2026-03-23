use crate::control::{Control, ControlFinding, ControlId, builtin};
use crate::evidence::{
    ApprovalDisposition, EvidenceBundle, EvidenceGap, EvidenceState, GovernedChange,
};
use crate::integrity::is_approver_independent;

/// Verifies that at least one approver is independent from the change author and requester.
pub struct ReviewIndependenceControl;

impl Control for ReviewIndependenceControl {
    fn id(&self) -> ControlId {
        builtin::id(builtin::REVIEW_INDEPENDENCE)
    }

    fn evaluate(&self, evidence: &EvidenceBundle) -> Vec<ControlFinding> {
        if evidence.change_requests.is_empty() {
            return vec![ControlFinding::not_applicable(
                self.id(),
                "No governed changes were supplied",
            )];
        }

        evidence
            .change_requests
            .iter()
            .map(evaluate_change)
            .collect()
    }
}

fn evaluate_change(change: &GovernedChange) -> ControlFinding {
    let id = builtin::id(builtin::REVIEW_INDEPENDENCE);
    let subject = change.id.to_string();
    let mut gaps = collect_gaps(&change.approval_decisions);
    gaps.extend(collect_gaps(&change.source_revisions));

    let approvals = match change.approval_decisions.value() {
        Some(approvals) => approvals,
        None => {
            return ControlFinding::indeterminate(
                id,
                "Approval evidence is unavailable",
                vec![subject],
                gaps,
            );
        }
    };

    let revisions = match change.source_revisions.value() {
        Some(revisions) => revisions,
        None => {
            return ControlFinding::indeterminate(
                id,
                "Source revision evidence is unavailable",
                vec![subject],
                gaps,
            );
        }
    };

    let mut authors: Vec<&str> = revisions
        .iter()
        .filter_map(|revision| revision.authored_by.as_deref())
        .collect();
    authors.sort_unstable();
    authors.dedup();

    if change.submitted_by.is_none() {
        gaps.push(EvidenceGap::MissingField {
            source: "control-normalization".to_string(),
            subject: subject.clone(),
            field: "submitted_by".to_string(),
        });
    }

    if authors.is_empty() {
        gaps.push(EvidenceGap::MissingField {
            source: "control-normalization".to_string(),
            subject: subject.clone(),
            field: "source_revisions.authored_by".to_string(),
        });
    }

    if !gaps.is_empty() {
        return ControlFinding::indeterminate(
            id,
            "Independent review cannot be proven from partial evidence",
            vec![subject],
            gaps,
        );
    }

    let requester = change
        .submitted_by
        .as_deref()
        .expect("submitted_by guaranteed Some: early return on missing field");
    let has_independent_approval = approvals.iter().any(|approval| {
        if approval.disposition != ApprovalDisposition::Approved {
            return false;
        }
        let is_commit_author = authors.contains(&approval.actor.as_str());
        let is_pr_author = approval.actor == requester;
        is_approver_independent(is_commit_author, is_pr_author)
    });

    if has_independent_approval {
        ControlFinding::satisfied(
            id,
            "At least one approver is independent from both author and requester",
            vec![subject],
        )
    } else {
        ControlFinding::violated(
            id,
            "No independent approver was found for the change request",
            vec![subject],
        )
    }
}

fn collect_gaps<T>(state: &EvidenceState<T>) -> Vec<EvidenceGap> {
    state.gaps().to_vec()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::evidence::{
        ApprovalDecision, AuthenticityEvidence, ChangeRequestId, EvidenceBundle, SourceRevision,
    };

    fn make_change() -> GovernedChange {
        GovernedChange {
            id: ChangeRequestId::new("github_pr", "owner/repo#1"),
            title: "feat: add evidence layer".to_string(),
            summary: None,
            submitted_by: Some("author".to_string()),
            changed_assets: EvidenceState::complete(vec![]),
            approval_decisions: EvidenceState::complete(vec![ApprovalDecision {
                actor: "reviewer".to_string(),
                disposition: ApprovalDisposition::Approved,
                submitted_at: Some("2026-03-15T00:00:00Z".to_string()),
            }]),
            source_revisions: EvidenceState::complete(vec![SourceRevision {
                id: "abc123".to_string(),
                authored_by: Some("author".to_string()),
                committed_at: Some("2026-03-14T00:00:00Z".to_string()),
                merge: false,
                authenticity: EvidenceState::complete(AuthenticityEvidence::new(
                    true,
                    Some("gpg".to_string()),
                )),
            }]),
            work_item_refs: EvidenceState::complete(vec![]),
        }
    }

    #[test]
    fn independent_approval_is_satisfied() {
        let finding = evaluate_change(&make_change());
        assert_eq!(finding.status, crate::control::ControlStatus::Satisfied);
    }

    #[test]
    fn self_approval_is_violated() {
        let mut change = make_change();
        change.approval_decisions = EvidenceState::complete(vec![ApprovalDecision {
            actor: "author".to_string(),
            disposition: ApprovalDisposition::Approved,
            submitted_at: None,
        }]);

        let finding = evaluate_change(&change);
        assert_eq!(finding.status, crate::control::ControlStatus::Violated);
    }

    #[test]
    fn missing_authorship_is_indeterminate() {
        let mut change = make_change();
        change.source_revisions = EvidenceState::partial(
            vec![SourceRevision {
                id: "abc123".to_string(),
                authored_by: None,
                committed_at: Some("2026-03-14T00:00:00Z".to_string()),
                merge: false,
                authenticity: EvidenceState::not_applicable(),
            }],
            vec![EvidenceGap::Unsupported {
                source: "github".to_string(),
                capability: "author login unavailable for PR commit evidence".to_string(),
            }],
        );

        let findings = ReviewIndependenceControl.evaluate(&EvidenceBundle {
            change_requests: vec![change],
            promotion_batches: vec![],
            ..Default::default()
        });

        assert_eq!(
            findings[0].status,
            crate::control::ControlStatus::Indeterminate
        );
    }
}
