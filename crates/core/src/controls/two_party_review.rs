use crate::control::{Control, ControlFinding, ControlId, builtin};
use crate::evidence::{
    ApprovalDisposition, EvidenceBundle, EvidenceGap, EvidenceState, GovernedChange,
};
use crate::integrity::{is_approver_independent, two_party_review_severity};
use crate::verdict::Severity;

/// Source L4: Verifies that at least two independent reviewers approved each change.
pub struct TwoPartyReviewControl;

impl Control for TwoPartyReviewControl {
    fn id(&self) -> ControlId {
        builtin::id(builtin::TWO_PARTY_REVIEW)
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
    let subject = change.id.to_string();
    let mut gaps = collect_gaps(&change.approval_decisions);
    gaps.extend(collect_gaps(&change.source_revisions));

    let approvals = match change.approval_decisions.value() {
        Some(approvals) => approvals,
        None => {
            return ControlFinding::indeterminate(
                builtin::id(builtin::TWO_PARTY_REVIEW),
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
                builtin::id(builtin::TWO_PARTY_REVIEW),
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
            builtin::id(builtin::TWO_PARTY_REVIEW),
            "Two-party review cannot be proven from partial evidence",
            vec![subject],
            gaps,
        );
    }

    let requester = change
        .submitted_by
        .as_deref()
        .expect("submitted_by guaranteed Some: early return on missing field");

    let independent_count = approvals
        .iter()
        .filter(|approval| {
            if approval.disposition != ApprovalDisposition::Approved {
                return false;
            }
            let is_commit_author = authors.contains(&approval.actor.as_str());
            let is_pr_author = approval.actor == requester;
            is_approver_independent(is_commit_author, is_pr_author)
        })
        .count();

    match two_party_review_severity(independent_count) {
        Severity::Pass => ControlFinding::satisfied(
            builtin::id(builtin::TWO_PARTY_REVIEW),
            format!("{independent_count} independent approver(s) found (>= 2 required)"),
            vec![subject],
        ),
        _ => ControlFinding::violated(
            builtin::id(builtin::TWO_PARTY_REVIEW),
            format!("Only {independent_count} independent approver(s) found; at least 2 required"),
            vec![subject],
        ),
    }
}

fn collect_gaps<T>(state: &EvidenceState<T>) -> Vec<EvidenceGap> {
    state.gaps().to_vec()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::control::ControlStatus;
    use crate::evidence::{
        ApprovalDecision, AuthenticityEvidence, ChangeRequestId, EvidenceBundle, SourceRevision,
    };

    fn make_change(approvers: Vec<&str>) -> GovernedChange {
        let decisions = approvers
            .into_iter()
            .map(|actor| ApprovalDecision {
                actor: actor.to_string(),
                disposition: ApprovalDisposition::Approved,
                submitted_at: Some("2026-03-15T00:00:00Z".to_string()),
            })
            .collect();

        GovernedChange {
            id: ChangeRequestId::new("github_pr", "owner/repo#1"),
            title: "feat: add new control".to_string(),
            summary: None,
            submitted_by: Some("author".to_string()),
            changed_assets: EvidenceState::complete(vec![]),
            approval_decisions: EvidenceState::complete(decisions),
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

    fn bundle(change: GovernedChange) -> EvidenceBundle {
        EvidenceBundle {
            change_requests: vec![change],
            ..Default::default()
        }
    }

    #[test]
    fn satisfied_with_two_independent_approvers() {
        let change = make_change(vec!["reviewer-a", "reviewer-b"]);
        let findings = TwoPartyReviewControl.evaluate(&bundle(change));
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].status, ControlStatus::Satisfied);
        assert!(findings[0].rationale.contains("2"));
    }

    #[test]
    fn violated_with_only_one_independent_approver() {
        let change = make_change(vec!["reviewer-a"]);
        let findings = TwoPartyReviewControl.evaluate(&bundle(change));
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].status, ControlStatus::Violated);
        assert!(findings[0].rationale.contains("1"));
    }

    #[test]
    fn violated_when_self_approval_reduces_count() {
        // author + one independent = only 1 independent
        let change = make_change(vec!["author", "reviewer-a"]);
        let findings = TwoPartyReviewControl.evaluate(&bundle(change));
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].status, ControlStatus::Violated);
    }

    #[test]
    fn not_applicable_when_no_changes() {
        let evidence = EvidenceBundle::default();
        let findings = TwoPartyReviewControl.evaluate(&evidence);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].status, ControlStatus::NotApplicable);
    }

    #[test]
    fn indeterminate_when_approvals_missing() {
        let mut change = make_change(vec![]);
        change.approval_decisions = EvidenceState::missing(vec![EvidenceGap::CollectionFailed {
            source: "github".to_string(),
            subject: "reviews".to_string(),
            detail: "API error".to_string(),
        }]);
        let findings = TwoPartyReviewControl.evaluate(&bundle(change));
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].status, ControlStatus::Indeterminate);
    }

    #[test]
    fn indeterminate_when_revisions_missing() {
        let mut change = make_change(vec!["reviewer-a", "reviewer-b"]);
        change.source_revisions = EvidenceState::missing(vec![EvidenceGap::CollectionFailed {
            source: "github".to_string(),
            subject: "commits".to_string(),
            detail: "API error".to_string(),
        }]);
        let findings = TwoPartyReviewControl.evaluate(&bundle(change));
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].status, ControlStatus::Indeterminate);
    }

    #[test]
    fn satisfied_with_three_independent_approvers() {
        let change = make_change(vec!["reviewer-a", "reviewer-b", "reviewer-c"]);
        let findings = TwoPartyReviewControl.evaluate(&bundle(change));
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].status, ControlStatus::Satisfied);
        assert!(findings[0].rationale.contains("3"));
    }

    #[test]
    fn violated_when_zero_approvals() {
        let change = make_change(vec![]);
        let findings = TwoPartyReviewControl.evaluate(&bundle(change));
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].status, ControlStatus::Violated);
        assert!(findings[0].rationale.contains("0"));
    }

    #[test]
    fn indeterminate_when_submitted_by_missing() {
        let mut change = make_change(vec!["reviewer-a", "reviewer-b"]);
        change.submitted_by = None;
        let findings = TwoPartyReviewControl.evaluate(&bundle(change));
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].status, ControlStatus::Indeterminate);
    }

    #[test]
    fn correct_control_id() {
        assert_eq!(
            TwoPartyReviewControl.id(),
            builtin::id(builtin::TWO_PARTY_REVIEW)
        );
    }
}
