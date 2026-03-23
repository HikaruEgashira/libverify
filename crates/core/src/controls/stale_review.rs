use crate::control::{Control, ControlFinding, ControlId, builtin};
use crate::evidence::{ApprovalDisposition, EvidenceBundle, EvidenceState, GovernedChange};

/// Detects approval decisions that predate the latest non-merge source revision.
///
/// Maps to SOC2 CC7.2: monitoring for anomalies in change governance.
/// A review approved before subsequent code changes is stale and may not
/// reflect the final state of the change request.
pub struct StaleReviewControl;

impl Control for StaleReviewControl {
    fn id(&self) -> ControlId {
        builtin::id(builtin::STALE_REVIEW)
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

    let approvals = match &cr.approval_decisions {
        EvidenceState::Complete { value } | EvidenceState::Partial { value, .. } => value,
        EvidenceState::Missing { gaps } => {
            return ControlFinding::indeterminate(
                id,
                format!("{cr_subject}: approval evidence could not be collected"),
                vec![cr_subject],
                gaps.clone(),
            );
        }
        EvidenceState::NotApplicable => {
            return ControlFinding::not_applicable(id, "Approval decisions not applicable");
        }
    };

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

    // Find the latest non-merge commit timestamp.
    let latest_commit_ts = revisions
        .iter()
        .filter(|r| !r.merge)
        .filter_map(|r| r.committed_at.as_deref())
        .max();

    let latest_commit_ts = match latest_commit_ts {
        Some(ts) => ts,
        None => {
            return ControlFinding::not_applicable(
                id,
                format!("{cr_subject}: no non-merge commits with timestamps"),
            );
        }
    };

    // Check each approval: if submitted_at < latest_commit_ts, it is stale.
    let stale_approvals: Vec<String> = approvals
        .iter()
        .filter(|a| a.disposition == ApprovalDisposition::Approved)
        .filter(|a| {
            a.submitted_at
                .as_deref()
                .is_some_and(|ts| ts < latest_commit_ts)
        })
        .map(|a| a.actor.clone())
        .collect();

    if stale_approvals.is_empty() {
        // Check if there are any approvals at all.
        let has_approvals = approvals
            .iter()
            .any(|a| a.disposition == ApprovalDisposition::Approved);
        if !has_approvals {
            return ControlFinding::not_applicable(
                id,
                format!("{cr_subject}: no approval decisions to evaluate for staleness"),
            );
        }
        ControlFinding::satisfied(
            id,
            format!("{cr_subject}: all approvals postdate the latest source revision"),
            vec![cr_subject],
        )
    } else {
        ControlFinding::violated(
            id,
            format!(
                "{cr_subject}: {} approval(s) predate the latest commit ({}): {}",
                stale_approvals.len(),
                latest_commit_ts,
                stale_approvals.join(", ")
            ),
            stale_approvals,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::control::ControlStatus;
    use crate::evidence::{ApprovalDecision, ChangeRequestId, EvidenceGap, SourceRevision};

    fn make_change(
        approvals: EvidenceState<Vec<ApprovalDecision>>,
        revisions: EvidenceState<Vec<SourceRevision>>,
    ) -> GovernedChange {
        GovernedChange {
            id: ChangeRequestId::new("github_pr", "owner/repo#1"),
            title: "test".to_string(),
            summary: None,
            submitted_by: None,
            changed_assets: EvidenceState::not_applicable(),
            approval_decisions: approvals,
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

    fn approval(actor: &str, ts: &str) -> ApprovalDecision {
        ApprovalDecision {
            actor: actor.to_string(),
            disposition: ApprovalDisposition::Approved,
            submitted_at: Some(ts.to_string()),
        }
    }

    fn revision(id: &str, ts: &str, merge: bool) -> SourceRevision {
        SourceRevision {
            id: id.to_string(),
            authored_by: Some("dev".to_string()),
            committed_at: Some(ts.to_string()),
            merge,
            authenticity: EvidenceState::not_applicable(),
        }
    }

    #[test]
    fn not_applicable_when_no_changes() {
        let findings = StaleReviewControl.evaluate(&EvidenceBundle::default());
        assert_eq!(findings[0].status, ControlStatus::NotApplicable);
    }

    #[test]
    fn satisfied_when_approval_postdates_latest_commit() {
        let cr = make_change(
            EvidenceState::complete(vec![approval("reviewer", "2026-03-15T12:00:00Z")]),
            EvidenceState::complete(vec![revision("abc", "2026-03-15T10:00:00Z", false)]),
        );
        let findings = StaleReviewControl.evaluate(&bundle(vec![cr]));
        assert_eq!(findings[0].status, ControlStatus::Satisfied);
    }

    #[test]
    fn violated_when_approval_predates_latest_commit() {
        let cr = make_change(
            EvidenceState::complete(vec![approval("reviewer", "2026-03-15T10:00:00Z")]),
            EvidenceState::complete(vec![revision("abc", "2026-03-15T12:00:00Z", false)]),
        );
        let findings = StaleReviewControl.evaluate(&bundle(vec![cr]));
        assert_eq!(findings[0].status, ControlStatus::Violated);
        assert!(findings[0].rationale.contains("reviewer"));
    }

    #[test]
    fn ignores_merge_commits_for_latest_timestamp() {
        let cr = make_change(
            EvidenceState::complete(vec![approval("reviewer", "2026-03-15T11:00:00Z")]),
            EvidenceState::complete(vec![
                revision("abc", "2026-03-15T10:00:00Z", false),
                revision("merge", "2026-03-15T14:00:00Z", true),
            ]),
        );
        let findings = StaleReviewControl.evaluate(&bundle(vec![cr]));
        assert_eq!(findings[0].status, ControlStatus::Satisfied);
    }

    #[test]
    fn indeterminate_when_approvals_missing() {
        let cr = make_change(
            EvidenceState::missing(vec![EvidenceGap::CollectionFailed {
                source: "github".to_string(),
                subject: "reviews".to_string(),
                detail: "API error".to_string(),
            }]),
            EvidenceState::complete(vec![revision("abc", "2026-03-15T10:00:00Z", false)]),
        );
        let findings = StaleReviewControl.evaluate(&bundle(vec![cr]));
        assert_eq!(findings[0].status, ControlStatus::Indeterminate);
    }

    #[test]
    fn not_applicable_when_no_approvals() {
        let cr = make_change(
            EvidenceState::complete(vec![]),
            EvidenceState::complete(vec![revision("abc", "2026-03-15T10:00:00Z", false)]),
        );
        let findings = StaleReviewControl.evaluate(&bundle(vec![cr]));
        assert_eq!(findings[0].status, ControlStatus::NotApplicable);
    }
}
