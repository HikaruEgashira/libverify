use crate::control::{Control, ControlFinding, ControlId, builtin};
use crate::evidence::{
    ApprovalDisposition, CheckConclusion, EvidenceBundle, EvidenceState, GovernedChange,
};
use crate::integrity::{branch_protection_enforcement_severity, is_approver_independent};
use crate::verdict::Severity;

/// Source L3: Verifies that continuous technical controls were actually enforced
/// by checking factual evidence: all CI checks passed AND an independent review
/// approved the change.
///
/// Instead of checking branch protection API settings (which require admin permissions),
/// this control examines whether the enforcement actually happened.
/// See ADR-0002 for rationale.
pub struct BranchProtectionEnforcementControl;

impl Control for BranchProtectionEnforcementControl {
    fn id(&self) -> ControlId {
        builtin::id(builtin::BRANCH_PROTECTION_ENFORCEMENT)
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
            .map(|cr| evaluate_change(id.clone(), cr, &evidence.check_runs))
            .collect()
    }
}

fn evaluate_change(
    id: ControlId,
    change: &GovernedChange,
    check_runs: &EvidenceState<Vec<crate::evidence::CheckRunEvidence>>,
) -> ControlFinding {
    let subject = change.id.to_string();
    let mut violations = Vec::new();

    // Check 1: CI checks all passed
    match check_runs {
        EvidenceState::NotApplicable => {}
        EvidenceState::Missing { gaps } => {
            return ControlFinding::indeterminate(
                id,
                "Check runs evidence could not be collected",
                vec![subject],
                gaps.clone(),
            );
        }
        EvidenceState::Complete { value } | EvidenceState::Partial { value, .. } => {
            if value.is_empty() {
                violations.push("no CI checks were executed".to_string());
            } else {
                let failed: Vec<&str> = value
                    .iter()
                    .filter(|r| is_failing_conclusion(&r.conclusion))
                    .map(|r| r.name.as_str())
                    .collect();
                if !failed.is_empty() {
                    violations.push(format!("CI check(s) failed: {}", failed.join(", ")));
                }
            }
        }
    }

    // Check 2: Independent review approval exists
    match &change.approval_decisions {
        EvidenceState::Missing { gaps } => {
            return ControlFinding::indeterminate(
                id,
                "Approval evidence could not be collected",
                vec![subject],
                gaps.clone(),
            );
        }
        EvidenceState::NotApplicable => {}
        EvidenceState::Complete { value } | EvidenceState::Partial { value, .. } => {
            let authors: Vec<&str> = change
                .source_revisions
                .value()
                .map(|revs| {
                    revs.iter()
                        .filter_map(|r| r.authored_by.as_deref())
                        .collect()
                })
                .unwrap_or_default();

            let requester = change.submitted_by.as_deref().unwrap_or("");

            let has_independent = value.iter().any(|a| {
                if a.disposition != ApprovalDisposition::Approved {
                    return false;
                }
                let is_commit_author = authors.contains(&a.actor.as_str());
                let is_pr_author = a.actor == requester;
                is_approver_independent(is_commit_author, is_pr_author)
            });

            if !has_independent {
                violations.push("no independent review approval found".to_string());
            }
        }
    }

    match branch_protection_enforcement_severity(violations.len()) {
        Severity::Pass => ControlFinding::satisfied(
            id,
            "Technical controls were enforced: CI checks passed and independent review approved",
            vec![subject],
        ),
        _ => ControlFinding::violated(
            id,
            format!("Enforcement gaps: {}", violations.join("; ")),
            vec![subject],
        ),
    }
}

fn is_failing_conclusion(conclusion: &CheckConclusion) -> bool {
    matches!(
        conclusion,
        CheckConclusion::Failure
            | CheckConclusion::Cancelled
            | CheckConclusion::TimedOut
            | CheckConclusion::ActionRequired
            | CheckConclusion::Pending
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::control::ControlStatus;
    use crate::evidence::{
        ApprovalDecision, AuthenticityEvidence, ChangeRequestId, CheckRunEvidence, EvidenceGap,
        SourceRevision,
    };

    fn make_change(
        approvals: EvidenceState<Vec<ApprovalDecision>>,
        revisions: EvidenceState<Vec<SourceRevision>>,
    ) -> GovernedChange {
        GovernedChange {
            id: ChangeRequestId::new("github_pr", "owner/repo#1"),
            title: "feat: test".to_string(),
            summary: None,
            submitted_by: Some("author".to_string()),
            changed_assets: EvidenceState::complete(vec![]),
            approval_decisions: approvals,
            source_revisions: revisions,
            work_item_refs: EvidenceState::complete(vec![]),
        }
    }

    fn make_approved_change() -> GovernedChange {
        make_change(
            EvidenceState::complete(vec![ApprovalDecision {
                actor: "reviewer".to_string(),
                disposition: ApprovalDisposition::Approved,
                submitted_at: Some("2026-03-15T00:00:00Z".to_string()),
            }]),
            EvidenceState::complete(vec![SourceRevision {
                id: "abc123".to_string(),
                authored_by: Some("author".to_string()),
                committed_at: Some("2026-03-14T00:00:00Z".to_string()),
                merge: false,
                authenticity: EvidenceState::complete(AuthenticityEvidence::new(
                    true,
                    Some("gpg".to_string()),
                )),
            }]),
        )
    }

    fn passing_checks() -> EvidenceState<Vec<CheckRunEvidence>> {
        EvidenceState::complete(vec![
            CheckRunEvidence {
                name: "ci/build".to_string(),
                conclusion: CheckConclusion::Success,
                app_slug: None,
            },
            CheckRunEvidence {
                name: "ci/test".to_string(),
                conclusion: CheckConclusion::Success,
                app_slug: None,
            },
        ])
    }

    fn failing_checks() -> EvidenceState<Vec<CheckRunEvidence>> {
        EvidenceState::complete(vec![
            CheckRunEvidence {
                name: "ci/build".to_string(),
                conclusion: CheckConclusion::Success,
                app_slug: None,
            },
            CheckRunEvidence {
                name: "ci/test".to_string(),
                conclusion: CheckConclusion::Failure,
                app_slug: None,
            },
        ])
    }

    #[test]
    fn not_applicable_when_no_changes() {
        let evidence = EvidenceBundle {
            check_runs: passing_checks(),
            ..Default::default()
        };
        let findings = BranchProtectionEnforcementControl.evaluate(&evidence);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].status, ControlStatus::NotApplicable);
    }

    #[test]
    fn satisfied_when_checks_pass_and_independent_review() {
        let evidence = EvidenceBundle {
            change_requests: vec![make_approved_change()],
            check_runs: passing_checks(),
            ..Default::default()
        };
        let findings = BranchProtectionEnforcementControl.evaluate(&evidence);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].status, ControlStatus::Satisfied);
        assert!(
            findings[0]
                .rationale
                .contains("Technical controls were enforced")
        );
    }

    #[test]
    fn violated_when_checks_fail() {
        let evidence = EvidenceBundle {
            change_requests: vec![make_approved_change()],
            check_runs: failing_checks(),
            ..Default::default()
        };
        let findings = BranchProtectionEnforcementControl.evaluate(&evidence);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].status, ControlStatus::Violated);
        assert!(findings[0].rationale.contains("CI check(s) failed"));
    }

    #[test]
    fn violated_when_no_independent_review() {
        let change = make_change(
            EvidenceState::complete(vec![ApprovalDecision {
                actor: "author".to_string(), // self-approval
                disposition: ApprovalDisposition::Approved,
                submitted_at: None,
            }]),
            EvidenceState::complete(vec![SourceRevision {
                id: "abc123".to_string(),
                authored_by: Some("author".to_string()),
                committed_at: None,
                merge: false,
                authenticity: EvidenceState::not_applicable(),
            }]),
        );
        let evidence = EvidenceBundle {
            change_requests: vec![change],
            check_runs: passing_checks(),
            ..Default::default()
        };
        let findings = BranchProtectionEnforcementControl.evaluate(&evidence);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].status, ControlStatus::Violated);
        assert!(findings[0].rationale.contains("no independent review"));
    }

    #[test]
    fn violated_when_no_checks_executed() {
        let evidence = EvidenceBundle {
            change_requests: vec![make_approved_change()],
            check_runs: EvidenceState::complete(vec![]),
            ..Default::default()
        };
        let findings = BranchProtectionEnforcementControl.evaluate(&evidence);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].status, ControlStatus::Violated);
        assert!(findings[0].rationale.contains("no CI checks were executed"));
    }

    #[test]
    fn violated_reports_both_gaps() {
        let change = make_change(
            EvidenceState::complete(vec![]), // no approvals
            EvidenceState::complete(vec![]),
        );
        let evidence = EvidenceBundle {
            change_requests: vec![change],
            check_runs: EvidenceState::complete(vec![]), // no checks
            ..Default::default()
        };
        let findings = BranchProtectionEnforcementControl.evaluate(&evidence);
        assert_eq!(findings[0].status, ControlStatus::Violated);
        assert!(findings[0].rationale.contains("no CI checks"));
        assert!(findings[0].rationale.contains("no independent review"));
    }

    #[test]
    fn indeterminate_when_check_runs_missing() {
        let evidence = EvidenceBundle {
            change_requests: vec![make_approved_change()],
            check_runs: EvidenceState::missing(vec![EvidenceGap::CollectionFailed {
                source: "github".to_string(),
                subject: "check-runs".to_string(),
                detail: "API returned 403".to_string(),
            }]),
            ..Default::default()
        };
        let findings = BranchProtectionEnforcementControl.evaluate(&evidence);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].status, ControlStatus::Indeterminate);
    }

    #[test]
    fn indeterminate_when_approvals_missing() {
        let change = make_change(
            EvidenceState::missing(vec![EvidenceGap::CollectionFailed {
                source: "github".to_string(),
                subject: "reviews".to_string(),
                detail: "API returned 403".to_string(),
            }]),
            EvidenceState::complete(vec![]),
        );
        let evidence = EvidenceBundle {
            change_requests: vec![change],
            check_runs: passing_checks(),
            ..Default::default()
        };
        let findings = BranchProtectionEnforcementControl.evaluate(&evidence);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].status, ControlStatus::Indeterminate);
    }

    #[test]
    fn correct_control_id() {
        assert_eq!(
            BranchProtectionEnforcementControl.id(),
            builtin::id(builtin::BRANCH_PROTECTION_ENFORCEMENT)
        );
    }
}
