use crate::control::{builtin, Control, ControlFinding, ControlId};
use crate::evidence::{
    AuthenticityEvidence, EvidenceBundle, EvidenceGap, EvidenceState, SourceRevision,
};
use crate::integrity::signature_severity;
use crate::verdict::Severity;

/// Verifies that all source revisions carry valid cryptographic signatures.
pub struct SourceAuthenticityControl;

impl Control for SourceAuthenticityControl {
    fn id(&self) -> ControlId {
        builtin::id(builtin::SOURCE_AUTHENTICITY)
    }

    fn evaluate(&self, evidence: &EvidenceBundle) -> Vec<ControlFinding> {
        let mut findings = Vec::new();

        for change in &evidence.change_requests {
            findings.push(evaluate_revisions(
                change.id.to_string(),
                &change.source_revisions,
                "change request",
            ));
        }

        for batch in &evidence.promotion_batches {
            findings.push(evaluate_revisions(
                batch.id.clone(),
                &batch.source_revisions,
                "promotion batch",
            ));
        }

        if findings.is_empty() {
            findings.push(ControlFinding::not_applicable(
                self.id(),
                "No source revisions were supplied",
            ));
        }

        findings
    }
}

fn evaluate_revisions(
    subject: String,
    revisions_state: &EvidenceState<Vec<SourceRevision>>,
    scope_label: &str,
) -> ControlFinding {
    let mut gaps = revisions_state.gaps().to_vec();
    let revisions = match revisions_state.value() {
        Some(revisions) => revisions,
        None => {
            return ControlFinding::indeterminate(
                builtin::id(builtin::SOURCE_AUTHENTICITY),
                format!("Source authenticity evidence is unavailable for the {scope_label}"),
                vec![subject],
                gaps,
            );
        }
    };

    let mut unsigned = Vec::new();
    for revision in revisions {
        match authenticity_state(&revision.authenticity) {
            Ok(auth) => {
                if !auth.verified {
                    unsigned.push(revision.id.clone());
                }
            }
            Err(mut revision_gaps) => {
                gaps.append(&mut revision_gaps);
            }
        }
    }

    if !gaps.is_empty() {
        return ControlFinding::indeterminate(
            builtin::id(builtin::SOURCE_AUTHENTICITY),
            format!("Source authenticity cannot be proven for the {scope_label}"),
            vec![subject],
            gaps,
        );
    }

    match signature_severity(unsigned.len()) {
        Severity::Pass => ControlFinding::satisfied(
            builtin::id(builtin::SOURCE_AUTHENTICITY),
            format!("All revisions in the {scope_label} carry authenticity evidence"),
            vec![subject],
        ),
        _ => ControlFinding::violated(
            builtin::id(builtin::SOURCE_AUTHENTICITY),
            format!(
                "Unsigned or unverified revisions were found in the {scope_label}: {}",
                unsigned.join(", ")
            ),
            vec![subject],
        ),
    }
}

fn authenticity_state(
    state: &EvidenceState<AuthenticityEvidence>,
) -> Result<&AuthenticityEvidence, Vec<EvidenceGap>> {
    match state {
        EvidenceState::Complete { value } => Ok(value),
        EvidenceState::Partial { gaps, .. } | EvidenceState::Missing { gaps } => Err(gaps.clone()),
        EvidenceState::NotApplicable => Err(vec![EvidenceGap::Unsupported {
            source: "control-normalization".to_string(),
            capability: "source authenticity not collected for revision".to_string(),
        }]),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::control::ControlStatus;
    use crate::evidence::{ChangeRequestId, EvidenceBundle, GovernedChange, SourceRevision};

    fn make_change(verified: bool) -> GovernedChange {
        GovernedChange {
            id: ChangeRequestId::new("github_pr", "owner/repo#7"),
            title: "fix: sign commits".to_string(),
            summary: None,
            submitted_by: Some("author".to_string()),
            changed_assets: EvidenceState::complete(vec![]),
            approval_decisions: EvidenceState::complete(vec![]),
            source_revisions: EvidenceState::complete(vec![SourceRevision {
                id: "deadbeef".to_string(),
                authored_by: Some("author".to_string()),
                committed_at: Some("2026-03-15T00:00:00Z".to_string()),
                merge: false,
                authenticity: EvidenceState::complete(AuthenticityEvidence::new(
                    verified,
                    Some("gpg".to_string()),
                )),
            }]),
            work_item_refs: EvidenceState::complete(vec![]),
        }
    }

    #[test]
    fn verified_revisions_are_satisfied() {
        let findings = SourceAuthenticityControl.evaluate(&EvidenceBundle {
            change_requests: vec![make_change(true)],
            promotion_batches: vec![],
            ..Default::default()
        });
        assert_eq!(findings[0].status, ControlStatus::Satisfied);
    }

    #[test]
    fn unsigned_revisions_are_violated() {
        let findings = SourceAuthenticityControl.evaluate(&EvidenceBundle {
            change_requests: vec![make_change(false)],
            promotion_batches: vec![],
            ..Default::default()
        });
        assert_eq!(findings[0].status, ControlStatus::Violated);
    }

    #[test]
    fn missing_authenticity_is_indeterminate() {
        let mut change = make_change(true);
        change.source_revisions = EvidenceState::complete(vec![SourceRevision {
            id: "deadbeef".to_string(),
            authored_by: Some("author".to_string()),
            committed_at: Some("2026-03-15T00:00:00Z".to_string()),
            merge: false,
            authenticity: EvidenceState::not_applicable(),
        }]);

        let findings = SourceAuthenticityControl.evaluate(&EvidenceBundle {
            change_requests: vec![change],
            promotion_batches: vec![],
            ..Default::default()
        });
        assert_eq!(findings[0].status, ControlStatus::Indeterminate);
    }
}
