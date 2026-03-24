use crate::control::{Control, ControlFinding, ControlId, builtin};
use crate::evidence::{EvidenceBundle, EvidenceState, GovernedChange};

/// Verifies that change requests reference at least one issue or ticket.
pub struct IssueLinkageControl;

impl Control for IssueLinkageControl {
    fn id(&self) -> ControlId {
        builtin::id(builtin::ISSUE_LINKAGE)
    }

    fn description(&self) -> &'static str {
        "Change request must reference at least one issue or ticket"
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

    match &cr.work_item_refs {
        EvidenceState::NotApplicable => {
            ControlFinding::not_applicable(id, "Issue linkage not applicable")
        }
        EvidenceState::Missing { gaps } => ControlFinding::indeterminate(
            id,
            format!("{cr_subject}: issue linkage evidence could not be collected"),
            vec![cr_subject],
            gaps.clone(),
        ),
        EvidenceState::Complete { value } | EvidenceState::Partial { value, .. } => {
            if value.is_empty() {
                ControlFinding::violated(
                    id,
                    format!("{cr_subject}: no issue or ticket references found"),
                    vec![cr_subject],
                )
            } else {
                let subjects: Vec<String> = value
                    .iter()
                    .map(|r| format!("{}:{}", r.system, r.value))
                    .collect();
                ControlFinding::satisfied(
                    id,
                    format!(
                        "{cr_subject}: references {} issue(s)/ticket(s)",
                        value.len()
                    ),
                    subjects,
                )
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::control::ControlStatus;
    use crate::evidence::{ChangeRequestId, EvidenceGap, WorkItemRef};

    fn make_change(refs: EvidenceState<Vec<WorkItemRef>>) -> GovernedChange {
        GovernedChange {
            id: ChangeRequestId::new("test", "owner/repo#1"),
            title: "test".to_string(),
            summary: None,
            submitted_by: None,
            changed_assets: EvidenceState::not_applicable(),
            approval_decisions: EvidenceState::not_applicable(),
            source_revisions: EvidenceState::not_applicable(),
            work_item_refs: refs,
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
        let findings = IssueLinkageControl.evaluate(&EvidenceBundle::default());
        assert_eq!(findings[0].status, ControlStatus::NotApplicable);
    }

    #[test]
    fn satisfied_when_refs_present() {
        let cr = make_change(EvidenceState::complete(vec![WorkItemRef {
            system: "github_issue".to_string(),
            value: "#42".to_string(),
        }]));
        let findings = IssueLinkageControl.evaluate(&bundle(vec![cr]));
        assert_eq!(findings[0].status, ControlStatus::Satisfied);
        assert!(findings[0].subjects.iter().any(|s| s.contains("#42")));
    }

    #[test]
    fn violated_when_no_refs() {
        let cr = make_change(EvidenceState::complete(vec![]));
        let findings = IssueLinkageControl.evaluate(&bundle(vec![cr]));
        assert_eq!(findings[0].status, ControlStatus::Violated);
    }

    #[test]
    fn indeterminate_when_missing() {
        let cr = make_change(EvidenceState::missing(vec![
            EvidenceGap::CollectionFailed {
                source: "github".to_string(),
                subject: "body".to_string(),
                detail: "parse error".to_string(),
            },
        ]));
        let findings = IssueLinkageControl.evaluate(&bundle(vec![cr]));
        assert_eq!(findings[0].status, ControlStatus::Indeterminate);
    }
}
