use crate::control::{Control, ControlFinding, ControlId, builtin};
use crate::evidence::{EvidenceBundle, GovernedChange};

/// Minimum body length (in characters) for a change request description.
const MIN_BODY_LENGTH: usize = 10;

/// Verifies that change requests include a meaningful description.
///
/// Maps to SOC2 CC8.1: change management documentation.
/// A well-documented change request ensures reviewers understand intent,
/// scope, and rationale before approving.
pub struct DescriptionQualityControl;

impl Control for DescriptionQualityControl {
    fn id(&self) -> ControlId {
        builtin::id(builtin::DESCRIPTION_QUALITY)
    }

    fn description(&self) -> &'static str {
        "Change requests must include a meaningful description"
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

    let body = cr.summary.as_deref().unwrap_or("").trim();

    if body.is_empty() {
        return ControlFinding::violated(
            id,
            format!("{cr_subject}: change request has no description"),
            vec![cr_subject],
        );
    }

    if body.len() < MIN_BODY_LENGTH {
        return ControlFinding::violated(
            id,
            format!(
                "{cr_subject}: description too short ({} chars, minimum {MIN_BODY_LENGTH})",
                body.len()
            ),
            vec![cr_subject],
        );
    }

    ControlFinding::satisfied(
        id,
        format!("{cr_subject}: description present ({} chars)", body.len()),
        vec![cr_subject],
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::control::ControlStatus;
    use crate::evidence::{ChangeRequestId, EvidenceState};

    fn make_change(summary: Option<&str>) -> GovernedChange {
        GovernedChange {
            id: ChangeRequestId::new("test", "owner/repo#1"),
            title: "test".to_string(),
            summary: summary.map(|s| s.to_string()),
            submitted_by: None,
            changed_assets: EvidenceState::not_applicable(),
            approval_decisions: EvidenceState::not_applicable(),
            source_revisions: EvidenceState::not_applicable(),
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
        let findings = DescriptionQualityControl.evaluate(&EvidenceBundle::default());
        assert_eq!(findings[0].status, ControlStatus::NotApplicable);
    }

    #[test]
    fn satisfied_when_body_present() {
        let cr = make_change(Some(
            "This PR adds a new compliance control for description quality.",
        ));
        let findings = DescriptionQualityControl.evaluate(&bundle(vec![cr]));
        assert_eq!(findings[0].status, ControlStatus::Satisfied);
    }

    #[test]
    fn violated_when_body_none() {
        let cr = make_change(None);
        let findings = DescriptionQualityControl.evaluate(&bundle(vec![cr]));
        assert_eq!(findings[0].status, ControlStatus::Violated);
        assert!(findings[0].rationale.contains("no description"));
    }

    #[test]
    fn violated_when_body_empty() {
        let cr = make_change(Some(""));
        let findings = DescriptionQualityControl.evaluate(&bundle(vec![cr]));
        assert_eq!(findings[0].status, ControlStatus::Violated);
    }

    #[test]
    fn violated_when_body_too_short() {
        let cr = make_change(Some("fix"));
        let findings = DescriptionQualityControl.evaluate(&bundle(vec![cr]));
        assert_eq!(findings[0].status, ControlStatus::Violated);
        assert!(findings[0].rationale.contains("too short"));
    }

    #[test]
    fn violated_when_body_only_whitespace() {
        let cr = make_change(Some("   \n\t  "));
        let findings = DescriptionQualityControl.evaluate(&bundle(vec![cr]));
        assert_eq!(findings[0].status, ControlStatus::Violated);
        assert!(findings[0].rationale.contains("no description"));
    }
}
