use crate::control::{builtin, Control, ControlFinding, ControlId};
use crate::evidence::{EvidenceBundle, EvidenceState, PromotionBatch};

/// Verifies that release promotion batches have linked change requests.
///
/// Maps to SOC2 CC7.1: change traceability through the release pipeline.
/// Every release should trace back to governed change requests (PRs) to
/// maintain a complete audit trail from code change to production deployment.
pub struct ReleaseTraceabilityControl;

impl Control for ReleaseTraceabilityControl {
    fn id(&self) -> ControlId {
        builtin::id(builtin::RELEASE_TRACEABILITY)
    }

    fn evaluate(&self, evidence: &EvidenceBundle) -> Vec<ControlFinding> {
        if evidence.promotion_batches.is_empty() {
            return vec![ControlFinding::not_applicable(
                self.id(),
                "No promotion batches found",
            )];
        }

        evidence
            .promotion_batches
            .iter()
            .map(|batch| evaluate_batch(self.id(), batch))
            .collect()
    }
}

fn evaluate_batch(id: ControlId, batch: &PromotionBatch) -> ControlFinding {
    let batch_subject = batch.id.clone();

    match &batch.linked_change_requests {
        EvidenceState::NotApplicable => {
            ControlFinding::not_applicable(id, "Linked change requests not applicable")
        }
        EvidenceState::Missing { gaps } => ControlFinding::indeterminate(
            id,
            format!("{batch_subject}: linked change request evidence could not be collected"),
            vec![batch_subject],
            gaps.clone(),
        ),
        EvidenceState::Complete { value } | EvidenceState::Partial { value, .. } => {
            if value.is_empty() {
                ControlFinding::violated(
                    id,
                    format!(
                        "{batch_subject}: no linked change requests found — release has no PR traceability"
                    ),
                    vec![batch_subject],
                )
            } else {
                let cr_ids: Vec<String> = value.iter().map(|cr| cr.to_string()).collect();
                ControlFinding::satisfied(
                    id,
                    format!(
                        "{batch_subject}: traces to {} change request(s)",
                        value.len()
                    ),
                    cr_ids,
                )
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::control::ControlStatus;
    use crate::evidence::{ChangeRequestId, EvidenceGap, SourceRevision};

    fn make_batch(linked_crs: EvidenceState<Vec<ChangeRequestId>>) -> PromotionBatch {
        PromotionBatch {
            id: "github_release:owner/repo:v0.1.0..v0.2.0".to_string(),
            source_revisions: EvidenceState::complete(vec![SourceRevision {
                id: "abc123".to_string(),
                authored_by: Some("dev".to_string()),
                committed_at: None,
                merge: false,
                authenticity: EvidenceState::not_applicable(),
            }]),
            linked_change_requests: linked_crs,
        }
    }

    fn bundle(batches: Vec<PromotionBatch>) -> EvidenceBundle {
        EvidenceBundle {
            promotion_batches: batches,
            ..Default::default()
        }
    }

    #[test]
    fn not_applicable_when_no_batches() {
        let findings = ReleaseTraceabilityControl.evaluate(&EvidenceBundle::default());
        assert_eq!(findings[0].status, ControlStatus::NotApplicable);
    }

    #[test]
    fn satisfied_when_crs_linked() {
        let batch = make_batch(EvidenceState::complete(vec![
            ChangeRequestId::new("github_pr", "owner/repo#1"),
            ChangeRequestId::new("github_pr", "owner/repo#2"),
        ]));
        let findings = ReleaseTraceabilityControl.evaluate(&bundle(vec![batch]));
        assert_eq!(findings[0].status, ControlStatus::Satisfied);
        assert!(findings[0].rationale.contains("2 change request(s)"));
    }

    #[test]
    fn violated_when_no_crs_linked() {
        let batch = make_batch(EvidenceState::complete(vec![]));
        let findings = ReleaseTraceabilityControl.evaluate(&bundle(vec![batch]));
        assert_eq!(findings[0].status, ControlStatus::Violated);
        assert!(findings[0].rationale.contains("no linked change requests"));
    }

    #[test]
    fn indeterminate_when_evidence_missing() {
        let batch = make_batch(EvidenceState::missing(vec![
            EvidenceGap::CollectionFailed {
                source: "github".to_string(),
                subject: "commits".to_string(),
                detail: "API error".to_string(),
            },
        ]));
        let findings = ReleaseTraceabilityControl.evaluate(&bundle(vec![batch]));
        assert_eq!(findings[0].status, ControlStatus::Indeterminate);
    }

    #[test]
    fn not_applicable_when_crs_not_applicable() {
        let batch = make_batch(EvidenceState::not_applicable());
        let findings = ReleaseTraceabilityControl.evaluate(&bundle(vec![batch]));
        assert_eq!(findings[0].status, ControlStatus::NotApplicable);
    }
}
