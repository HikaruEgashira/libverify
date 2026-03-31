use crate::control::{Control, ControlFinding, ControlId, builtin};
use crate::evidence::EvidenceBundle;

/// Validates that stale pull request reviews are dismissed on new push.
///
/// Maps to SOC2 CC8.1: ensure that approved reviews remain valid for the
/// final state of the code. Without this setting, a developer can obtain
/// approval and then push additional unreviewed changes before merge.
pub struct DismissStaleReviewsOnPushControl;

impl Control for DismissStaleReviewsOnPushControl {
    fn id(&self) -> ControlId {
        builtin::id(builtin::DISMISS_STALE_REVIEWS_ON_PUSH)
    }

    fn description(&self) -> &'static str {
        "Stale reviews must be dismissed on new push to ensure approvals cover final code"
    }

    fn evaluate(&self, evidence: &EvidenceBundle) -> Vec<ControlFinding> {
        let posture = match ControlFinding::extract_posture(self.id(), evidence) {
            Ok(p) => p,
            Err(findings) => return findings,
        };

        if !posture.default_branch_protected {
            return vec![ControlFinding::violated(
                self.id(),
                "Default branch has no protection rules — stale review dismissal cannot be evaluated",
                vec!["repository:branch-protection".into()],
            )];
        }

        if posture.dismiss_stale_reviews {
            vec![ControlFinding::satisfied(
                self.id(),
                "Stale reviews are automatically dismissed on new push — approvals always cover the final code",
                vec!["repository:branch-protection:dismiss-stale-reviews".into()],
            )]
        } else {
            vec![ControlFinding::violated(
                self.id(),
                "Stale reviews are not dismissed on new push — approved code may differ from merged code",
                vec!["repository:branch-protection:dismiss-stale-reviews".into()],
            )]
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::control::ControlStatus;
    use crate::evidence::{EvidenceGap, EvidenceState, RepositoryPosture};

    fn posture(protected: bool, dismiss_stale: bool) -> RepositoryPosture {
        RepositoryPosture {
            default_branch_protected: protected,
            dismiss_stale_reviews: dismiss_stale,
            ..Default::default()
        }
    }

    fn bundle(state: EvidenceState<RepositoryPosture>) -> EvidenceBundle {
        EvidenceBundle {
            repository_posture: state,
            ..Default::default()
        }
    }

    #[test]
    fn not_applicable_when_posture_not_applicable() {
        let findings =
            DismissStaleReviewsOnPushControl.evaluate(&bundle(EvidenceState::not_applicable()));
        assert_eq!(findings[0].status, ControlStatus::NotApplicable);
    }

    #[test]
    fn indeterminate_when_posture_missing() {
        let findings =
            DismissStaleReviewsOnPushControl.evaluate(&bundle(EvidenceState::missing(vec![
                EvidenceGap::CollectionFailed {
                    source: "github".to_string(),
                    subject: "posture".to_string(),
                    detail: "API error".to_string(),
                },
            ])));
        assert_eq!(findings[0].status, ControlStatus::Indeterminate);
    }

    #[test]
    fn satisfied_when_dismiss_stale_reviews_enabled() {
        let findings = DismissStaleReviewsOnPushControl
            .evaluate(&bundle(EvidenceState::complete(posture(true, true))));
        assert_eq!(findings[0].status, ControlStatus::Satisfied);
        assert!(
            findings[0]
                .rationale
                .contains("automatically dismissed on new push")
        );
    }

    #[test]
    fn violated_when_dismiss_stale_reviews_disabled() {
        let findings = DismissStaleReviewsOnPushControl
            .evaluate(&bundle(EvidenceState::complete(posture(true, false))));
        assert_eq!(findings[0].status, ControlStatus::Violated);
        assert!(findings[0].rationale.contains("not dismissed on new push"));
    }

    #[test]
    fn violated_when_no_branch_protection() {
        let findings = DismissStaleReviewsOnPushControl
            .evaluate(&bundle(EvidenceState::complete(posture(false, false))));
        assert_eq!(findings[0].status, ControlStatus::Violated);
        assert!(findings[0].rationale.contains("no protection rules"));
    }
}
