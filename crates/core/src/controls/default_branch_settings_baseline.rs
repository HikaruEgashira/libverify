use crate::control::{Control, ControlFinding, ControlId, builtin};
use crate::evidence::EvidenceBundle;

/// Validates that the default branch has a minimum security baseline.
///
/// Maps to NIST 800-53 CM-2 (Baseline Configuration).
///
/// Requires ALL of the following to be satisfied:
/// - Branch protection is enabled on the default branch
/// - Admin enforcement is enabled (no bypass for admins)
/// - Stale reviews are dismissed on new push
///
/// This is a composite control that verifies multiple branch protection
/// settings together, providing a holistic "baseline" check rather than
/// individual setting checks.
pub struct DefaultBranchSettingsBaselineControl;

impl Control for DefaultBranchSettingsBaselineControl {
    fn id(&self) -> ControlId {
        builtin::id(builtin::DEFAULT_BRANCH_SETTINGS_BASELINE)
    }

    fn description(&self) -> &'static str {
        "Default branch must have protection baseline: protection enabled, admin enforcement, stale review dismissal"
    }

    fn evaluate(&self, evidence: &EvidenceBundle) -> Vec<ControlFinding> {
        let posture = match ControlFinding::extract_posture(self.id(), evidence) {
            Ok(p) => p,
            Err(findings) => return findings,
        };

        let mut missing = Vec::new();

        if !posture.default_branch_protected {
            missing.push("branch protection not enabled");
        }
        if !posture.enforce_admins {
            missing.push("admin enforcement not enabled");
        }
        if !posture.dismiss_stale_reviews {
            missing.push("stale review dismissal not enabled");
        }

        if missing.is_empty() {
            vec![ControlFinding::satisfied(
                self.id(),
                "Default branch meets security baseline: protection, admin enforcement, stale review dismissal all enabled",
                vec!["repository:branch-protection:baseline".into()],
            )]
        } else {
            vec![ControlFinding::violated(
                self.id(),
                format!(
                    "Default branch does not meet security baseline: {}",
                    missing.join(", ")
                ),
                vec!["repository:branch-protection:baseline".into()],
            )]
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::control::ControlStatus;
    use crate::evidence::{EvidenceState, RepositoryPosture};

    fn bundle_with(protected: bool, enforce: bool, dismiss: bool) -> EvidenceBundle {
        EvidenceBundle {
            repository_posture: EvidenceState::complete(RepositoryPosture {
                default_branch_protected: protected,
                enforce_admins: enforce,
                dismiss_stale_reviews: dismiss,
                ..Default::default()
            }),
            ..Default::default()
        }
    }

    #[test]
    fn satisfied_when_all_enabled() {
        let findings =
            DefaultBranchSettingsBaselineControl.evaluate(&bundle_with(true, true, true));
        assert_eq!(findings[0].status, ControlStatus::Satisfied);
    }

    #[test]
    fn violated_when_no_protection() {
        let findings =
            DefaultBranchSettingsBaselineControl.evaluate(&bundle_with(false, false, false));
        assert_eq!(findings[0].status, ControlStatus::Violated);
        assert!(
            findings[0]
                .rationale
                .contains("branch protection not enabled")
        );
    }

    #[test]
    fn violated_when_no_admin_enforcement() {
        let findings =
            DefaultBranchSettingsBaselineControl.evaluate(&bundle_with(true, false, true));
        assert_eq!(findings[0].status, ControlStatus::Violated);
        assert!(findings[0].rationale.contains("admin enforcement"));
    }

    #[test]
    fn violated_when_no_stale_dismissal() {
        let findings =
            DefaultBranchSettingsBaselineControl.evaluate(&bundle_with(true, true, false));
        assert_eq!(findings[0].status, ControlStatus::Violated);
        assert!(findings[0].rationale.contains("stale review dismissal"));
    }

    #[test]
    fn violated_lists_all_missing() {
        let findings =
            DefaultBranchSettingsBaselineControl.evaluate(&bundle_with(false, false, false));
        assert_eq!(findings[0].status, ControlStatus::Violated);
        assert!(
            findings[0]
                .rationale
                .contains("branch protection not enabled")
        );
        assert!(findings[0].rationale.contains("admin enforcement"));
        assert!(findings[0].rationale.contains("stale review dismissal"));
    }

    #[test]
    fn indeterminate_when_posture_missing() {
        let findings = DefaultBranchSettingsBaselineControl.evaluate(&EvidenceBundle {
            repository_posture: EvidenceState::missing(vec![]),
            ..Default::default()
        });
        assert_eq!(findings[0].status, ControlStatus::Indeterminate);
    }
}
