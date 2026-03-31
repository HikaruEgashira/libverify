use crate::control::{Control, ControlFinding, ControlId, builtin};
use crate::evidence::EvidenceBundle;

/// Validates that branch protection rules are enforced for admins (no bypass).
///
/// Maps to SOC2 CC6.1 / CC8.1: ensure that privileged users cannot bypass
/// change management controls. When `enforce_admins` is disabled, repository
/// admins can push directly to protected branches, undermining review and CI gates.
pub struct BranchProtectionAdminEnforcementControl;

impl Control for BranchProtectionAdminEnforcementControl {
    fn id(&self) -> ControlId {
        builtin::id(builtin::BRANCH_PROTECTION_ADMIN_ENFORCEMENT)
    }

    fn description(&self) -> &'static str {
        "Branch protection must be enforced for admins to prevent bypass"
    }

    fn evaluate(&self, evidence: &EvidenceBundle) -> Vec<ControlFinding> {
        let posture = match ControlFinding::extract_posture(self.id(), evidence) {
            Ok(p) => p,
            Err(findings) => return findings,
        };

        if !posture.default_branch_protected {
            return vec![ControlFinding::violated(
                self.id(),
                "Default branch has no protection rules — admin enforcement cannot be evaluated",
                vec!["repository:branch-protection".into()],
            )];
        }

        if posture.enforce_admins {
            vec![ControlFinding::satisfied(
                self.id(),
                "Branch protection rules are enforced for admins — no bypass is possible",
                vec!["repository:branch-protection:enforce-admins".into()],
            )]
        } else {
            vec![ControlFinding::violated(
                self.id(),
                "Branch protection rules do not apply to admins — admins can bypass review and CI gates",
                vec!["repository:branch-protection:enforce-admins".into()],
            )]
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::control::ControlStatus;
    use crate::evidence::{EvidenceGap, EvidenceState, RepositoryPosture};

    fn posture(protected: bool, enforce_admins: bool) -> RepositoryPosture {
        RepositoryPosture {
            default_branch_protected: protected,
            enforce_admins,
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
        let findings = BranchProtectionAdminEnforcementControl
            .evaluate(&bundle(EvidenceState::not_applicable()));
        assert_eq!(findings[0].status, ControlStatus::NotApplicable);
    }

    #[test]
    fn indeterminate_when_posture_missing() {
        let findings = BranchProtectionAdminEnforcementControl.evaluate(&bundle(
            EvidenceState::missing(vec![EvidenceGap::CollectionFailed {
                source: "github".to_string(),
                subject: "posture".to_string(),
                detail: "API error".to_string(),
            }]),
        ));
        assert_eq!(findings[0].status, ControlStatus::Indeterminate);
    }

    #[test]
    fn satisfied_when_enforce_admins_enabled() {
        let findings = BranchProtectionAdminEnforcementControl
            .evaluate(&bundle(EvidenceState::complete(posture(true, true))));
        assert_eq!(findings[0].status, ControlStatus::Satisfied);
        assert!(findings[0].rationale.contains("enforced for admins"));
    }

    #[test]
    fn violated_when_enforce_admins_disabled() {
        let findings = BranchProtectionAdminEnforcementControl
            .evaluate(&bundle(EvidenceState::complete(posture(true, false))));
        assert_eq!(findings[0].status, ControlStatus::Violated);
        assert!(findings[0].rationale.contains("do not apply to admins"));
    }

    #[test]
    fn violated_when_no_branch_protection() {
        let findings = BranchProtectionAdminEnforcementControl
            .evaluate(&bundle(EvidenceState::complete(posture(false, false))));
        assert_eq!(findings[0].status, ControlStatus::Violated);
        assert!(findings[0].rationale.contains("no protection rules"));
    }
}
