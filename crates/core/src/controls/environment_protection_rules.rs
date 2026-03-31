use crate::control::{Control, ControlFinding, ControlId, builtin};
use crate::evidence::EvidenceBundle;

/// Validates that production/release environments have required reviewer protection rules.
///
/// Maps to SOC2 CC6.1 / CC8.1: enforce separation of duties for production deployments.
/// GitHub environment protection rules ensure that deployments to production require
/// explicit approval from designated reviewers.
///
/// Evaluation:
/// - **Satisfied**: production environment has required reviewer rules
/// - **Violated**: production environment lacks required reviewer rules
/// - **Indeterminate**: branch protection is not configured (cannot assess environment rules)
pub struct EnvironmentProtectionRulesControl;

impl Control for EnvironmentProtectionRulesControl {
    fn id(&self) -> ControlId {
        builtin::id(builtin::ENVIRONMENT_PROTECTION_RULES)
    }

    fn description(&self) -> &'static str {
        "Production environments must have required reviewer protection rules"
    }

    fn evaluate(&self, evidence: &EvidenceBundle) -> Vec<ControlFinding> {
        let posture = match ControlFinding::extract_posture(self.id(), evidence) {
            Ok(p) => p,
            Err(findings) => return findings,
        };

        if !posture.default_branch_protected {
            return vec![ControlFinding::indeterminate(
                self.id(),
                "Branch protection is not configured — \
                 cannot assess environment protection rules without baseline branch controls",
                vec!["repository:branch-protection:missing".to_string()],
                vec![],
            )];
        }

        if posture.production_environment_protected {
            vec![ControlFinding::satisfied(
                self.id(),
                "Production environment has required reviewer protection rules configured",
                vec!["repository:environment:production:protected".to_string()],
            )]
        } else {
            vec![ControlFinding::violated(
                self.id(),
                "Production environment lacks required reviewer protection rules — \
                 deployments can proceed without approval",
                vec!["repository:environment:production:unprotected".to_string()],
            )]
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::control::ControlStatus;
    use crate::evidence::{EvidenceGap, EvidenceState, RepositoryPosture};

    fn posture(branch_protected: bool, env_protected: bool) -> RepositoryPosture {
        RepositoryPosture {
            default_branch_protected: branch_protected,
            production_environment_protected: env_protected,
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
            EnvironmentProtectionRulesControl.evaluate(&bundle(EvidenceState::not_applicable()));
        assert_eq!(findings[0].status, ControlStatus::NotApplicable);
    }

    #[test]
    fn indeterminate_when_posture_missing() {
        let findings =
            EnvironmentProtectionRulesControl.evaluate(&bundle(EvidenceState::missing(vec![
                EvidenceGap::CollectionFailed {
                    source: "github".to_string(),
                    subject: "posture".to_string(),
                    detail: "API error".to_string(),
                },
            ])));
        assert_eq!(findings[0].status, ControlStatus::Indeterminate);
    }

    #[test]
    fn indeterminate_when_branch_protection_missing() {
        let findings = EnvironmentProtectionRulesControl
            .evaluate(&bundle(EvidenceState::complete(posture(false, false))));
        assert_eq!(findings[0].status, ControlStatus::Indeterminate);
        assert!(findings[0].rationale.contains("Branch protection"));
    }

    #[test]
    fn satisfied_when_environment_protected() {
        let findings = EnvironmentProtectionRulesControl
            .evaluate(&bundle(EvidenceState::complete(posture(true, true))));
        assert_eq!(findings[0].status, ControlStatus::Satisfied);
        assert!(findings[0].rationale.contains("required reviewer"));
    }

    #[test]
    fn violated_when_environment_not_protected() {
        let findings = EnvironmentProtectionRulesControl
            .evaluate(&bundle(EvidenceState::complete(posture(true, false))));
        assert_eq!(findings[0].status, ControlStatus::Violated);
        assert!(findings[0].rationale.contains("lacks required reviewer"));
    }
}
