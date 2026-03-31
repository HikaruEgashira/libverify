use crate::control::{Control, ControlFinding, ControlId, builtin};
use crate::evidence::EvidenceBundle;

/// Validates that a dependency update tool is configured.
///
/// Maps to OpenSSF Scorecard Dependency-Update-Tool (High risk).
///
/// Checks whether Dependabot (`.github/dependabot.yml`) or Renovate
/// (`renovate.json`, `renovate.json5`, `.renovaterc`) is configured,
/// indicating proactive dependency update management.
pub struct DependencyUpdateToolControl;

impl Control for DependencyUpdateToolControl {
    fn id(&self) -> ControlId {
        builtin::id(builtin::DEPENDENCY_UPDATE_TOOL)
    }

    fn description(&self) -> &'static str {
        "A dependency update tool (Dependabot or Renovate) must be configured"
    }

    fn evaluate(&self, evidence: &EvidenceBundle) -> Vec<ControlFinding> {
        let posture = match ControlFinding::extract_posture(self.id(), evidence) {
            Ok(p) => p,
            Err(findings) => return findings,
        };

        if posture.dependency_update_tool_configured {
            vec![ControlFinding::satisfied(
                self.id(),
                "Dependency update tool is configured (Dependabot or Renovate)",
                vec!["repository:dependency-update-tool".into()],
            )]
        } else {
            vec![ControlFinding::violated(
                self.id(),
                "No dependency update tool detected — configure .github/dependabot.yml or renovate.json",
                vec!["repository:dependency-update-tool".into()],
            )]
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::control::ControlStatus;
    use crate::evidence::{EvidenceState, RepositoryPosture};

    fn bundle_with(configured: bool) -> EvidenceBundle {
        EvidenceBundle {
            repository_posture: EvidenceState::complete(RepositoryPosture {
                dependency_update_tool_configured: configured,
                ..Default::default()
            }),
            ..Default::default()
        }
    }

    #[test]
    fn satisfied_when_configured() {
        let findings = DependencyUpdateToolControl.evaluate(&bundle_with(true));
        assert_eq!(findings[0].status, ControlStatus::Satisfied);
    }

    #[test]
    fn violated_when_not_configured() {
        let findings = DependencyUpdateToolControl.evaluate(&bundle_with(false));
        assert_eq!(findings[0].status, ControlStatus::Violated);
        assert!(findings[0].rationale.contains("dependabot.yml"));
    }

    #[test]
    fn indeterminate_when_posture_missing() {
        let findings = DependencyUpdateToolControl.evaluate(&EvidenceBundle {
            repository_posture: EvidenceState::missing(vec![]),
            ..Default::default()
        });
        assert_eq!(findings[0].status, ControlStatus::Indeterminate);
    }

    #[test]
    fn not_applicable_when_posture_not_applicable() {
        let findings = DependencyUpdateToolControl.evaluate(&EvidenceBundle {
            repository_posture: EvidenceState::not_applicable(),
            ..Default::default()
        });
        assert_eq!(findings[0].status, ControlStatus::NotApplicable);
    }
}
