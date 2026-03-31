use crate::control::{Control, ControlFinding, ControlId, builtin};
use crate::evidence::EvidenceBundle;

/// Validates that default workflow permissions are set to read-only.
///
/// Maps to SOC2 CC6.8 (Prevention of Unauthorized Software),
/// OpenSSF Scorecard Token-Permissions (High risk).
///
/// GitHub Actions workflows should use the principle of least privilege
/// for the GITHUB_TOKEN. The default should be "read" not "write".
pub struct WorkflowPermissionsRestrictedControl;

impl Control for WorkflowPermissionsRestrictedControl {
    fn id(&self) -> ControlId {
        builtin::id(builtin::WORKFLOW_PERMISSIONS_RESTRICTED)
    }

    fn description(&self) -> &'static str {
        "Default workflow permissions must be restricted to read-only"
    }

    fn evaluate(&self, evidence: &EvidenceBundle) -> Vec<ControlFinding> {
        let posture = match ControlFinding::extract_posture(self.id(), evidence) {
            Ok(p) => p,
            Err(findings) => return findings,
        };

        if posture.default_workflow_permissions.is_empty() {
            return vec![ControlFinding::indeterminate(
                self.id(),
                "Cannot determine default workflow permissions — API token may lack admin permissions",
                vec!["repository:workflow-permissions".into()],
                vec![],
            )];
        }

        if posture.default_workflow_permissions == "read" {
            vec![ControlFinding::satisfied(
                self.id(),
                "Default workflow permissions are set to read-only",
                vec!["repository:workflow-permissions".into()],
            )]
        } else {
            vec![ControlFinding::violated(
                self.id(),
                format!(
                    "Default workflow permissions are '{}' — should be 'read' for least privilege",
                    posture.default_workflow_permissions
                ),
                vec!["repository:workflow-permissions".into()],
            )]
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::control::ControlStatus;
    use crate::evidence::{EvidenceState, RepositoryPosture};

    fn bundle_with_perms(perms: &str) -> EvidenceBundle {
        EvidenceBundle {
            repository_posture: EvidenceState::complete(RepositoryPosture {
                default_workflow_permissions: perms.to_string(),
                ..Default::default()
            }),
            ..Default::default()
        }
    }

    #[test]
    fn satisfied_when_read_only() {
        let findings = WorkflowPermissionsRestrictedControl.evaluate(&bundle_with_perms("read"));
        assert_eq!(findings[0].status, ControlStatus::Satisfied);
    }

    #[test]
    fn violated_when_write() {
        let findings = WorkflowPermissionsRestrictedControl.evaluate(&bundle_with_perms("write"));
        assert_eq!(findings[0].status, ControlStatus::Violated);
        assert!(findings[0].rationale.contains("write"));
    }

    #[test]
    fn indeterminate_when_empty() {
        let findings = WorkflowPermissionsRestrictedControl.evaluate(&bundle_with_perms(""));
        assert_eq!(findings[0].status, ControlStatus::Indeterminate);
    }

    #[test]
    fn indeterminate_when_posture_missing() {
        let findings = WorkflowPermissionsRestrictedControl.evaluate(&EvidenceBundle {
            repository_posture: EvidenceState::missing(vec![]),
            ..Default::default()
        });
        assert_eq!(findings[0].status, ControlStatus::Indeterminate);
    }

    #[test]
    fn not_applicable_when_posture_not_applicable() {
        let findings = WorkflowPermissionsRestrictedControl.evaluate(&EvidenceBundle {
            repository_posture: EvidenceState::not_applicable(),
            ..Default::default()
        });
        assert_eq!(findings[0].status, ControlStatus::NotApplicable);
    }
}
