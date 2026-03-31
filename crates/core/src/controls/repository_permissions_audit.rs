use crate::control::{Control, ControlFinding, ControlId, builtin};
use crate::evidence::EvidenceBundle;

/// Validates that repository access follows least-privilege principles.
///
/// Maps to SOC2 CC6.1 (Logical Access), NIST 800-53 CM-5 / AC-6,
/// ISMAP Ch.9.2.3 (Privileged Access Management).
///
/// Checks:
/// - Admin count is reasonable (threshold: <= 3)
/// - Direct (non-team) collaborators with write/admin access are minimized
///   (threshold: 0 — all access should be team-based)
pub struct RepositoryPermissionsAuditControl;

/// Maximum admins before the control is violated.
const MAX_ADMINS: u32 = 3;

impl Control for RepositoryPermissionsAuditControl {
    fn id(&self) -> ControlId {
        builtin::id(builtin::REPOSITORY_PERMISSIONS_AUDIT)
    }

    fn description(&self) -> &'static str {
        "Repository access must follow least-privilege: limited admins, team-based access"
    }

    fn evaluate(&self, evidence: &EvidenceBundle) -> Vec<ControlFinding> {
        let posture = match ControlFinding::extract_posture(self.id(), evidence) {
            Ok(p) => p,
            Err(findings) => return findings,
        };

        let mut issues = Vec::new();

        if posture.admin_count > MAX_ADMINS {
            issues.push(format!(
                "{} admins detected (maximum {})",
                posture.admin_count, MAX_ADMINS
            ));
        }

        if posture.direct_collaborator_count > 0 {
            issues.push(format!(
                "{} direct collaborators with write/admin access (should use team-based access)",
                posture.direct_collaborator_count
            ));
        }

        if issues.is_empty() {
            vec![ControlFinding::satisfied(
                self.id(),
                &format!(
                    "Repository access follows least-privilege: {} admin(s), no direct collaborators",
                    posture.admin_count
                ),
                vec!["repository:permissions".into()],
            )]
        } else {
            vec![ControlFinding::violated(
                self.id(),
                &issues.join("; "),
                vec!["repository:permissions".into()],
            )]
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::control::ControlStatus;
    use crate::evidence::{EvidenceState, RepositoryPosture};

    fn bundle_with(admin_count: u32, direct_collaborator_count: u32) -> EvidenceBundle {
        EvidenceBundle {
            repository_posture: EvidenceState::complete(RepositoryPosture {
                admin_count,
                direct_collaborator_count,
                ..Default::default()
            }),
            ..Default::default()
        }
    }

    #[test]
    fn satisfied_when_few_admins_no_direct() {
        let findings = RepositoryPermissionsAuditControl.evaluate(&bundle_with(2, 0));
        assert_eq!(findings[0].status, ControlStatus::Satisfied);
    }

    #[test]
    fn violated_when_too_many_admins() {
        let findings = RepositoryPermissionsAuditControl.evaluate(&bundle_with(5, 0));
        assert_eq!(findings[0].status, ControlStatus::Violated);
        assert!(findings[0].rationale.contains("5 admins"));
    }

    #[test]
    fn violated_when_direct_collaborators_exist() {
        let findings = RepositoryPermissionsAuditControl.evaluate(&bundle_with(1, 3));
        assert_eq!(findings[0].status, ControlStatus::Violated);
        assert!(findings[0].rationale.contains("3 direct collaborators"));
    }

    #[test]
    fn violated_when_both_issues() {
        let findings = RepositoryPermissionsAuditControl.evaluate(&bundle_with(10, 5));
        assert_eq!(findings[0].status, ControlStatus::Violated);
        assert!(findings[0].rationale.contains("10 admins"));
        assert!(findings[0].rationale.contains("5 direct collaborators"));
    }

    #[test]
    fn indeterminate_when_posture_missing() {
        let findings = RepositoryPermissionsAuditControl.evaluate(&EvidenceBundle {
            repository_posture: EvidenceState::missing(vec![]),
            ..Default::default()
        });
        assert_eq!(findings[0].status, ControlStatus::Indeterminate);
    }

    #[test]
    fn not_applicable_when_posture_not_applicable() {
        let findings = RepositoryPermissionsAuditControl.evaluate(&EvidenceBundle {
            repository_posture: EvidenceState::not_applicable(),
            ..Default::default()
        });
        assert_eq!(findings[0].status, ControlStatus::NotApplicable);
    }
}
