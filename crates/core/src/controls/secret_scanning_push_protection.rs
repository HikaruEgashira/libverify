use crate::control::{Control, ControlFinding, ControlId, builtin};
use crate::evidence::EvidenceBundle;

/// Validates that secret scanning push protection is enabled.
///
/// Maps to PCI DSS Req 3.5.1, NIST SI-7, SOC2 CC6.1 / CC6.6.
/// Push protection actively blocks credential commits at push time,
/// going beyond detection-only secret scanning.
///
/// Requires secret scanning to be enabled as a prerequisite.
pub struct SecretScanningPushProtectionControl;

impl Control for SecretScanningPushProtectionControl {
    fn id(&self) -> ControlId {
        builtin::id(builtin::SECRET_SCANNING_PUSH_PROTECTION)
    }

    fn description(&self) -> &'static str {
        "Secret scanning push protection must be enabled to block credential commits"
    }

    fn evaluate(&self, evidence: &EvidenceBundle) -> Vec<ControlFinding> {
        let posture = match ControlFinding::extract_posture(self.id(), evidence) {
            Ok(p) => p,
            Err(findings) => return findings,
        };

        if !posture.secret_scanning_enabled {
            return vec![ControlFinding::violated(
                self.id(),
                "Secret scanning is not enabled — push protection requires secret scanning",
                vec!["repository".into()],
            )];
        }

        if posture.secret_push_protection_enabled {
            vec![ControlFinding::satisfied(
                self.id(),
                "Secret scanning push protection is enabled — credential commits are blocked",
                vec!["repository:secret-scanning:push-protection".into()],
            )]
        } else {
            vec![ControlFinding::violated(
                self.id(),
                "Secret scanning push protection is not enabled — credentials can be pushed to the repository",
                vec!["repository:secret-scanning:push-protection".into()],
            )]
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::control::ControlStatus;
    use crate::evidence::{EvidenceGap, EvidenceState, RepositoryPosture};

    fn posture(secret_scanning: bool, push_protection: bool) -> RepositoryPosture {
        RepositoryPosture {
            secret_scanning_enabled: secret_scanning,
            secret_push_protection_enabled: push_protection,
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
            SecretScanningPushProtectionControl.evaluate(&bundle(EvidenceState::not_applicable()));
        assert_eq!(findings[0].status, ControlStatus::NotApplicable);
    }

    #[test]
    fn indeterminate_when_posture_missing() {
        let findings =
            SecretScanningPushProtectionControl.evaluate(&bundle(EvidenceState::missing(vec![
                EvidenceGap::CollectionFailed {
                    source: "github".to_string(),
                    subject: "posture".to_string(),
                    detail: "API error".to_string(),
                },
            ])));
        assert_eq!(findings[0].status, ControlStatus::Indeterminate);
    }

    #[test]
    fn satisfied_when_push_protection_enabled() {
        let findings = SecretScanningPushProtectionControl
            .evaluate(&bundle(EvidenceState::complete(posture(true, true))));
        assert_eq!(findings[0].status, ControlStatus::Satisfied);
        assert!(findings[0].rationale.contains("push protection is enabled"));
    }

    #[test]
    fn violated_when_push_protection_disabled() {
        let findings = SecretScanningPushProtectionControl
            .evaluate(&bundle(EvidenceState::complete(posture(true, false))));
        assert_eq!(findings[0].status, ControlStatus::Violated);
        assert!(findings[0]
            .rationale
            .contains("push protection is not enabled"));
    }

    #[test]
    fn violated_when_secret_scanning_disabled() {
        let findings = SecretScanningPushProtectionControl
            .evaluate(&bundle(EvidenceState::complete(posture(false, false))));
        assert_eq!(findings[0].status, ControlStatus::Violated);
        assert!(findings[0]
            .rationale
            .contains("Secret scanning is not enabled"));
    }
}
