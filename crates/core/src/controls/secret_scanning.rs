use crate::control::{Control, ControlFinding, ControlId, builtin};
use crate::evidence::EvidenceBundle;

/// Validates that secret scanning is enabled on the repository.
///
/// Maps to SOC2 CC6.1 / CC6.6: protect credentials and prevent leakage.
/// ASPM signal — secret scanning prevents accidental exposure of API keys,
/// tokens, and other credentials in source code.
///
/// Evaluation tiers:
/// - **Satisfied**: scanning enabled AND push protection enabled (prevention)
/// - **Satisfied (with caveat)**: scanning enabled but push protection off (detection only)
/// - **Violated**: scanning not enabled
pub struct SecretScanningControl;

impl Control for SecretScanningControl {
    fn id(&self) -> ControlId {
        builtin::id(builtin::SECRET_SCANNING)
    }

    fn description(&self) -> &'static str {
        "Secret scanning must be enabled to prevent credential leakage"
    }

    fn evaluate(&self, evidence: &EvidenceBundle) -> Vec<ControlFinding> {
        let posture = match ControlFinding::extract_posture(self.id(), evidence) {
            Ok(p) => p,
            Err(findings) => return findings,
        };

        if !posture.secret_scanning_enabled {
            return vec![ControlFinding::violated(
                self.id(),
                "Secret scanning is not enabled — credentials may be exposed in source code",
                vec!["repository".to_string()],
            )];
        }

        if posture.secret_push_protection_enabled {
            vec![ControlFinding::satisfied(
                self.id(),
                "Secret scanning with push protection is enabled",
                vec!["repository:secret-scanning:prevention".to_string()],
            )]
        } else {
            // Detection-only: scanning enabled but push protection off.
            // Still satisfied (detecting leaks is better than nothing),
            // but rationale notes the gap for remediation.
            vec![ControlFinding::satisfied(
                self.id(),
                "Secret scanning is enabled (detection only — \
                 consider enabling push protection for prevention)",
                vec!["repository:secret-scanning:detection".to_string()],
            )]
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::control::ControlStatus;
    use crate::evidence::{EvidenceGap, EvidenceState, RepositoryPosture};

    fn posture(secret_scanning: bool) -> RepositoryPosture {
        RepositoryPosture {
            codeowners_entries: vec![],
            secret_scanning_enabled: secret_scanning,
            secret_push_protection_enabled: false,
            vulnerability_scanning_enabled: false,
            code_scanning_enabled: false,
            security_policy_present: false,
            security_policy_has_disclosure: false,
            default_branch_protected: false,
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
        let findings = SecretScanningControl.evaluate(&bundle(EvidenceState::not_applicable()));
        assert_eq!(findings[0].status, ControlStatus::NotApplicable);
    }

    #[test]
    fn indeterminate_when_posture_missing() {
        let findings = SecretScanningControl.evaluate(&bundle(EvidenceState::missing(vec![
            EvidenceGap::CollectionFailed {
                source: "github".to_string(),
                subject: "posture".to_string(),
                detail: "API error".to_string(),
            },
        ])));
        assert_eq!(findings[0].status, ControlStatus::Indeterminate);
    }

    #[test]
    fn satisfied_when_enabled() {
        let findings =
            SecretScanningControl.evaluate(&bundle(EvidenceState::complete(posture(true))));
        assert_eq!(findings[0].status, ControlStatus::Satisfied);
    }

    #[test]
    fn violated_when_disabled() {
        let findings =
            SecretScanningControl.evaluate(&bundle(EvidenceState::complete(posture(false))));
        assert_eq!(findings[0].status, ControlStatus::Violated);
        assert!(findings[0].rationale.contains("not enabled"));
    }

    #[test]
    fn satisfied_with_push_protection_has_prevention_tier() {
        let mut p = posture(true);
        p.secret_push_protection_enabled = true;
        let findings = SecretScanningControl.evaluate(&bundle(EvidenceState::complete(p)));
        assert_eq!(findings[0].status, ControlStatus::Satisfied);
        assert!(findings[0].rationale.contains("push protection"));
        assert!(findings[0].subjects[0].contains("prevention"));
    }

    #[test]
    fn satisfied_detection_only_has_detection_tier() {
        let findings =
            SecretScanningControl.evaluate(&bundle(EvidenceState::complete(posture(true))));
        assert_eq!(findings[0].status, ControlStatus::Satisfied);
        assert!(findings[0].rationale.contains("detection only"));
        assert!(findings[0].subjects[0].contains("detection"));
    }
}
