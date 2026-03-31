use crate::control::{Control, ControlFinding, ControlId, builtin};
use crate::evidence::EvidenceBundle;

/// Validates that security testing (SAST/DAST) is integrated into CI.
///
/// Maps to UN-R155 Clause 7.2.2.2 (Security testing throughout lifecycle),
/// NIST 800-53 SA-11 (Developer Testing and Evaluation).
///
/// Uses `code_scanning_enabled` as evidence — this is true when CodeQL
/// or other SAST tools have produced at least one analysis result,
/// indicating active security testing in the CI pipeline.
pub struct SecurityTestInCiControl;

impl Control for SecurityTestInCiControl {
    fn id(&self) -> ControlId {
        builtin::id(builtin::SECURITY_TEST_IN_CI)
    }

    fn description(&self) -> &'static str {
        "Security testing (SAST/DAST) must be integrated into CI pipelines"
    }

    fn evaluate(&self, evidence: &EvidenceBundle) -> Vec<ControlFinding> {
        let posture = match ControlFinding::extract_posture(self.id(), evidence) {
            Ok(p) => p,
            Err(findings) => return findings,
        };

        if !posture.security_analysis_available {
            return vec![ControlFinding::indeterminate(
                self.id(),
                "Cannot determine security testing status — API token may lack sufficient permissions",
                vec!["repository".into()],
                vec![],
            )];
        }

        if posture.code_scanning_enabled {
            vec![ControlFinding::satisfied(
                self.id(),
                "Security testing is active in CI — code scanning analyses detected",
                vec!["repository:code-scanning:ci".into()],
            )]
        } else {
            vec![ControlFinding::violated(
                self.id(),
                "No security testing detected in CI — configure CodeQL, Semgrep, or other SAST tools in GitHub Actions",
                vec!["repository:code-scanning:ci".into()],
            )]
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::control::ControlStatus;
    use crate::evidence::{EvidenceState, RepositoryPosture};

    fn bundle_with(analysis_available: bool, code_scanning: bool) -> EvidenceBundle {
        EvidenceBundle {
            repository_posture: EvidenceState::complete(RepositoryPosture {
                security_analysis_available: analysis_available,
                code_scanning_enabled: code_scanning,
                ..Default::default()
            }),
            ..Default::default()
        }
    }

    #[test]
    fn satisfied_when_code_scanning_enabled() {
        let findings = SecurityTestInCiControl.evaluate(&bundle_with(true, true));
        assert_eq!(findings[0].status, ControlStatus::Satisfied);
    }

    #[test]
    fn violated_when_no_code_scanning() {
        let findings = SecurityTestInCiControl.evaluate(&bundle_with(true, false));
        assert_eq!(findings[0].status, ControlStatus::Violated);
        assert!(findings[0].rationale.contains("No security testing"));
    }

    #[test]
    fn indeterminate_when_api_unavailable() {
        let findings = SecurityTestInCiControl.evaluate(&bundle_with(false, false));
        assert_eq!(findings[0].status, ControlStatus::Indeterminate);
    }

    #[test]
    fn indeterminate_when_posture_missing() {
        let findings = SecurityTestInCiControl.evaluate(&EvidenceBundle {
            repository_posture: EvidenceState::missing(vec![]),
            ..Default::default()
        });
        assert_eq!(findings[0].status, ControlStatus::Indeterminate);
    }
}
