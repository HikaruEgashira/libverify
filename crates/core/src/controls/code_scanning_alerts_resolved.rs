use crate::control::{Control, ControlFinding, ControlId, builtin};
use crate::evidence::EvidenceBundle;

/// Validates that no high-or-above severity code scanning alerts are open.
///
/// Maps to SOC2 CC7.1: detect and remediate vulnerabilities in source code.
/// Open high/critical code scanning alerts indicate known security weaknesses
/// that could be exploited in production.
///
/// Evaluation:
/// - **NotApplicable**: code scanning is not enabled
/// - **Satisfied**: zero open high-or-above severity alerts
/// - **Violated**: one or more open high-or-above severity alerts
pub struct CodeScanningAlertsResolvedControl;

impl Control for CodeScanningAlertsResolvedControl {
    fn id(&self) -> ControlId {
        builtin::id(builtin::CODE_SCANNING_ALERTS_RESOLVED)
    }

    fn description(&self) -> &'static str {
        "All high-or-above severity code scanning alerts must be resolved"
    }

    fn evaluate(&self, evidence: &EvidenceBundle) -> Vec<ControlFinding> {
        let posture = match ControlFinding::extract_posture(self.id(), evidence) {
            Ok(p) => p,
            Err(findings) => return findings,
        };

        if !posture.code_scanning_enabled {
            return vec![ControlFinding::not_applicable(
                self.id(),
                "Code scanning is not enabled — alert resolution check is not applicable",
            )];
        }

        if posture.open_high_severity_alerts == 0 {
            vec![ControlFinding::satisfied(
                self.id(),
                "No open high-or-above severity code scanning alerts",
                vec!["repository:code-scanning:alerts:clear".to_string()],
            )]
        } else {
            vec![ControlFinding::violated(
                self.id(),
                format!(
                    "{} open high-or-above severity code scanning alert(s) — \
                     resolve before deploying to production",
                    posture.open_high_severity_alerts
                ),
                vec![format!(
                    "repository:code-scanning:alerts:open:{}",
                    posture.open_high_severity_alerts
                )],
            )]
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::control::ControlStatus;
    use crate::evidence::{EvidenceGap, EvidenceState, RepositoryPosture};

    fn posture(code_scanning: bool, open_alerts: u32) -> RepositoryPosture {
        RepositoryPosture {
            code_scanning_enabled: code_scanning,
            open_high_severity_alerts: open_alerts,
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
            CodeScanningAlertsResolvedControl.evaluate(&bundle(EvidenceState::not_applicable()));
        assert_eq!(findings[0].status, ControlStatus::NotApplicable);
    }

    #[test]
    fn indeterminate_when_posture_missing() {
        let findings =
            CodeScanningAlertsResolvedControl.evaluate(&bundle(EvidenceState::missing(vec![
                EvidenceGap::CollectionFailed {
                    source: "github".to_string(),
                    subject: "posture".to_string(),
                    detail: "API error".to_string(),
                },
            ])));
        assert_eq!(findings[0].status, ControlStatus::Indeterminate);
    }

    #[test]
    fn not_applicable_when_code_scanning_disabled() {
        let findings = CodeScanningAlertsResolvedControl
            .evaluate(&bundle(EvidenceState::complete(posture(false, 0))));
        assert_eq!(findings[0].status, ControlStatus::NotApplicable);
        assert!(findings[0].rationale.contains("not enabled"));
    }

    #[test]
    fn satisfied_when_no_open_alerts() {
        let findings = CodeScanningAlertsResolvedControl
            .evaluate(&bundle(EvidenceState::complete(posture(true, 0))));
        assert_eq!(findings[0].status, ControlStatus::Satisfied);
        assert!(findings[0].rationale.contains("No open"));
    }

    #[test]
    fn violated_when_open_alerts_exist() {
        let findings = CodeScanningAlertsResolvedControl
            .evaluate(&bundle(EvidenceState::complete(posture(true, 3))));
        assert_eq!(findings[0].status, ControlStatus::Violated);
        assert!(findings[0].rationale.contains("3 open"));
        assert!(findings[0].subjects[0].contains("open:3"));
    }
}
