use crate::control::{Control, ControlFinding, ControlId, builtin};
use crate::evidence::EvidenceBundle;

/// Detects workflows using `pull_request_target` with elevated permissions,
/// which is a known attack vector for CI/CD pipeline exploitation.
///
/// Maps to SOC2 CC6.1 / CC7.1: access control and threat detection.
/// A `pull_request_target` workflow runs in the context of the *base* branch
/// with write access to secrets. If combined with `actions/checkout` of the
/// PR head, an external contributor can exfiltrate secrets or inject code.
///
/// Evaluation tiers:
/// - **Satisfied**: no privileged workflow patterns detected
/// - **Violated**: one or more workflows use dangerous `pull_request_target` patterns
pub struct PrivilegedWorkflowDetectionControl;

impl Control for PrivilegedWorkflowDetectionControl {
    fn id(&self) -> ControlId {
        builtin::id(builtin::PRIVILEGED_WORKFLOW_DETECTION)
    }

    fn description(&self) -> &'static str {
        "Workflows must not use pull_request_target with elevated permissions"
    }

    fn evaluate(&self, evidence: &EvidenceBundle) -> Vec<ControlFinding> {
        let posture = match ControlFinding::extract_posture(self.id(), evidence) {
            Ok(p) => p,
            Err(findings) => return findings,
        };

        if posture.privileged_workflows.is_empty() {
            vec![ControlFinding::satisfied(
                self.id(),
                "No privileged workflow patterns detected",
                vec!["workflows".to_string()],
            )]
        } else {
            let subjects: Vec<String> = posture
                .privileged_workflows
                .iter()
                .map(|w| format!("{}:{} ({})", w.file, w.trigger, w.risk))
                .collect();
            let count = posture.privileged_workflows.len();
            vec![ControlFinding::violated(
                self.id(),
                format!(
                    "{count} workflow(s) use pull_request_target with elevated permissions — \
                     external contributors may exploit these to exfiltrate secrets"
                ),
                subjects,
            )]
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::control::ControlStatus;
    use crate::evidence::{
        EvidenceGap, EvidenceState, PrivilegedWorkflow, RepositoryPosture,
    };

    fn posture(workflows: Vec<PrivilegedWorkflow>) -> RepositoryPosture {
        RepositoryPosture {
            privileged_workflows: workflows,
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
        let findings = PrivilegedWorkflowDetectionControl
            .evaluate(&bundle(EvidenceState::not_applicable()));
        assert_eq!(findings[0].status, ControlStatus::NotApplicable);
    }

    #[test]
    fn indeterminate_when_posture_missing() {
        let findings = PrivilegedWorkflowDetectionControl
            .evaluate(&bundle(EvidenceState::missing(vec![
                EvidenceGap::CollectionFailed {
                    source: "github".to_string(),
                    subject: "posture".to_string(),
                    detail: "API error".to_string(),
                },
            ])));
        assert_eq!(findings[0].status, ControlStatus::Indeterminate);
    }

    #[test]
    fn satisfied_when_no_privileged_workflows() {
        let findings = PrivilegedWorkflowDetectionControl
            .evaluate(&bundle(EvidenceState::complete(posture(vec![]))));
        assert_eq!(findings[0].status, ControlStatus::Satisfied);
    }

    #[test]
    fn violated_when_privileged_workflows_detected() {
        let workflows = vec![
            PrivilegedWorkflow {
                file: ".github/workflows/ci.yml".to_string(),
                trigger: "pull_request_target".to_string(),
                risk: "checks out PR head with write access".to_string(),
            },
            PrivilegedWorkflow {
                file: ".github/workflows/label.yml".to_string(),
                trigger: "pull_request_target".to_string(),
                risk: "runs untrusted code with secrets".to_string(),
            },
        ];
        let findings = PrivilegedWorkflowDetectionControl
            .evaluate(&bundle(EvidenceState::complete(posture(workflows))));
        assert_eq!(findings[0].status, ControlStatus::Violated);
        assert!(findings[0].rationale.contains("2 workflow(s)"));
        assert_eq!(findings[0].subjects.len(), 2);
        assert!(findings[0].subjects[0].contains("ci.yml"));
        assert!(findings[0].subjects[1].contains("label.yml"));
    }
}
