use crate::control::{Control, ControlFinding, ControlId, builtin};
use crate::evidence::EvidenceBundle;

/// Validates that no copyleft-licensed dependencies (GPL, AGPL) are present.
///
/// Maps to SOC2 CC7.1: ensure compliance with third-party license obligations.
/// Copyleft licenses impose viral obligations that may conflict with proprietary
/// licensing or organizational policy. This control flags dependencies with
/// GPL, AGPL, or similar copyleft licenses for legal review.
///
/// Evaluation:
/// - **Satisfied**: no copyleft-licensed dependencies detected
/// - **Violated**: one or more copyleft-licensed dependencies found
pub struct DependencyLicenseComplianceControl;

impl Control for DependencyLicenseComplianceControl {
    fn id(&self) -> ControlId {
        builtin::id(builtin::DEPENDENCY_LICENSE_COMPLIANCE)
    }

    fn description(&self) -> &'static str {
        "Dependencies must not include copyleft-licensed (GPL/AGPL) packages without review"
    }

    fn evaluate(&self, evidence: &EvidenceBundle) -> Vec<ControlFinding> {
        let posture = match ControlFinding::extract_posture(self.id(), evidence) {
            Ok(p) => p,
            Err(findings) => return findings,
        };

        if posture.copyleft_dependencies.is_empty() {
            return vec![ControlFinding::satisfied(
                self.id(),
                "No copyleft-licensed dependencies detected in the dependency graph",
                vec!["repository:licenses:compliant".to_string()],
            )];
        }

        let subjects: Vec<String> = posture
            .copyleft_dependencies
            .iter()
            .map(|d| format!("{}:{}", d.name, d.license))
            .collect();

        let count = posture.copyleft_dependencies.len();
        vec![ControlFinding::violated(
            self.id(),
            format!(
                "{count} copyleft-licensed dependency(ies) detected — \
                 review for license compliance before distribution"
            ),
            subjects,
        )]
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::control::ControlStatus;
    use crate::evidence::{
        CopyleftDependency, EvidenceGap, EvidenceState, RepositoryPosture,
    };

    fn posture(deps: Vec<CopyleftDependency>) -> RepositoryPosture {
        RepositoryPosture {
            copyleft_dependencies: deps,
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
        let findings = DependencyLicenseComplianceControl
            .evaluate(&bundle(EvidenceState::not_applicable()));
        assert_eq!(findings[0].status, ControlStatus::NotApplicable);
    }

    #[test]
    fn indeterminate_when_posture_missing() {
        let findings =
            DependencyLicenseComplianceControl.evaluate(&bundle(EvidenceState::missing(vec![
                EvidenceGap::CollectionFailed {
                    source: "github".to_string(),
                    subject: "posture".to_string(),
                    detail: "API error".to_string(),
                },
            ])));
        assert_eq!(findings[0].status, ControlStatus::Indeterminate);
    }

    #[test]
    fn satisfied_when_no_copyleft_deps() {
        let findings = DependencyLicenseComplianceControl
            .evaluate(&bundle(EvidenceState::complete(posture(vec![]))));
        assert_eq!(findings[0].status, ControlStatus::Satisfied);
        assert!(findings[0].rationale.contains("No copyleft"));
    }

    #[test]
    fn violated_when_copyleft_deps_exist() {
        let deps = vec![
            CopyleftDependency {
                name: "libfoo".to_string(),
                license: "GPL-3.0".to_string(),
            },
            CopyleftDependency {
                name: "libbar".to_string(),
                license: "AGPL-3.0".to_string(),
            },
        ];
        let findings = DependencyLicenseComplianceControl
            .evaluate(&bundle(EvidenceState::complete(posture(deps))));
        assert_eq!(findings[0].status, ControlStatus::Violated);
        assert!(findings[0].rationale.contains("2 copyleft"));
        assert_eq!(findings[0].subjects.len(), 2);
        assert!(findings[0].subjects[0].contains("libfoo:GPL-3.0"));
        assert!(findings[0].subjects[1].contains("libbar:AGPL-3.0"));
    }
}
