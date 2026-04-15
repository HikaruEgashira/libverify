use crate::control::{Control, ControlFinding, ControlId, builtin};
use crate::evidence::EvidenceBundle;

/// Validates that no copyleft-licensed dependencies exist without explicit approval.
///
/// Maps to SOC2 CC7.1: monitor and evaluate system components.
/// Copyleft licenses (GPL, AGPL, SSPL) impose distribution obligations
/// that may conflict with proprietary licensing. This control flags
/// copyleft dependencies for legal review.
///
/// Evaluation:
/// - **Satisfied**: no copyleft dependencies detected
/// - **Violated**: one or more copyleft dependencies found
pub struct LicenseComplianceControl;

impl Control for LicenseComplianceControl {
    fn id(&self) -> ControlId {
        builtin::id(builtin::LICENSE_COMPLIANCE)
    }

    fn description(&self) -> &'static str {
        "Dependencies must not include copyleft licenses without explicit approval"
    }

    fn evaluate(&self, evidence: &EvidenceBundle) -> Vec<ControlFinding> {
        let posture = match ControlFinding::extract_posture(self.id(), evidence) {
            Ok(p) => p,
            Err(findings) => return findings,
        };

        if posture.copyleft_dependencies.is_empty() {
            return vec![ControlFinding::satisfied(
                self.id(),
                "No copyleft dependencies detected",
                vec!["repository:license-compliance".to_string()],
            )];
        }

        let subjects: Vec<String> = posture
            .copyleft_dependencies
            .iter()
            .map(|dep| format!("{}:{}", dep.name, dep.license))
            .collect();

        let dep_list: Vec<String> = posture
            .copyleft_dependencies
            .iter()
            .map(|dep| format!("{} ({})", dep.name, dep.license))
            .collect();

        vec![ControlFinding::violated(
            self.id(),
            format!("Copyleft dependencies detected: {}", dep_list.join(", ")),
            subjects,
        )]
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::control::ControlStatus;
    use crate::evidence::{CopyleftDependency, EvidenceGap, EvidenceState, RepositoryPosture};

    fn bundle(state: EvidenceState<RepositoryPosture>) -> EvidenceBundle {
        EvidenceBundle {
            repository_posture: state,
            ..Default::default()
        }
    }

    #[test]
    fn satisfied_when_no_copyleft_deps() {
        let posture = RepositoryPosture::default();
        let findings = LicenseComplianceControl.evaluate(&bundle(EvidenceState::complete(posture)));
        assert_eq!(findings[0].status, ControlStatus::Satisfied);
        assert!(findings[0].rationale.contains("No copyleft"));
    }

    #[test]
    fn violated_when_copyleft_deps_exist() {
        let posture = RepositoryPosture {
            copyleft_dependencies: vec![
                CopyleftDependency {
                    name: "libfoo".to_string(),
                    license: "GPL-3.0".to_string(),
                },
                CopyleftDependency {
                    name: "libbar".to_string(),
                    license: "AGPL-3.0".to_string(),
                },
            ],
            ..Default::default()
        };
        let findings = LicenseComplianceControl.evaluate(&bundle(EvidenceState::complete(posture)));
        assert_eq!(findings[0].status, ControlStatus::Violated);
        assert!(findings[0].rationale.contains("libfoo"));
        assert!(findings[0].rationale.contains("GPL-3.0"));
        assert_eq!(findings[0].subjects.len(), 2);
        assert!(findings[0].subjects[0].contains("libfoo:GPL-3.0"));
    }

    #[test]
    fn indeterminate_when_posture_missing() {
        let findings = LicenseComplianceControl.evaluate(&bundle(EvidenceState::missing(vec![
            EvidenceGap::CollectionFailed {
                source: "github".to_string(),
                subject: "posture".to_string(),
                detail: "API error".to_string(),
            },
        ])));
        assert_eq!(findings[0].status, ControlStatus::Indeterminate);
    }

    #[test]
    fn not_applicable_when_posture_not_applicable() {
        let findings = LicenseComplianceControl.evaluate(&bundle(EvidenceState::not_applicable()));
        assert_eq!(findings[0].status, ControlStatus::NotApplicable);
    }
}
