use crate::control::{Control, ControlFinding, ControlId, builtin};
use crate::evidence::EvidenceBundle;

/// Validates that GitHub Actions workflow `uses:` references are pinned to commit SHAs.
///
/// Maps to SOC2 CC7.1 / PI1.4: prevent supply-chain attacks via mutable action tags.
/// Unpinned action references (e.g. `actions/checkout@v4`) can be silently replaced
/// by a compromised upstream, whereas SHA-pinned references are immutable.
///
/// Evaluation:
/// - **Satisfied**: no unpinned action references found
/// - **Violated**: one or more workflow files contain unpinned `uses:` references
pub struct ActionsPinnedDependenciesControl;

impl Control for ActionsPinnedDependenciesControl {
    fn id(&self) -> ControlId {
        builtin::id(builtin::ACTIONS_PINNED_DEPENDENCIES)
    }

    fn description(&self) -> &'static str {
        "GitHub Actions must pin action references to commit SHAs to prevent supply-chain attacks"
    }

    fn evaluate(&self, evidence: &EvidenceBundle) -> Vec<ControlFinding> {
        let posture = match ControlFinding::extract_posture(self.id(), evidence) {
            Ok(p) => p,
            Err(findings) => return findings,
        };

        if posture.unpinned_action_refs.is_empty() {
            return vec![ControlFinding::satisfied(
                self.id(),
                "All GitHub Actions references are pinned to commit SHAs",
                vec!["repository:actions:pinned".to_string()],
            )];
        }

        let subjects: Vec<String> = posture
            .unpinned_action_refs
            .iter()
            .map(|r| format!("{}:{}", r.workflow_file, r.action_ref))
            .collect();

        let count = posture.unpinned_action_refs.len();
        vec![ControlFinding::violated(
            self.id(),
            format!(
                "{count} unpinned action reference(s) found — \
                 pin to commit SHAs to prevent supply-chain attacks"
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
        EvidenceGap, EvidenceState, RepositoryPosture, UnpinnedActionRef,
    };

    fn posture(unpinned: Vec<UnpinnedActionRef>) -> RepositoryPosture {
        RepositoryPosture {
            unpinned_action_refs: unpinned,
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
            ActionsPinnedDependenciesControl.evaluate(&bundle(EvidenceState::not_applicable()));
        assert_eq!(findings[0].status, ControlStatus::NotApplicable);
    }

    #[test]
    fn indeterminate_when_posture_missing() {
        let findings =
            ActionsPinnedDependenciesControl.evaluate(&bundle(EvidenceState::missing(vec![
                EvidenceGap::CollectionFailed {
                    source: "github".to_string(),
                    subject: "posture".to_string(),
                    detail: "API error".to_string(),
                },
            ])));
        assert_eq!(findings[0].status, ControlStatus::Indeterminate);
    }

    #[test]
    fn satisfied_when_all_pinned() {
        let findings = ActionsPinnedDependenciesControl
            .evaluate(&bundle(EvidenceState::complete(posture(vec![]))));
        assert_eq!(findings[0].status, ControlStatus::Satisfied);
        assert!(findings[0].rationale.contains("pinned"));
    }

    #[test]
    fn violated_when_unpinned_refs_exist() {
        let unpinned = vec![
            UnpinnedActionRef {
                workflow_file: ".github/workflows/ci.yml".to_string(),
                action_ref: "actions/checkout@v4".to_string(),
            },
            UnpinnedActionRef {
                workflow_file: ".github/workflows/release.yml".to_string(),
                action_ref: "actions/setup-node@v3".to_string(),
            },
        ];
        let findings = ActionsPinnedDependenciesControl
            .evaluate(&bundle(EvidenceState::complete(posture(unpinned))));
        assert_eq!(findings[0].status, ControlStatus::Violated);
        assert!(findings[0].rationale.contains("2 unpinned"));
        assert_eq!(findings[0].subjects.len(), 2);
        assert!(findings[0].subjects[0].contains("ci.yml"));
    }
}
