use crate::control::{Control, ControlFinding, ControlId, builtin};
use crate::evidence::EvidenceBundle;

/// Validates that tag protection rules exist to prevent unauthorized releases.
///
/// Maps to NIST 800-53 SA-10 (Developer Configuration Management).
///
/// Tag protection rules prevent unauthorized creation of release tags,
/// which is critical for supply chain integrity — without them, any
/// collaborator with write access can create a release tag.
pub struct ProtectedTagsControl;

impl Control for ProtectedTagsControl {
    fn id(&self) -> ControlId {
        builtin::id(builtin::PROTECTED_TAGS)
    }

    fn description(&self) -> &'static str {
        "Tag protection rules must exist to prevent unauthorized release tag creation"
    }

    fn evaluate(&self, evidence: &EvidenceBundle) -> Vec<ControlFinding> {
        let posture = match ControlFinding::extract_posture(self.id(), evidence) {
            Ok(p) => p,
            Err(findings) => return findings,
        };

        if posture.tag_protection_enabled {
            vec![ControlFinding::satisfied(
                self.id(),
                "Tag protection rules are configured — unauthorized release tags are prevented",
                vec!["repository:tag-protection".into()],
            )]
        } else {
            vec![ControlFinding::violated(
                self.id(),
                "No tag protection rules found — any collaborator with write access can create release tags",
                vec!["repository:tag-protection".into()],
            )]
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::control::ControlStatus;
    use crate::evidence::{EvidenceState, RepositoryPosture};

    fn bundle_with(enabled: bool) -> EvidenceBundle {
        EvidenceBundle {
            repository_posture: EvidenceState::complete(RepositoryPosture {
                tag_protection_enabled: enabled,
                ..Default::default()
            }),
            ..Default::default()
        }
    }

    #[test]
    fn satisfied_when_tag_protection_enabled() {
        let findings = ProtectedTagsControl.evaluate(&bundle_with(true));
        assert_eq!(findings[0].status, ControlStatus::Satisfied);
    }

    #[test]
    fn violated_when_no_tag_protection() {
        let findings = ProtectedTagsControl.evaluate(&bundle_with(false));
        assert_eq!(findings[0].status, ControlStatus::Violated);
    }

    #[test]
    fn indeterminate_when_posture_missing() {
        let findings = ProtectedTagsControl.evaluate(&EvidenceBundle {
            repository_posture: EvidenceState::missing(vec![]),
            ..Default::default()
        });
        assert_eq!(findings[0].status, ControlStatus::Indeterminate);
    }
}
