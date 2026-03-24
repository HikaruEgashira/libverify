use crate::control::{Control, ControlFinding, ControlId, builtin};
use crate::evidence::EvidenceBundle;

/// Validates that a security policy (SECURITY.md) exists with a responsible
/// disclosure process.
///
/// Maps to SOC2 CC7.3 / CC7.4: incident response communication.
/// ASPM signal — a published security policy enables external reporters to
/// disclose vulnerabilities responsibly, reducing exposure window.
///
/// Note: In enterprise settings (SOC2 preset), this control's violations are
/// treated as "review" rather than "fail" because enterprises typically
/// maintain disclosure processes in internal portals, not repo-level files.
/// In OSS (OSS preset), this is strict — SECURITY.md is the primary channel.
pub struct SecurityPolicyControl;

impl Control for SecurityPolicyControl {
    fn id(&self) -> ControlId {
        builtin::id(builtin::SECURITY_POLICY)
    }

    fn description(&self) -> &'static str {
        "A security policy (SECURITY.md) with responsible disclosure process must exist"
    }

    fn evaluate(&self, evidence: &EvidenceBundle) -> Vec<ControlFinding> {
        let posture = match ControlFinding::extract_posture(self.id(), evidence) {
            Ok(p) => p,
            Err(findings) => return findings,
        };

        if !posture.security_policy_present {
            return vec![ControlFinding::violated(
                self.id(),
                "No SECURITY.md or security policy file found",
                vec!["SECURITY.md".to_string()],
            )];
        }

        if posture.security_policy_has_disclosure {
            vec![ControlFinding::satisfied(
                self.id(),
                "Security policy exists with responsible disclosure process",
                vec!["SECURITY.md".to_string()],
            )]
        } else {
            vec![ControlFinding::violated(
                self.id(),
                "Security policy exists but lacks a responsible disclosure process",
                vec!["SECURITY.md".to_string()],
            )]
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::control::ControlStatus;
    use crate::evidence::{EvidenceGap, EvidenceState, RepositoryPosture};

    fn posture(present: bool, disclosure: bool) -> RepositoryPosture {
        RepositoryPosture {
            codeowners_entries: vec![],
            secret_scanning_enabled: false,
            secret_push_protection_enabled: false,
            vulnerability_scanning_enabled: false,
            code_scanning_enabled: false,
            security_policy_present: present,
            security_policy_has_disclosure: disclosure,
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
        let findings = SecurityPolicyControl.evaluate(&bundle(EvidenceState::not_applicable()));
        assert_eq!(findings[0].status, ControlStatus::NotApplicable);
    }

    #[test]
    fn indeterminate_when_posture_missing() {
        let findings = SecurityPolicyControl.evaluate(&bundle(EvidenceState::missing(vec![
            EvidenceGap::CollectionFailed {
                source: "github".to_string(),
                subject: "posture".to_string(),
                detail: "API error".to_string(),
            },
        ])));
        assert_eq!(findings[0].status, ControlStatus::Indeterminate);
    }

    #[test]
    fn violated_when_no_policy() {
        let findings =
            SecurityPolicyControl.evaluate(&bundle(EvidenceState::complete(posture(false, false))));
        assert_eq!(findings[0].status, ControlStatus::Violated);
        assert!(findings[0].rationale.contains("No SECURITY.md"));
    }

    #[test]
    fn violated_when_policy_without_disclosure() {
        let findings =
            SecurityPolicyControl.evaluate(&bundle(EvidenceState::complete(posture(true, false))));
        assert_eq!(findings[0].status, ControlStatus::Violated);
        assert!(
            findings[0]
                .rationale
                .contains("lacks a responsible disclosure")
        );
    }

    #[test]
    fn satisfied_when_policy_with_disclosure() {
        let findings =
            SecurityPolicyControl.evaluate(&bundle(EvidenceState::complete(posture(true, true))));
        assert_eq!(findings[0].status, ControlStatus::Satisfied);
    }
}
