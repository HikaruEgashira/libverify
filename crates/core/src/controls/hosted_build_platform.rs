use crate::control::{Control, ControlFinding, ControlId, builtin};
use crate::evidence::{EvidenceBundle, EvidenceState};
use crate::integrity::hosted_build_severity;
use crate::verdict::Severity;

/// Verifies that all builds run on hosted infrastructure, not developer workstations.
pub struct HostedBuildPlatformControl;

impl Control for HostedBuildPlatformControl {
    fn id(&self) -> ControlId {
        builtin::id(builtin::HOSTED_BUILD_PLATFORM)
    }

    fn evaluate(&self, evidence: &EvidenceBundle) -> Vec<ControlFinding> {
        let id = self.id();

        match &evidence.build_platform {
            EvidenceState::NotApplicable => {
                vec![ControlFinding::not_applicable(
                    id,
                    "Build platform evidence is not applicable",
                )]
            }
            EvidenceState::Missing { gaps } => {
                vec![ControlFinding::indeterminate(
                    id,
                    "Build platform evidence could not be collected",
                    Vec::new(),
                    gaps.clone(),
                )]
            }
            EvidenceState::Complete { value } | EvidenceState::Partial { value, .. } => {
                if value.is_empty() {
                    return vec![ControlFinding::not_applicable(
                        id,
                        "No build platform evidence was present",
                    )];
                }

                let subjects: Vec<String> = value.iter().map(|p| p.platform.clone()).collect();

                let non_hosted: Vec<&str> = value
                    .iter()
                    .filter(|p| !p.hosted)
                    .map(|p| p.platform.as_str())
                    .collect();

                let finding = match hosted_build_severity(non_hosted.len()) {
                    Severity::Pass => ControlFinding::satisfied(
                        id,
                        format!("All {} build platform(s) are hosted", value.len()),
                        subjects,
                    ),
                    _ => ControlFinding::violated(
                        id,
                        format!("Non-hosted build platform(s): {}", non_hosted.join(", ")),
                        subjects,
                    ),
                };
                vec![finding]
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::control::ControlStatus;
    use crate::evidence::{BuildPlatformEvidence, EvidenceGap};

    fn make_platform(name: &str, hosted: bool) -> BuildPlatformEvidence {
        BuildPlatformEvidence {
            platform: name.to_string(),
            hosted,
            ephemeral: true,
            isolated: true,
            runner_labels: vec!["ubuntu-latest".to_string()],
            signing_key_isolated: true,
        }
    }

    fn make_bundle(platforms: Vec<BuildPlatformEvidence>) -> EvidenceBundle {
        EvidenceBundle {
            build_platform: EvidenceState::complete(platforms),
            ..Default::default()
        }
    }

    // --- NotApplicable ---

    #[test]
    fn not_applicable_when_evidence_state_is_not_applicable() {
        let evidence = EvidenceBundle {
            build_platform: EvidenceState::not_applicable(),
            ..Default::default()
        };
        let findings = HostedBuildPlatformControl.evaluate(&evidence);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].status, ControlStatus::NotApplicable);
        assert_eq!(
            findings[0].control_id,
            builtin::id(builtin::HOSTED_BUILD_PLATFORM)
        );
    }

    #[test]
    fn not_applicable_when_platform_list_empty() {
        let findings = HostedBuildPlatformControl.evaluate(&make_bundle(vec![]));
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].status, ControlStatus::NotApplicable);
    }

    // --- Indeterminate ---

    #[test]
    fn indeterminate_when_evidence_missing() {
        let evidence = EvidenceBundle {
            build_platform: EvidenceState::missing(vec![EvidenceGap::CollectionFailed {
                source: "github".to_string(),
                subject: "build-platform".to_string(),
                detail: "API returned 403".to_string(),
            }]),
            ..Default::default()
        };
        let findings = HostedBuildPlatformControl.evaluate(&evidence);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].status, ControlStatus::Indeterminate);
        assert_eq!(findings[0].evidence_gaps.len(), 1);
    }

    // --- Satisfied ---

    #[test]
    fn satisfied_when_all_platforms_hosted() {
        let findings = HostedBuildPlatformControl.evaluate(&make_bundle(vec![
            make_platform("github-actions", true),
            make_platform("cloud-build", true),
        ]));
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].status, ControlStatus::Satisfied);
        assert_eq!(findings[0].subjects.len(), 2);
        assert!(
            findings[0]
                .rationale
                .contains("2 build platform(s) are hosted")
        );
    }

    #[test]
    fn satisfied_single_hosted_platform() {
        let findings = HostedBuildPlatformControl
            .evaluate(&make_bundle(vec![make_platform("github-actions", true)]));
        assert_eq!(findings[0].status, ControlStatus::Satisfied);
        assert_eq!(findings[0].subjects, vec!["github-actions"]);
    }

    // --- Violated ---

    #[test]
    fn violated_when_any_platform_not_hosted() {
        let findings = HostedBuildPlatformControl.evaluate(&make_bundle(vec![
            make_platform("github-actions", true),
            make_platform("developer-laptop", false),
        ]));
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].status, ControlStatus::Violated);
        assert!(findings[0].rationale.contains("developer-laptop"));
        assert_eq!(findings[0].subjects.len(), 2);
    }

    #[test]
    fn violated_when_all_platforms_not_hosted() {
        let findings = HostedBuildPlatformControl.evaluate(&make_bundle(vec![
            make_platform("local-runner-a", false),
            make_platform("local-runner-b", false),
        ]));
        assert_eq!(findings[0].status, ControlStatus::Violated);
        assert!(findings[0].rationale.contains("local-runner-a"));
        assert!(findings[0].rationale.contains("local-runner-b"));
    }

    // --- Edge cases ---

    #[test]
    fn partial_evidence_with_hosted_platforms_satisfied() {
        let evidence = EvidenceBundle {
            build_platform: EvidenceState::partial(
                vec![make_platform("github-actions", true)],
                vec![EvidenceGap::Truncated {
                    source: "github".to_string(),
                    subject: "build-platforms".to_string(),
                }],
            ),
            ..Default::default()
        };
        let findings = HostedBuildPlatformControl.evaluate(&evidence);
        assert_eq!(findings[0].status, ControlStatus::Satisfied);
    }

    #[test]
    fn partial_evidence_with_non_hosted_platform_violated() {
        let evidence = EvidenceBundle {
            build_platform: EvidenceState::partial(
                vec![make_platform("self-hosted-runner", false)],
                vec![EvidenceGap::Truncated {
                    source: "github".to_string(),
                    subject: "build-platforms".to_string(),
                }],
            ),
            ..Default::default()
        };
        let findings = HostedBuildPlatformControl.evaluate(&evidence);
        assert_eq!(findings[0].status, ControlStatus::Violated);
    }

    #[test]
    fn correct_control_id() {
        assert_eq!(
            HostedBuildPlatformControl.id(),
            builtin::id(builtin::HOSTED_BUILD_PLATFORM)
        );
    }
}
