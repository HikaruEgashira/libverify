use crate::control::{builtin, Control, ControlFinding, ControlId};
use crate::evidence::{EvidenceBundle, EvidenceState};
use crate::integrity::build_isolation_severity;
use crate::verdict::Severity;

/// Verifies that builds run in isolated, ephemeral environments with signing key isolation.
pub struct BuildIsolationControl;

impl Control for BuildIsolationControl {
    fn id(&self) -> ControlId {
        builtin::id(builtin::BUILD_ISOLATION)
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

                let violations: Vec<String> = value
                    .iter()
                    .filter(|p| !p.isolated || !p.ephemeral || !p.signing_key_isolated)
                    .map(|p| {
                        let mut failed = Vec::new();
                        if !p.isolated {
                            failed.push("not isolated");
                        }
                        if !p.ephemeral {
                            failed.push("not ephemeral");
                        }
                        if !p.signing_key_isolated {
                            failed.push("signing key not isolated");
                        }
                        format!("{} ({})", p.platform, failed.join(", "))
                    })
                    .collect();

                let finding = match build_isolation_severity(violations.len()) {
                    Severity::Pass => ControlFinding::satisfied(
                        id,
                        format!(
                            "All {} build platform(s) are isolated, ephemeral, and have signing key isolation",
                            value.len()
                        ),
                        subjects,
                    ),
                    _ => ControlFinding::violated(
                        id,
                        format!("Build isolation violation(s): {}", violations.join("; ")),
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

    fn make_platform(
        name: &str,
        isolated: bool,
        ephemeral: bool,
        signing_key_isolated: bool,
    ) -> BuildPlatformEvidence {
        BuildPlatformEvidence {
            platform: name.to_string(),
            hosted: true,
            ephemeral,
            isolated,
            runner_labels: vec!["ubuntu-latest".to_string()],
            signing_key_isolated,
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
        let findings = BuildIsolationControl.evaluate(&evidence);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].status, ControlStatus::NotApplicable);
        assert_eq!(findings[0].control_id, builtin::id(builtin::BUILD_ISOLATION));
    }

    #[test]
    fn not_applicable_when_platform_list_empty() {
        let findings = BuildIsolationControl.evaluate(&make_bundle(vec![]));
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
        let findings = BuildIsolationControl.evaluate(&evidence);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].status, ControlStatus::Indeterminate);
        assert_eq!(findings[0].evidence_gaps.len(), 1);
    }

    // --- Satisfied ---

    #[test]
    fn satisfied_when_all_conditions_met() {
        let findings = BuildIsolationControl.evaluate(&make_bundle(vec![
            make_platform("github-actions", true, true, true),
            make_platform("cloud-build", true, true, true),
        ]));
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].status, ControlStatus::Satisfied);
        assert_eq!(findings[0].subjects.len(), 2);
        assert!(findings[0].rationale.contains("2 build platform(s)"));
    }

    #[test]
    fn satisfied_single_fully_isolated_platform() {
        let findings = BuildIsolationControl.evaluate(&make_bundle(vec![make_platform(
            "github-actions",
            true,
            true,
            true,
        )]));
        assert_eq!(findings[0].status, ControlStatus::Satisfied);
        assert_eq!(findings[0].subjects, vec!["github-actions"]);
    }

    // --- Violated ---

    #[test]
    fn violated_when_not_isolated() {
        let findings = BuildIsolationControl.evaluate(&make_bundle(vec![make_platform(
            "shared-runner",
            false,
            true,
            true,
        )]));
        assert_eq!(findings[0].status, ControlStatus::Violated);
        assert!(findings[0].rationale.contains("shared-runner"));
        assert!(findings[0].rationale.contains("not isolated"));
    }

    #[test]
    fn violated_when_not_ephemeral() {
        let findings = BuildIsolationControl.evaluate(&make_bundle(vec![make_platform(
            "persistent-runner",
            true,
            false,
            true,
        )]));
        assert_eq!(findings[0].status, ControlStatus::Violated);
        assert!(findings[0].rationale.contains("persistent-runner"));
        assert!(findings[0].rationale.contains("not ephemeral"));
    }

    #[test]
    fn violated_when_signing_key_not_isolated() {
        let findings = BuildIsolationControl.evaluate(&make_bundle(vec![make_platform(
            "leaky-runner",
            true,
            true,
            false,
        )]));
        assert_eq!(findings[0].status, ControlStatus::Violated);
        assert!(findings[0].rationale.contains("leaky-runner"));
        assert!(findings[0].rationale.contains("signing key not isolated"));
    }

    #[test]
    fn violated_reports_multiple_failures() {
        let findings = BuildIsolationControl.evaluate(&make_bundle(vec![make_platform(
            "bad-runner",
            false,
            false,
            false,
        )]));
        assert_eq!(findings[0].status, ControlStatus::Violated);
        assert!(findings[0].rationale.contains("not isolated"));
        assert!(findings[0].rationale.contains("not ephemeral"));
        assert!(findings[0].rationale.contains("signing key not isolated"));
    }

    #[test]
    fn violated_when_any_platform_fails() {
        let findings = BuildIsolationControl.evaluate(&make_bundle(vec![
            make_platform("github-actions", true, true, true),
            make_platform("self-hosted", false, false, false),
        ]));
        assert_eq!(findings[0].status, ControlStatus::Violated);
        assert!(findings[0].rationale.contains("self-hosted"));
        assert_eq!(findings[0].subjects.len(), 2);
    }

    // --- Edge cases ---

    #[test]
    fn partial_evidence_with_isolated_platforms_satisfied() {
        let evidence = EvidenceBundle {
            build_platform: EvidenceState::partial(
                vec![make_platform("github-actions", true, true, true)],
                vec![EvidenceGap::Truncated {
                    source: "github".to_string(),
                    subject: "build-platforms".to_string(),
                }],
            ),
            ..Default::default()
        };
        let findings = BuildIsolationControl.evaluate(&evidence);
        assert_eq!(findings[0].status, ControlStatus::Satisfied);
    }

    #[test]
    fn partial_evidence_with_non_isolated_platform_violated() {
        let evidence = EvidenceBundle {
            build_platform: EvidenceState::partial(
                vec![make_platform("shared-runner", false, true, true)],
                vec![EvidenceGap::Truncated {
                    source: "github".to_string(),
                    subject: "build-platforms".to_string(),
                }],
            ),
            ..Default::default()
        };
        let findings = BuildIsolationControl.evaluate(&evidence);
        assert_eq!(findings[0].status, ControlStatus::Violated);
    }

    #[test]
    fn correct_control_id() {
        assert_eq!(BuildIsolationControl.id(), builtin::id(builtin::BUILD_ISOLATION));
    }
}
