use crate::control::{Control, ControlFinding, ControlId, builtin};
use crate::evidence::EvidenceBundle;

/// Minimum number of targeted entries (without catch-all) considered
/// intentional ownership coverage.
const TARGETED_COVERAGE_THRESHOLD: usize = 3;

/// Validates that a CODEOWNERS file exists and provides meaningful coverage.
///
/// Maps to SOC2 CC6.1: logical access controls ensure that code changes to
/// sensitive areas are routed to designated owners for review.
/// Also an ASPM signal — code ownership coverage reduces unreviewed blast radius.
///
/// Evaluation tiers:
/// - **Satisfied**: catch-all pattern exists, OR 3+ targeted entries (intentional ownership)
/// - **Violated**: no entries, or fewer than 3 entries without catch-all
pub struct CodeownersCoverageControl;

impl Control for CodeownersCoverageControl {
    fn id(&self) -> ControlId {
        builtin::id(builtin::CODEOWNERS_COVERAGE)
    }

    fn description(&self) -> &'static str {
        "CODEOWNERS must exist with meaningful ownership coverage for review routing"
    }

    fn evaluate(&self, evidence: &EvidenceBundle) -> Vec<ControlFinding> {
        let posture = match ControlFinding::extract_posture(self.id(), evidence) {
            Ok(p) => p,
            Err(findings) => return findings,
        };

        if posture.codeowners_entries.is_empty() {
            return vec![ControlFinding::violated(
                self.id(),
                "No CODEOWNERS file found or file contains no entries",
                vec!["CODEOWNERS".to_string()],
            )];
        }

        let has_catch_all = posture
            .codeowners_entries
            .iter()
            .any(|e| e.pattern == "*" || e.pattern == "/**");

        let entry_count = posture.codeowners_entries.len();

        if has_catch_all {
            vec![ControlFinding::satisfied(
                self.id(),
                format!("CODEOWNERS has {entry_count} entries with catch-all coverage"),
                vec!["CODEOWNERS".to_string()],
            )]
        } else if entry_count >= TARGETED_COVERAGE_THRESHOLD {
            // Intentional targeted ownership without catch-all is valid —
            // many projects deliberately omit * so uncovered paths don't block
            vec![ControlFinding::satisfied(
                self.id(),
                format!(
                    "CODEOWNERS has {entry_count} targeted entries \
                     (no catch-all, but coverage appears intentional)"
                ),
                vec!["CODEOWNERS".to_string()],
            )]
        } else {
            vec![ControlFinding::violated(
                self.id(),
                format!(
                    "CODEOWNERS has only {entry_count} entries and no catch-all pattern — \
                     coverage appears incomplete"
                ),
                vec!["CODEOWNERS".to_string()],
            )]
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::control::ControlStatus;
    use crate::evidence::{CodeownersEntry, EvidenceGap, EvidenceState, RepositoryPosture};

    fn posture(entries: Vec<CodeownersEntry>) -> RepositoryPosture {
        RepositoryPosture {
            codeowners_entries: entries,
            ..Default::default()
        }
    }

    fn bundle(state: EvidenceState<RepositoryPosture>) -> EvidenceBundle {
        EvidenceBundle {
            repository_posture: state,
            ..Default::default()
        }
    }

    fn entry(pattern: &str, owners: &[&str]) -> CodeownersEntry {
        CodeownersEntry {
            pattern: pattern.to_string(),
            owners: owners.iter().map(|s| s.to_string()).collect(),
        }
    }

    #[test]
    fn not_applicable_when_posture_not_applicable() {
        let findings = CodeownersCoverageControl.evaluate(&bundle(EvidenceState::not_applicable()));
        assert_eq!(findings[0].status, ControlStatus::NotApplicable);
    }

    #[test]
    fn indeterminate_when_posture_missing() {
        let findings = CodeownersCoverageControl.evaluate(&bundle(EvidenceState::missing(vec![
            EvidenceGap::CollectionFailed {
                source: "github".to_string(),
                subject: "posture".to_string(),
                detail: "API error".to_string(),
            },
        ])));
        assert_eq!(findings[0].status, ControlStatus::Indeterminate);
    }

    #[test]
    fn violated_when_no_entries() {
        let findings =
            CodeownersCoverageControl.evaluate(&bundle(EvidenceState::complete(posture(vec![]))));
        assert_eq!(findings[0].status, ControlStatus::Violated);
    }

    #[test]
    fn violated_when_too_few_entries_without_catch_all() {
        let findings =
            CodeownersCoverageControl.evaluate(&bundle(EvidenceState::complete(posture(vec![
                entry("/src/", &["@org/core-team"]),
            ]))));
        assert_eq!(findings[0].status, ControlStatus::Violated);
        assert!(findings[0].rationale.contains("only 1 entries"));
    }

    #[test]
    fn satisfied_with_catch_all() {
        let findings =
            CodeownersCoverageControl.evaluate(&bundle(EvidenceState::complete(posture(vec![
                entry("/src/auth/", &["@org/security-team"]),
                entry("*", &["@org/default-reviewers"]),
            ]))));
        assert_eq!(findings[0].status, ControlStatus::Satisfied);
    }

    #[test]
    fn satisfied_with_glob_catch_all() {
        let findings =
            CodeownersCoverageControl.evaluate(&bundle(EvidenceState::complete(posture(vec![
                entry("/**", &["@org/default-reviewers"]),
            ]))));
        assert_eq!(findings[0].status, ControlStatus::Satisfied);
    }

    #[test]
    fn satisfied_with_targeted_entries_no_catch_all() {
        let findings =
            CodeownersCoverageControl.evaluate(&bundle(EvidenceState::complete(posture(vec![
                entry("/src/auth/", &["@org/security-team"]),
                entry("/infra/", &["@org/platform-team"]),
                entry("/.github/", &["@org/devops"]),
            ]))));
        assert_eq!(findings[0].status, ControlStatus::Satisfied);
        assert!(findings[0].rationale.contains("targeted entries"));
    }

    #[test]
    fn violated_with_two_entries_no_catch_all() {
        let findings =
            CodeownersCoverageControl.evaluate(&bundle(EvidenceState::complete(posture(vec![
                entry("/src/auth/", &["@org/security-team"]),
                entry("/infra/", &["@org/platform-team"]),
            ]))));
        assert_eq!(findings[0].status, ControlStatus::Violated);
    }
}
