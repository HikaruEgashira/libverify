use crate::control::{Control, ControlFinding, ControlId, builtin};
use crate::evidence::{EvidenceBundle, EvidenceState, GovernedChange};

/// Path patterns that indicate security-sensitive files.
///
/// Changes to these files alter CI pipelines, access control, dependency
/// resolution, or authentication configuration — all of which require
/// heightened review scrutiny.
const SENSITIVE_PATTERNS: &[&str] = &[
    // CI / CD configuration
    ".github/workflows/",
    ".github/actions/",
    ".gitlab-ci.yml",
    "Jenkinsfile",
    ".circleci/",
    ".travis.yml",
    // Access control
    "CODEOWNERS",
    ".github/CODEOWNERS",
    // Dependency management (supply chain)
    "Cargo.lock",
    "package-lock.json",
    "yarn.lock",
    "pnpm-lock.yaml",
    "Gemfile.lock",
    "poetry.lock",
    "go.sum",
    // Security configuration
    ".gitattributes",
    ".gitmodules",
    // Docker / container
    "Dockerfile",
    "docker-compose",
    // Infrastructure as Code
    "terraform/",
    ".terraform",
    "pulumi/",
];

/// Detects changes to security-sensitive files that require heightened review.
///
/// Maps to SOC2 CC7.2: monitoring for anomalies in change governance.
/// Changes to CI configs, access control, lock files, and infrastructure
/// definitions have outsized blast radius and should be flagged for scrutiny.
pub struct SecurityFileChangeControl;

impl Control for SecurityFileChangeControl {
    fn id(&self) -> ControlId {
        builtin::id(builtin::SECURITY_FILE_CHANGE)
    }

    fn evaluate(&self, evidence: &EvidenceBundle) -> Vec<ControlFinding> {
        if evidence.change_requests.is_empty() {
            return vec![ControlFinding::not_applicable(
                self.id(),
                "No change requests found",
            )];
        }

        evidence
            .change_requests
            .iter()
            .map(|cr| evaluate_change(self.id(), cr))
            .collect()
    }
}

fn evaluate_change(id: ControlId, cr: &GovernedChange) -> ControlFinding {
    let cr_subject = cr.id.to_string();

    let assets = match &cr.changed_assets {
        EvidenceState::Complete { value } | EvidenceState::Partial { value, .. } => value,
        EvidenceState::Missing { gaps } => {
            return ControlFinding::indeterminate(
                id,
                format!("{cr_subject}: changed asset evidence could not be collected"),
                vec![cr_subject],
                gaps.clone(),
            );
        }
        EvidenceState::NotApplicable => {
            return ControlFinding::not_applicable(id, "Changed assets not applicable");
        }
    };

    let sensitive_files: Vec<&str> = assets
        .iter()
        .filter(|a| is_sensitive_path(&a.path))
        .map(|a| a.path.as_str())
        .collect();

    if sensitive_files.is_empty() {
        ControlFinding::satisfied(
            id,
            format!("{cr_subject}: no security-sensitive files changed"),
            vec![cr_subject],
        )
    } else {
        ControlFinding::violated(
            id,
            format!(
                "{cr_subject}: {} security-sensitive file(s) changed: {}",
                sensitive_files.len(),
                sensitive_files.join(", ")
            ),
            sensitive_files.into_iter().map(String::from).collect(),
        )
    }
}

/// Returns true if the path matches a security-sensitive pattern.
fn is_sensitive_path(path: &str) -> bool {
    let lower = path.to_lowercase();
    SENSITIVE_PATTERNS
        .iter()
        .any(|pattern| lower.contains(&pattern.to_lowercase()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::control::ControlStatus;
    use crate::evidence::{ChangeRequestId, ChangedAsset, EvidenceGap};

    fn asset(path: &str) -> ChangedAsset {
        ChangedAsset {
            path: path.to_string(),
            diff_available: true,
            additions: 1,
            deletions: 0,
            status: "modified".to_string(),
            diff: None,
        }
    }

    fn make_change(assets: EvidenceState<Vec<ChangedAsset>>) -> GovernedChange {
        GovernedChange {
            id: ChangeRequestId::new("test", "owner/repo#1"),
            title: "test".to_string(),
            summary: None,
            submitted_by: None,
            changed_assets: assets,
            approval_decisions: EvidenceState::not_applicable(),
            source_revisions: EvidenceState::not_applicable(),
            work_item_refs: EvidenceState::not_applicable(),
        }
    }

    fn bundle(changes: Vec<GovernedChange>) -> EvidenceBundle {
        EvidenceBundle {
            change_requests: changes,
            ..Default::default()
        }
    }

    #[test]
    fn not_applicable_when_no_changes() {
        let findings = SecurityFileChangeControl.evaluate(&EvidenceBundle::default());
        assert_eq!(findings[0].status, ControlStatus::NotApplicable);
    }

    #[test]
    fn satisfied_when_no_sensitive_files() {
        let cr = make_change(EvidenceState::complete(vec![
            asset("src/main.rs"),
            asset("src/lib.rs"),
        ]));
        let findings = SecurityFileChangeControl.evaluate(&bundle(vec![cr]));
        assert_eq!(findings[0].status, ControlStatus::Satisfied);
    }

    #[test]
    fn violated_when_workflow_changed() {
        let cr = make_change(EvidenceState::complete(vec![
            asset("src/main.rs"),
            asset(".github/workflows/ci.yml"),
        ]));
        let findings = SecurityFileChangeControl.evaluate(&bundle(vec![cr]));
        assert_eq!(findings[0].status, ControlStatus::Violated);
        assert!(findings[0].rationale.contains("ci.yml"));
    }

    #[test]
    fn violated_when_codeowners_changed() {
        let cr = make_change(EvidenceState::complete(vec![asset("CODEOWNERS")]));
        let findings = SecurityFileChangeControl.evaluate(&bundle(vec![cr]));
        assert_eq!(findings[0].status, ControlStatus::Violated);
    }

    #[test]
    fn violated_when_lockfile_changed() {
        let cr = make_change(EvidenceState::complete(vec![asset("Cargo.lock")]));
        let findings = SecurityFileChangeControl.evaluate(&bundle(vec![cr]));
        assert_eq!(findings[0].status, ControlStatus::Violated);
    }

    #[test]
    fn violated_when_dockerfile_changed() {
        let cr = make_change(EvidenceState::complete(vec![asset("Dockerfile")]));
        let findings = SecurityFileChangeControl.evaluate(&bundle(vec![cr]));
        assert_eq!(findings[0].status, ControlStatus::Violated);
    }

    #[test]
    fn indeterminate_when_assets_missing() {
        let cr = make_change(EvidenceState::missing(vec![
            EvidenceGap::CollectionFailed {
                source: "github".to_string(),
                subject: "files".to_string(),
                detail: "API error".to_string(),
            },
        ]));
        let findings = SecurityFileChangeControl.evaluate(&bundle(vec![cr]));
        assert_eq!(findings[0].status, ControlStatus::Indeterminate);
    }

    #[test]
    fn multiple_sensitive_files_all_reported() {
        let cr = make_change(EvidenceState::complete(vec![
            asset(".github/workflows/release.yml"),
            asset("CODEOWNERS"),
            asset("Cargo.lock"),
        ]));
        let findings = SecurityFileChangeControl.evaluate(&bundle(vec![cr]));
        assert_eq!(findings[0].status, ControlStatus::Violated);
        assert_eq!(findings[0].subjects.len(), 3);
    }
}
