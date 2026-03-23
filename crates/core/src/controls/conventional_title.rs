use crate::control::{Control, ControlFinding, ControlId, builtin};
use crate::evidence::{EvidenceBundle, GovernedChange};

/// Recognized conventional commit type prefixes.
const CONVENTIONAL_TYPES: &[&str] = &[
    "feat", "fix", "docs", "style", "refactor", "perf", "test", "build", "ci", "chore", "revert",
];

/// Verifies that change request titles follow the Conventional Commits format.
///
/// Maps to SOC2 CC8.1: structured change documentation.
/// Conventional commit titles (e.g. `feat: add X`, `fix!: resolve Y`) enable
/// automated changelog generation and ensure changes are categorized consistently.
pub struct ConventionalTitleControl;

impl Control for ConventionalTitleControl {
    fn id(&self) -> ControlId {
        builtin::id(builtin::CONVENTIONAL_TITLE)
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
    let title = cr.title.trim();

    if title.is_empty() {
        return ControlFinding::violated(
            id,
            format!("{cr_subject}: change request has an empty title"),
            vec![cr_subject],
        );
    }

    if is_conventional(title) {
        ControlFinding::satisfied(
            id,
            format!("{cr_subject}: title follows Conventional Commits format"),
            vec![cr_subject],
        )
    } else {
        ControlFinding::violated(
            id,
            format!(
                "{cr_subject}: title does not follow Conventional Commits format (expected `type: description` or `type(scope): description`)"
            ),
            vec![cr_subject],
        )
    }
}

/// Checks if a title matches `type[(scope)][!]: description`.
fn is_conventional(title: &str) -> bool {
    // Find the colon separator
    let colon_pos = match title.find(": ") {
        Some(pos) => pos,
        None => return false,
    };

    let prefix = &title[..colon_pos];
    let description = title[colon_pos + 2..].trim();

    if description.is_empty() {
        return false;
    }

    // Strip optional breaking change marker
    let prefix = prefix.strip_suffix('!').unwrap_or(prefix);

    // Strip optional scope
    let type_part = if let Some(paren_start) = prefix.find('(') {
        if !prefix.ends_with(')') {
            return false;
        }
        &prefix[..paren_start]
    } else {
        prefix
    };

    CONVENTIONAL_TYPES.contains(&type_part)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::control::ControlStatus;
    use crate::evidence::{ChangeRequestId, EvidenceState};

    fn make_change(title: &str) -> GovernedChange {
        GovernedChange {
            id: ChangeRequestId::new("test", "owner/repo#1"),
            title: title.to_string(),
            summary: None,
            submitted_by: None,
            changed_assets: EvidenceState::not_applicable(),
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
        let findings = ConventionalTitleControl.evaluate(&EvidenceBundle::default());
        assert_eq!(findings[0].status, ControlStatus::NotApplicable);
    }

    #[test]
    fn satisfied_for_feat() {
        let cr = make_change("feat: add new compliance control");
        let findings = ConventionalTitleControl.evaluate(&bundle(vec![cr]));
        assert_eq!(findings[0].status, ControlStatus::Satisfied);
    }

    #[test]
    fn satisfied_for_fix_with_scope() {
        let cr = make_change("fix(core): resolve null pointer");
        let findings = ConventionalTitleControl.evaluate(&bundle(vec![cr]));
        assert_eq!(findings[0].status, ControlStatus::Satisfied);
    }

    #[test]
    fn satisfied_for_breaking_change() {
        let cr = make_change("refactor!: rename API endpoint");
        let findings = ConventionalTitleControl.evaluate(&bundle(vec![cr]));
        assert_eq!(findings[0].status, ControlStatus::Satisfied);
    }

    #[test]
    fn satisfied_for_breaking_with_scope() {
        let cr = make_change("feat(api)!: redesign auth flow");
        let findings = ConventionalTitleControl.evaluate(&bundle(vec![cr]));
        assert_eq!(findings[0].status, ControlStatus::Satisfied);
    }

    #[test]
    fn violated_for_untyped_title() {
        let cr = make_change("Add new feature");
        let findings = ConventionalTitleControl.evaluate(&bundle(vec![cr]));
        assert_eq!(findings[0].status, ControlStatus::Violated);
    }

    #[test]
    fn violated_for_unknown_type() {
        let cr = make_change("wip: work in progress");
        let findings = ConventionalTitleControl.evaluate(&bundle(vec![cr]));
        assert_eq!(findings[0].status, ControlStatus::Violated);
    }

    #[test]
    fn violated_for_missing_space_after_colon() {
        let cr = make_change("feat:no space");
        let findings = ConventionalTitleControl.evaluate(&bundle(vec![cr]));
        assert_eq!(findings[0].status, ControlStatus::Violated);
    }

    #[test]
    fn violated_for_empty_description() {
        let cr = make_change("feat: ");
        let findings = ConventionalTitleControl.evaluate(&bundle(vec![cr]));
        assert_eq!(findings[0].status, ControlStatus::Violated);
    }

    #[test]
    fn violated_for_empty_title() {
        let cr = make_change("");
        let findings = ConventionalTitleControl.evaluate(&bundle(vec![cr]));
        assert_eq!(findings[0].status, ControlStatus::Violated);
    }

    #[test]
    fn all_conventional_types_accepted() {
        for ty in CONVENTIONAL_TYPES {
            let cr = make_change(&format!("{ty}: test description"));
            let findings = ConventionalTitleControl.evaluate(&bundle(vec![cr]));
            assert_eq!(
                findings[0].status,
                ControlStatus::Satisfied,
                "type '{ty}' should be accepted"
            );
        }
    }
}
