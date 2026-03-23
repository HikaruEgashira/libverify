use crate::control::{Control, ControlFinding, ControlId, builtin};
use crate::evidence::{EvidenceBundle, EvidenceState, GovernedChange};
use crate::scope::{
    FileRole, classify_file_role, classify_scope, extract_feature_namespace, is_non_code_file,
    should_bridge_aux_to_source, should_bridge_colocated_sources, should_bridge_fork_variants,
    should_bridge_patch_semantic_tokens, should_bridge_test_fixture_pair,
};
use crate::union_find::{NodeKind, UnionFind};
use crate::verdict::Severity;

/// Verifies that change request changes are well-scoped (single logical unit).
pub struct ScopedChangeControl;

impl Control for ScopedChangeControl {
    fn id(&self) -> ControlId {
        builtin::id(builtin::SCOPED_CHANGE)
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

/// Extract identifier tokens from a unified diff patch for semantic matching.
fn extract_identifiers_from_patch(patch: &str) -> Vec<String> {
    let mut ids = Vec::new();
    for line in patch.lines() {
        if line.starts_with('+') || line.starts_with('-') {
            let content = &line[1..];
            for word in content.split(|c: char| !c.is_alphanumeric() && c != '_') {
                if word.len() >= 3 && word.chars().next().is_some_and(|c| c.is_alphabetic()) {
                    ids.push(word.to_string());
                }
            }
        }
    }
    ids.sort();
    ids.dedup();
    ids
}

fn evaluate_change(id: ControlId, cr: &GovernedChange) -> ControlFinding {
    let cr_subject = cr.id.to_string();

    let assets = match &cr.changed_assets {
        EvidenceState::NotApplicable => {
            return ControlFinding::not_applicable(id, "Changed assets not applicable");
        }
        EvidenceState::Missing { gaps } => {
            return ControlFinding::indeterminate(
                id,
                "Changed assets evidence could not be collected",
                Vec::new(),
                gaps.clone(),
            );
        }
        EvidenceState::Complete { value } | EvidenceState::Partial { value, .. } => value,
    };

    // Filter to code files with diffs
    let code_files: Vec<_> = assets
        .iter()
        .filter(|a| !is_non_code_file(&a.path) && a.diff_available)
        .collect();

    // 0-1 code files: trivially scoped
    if code_files.len() <= 1 {
        return ControlFinding::satisfied(
            id,
            format!("{cr_subject}: change request is well-scoped"),
            code_files.iter().map(|a| a.path.clone()).collect(),
        );
    }

    // Build union-find graph
    let mut graph = UnionFind::new();
    let mut file_nodes = Vec::new();

    for (idx, asset) in code_files.iter().enumerate() {
        let node = graph.add_node(idx as u16, &asset.path, NodeKind::File);
        file_nodes.push(node);
    }

    let aux_count = code_files
        .iter()
        .filter(|a| classify_file_role(&a.path) != FileRole::Source)
        .count();
    let source_count = code_files.len().saturating_sub(aux_count);

    // Extract identifiers from patches for semantic token matching
    let all_identifiers: Vec<Vec<String>> = code_files
        .iter()
        .map(|a| extract_identifiers_from_patch(a.diff.as_deref().unwrap_or("")))
        .collect();

    // Apply heuristic bridges
    for i in 0..code_files.len() {
        for j in (i + 1)..code_files.len() {
            let path_a = &code_files[i].path;
            let path_b = &code_files[j].path;

            let should_merge = should_bridge_colocated_sources(path_a, path_b)
                || should_bridge_aux_to_source(path_a, path_b, source_count, aux_count)
                || should_bridge_aux_to_source(path_b, path_a, source_count, aux_count)
                || should_bridge_fork_variants(path_a, path_b)
                || should_bridge_test_fixture_pair(path_a, path_b)
                || should_bridge_patch_semantic_tokens(
                    path_a,
                    path_b,
                    &all_identifiers[i],
                    &all_identifiers[j],
                    source_count,
                    aux_count,
                );

            if should_merge {
                graph.merge(file_nodes[i], file_nodes[j]);
            }
        }
    }

    // Feature namespace bridging
    if aux_count > 0 {
        let paths: Vec<&str> = code_files.iter().map(|a| a.path.as_str()).collect();
        if let Some(ns) = extract_feature_namespace(&paths)
            && ns.member_indices.len() >= 2
        {
            let anchor = file_nodes[ns.member_indices[0]];
            for &idx in &ns.member_indices[1..] {
                graph.merge(anchor, file_nodes[idx]);
            }
        }
    }

    let components = graph.component_count();
    let severity = classify_scope(code_files.len(), components);
    let subjects: Vec<String> = code_files.iter().map(|a| a.path.clone()).collect();

    match severity {
        Severity::Pass => ControlFinding::satisfied(
            id,
            format!("{cr_subject}: change request is well-scoped"),
            subjects,
        ),
        _ => {
            let comp_groups = graph.get_components();
            let mut detail = String::new();
            for (comp_idx, group) in comp_groups.iter().enumerate() {
                detail.push_str(&format!("  Component {}:", comp_idx + 1));
                for &file_idx in group {
                    detail.push_str(&format!(" {}", code_files[file_idx as usize].path));
                }
                detail.push('\n');
            }
            ControlFinding::violated(
                id,
                format!(
                    "{cr_subject}: change request has {components} disconnected change clusters\n{detail}"
                ),
                subjects,
            )
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::control::ControlStatus;
    use crate::evidence::{ChangeRequestId, ChangedAsset};

    fn asset(path: &str) -> ChangedAsset {
        ChangedAsset {
            path: path.to_string(),
            diff_available: true,
            additions: 1,
            deletions: 0,
            status: "modified".to_string(),
            diff: Some("@@ -1 +1 @@\n+changed\n".to_string()),
        }
    }

    fn bundle_with(assets: Vec<ChangedAsset>) -> EvidenceBundle {
        EvidenceBundle {
            change_requests: vec![GovernedChange {
                id: ChangeRequestId::new("test", "owner/repo#1"),
                title: "test".to_string(),
                summary: None,
                submitted_by: None,
                changed_assets: EvidenceState::complete(assets),
                approval_decisions: EvidenceState::not_applicable(),
                source_revisions: EvidenceState::not_applicable(),
                work_item_refs: EvidenceState::not_applicable(),
            }],
            ..Default::default()
        }
    }

    #[test]
    fn not_applicable_when_no_changes() {
        let findings = ScopedChangeControl.evaluate(&EvidenceBundle::default());
        assert_eq!(findings[0].status, ControlStatus::NotApplicable);
    }

    #[test]
    fn satisfied_for_single_file() {
        let bundle = bundle_with(vec![asset("src/foo.rs")]);
        let findings = ScopedChangeControl.evaluate(&bundle);
        assert_eq!(findings[0].status, ControlStatus::Satisfied);
    }

    #[test]
    fn satisfied_for_connected_source_and_test() {
        let bundle = bundle_with(vec![asset("src/foo.rs"), asset("tests/foo_test.rs")]);
        let findings = ScopedChangeControl.evaluate(&bundle);
        assert_eq!(
            findings[0].status,
            ControlStatus::Satisfied,
            "source + test should be connected: {}",
            findings[0].rationale
        );
    }

    #[test]
    fn violated_for_disconnected_files() {
        let bundle = bundle_with(vec![
            asset("src/auth/login.rs"),
            asset("src/payment/checkout.rs"),
        ]);
        let findings = ScopedChangeControl.evaluate(&bundle);
        assert_eq!(
            findings[0].status,
            ControlStatus::Violated,
            "disconnected domains should be violated: {}",
            findings[0].rationale
        );
    }

    #[test]
    fn non_code_files_excluded() {
        let bundle = bundle_with(vec![asset("src/auth/login.rs"), asset("README.md")]);
        let findings = ScopedChangeControl.evaluate(&bundle);
        // Only one code file after filtering → satisfied
        assert_eq!(findings[0].status, ControlStatus::Satisfied);
    }
}
