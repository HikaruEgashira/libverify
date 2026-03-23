//! Test coverage heuristics for pull request diffs.
//!
//! This module maps changed source files to likely companion test files
//! using path conventions and strict semantic matching guards.

use std::collections::HashSet;

use crate::scope::{FileRole, classify_file_role, semantic_path_tokens};

/// A source file that appears to have no matching changed test file.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UncoveredSource {
    pub source_path: String,
    pub suggested_test_paths: Vec<String>,
}

/// Generate likely companion test file paths for a source file.
pub fn find_test_pair(source_path: &str) -> Vec<String> {
    if classify_file_role(source_path) != FileRole::Source {
        return vec![];
    }

    let file = source_path.rsplit('/').next().unwrap_or(source_path);
    let (stem, ext) = split_stem_ext(file);
    if stem.is_empty() {
        return vec![];
    }

    let ext_suffix = if ext.is_empty() {
        String::new()
    } else {
        format!(".{ext}")
    };
    let source_parent = parent_dir(source_path);

    let mut out = Vec::new();
    push_unique(
        &mut out,
        join_path(source_parent, &format!("{stem}_test{ext_suffix}")),
    );
    push_unique(
        &mut out,
        join_path(source_parent, &format!("test_{stem}{ext_suffix}")),
    );

    if let Some((prefix, rel)) = split_src_root(source_path) {
        let rel_parent = parent_dir(rel);
        let tests_root = if prefix.is_empty() {
            "tests".to_string()
        } else {
            format!("{prefix}/tests")
        };
        let src_tests_root = if prefix.is_empty() {
            "src/tests".to_string()
        } else {
            format!("{prefix}/src/tests")
        };

        push_unique(
            &mut out,
            join_path(
                &join_path(&tests_root, rel_parent),
                &format!("{stem}_test{ext_suffix}"),
            ),
        );
        push_unique(
            &mut out,
            join_path(
                &join_path(&tests_root, rel_parent),
                &format!("test_{stem}{ext_suffix}"),
            ),
        );
        push_unique(
            &mut out,
            join_path(
                &join_path(&src_tests_root, rel_parent),
                &format!("{stem}{ext_suffix}"),
            ),
        );
    }

    out
}

/// Return uncovered source files by checking changed test files.
pub fn has_test_coverage(source_files: &[&str], test_files: &[&str]) -> Vec<UncoveredSource> {
    let normalized_tests: HashSet<String> = test_files
        .iter()
        .map(|p| normalize_path_for_match(p))
        .collect();

    let mut uncovered = Vec::new();

    for source in source_files {
        if classify_file_role(source) != FileRole::Source {
            continue;
        }

        let suggestions = find_test_pair(source);
        let covered_by_convention = suggestions
            .iter()
            .any(|candidate| normalized_tests.contains(&normalize_path_for_match(candidate)));

        if covered_by_convention {
            continue;
        }

        let covered_by_semantics = test_files
            .iter()
            .any(|test| is_semantically_matching_test(source, test));
        if covered_by_semantics {
            continue;
        }

        uncovered.push(UncoveredSource {
            source_path: (*source).to_string(),
            suggested_test_paths: suggestions,
        });
    }

    uncovered
}

fn split_stem_ext(file: &str) -> (&str, &str) {
    if let Some((stem, ext)) = file.rsplit_once('.') {
        (stem, ext)
    } else {
        (file, "")
    }
}

fn split_src_root(path: &str) -> Option<(String, &str)> {
    if let Some(rest) = path.strip_prefix("src/") {
        return Some((String::new(), rest));
    }
    path.split_once("/src/")
        .map(|(prefix, rest)| (prefix.to_string(), rest))
}

fn parent_dir(path: &str) -> &str {
    path.rsplit_once('/').map(|(p, _)| p).unwrap_or("")
}

fn join_path(parent: &str, child: &str) -> String {
    if parent.is_empty() {
        return child.to_string();
    }
    if child.is_empty() {
        return parent.to_string();
    }
    format!("{parent}/{child}")
}

fn push_unique(out: &mut Vec<String>, value: String) {
    if !out.contains(&value) {
        out.push(value);
    }
}

fn normalize_path_for_match(path: &str) -> String {
    path.to_ascii_lowercase()
}

fn normalized_file_stem(path: &str) -> String {
    let file = path.rsplit('/').next().unwrap_or(path);
    let (stem, _) = split_stem_ext(file);
    stem.chars()
        .filter(|c| c.is_ascii_alphanumeric())
        .flat_map(char::to_lowercase)
        .collect()
}

fn is_semantically_matching_test(source_path: &str, test_path: &str) -> bool {
    if classify_file_role(test_path) != FileRole::Test {
        return false;
    }

    let source_stem = normalized_file_stem(source_path);
    if source_stem.len() >= 5
        && !is_generic_token(&source_stem)
        && normalize_path_for_match(test_path).contains(&source_stem)
    {
        return true;
    }

    let source_tokens = semantic_path_tokens(source_path);
    let test_tokens: HashSet<String> = semantic_path_tokens(test_path).into_iter().collect();

    source_tokens
        .iter()
        .any(|token| token.len() >= 5 && !is_generic_token(token) && test_tokens.contains(token))
}

fn is_generic_token(token: &str) -> bool {
    matches!(
        token,
        "test"
            | "tests"
            | "spec"
            | "fixture"
            | "fixtures"
            | "runtime"
            | "source"
            | "types"
            | "type"
            | "index"
            | "core"
            | "src"
            | "lib"
            | "util"
            | "utils"
            | "package"
            | "packages"
            | "private"
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn find_test_pair_for_src_file() {
        let pairs = find_test_pair("src/foo.rs");
        assert!(pairs.contains(&"tests/foo_test.rs".to_string()));
        assert!(pairs.contains(&"src/foo_test.rs".to_string()));
        assert!(pairs.contains(&"tests/test_foo.rs".to_string()));
        assert!(pairs.contains(&"src/tests/foo.rs".to_string()));
    }

    #[test]
    fn find_test_pair_for_nested_workspace_source() {
        let pairs = find_test_pair("crates/core/src/scope.rs");
        assert!(pairs.contains(&"crates/core/tests/scope_test.rs".to_string()));
        assert!(pairs.contains(&"crates/core/src/scope_test.rs".to_string()));
        assert!(pairs.contains(&"crates/core/tests/test_scope.rs".to_string()));
        assert!(pairs.contains(&"crates/core/src/tests/scope.rs".to_string()));
    }

    #[test]
    fn has_test_coverage_passes_when_pair_exists() {
        let sources = vec!["src/foo.rs"];
        let tests = vec!["tests/foo_test.rs"];
        let uncovered = has_test_coverage(&sources, &tests);
        assert!(uncovered.is_empty());
    }

    #[test]
    fn has_test_coverage_warns_missing_source_pair() {
        let sources = vec!["src/foo.rs", "src/bar.rs"];
        let tests = vec!["tests/foo_test.rs"];
        let uncovered = has_test_coverage(&sources, &tests);
        assert_eq!(uncovered.len(), 1);
        assert_eq!(uncovered[0].source_path, "src/bar.rs");
    }

    #[test]
    fn semantic_fallback_matches_named_test() {
        let sources = vec!["packages/runtime-core/src/apiDefineComponent.ts"];
        let tests = vec!["packages/runtime-core/__tests__/apiDefineComponent.spec.ts"];
        let uncovered = has_test_coverage(&sources, &tests);
        assert!(uncovered.is_empty());
    }

    #[test]
    fn semantic_fallback_rejects_generic_test_name() {
        let sources = vec!["src/auth.rs"];
        let tests = vec!["tests/index_test.rs"];
        let uncovered = has_test_coverage(&sources, &tests);
        assert_eq!(uncovered.len(), 1);
    }
}
