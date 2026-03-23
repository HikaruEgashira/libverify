//! Scope classification and semantic connectivity logic for PR change analysis.
//!
//! Determines whether a PR's changes are well-scoped (single logical unit)
//! or spread across disconnected domains.

use std::collections::{HashMap, HashSet};

use crate::verdict::Severity;

/// Classify the scope of a PR based on the number of connected components
/// among its changed code files.
/// Verified by Creusot in `gh-verify-verif` crate.
pub fn classify_scope(code_files_count: usize, components: usize) -> Severity {
    if code_files_count <= 1 {
        return Severity::Pass;
    }
    match components {
        0 | 1 => Severity::Pass,
        2 => Severity::Warning,
        _ => Severity::Error, // 3+
    }
}

/// Known non-code file extensions that should be excluded from scope analysis.
pub const NON_CODE_EXTENSIONS: &[&str] = &[
    ".md", ".rst", ".txt", ".adoc", ".json", ".yaml", ".yml", ".toml", ".lock", ".env", ".cfg",
    ".ini", ".css", ".scss", ".svg", ".png", ".jpg", ".gif", ".ico", ".woff", ".woff2",
];

/// Known non-code path prefixes that should be excluded from scope analysis.
pub const NON_CODE_PREFIXES: &[&str] = &[".github/", "docs/"];

/// Coarse role of a changed file for weak semantic connectivity.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FileRole {
    Source,
    Test,
    Fixture,
}

/// Determine whether a file path refers to a non-code file.
pub fn is_non_code_file(filename: &str) -> bool {
    for prefix in NON_CODE_PREFIXES {
        if filename.starts_with(prefix) {
            return true;
        }
    }
    // Dotfiles (e.g. .gitignore, .prettierignore) are infrastructure, not code.
    let basename = filename.rsplit('/').next().unwrap_or(filename);
    if basename.starts_with('.') {
        return true;
    }
    for ext in NON_CODE_EXTENSIONS {
        if filename.ends_with(ext) {
            return true;
        }
    }
    false
}

/// Resolve an import path against a set of changed file paths.
/// Returns the index of the matched file, if any.
pub fn resolve_import(import_path: &str, filenames: &[&str]) -> Option<usize> {
    let mut path = import_path;

    // Strip quotes (Go imports include them)
    if path.len() >= 2 && (path.starts_with('"') || path.starts_with('\'')) {
        path = &path[1..path.len() - 1];
    }

    // Strip relative prefixes
    if let Some(stripped) = path.strip_prefix("./") {
        path = stripped;
    } else if let Some(stripped) = path.strip_prefix("../") {
        path = stripped;
    } else if let Some(stripped) = path.strip_prefix("@/") {
        path = stripped;
    }

    // Convert Python dotted notation to path
    let converted: String;
    if path.contains('.') && !path.contains('/') {
        converted = path.replace('.', "/");
        path = &converted;
    } else {
        converted = String::new();
        let _ = &converted; // suppress unused warning
    }

    // Match against changed file names (suffix match)
    for (idx, fname) in filenames.iter().enumerate() {
        // Exact suffix match
        if fname.ends_with(path) {
            return Some(idx);
        }
        // Try with common extensions
        for ext in &[
            ".ts",
            ".tsx",
            ".js",
            ".jsx",
            ".py",
            ".go",
            "/index.ts",
            "/index.js",
        ] {
            let with_ext = format!("{path}{ext}");
            if fname.ends_with(&with_ext) {
                return Some(idx);
            }
        }
    }
    None
}

/// Classify file role from path shape and filename conventions.
pub fn classify_file_role(path: &str) -> FileRole {
    let normalized = path.to_ascii_lowercase();

    if has_fixture_marker(&normalized) {
        return FileRole::Fixture;
    }
    if has_test_marker(&normalized) {
        return FileRole::Test;
    }
    FileRole::Source
}

/// Extract semantic tokens from path for weak matching.
pub fn semantic_path_tokens(path: &str) -> Vec<String> {
    let mut out = Vec::new();

    for segment in path.split('/') {
        for dot_part in segment.split('.') {
            extend_split_tokens(dot_part, &mut out);
        }
    }

    out.sort();
    out.dedup();
    out
}

/// Source-source weak bridge used for colocated feature files.
/// Guarded by strict long-stem overlap to avoid short-name over-merging.
pub fn should_bridge_colocated_sources(path_a: &str, path_b: &str) -> bool {
    if classify_file_role(path_a) != FileRole::Source
        || classify_file_role(path_b) != FileRole::Source
    {
        return false;
    }
    if parent_dir(path_a) != parent_dir(path_b) {
        return false;
    }

    let stem_a = normalized_file_stem(path_a);
    let stem_b = normalized_file_stem(path_b);
    if common_prefix_len(&stem_a, &stem_b) >= 8 {
        return true;
    }

    let tokens_a = filename_tokens(path_a);
    let tokens_b = filename_tokens(path_b);
    has_token_overlap(&tokens_a, &tokens_b, 8, true)
}

/// Bridge test/fixture file to a source file with semantic token overlap.
/// Guards: source/aux balance, role check, parent_dir difference, and
/// token overlap (≥5 chars, non-generic).
pub fn should_bridge_aux_to_source(
    source_path: &str,
    aux_path: &str,
    source_count: usize,
    aux_count: usize,
) -> bool {
    // Too many aux files suggests bulk cleanup, not focused change.
    if aux_count > 6 {
        return false;
    }
    // A single aux file should not absorb a broad source-only change.
    if aux_count == 1 && source_count > 2 {
        return false;
    }

    if classify_file_role(source_path) != FileRole::Source {
        return false;
    }

    let aux_role = classify_file_role(aux_path);
    if aux_role != FileRole::Test && aux_role != FileRole::Fixture {
        return false;
    }

    // Do not collapse same-parent unit test pairs (can hide real split concerns).
    if parent_dir(source_path) == parent_dir(aux_path) {
        return false;
    }

    let source_tokens = semantic_path_tokens(source_path);
    let aux_tokens = semantic_path_tokens(aux_path);
    has_token_overlap(&source_tokens, &aux_tokens, 5, true)
}

/// Bridge files by semantic overlap of changed-patch identifiers.
///
/// This complements call/import edges when tree-sitter cannot recover a
/// complete AST from patch fragments, while keeping scope guards strict.
pub fn should_bridge_patch_semantic_tokens(
    path_a: &str,
    path_b: &str,
    tokens_a: &[String],
    tokens_b: &[String],
    source_count: usize,
    aux_count: usize,
) -> bool {
    if !has_token_overlap(tokens_a, tokens_b, 6, true) {
        return false;
    }

    let role_a = classify_file_role(path_a);
    let role_b = classify_file_role(path_b);

    match (role_a, role_b) {
        (FileRole::Source, FileRole::Source) => {
            // Keep source-source semantic bridging narrow: only small
            // implementation clusters that are accompanied by tests/fixtures.
            aux_count > 0 && source_count <= 3 && package_root(path_a) == package_root(path_b)
        }
        (FileRole::Source, FileRole::Test)
        | (FileRole::Source, FileRole::Fixture)
        | (FileRole::Test, FileRole::Source)
        | (FileRole::Fixture, FileRole::Source) => {
            if parent_dir(path_a) == parent_dir(path_b) {
                return false;
            }
            // If there is only one aux file, avoid bridging when source side
            // is broad. Otherwise allow focused source+aux semantic coupling.
            aux_count > 0
                && aux_count <= 4
                && source_count <= 3
                && (source_count <= 2 || aux_count >= 2)
        }
        (FileRole::Test, FileRole::Fixture) | (FileRole::Fixture, FileRole::Test) => {
            aux_count > 0 && aux_count <= 6
        }
        _ => false,
    }
}

/// Bridge between test and fixture files that target the same behavior.
pub fn should_bridge_test_fixture_pair(path_a: &str, path_b: &str) -> bool {
    let role_a = classify_file_role(path_a);
    let role_b = classify_file_role(path_b);
    let is_test_fixture = (role_a == FileRole::Test && role_b == FileRole::Fixture)
        || (role_a == FileRole::Fixture && role_b == FileRole::Test);

    if !is_test_fixture {
        return false;
    }

    let tokens_a = filename_tokens(path_a);
    let tokens_b = filename_tokens(path_b);
    has_token_overlap(&tokens_a, &tokens_b, 5, true)
}

/// Bridge build-fork variants that share one canonical feature surface.
pub fn should_bridge_fork_variants(path_a: &str, path_b: &str) -> bool {
    if classify_file_role(path_a) != FileRole::Source
        || classify_file_role(path_b) != FileRole::Source
    {
        return false;
    }

    if !is_fork_variant_path(path_a) && !is_fork_variant_path(path_b) {
        return false;
    }

    let family_a = fork_family_root(path_a);
    let family_b = fork_family_root(path_b);
    if family_a.is_empty() || family_a != family_b {
        return false;
    }

    let stem_a = normalized_file_stem(path_a);
    let stem_b = normalized_file_stem(path_b);
    if stem_a != stem_b {
        return false;
    }
    if stem_a.len() < 8 || is_generic_token(&stem_a) {
        return false;
    }

    true
}

/// Result of feature namespace extraction.
#[derive(Debug, Clone)]
pub struct FeatureNamespace {
    /// The dominant feature token.
    pub token: String,
    /// Indices into the input path slice for files that belong to this namespace.
    pub member_indices: Vec<usize>,
}

/// Extract a dominant feature namespace from a set of changed file paths.
///
/// Returns `Some` if a non-generic, non-structural token of sufficient length
/// appears in ≥ 35% of files across ≥ 2 directory subtrees, with ≥ 4 total files.
/// After finding a namespace, runs one absorption round to pull in files that share
/// any qualifying token with existing members.
pub fn extract_feature_namespace(paths: &[&str]) -> Option<FeatureNamespace> {
    let n = paths.len();
    if n < 4 {
        return None;
    }

    let all_tokens: Vec<Vec<String>> = paths.iter().map(|p| semantic_path_tokens(p)).collect();

    // Count file indices and subtrees per qualifying token.
    let mut token_stats: HashMap<&str, (Vec<usize>, HashSet<&str>)> = HashMap::new();

    for (i, tokens) in all_tokens.iter().enumerate() {
        let subtree = package_root(paths[i]);
        for tok in tokens {
            if tok.len() < 5 || is_structural_token(tok) {
                continue;
            }
            let entry = token_stats.entry(tok.as_str()).or_default();
            if entry.0.last() != Some(&i) {
                entry.0.push(i);
            }
            entry.1.insert(subtree);
        }
    }

    let threshold = (n as f64 * 0.35).ceil() as usize;
    // Exclude project-level tokens that appear in almost every file (only for larger PRs).
    let upper_bound = if n >= 10 {
        (n as f64 * 0.9).ceil() as usize
    } else {
        n + 1 // effectively disabled for small PRs
    };

    // Solo pass: single token with len >= 6.
    let mut best: Option<(&str, &Vec<usize>)> = None;
    let mut best_count: usize = 0;

    for (token, (indices, subtrees)) in &token_stats {
        if token.len() < 6
            || subtrees.len() < 2
            || indices.len() < threshold
            || indices.len() >= upper_bound
        {
            continue;
        }
        if indices.len() > best_count
            || (indices.len() == best_count && best.is_none_or(|(t, _)| *token < t))
        {
            best_count = indices.len();
            best = Some((token, indices));
        }
    }

    if let Some((token, indices)) = best {
        let mut ns = FeatureNamespace {
            token: token.to_string(),
            member_indices: indices.clone(),
        };
        absorb_related_files(&mut ns, &all_tokens, n);
        return Some(ns);
    }

    // Bigram pass: two tokens each >= 5 chars whose intersection covers threshold.
    let mut short_keys: Vec<&str> = token_stats
        .keys()
        .filter(|t| {
            t.len() >= 5 && {
                let (indices, subtrees) = &token_stats[**t];
                subtrees.len() >= 2 && indices.len() >= threshold && indices.len() < upper_bound
            }
        })
        .copied()
        .collect();
    short_keys.sort_unstable();

    let mut best_bigram: Option<(&str, Vec<usize>)> = None;
    let mut best_bigram_count: usize = 0;

    for i in 0..short_keys.len() {
        for j in (i + 1)..short_keys.len() {
            let set_a = &token_stats[short_keys[i]].0;
            let set_b = &token_stats[short_keys[j]].0;
            let intersection: Vec<usize> = set_a
                .iter()
                .filter(|idx| set_b.contains(idx))
                .copied()
                .collect();
            if intersection.len() >= threshold
                && (intersection.len() > best_bigram_count
                    || (intersection.len() == best_bigram_count
                        && best_bigram.as_ref().is_none_or(|(t, _)| short_keys[i] < *t)))
            {
                best_bigram_count = intersection.len();
                let label = if short_keys[i].len() >= short_keys[j].len() {
                    short_keys[i]
                } else {
                    short_keys[j]
                };
                best_bigram = Some((label, intersection));
            }
        }
    }

    best_bigram.map(|(token, member_indices)| {
        let mut ns = FeatureNamespace {
            token: token.to_string(),
            member_indices,
        };
        absorb_related_files(&mut ns, &all_tokens, n);
        ns
    })
}

/// One-round absorption: pull non-member files into the namespace if they share
/// a qualifying token with any *original* member. Uses only the token set from
/// the initial members to prevent transitive over-expansion.
fn absorb_related_files(ns: &mut FeatureNamespace, all_tokens: &[Vec<String>], n: usize) {
    // Collect qualifying tokens from original members.
    let member_tokens: HashSet<&str> = ns
        .member_indices
        .iter()
        .flat_map(|&i| all_tokens[i].iter())
        .filter(|t| t.len() >= 5 && !is_structural_token(t))
        .map(|t| t.as_str())
        .collect();

    for (i, tokens) in all_tokens.iter().enumerate().take(n) {
        if ns.member_indices.contains(&i) {
            continue;
        }
        let shares_token = tokens
            .iter()
            .any(|t| t.len() >= 5 && !is_structural_token(t) && member_tokens.contains(t.as_str()));
        if shares_token {
            ns.member_indices.push(i);
        }
    }
}

/// Check whether a token is a generic name OR a common directory-convention name
/// that should not serve as a feature namespace anchor.
fn is_structural_token(token: &str) -> bool {
    is_generic_token(token)
        || matches!(
            token,
            "components"
                | "internal"
                | "modules"
                | "output"
                | "targets"
                | "config"
                | "build"
                | "public"
                | "common"
                | "shared"
                | "vendor"
                | "helpers"
                | "middleware"
                | "handlers"
                | "services"
                | "models"
                | "views"
                | "controllers"
                | "server"
                | "client"
                | "scripts"
                | "tools"
                | "plugin"
                | "plugins"
                | "providers"
                | "resolvers"
                | "adapters"
                | "errors"
                | "generated"
                | "schemas"
                | "routes"
        )
}

fn has_fixture_marker(path: &str) -> bool {
    path.contains("/__fixtures__/")
        || path.contains("/fixtures/")
        || path.contains("/fixture/")
        || path.contains("/fixtures-")
        || path.starts_with("__fixtures__/")
        || path.starts_with("fixtures/")
        || path.starts_with("fixture/")
        || (path.contains("/cases/") && (path.contains("test") || path.contains("e2e")))
}

fn has_test_marker(path: &str) -> bool {
    // Directory-based markers (both nested and top-level)
    path.contains("/__tests__/")
        || path.contains("/tests/")
        || path.contains("/test/")
        || path.contains("/spec/")
        || path.contains("/e2e/")
        || path.starts_with("__tests__/")
        || path.starts_with("tests/")
        || path.starts_with("test/")
        || path.starts_with("spec/")
        || path.starts_with("e2e/")
        // Filename-based markers
        || path.contains(".test.")
        || path.contains("_test.")
        || path.contains(".spec.")
        || path.contains("-test.")
        || path.contains("-spec.")
        || path.contains("test-d.ts")
}

fn extend_split_tokens(input: &str, out: &mut Vec<String>) {
    let mut buf = String::new();
    let mut prev_is_lower = false;

    for ch in input.chars() {
        if ch.is_ascii_alphanumeric() {
            let is_upper = ch.is_ascii_uppercase();
            if is_upper && prev_is_lower && !buf.is_empty() {
                push_token(&buf, out);
                buf.clear();
            }
            buf.push(ch.to_ascii_lowercase());
            prev_is_lower = ch.is_ascii_lowercase();
        } else {
            if !buf.is_empty() {
                push_token(&buf, out);
                buf.clear();
            }
            prev_is_lower = false;
        }
    }

    if !buf.is_empty() {
        push_token(&buf, out);
    }
}

fn push_token(token: &str, out: &mut Vec<String>) {
    if token.len() >= 3 {
        out.push(token.to_string());
    }
}

fn normalized_file_stem(path: &str) -> String {
    let file = path.rsplit('/').next().unwrap_or(path);
    let stem = file.split('.').next().unwrap_or(file);
    stem.chars()
        .filter(|c| c.is_ascii_alphanumeric())
        .flat_map(char::to_lowercase)
        .collect::<String>()
}

fn filename_tokens(path: &str) -> Vec<String> {
    let file = path.rsplit('/').next().unwrap_or(path);
    let stem = file.split('.').next().unwrap_or(file);
    let mut out = Vec::new();
    extend_split_tokens(stem, &mut out);
    out.sort();
    out.dedup();
    out
}

fn parent_dir(path: &str) -> &str {
    path.rsplit_once('/').map(|(p, _)| p).unwrap_or("")
}

/// Detect the package root by finding the prefix before the first conventional
/// boundary directory (src, lib, test, tests, __tests__, e2e).
/// Falls back to parent_dir when no boundary is found.
fn package_root(path: &str) -> &str {
    // Handle repo-root boundaries (e.g. "src/...", "test/...")
    const ROOT_BOUNDARIES: &[&str] = &["src/", "lib/", "test/", "tests/", "__tests__/", "e2e/"];
    for boundary in ROOT_BOUNDARIES {
        if path.starts_with(boundary) {
            return &path[..boundary.len() - 1]; // "src", "test", etc.
        }
    }

    const BOUNDARIES: &[&str] = &[
        "/src/",
        "/lib/",
        "/test/",
        "/tests/",
        "/__tests__/",
        "/e2e/",
    ];
    for boundary in BOUNDARIES {
        if let Some(idx) = path.find(boundary) {
            return &path[..idx];
        }
    }
    parent_dir(path)
}

fn is_fork_variant_path(path: &str) -> bool {
    path.contains("/forks/")
}

fn fork_family_root(path: &str) -> String {
    if let Some((prefix, _)) = path.split_once("/forks/") {
        return prefix.to_string();
    }
    parent_dir(path).to_string()
}

fn common_prefix_len(a: &str, b: &str) -> usize {
    a.bytes().zip(b.bytes()).take_while(|(x, y)| x == y).count()
}

fn has_token_overlap(
    tokens_a: &[String],
    tokens_b: &[String],
    min_len: usize,
    require_non_generic: bool,
) -> bool {
    tokens_a.iter().any(|a| {
        if a.len() < min_len {
            return false;
        }
        if require_non_generic && is_generic_token(a) {
            return false;
        }
        tokens_b.iter().any(|b| b == a)
    })
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
            | "compiler"
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn zero_or_one_file_is_pass() {
        assert_eq!(classify_scope(0, 0), Severity::Pass);
        assert_eq!(classify_scope(1, 1), Severity::Pass);
        assert_eq!(classify_scope(1, 5), Severity::Pass);
    }

    #[test]
    fn single_component_is_pass() {
        assert_eq!(classify_scope(5, 1), Severity::Pass);
    }

    #[test]
    fn two_components_is_warning() {
        assert_eq!(classify_scope(5, 2), Severity::Warning);
    }

    #[test]
    fn three_or_more_components_is_error() {
        assert_eq!(classify_scope(5, 3), Severity::Error);
        assert_eq!(classify_scope(10, 7), Severity::Error);
    }

    #[test]
    fn markdown_is_non_code() {
        assert!(is_non_code_file("README.md"));
        assert!(is_non_code_file("docs/guide.md"));
    }

    #[test]
    fn github_dir_is_non_code() {
        assert!(is_non_code_file(".github/workflows/ci.yml"));
    }

    #[test]
    fn dotfiles_are_non_code() {
        assert!(is_non_code_file(".gitignore"));
        assert!(is_non_code_file(".prettierignore"));
        assert!(is_non_code_file("test/wdio/.gitignore"));
    }

    #[test]
    fn source_files_are_code() {
        assert!(!is_non_code_file("src/main.rs"));
        assert!(!is_non_code_file("lib/utils.ts"));
        assert!(!is_non_code_file("app.py"));
    }

    #[test]
    fn resolve_relative_import() {
        let files = vec!["src/utils/helper.ts"];
        assert_eq!(resolve_import("./helper", &files), Some(0));
    }

    #[test]
    fn resolve_python_dotted() {
        let files = vec!["src/foo/bar.py"];
        assert_eq!(resolve_import("foo.bar", &files), Some(0));
    }

    #[test]
    fn resolve_go_quoted() {
        let files = vec!["internal/handler.go"];
        assert_eq!(resolve_import("\"internal/handler\"", &files), Some(0));
    }

    #[test]
    fn no_match_returns_none() {
        let files = vec!["src/main.rs"];
        assert_eq!(resolve_import("nonexistent", &files), None);
    }

    #[test]
    fn classify_scope_exhaustive_for_small_inputs() {
        for files in 0..=10 {
            for comps in 0..=10 {
                let result = classify_scope(files, comps);
                if files <= 1 {
                    assert_eq!(result, Severity::Pass, "files={files}, comps={comps}");
                } else {
                    match comps {
                        0 | 1 => assert_eq!(result, Severity::Pass, "files={files}, comps={comps}"),
                        2 => {
                            assert_eq!(result, Severity::Warning, "files={files}, comps={comps}")
                        }
                        _ => assert_eq!(result, Severity::Error, "files={files}, comps={comps}"),
                    }
                }
            }
        }
    }

    #[test]
    fn classify_file_roles() {
        assert_eq!(
            classify_file_role("packages/runtime-core/src/foo.ts"),
            FileRole::Source
        );
        assert_eq!(
            classify_file_role("packages/runtime-core/__tests__/foo.spec.ts"),
            FileRole::Test
        );
        assert_eq!(
            classify_file_role("packages/runtime-core/__tests__/fixtures/foo.ts"),
            FileRole::Fixture
        );
        assert_eq!(
            classify_file_role("packages-private/vapor-e2e-test/transition/cases/mode/sample.vue"),
            FileRole::Fixture
        );
        // Top-level test directories (Express.js, Mocha, etc.)
        assert_eq!(classify_file_role("test/req.query.js"), FileRole::Test);
        assert_eq!(classify_file_role("test/app.use.js"), FileRole::Test);
        assert_eq!(classify_file_role("tests/unit/foo.py"), FileRole::Test);
        assert_eq!(classify_file_role("e2e/login.spec.ts"), FileRole::Test);
        assert_eq!(
            classify_file_role("__tests__/component.spec.tsx"),
            FileRole::Test
        );
        // RSpec spec/ directory (top-level and nested)
        assert_eq!(classify_file_role("spec/parser_spec.rb"), FileRole::Test);
        assert_eq!(classify_file_role("spec/models/user_spec.rb"), FileRole::Test);
        assert_eq!(
            classify_file_role("gems/mylib/spec/mylib_spec.rb"),
            FileRole::Test
        );
        // Top-level fixtures
        assert_eq!(
            classify_file_role("fixtures/sample.json"),
            FileRole::Fixture
        );
    }

    #[test]
    fn colocated_source_bridge_requires_long_stem() {
        assert!(should_bridge_colocated_sources(
            "packages/devtools/src/ContextMenu.tsx",
            "packages/devtools/src/ContextMenuItem.tsx"
        ));
        assert!(!should_bridge_colocated_sources(
            "packages/prisma/src/auth.ts",
            "packages/prisma/src/auth-client.ts"
        ));
    }

    #[test]
    fn aux_bridge_with_token_overlap() {
        // Same-dir unit test must NOT bridge
        assert!(!should_bridge_aux_to_source(
            "packages/client/src/mariadb.ts",
            "packages/client/src/mariadb.test.ts",
            1,
            1,
        ));

        // Same package, different dirs, token overlap → bridge
        assert!(should_bridge_aux_to_source(
            "packages/compiler-vapor/src/generators/expression.ts",
            "packages/compiler-vapor/__tests__/transforms/expression.spec.ts",
            1,
            1,
        ));

        // Scoped packages in monorepo → bridge
        assert!(should_bridge_aux_to_source(
            "packages/@ember/-internals/glimmer/lib/components/link-to.ts",
            "packages/@ember/-internals/glimmer/tests/integration/components/link-to/routing-angle-test.js",
            1,
            2,
        ));

        // Same package (compiler), src/ vs test/ → bridge
        assert!(should_bridge_aux_to_source(
            "packages/compiler/src/ml_parser/parser.ts",
            "packages/compiler/test/ml_parser/html_parser_spec.ts",
            1,
            1,
        ));

        // Cross-package with token overlap → bridge allowed
        assert!(should_bridge_aux_to_source(
            "packages/runtime-core/src/apiDefineComponent.ts",
            "packages-private/dts-test/defineComponent.test-d.ts",
            1,
            1,
        ));

        // Too many aux files → bulk operation, no bridge
        assert!(!should_bridge_aux_to_source(
            "packages/compiler/src/parser.ts",
            "packages/compiler/test/parser.spec.ts",
            1,
            7,
        ));
    }

    #[test]
    fn aux_bridge_rejects_single_aux_for_broad_source_cluster() {
        assert!(!should_bridge_aux_to_source(
            "packages/cli/src/Studio.ts",
            "packages/cli/src/__tests__/Studio.vitest.ts",
            3,
            1,
        ));
    }

    #[test]
    fn patch_semantic_bridge_connects_cross_package_source_test() {
        let source_tokens = vec!["undefined".to_string(), "setinssrsetupstate".to_string()];
        let test_tokens = vec!["undefined".to_string(), "withasynccontext".to_string()];
        assert!(should_bridge_patch_semantic_tokens(
            "packages/@glimmer/reference/lib/iterable.ts",
            "packages/ember-template-compiler/tests/plugins/assert-array-test.js",
            &source_tokens,
            &test_tokens,
            1,
            1,
        ));
    }

    #[test]
    fn patch_semantic_bridge_connects_small_source_cluster_with_aux() {
        let a = vec!["setinssrsetupstate".to_string()];
        let b = vec!["setinssrsetupstate".to_string()];
        assert!(should_bridge_patch_semantic_tokens(
            "packages/runtime-core/src/component.ts",
            "packages/runtime-core/src/apiSetupHelpers.ts",
            &a,
            &b,
            2,
            1,
        ));
    }

    #[test]
    fn patch_semantic_bridge_rejects_large_source_cluster_with_single_aux() {
        let source = vec!["studio".to_string(), "userfacingerror".to_string()];
        let aux = vec!["studio".to_string(), "userfacingerror".to_string()];
        assert!(!should_bridge_patch_semantic_tokens(
            "packages/cli/src/Studio.ts",
            "packages/cli/src/__tests__/Studio.vitest.ts",
            &source,
            &aux,
            3,
            1,
        ));
    }

    #[test]
    fn test_fixture_bridge_uses_semantic_overlap() {
        assert!(should_bridge_test_fixture_pair(
            "packages/vue/__tests__/transition.spec.ts",
            "packages/vue/__tests__/fixtures/transition.html"
        ));
        assert!(!should_bridge_test_fixture_pair(
            "packages/vue/__tests__/alpha.spec.ts",
            "packages/vue/__tests__/fixtures/beta.html"
        ));
    }

    #[test]
    fn fork_variant_bridge_requires_same_family_and_stem() {
        assert!(should_bridge_fork_variants(
            "packages/shared/ReactFeatureFlags.js",
            "packages/shared/forks/ReactFeatureFlags.native-oss.js"
        ));
        assert!(should_bridge_fork_variants(
            "packages/shared/forks/ReactFeatureFlags.test-renderer.js",
            "packages/shared/forks/ReactFeatureFlags.test-renderer.www.js"
        ));
    }

    #[test]
    fn fork_variant_bridge_rejects_broad_over_merge() {
        assert!(!should_bridge_fork_variants(
            "packages/shared/index.js",
            "packages/shared/forks/index.www.js"
        ));
        assert!(!should_bridge_fork_variants(
            "packages/shared/ReactFeatureFlags.js",
            "packages/other/forks/ReactFeatureFlags.native-oss.js"
        ));
        assert!(!should_bridge_fork_variants(
            "packages/shared/ReactFeatureFlags.js",
            "packages/shared/ReactFeatureFlags.native-oss.js"
        ));
    }

    #[test]
    fn feature_namespace_fires_on_single_feature_rollout() {
        // Realistic stencil PR paths (dotfiles already filtered by is_non_code_file)
        let paths = &[
            "src/compiler/config/outputs/validate-custom-element.ts",
            "src/compiler/config/test/validate-output-dist-custom-element.spec.ts",
            "src/compiler/output-targets/dist-custom-elements/custom-elements-types.ts",
            "src/compiler/output-targets/dist-custom-elements/generate-loader-module.ts",
            "src/compiler/output-targets/dist-custom-elements/index.ts",
            "src/compiler/output-targets/test/output-targets-dist-custom-elements.spec.ts",
            "src/declarations/stencil-public-compiler.ts",
            "test/bundle-size/stencil.config.ts",
            "test/wdio/auto-loader.stencil.config.ts",
            "test/wdio/auto-loader/auto-loader-child.tsx",
            "test/wdio/auto-loader/auto-loader-dynamic.tsx",
            "test/wdio/auto-loader/auto-loader-root.tsx",
            "test/wdio/auto-loader/cmp.test.tsx",
            "test/wdio/auto-loader/components.d.ts",
            "test/wdio/auto-loader/perf-dist.test.tsx",
            "test/wdio/auto-loader/perf.test.tsx",
            "test/wdio/stencil.config.ts",
        ];
        let ns = extract_feature_namespace(paths);
        assert!(ns.is_some(), "should detect feature namespace");
        let ns = ns.unwrap();
        // "loader" is the dominant token bridging implementation and test harness
        assert_eq!(ns.token, "loader", "token={}", ns.token);
        // After absorption, all files should be covered (they all share tokens
        // like "loader", "custom", "elements", or "stencil" with the core cluster)
        assert!(
            ns.member_indices.len() >= 15,
            "expected ≥15 members after absorption, got {}",
            ns.member_indices.len()
        );
    }

    #[test]
    fn feature_namespace_rejects_multi_domain_pr() {
        // Different domains: auth, billing, docs — no shared feature token
        let paths = &[
            "packages/auth/src/login.ts",
            "packages/billing/src/invoice.ts",
            "packages/docs/src/api-reference.ts",
            "packages/ci/scripts/deploy.sh",
        ];
        assert!(extract_feature_namespace(paths).is_none());
    }

    #[test]
    fn feature_namespace_rejects_fewer_than_4_files() {
        let paths = &[
            "src/dist-custom-elements/index.ts",
            "test/dist-custom-elements/test.ts",
            "lib/dist-custom-elements/util.ts",
        ];
        assert!(extract_feature_namespace(paths).is_none());
    }

    #[test]
    fn feature_namespace_rejects_single_subtree() {
        let paths = &[
            "src/feature/frobnicator-impl.ts",
            "src/feature/frobnicator-types.ts",
            "src/feature/frobnicator-config.ts",
            "src/feature/frobnicator-utils.ts",
            "src/feature/frobnicator-extra.ts",
        ];
        // All files under same tree root "src/feature" → no namespace bridge
        assert!(extract_feature_namespace(paths).is_none());
    }

    #[test]
    fn feature_namespace_rejects_generic_tokens() {
        // Token "compiler" is structural, "test" is generic
        let paths = &[
            "packages/compiler/alpha.ts",
            "tests/compiler/alpha.spec.ts",
            "lib/compiler/beta.ts",
            "tools/compiler/gamma.ts",
        ];
        assert!(extract_feature_namespace(paths).is_none());
    }

    #[test]
    fn feature_namespace_solo_fires_on_6char_token() {
        // "custom" (6 chars) appears in all files across 3 subtrees → solo match
        let paths = &[
            "src/components/custom-modal/index.ts",
            "src/components/custom-modal/styles.ts",
            "test/e2e/custom-modal/basic.spec.ts",
            "test/e2e/custom-modal/advanced.spec.ts",
            "docs-app/custom-modal/demo.tsx",
        ];
        let ns = extract_feature_namespace(paths);
        assert!(ns.is_some(), "solo should fire for 'custom'");
        let ns = ns.unwrap();
        assert_eq!(ns.token, "custom", "token={}", ns.token);
    }

    #[test]
    fn feature_namespace_bigram_fires_on_short_token_pair() {
        // "alpha" (5) + "bravo" (5) co-occur — neither qualifies solo (< 6 chars)
        let paths = &[
            "src/alpha-bravo/index.ts",
            "src/alpha-bravo/types.ts",
            "test/alpha-bravo/basic.spec.ts",
            "lib/alpha-bravo/util.ts",
        ];
        let ns = extract_feature_namespace(paths);
        assert!(ns.is_some(), "bigram should fire for alpha+bravo");
        let ns = ns.unwrap();
        assert!(
            ns.token == "alpha" || ns.token == "bravo",
            "token={}",
            ns.token
        );
    }

    #[test]
    fn feature_namespace_below_coverage_threshold() {
        // "frobnicator" appears in only 2/7 files (29% < 35%)
        let paths = &[
            "src/core/frobnicator.ts",
            "test/frobnicator.spec.ts",
            "src/auth/login.ts",
            "src/billing/invoice.ts",
            "lib/config/settings.ts",
            "pkg/analytics/tracker.ts",
            "tools/deployment/deploy.ts",
        ];
        assert!(extract_feature_namespace(paths).is_none());
    }

    #[test]
    fn is_structural_token_covers_directory_conventions() {
        assert!(is_structural_token("compiler")); // via is_generic_token
        assert!(is_structural_token("components"));
        assert!(is_structural_token("config"));
        assert!(is_structural_token("test"));
        assert!(is_structural_token("utils"));
        assert!(!is_structural_token("autoloader"));
        assert!(!is_structural_token("frobnicator"));
        assert!(!is_structural_token("elements"));
    }
}

#[cfg(test)]
#[path = "tests/scope_hardening.rs"]
mod scope_hardening;
