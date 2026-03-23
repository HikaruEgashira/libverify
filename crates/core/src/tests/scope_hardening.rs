use super::*;

// --- is_non_code_file extension coverage ---

#[test]
fn non_code_extensions_comprehensive() {
    // Kills: removing any single extension from NON_CODE_EXTENSIONS
    let extensions = vec![
        "file.md",
        "file.rst",
        "file.txt",
        "file.json",
        "file.yaml",
        "file.yml",
        "file.toml",
        "file.lock",
        "file.env",
        "file.cfg",
        "file.ini",
        "file.css",
        "file.scss",
        "file.svg",
        "file.png",
        "file.jpg",
        "file.gif",
        "file.ico",
        "file.woff",
        "file.woff2",
    ];
    for f in &extensions {
        assert!(is_non_code_file(f), "{f} should be non-code");
    }
}

#[test]
fn dotfile_in_subdirectory_is_non_code() {
    assert!(is_non_code_file("src/.eslintrc"));
    assert!(is_non_code_file("deep/path/.env.local"));
}

// --- resolve_import mutations ---

#[test]
fn resolve_import_single_quoted() {
    let files = vec!["internal/handler.go"];
    assert_eq!(resolve_import("'internal/handler'", &files), Some(0));
}

#[test]
fn resolve_import_at_prefix() {
    // Kills: removing @/ prefix stripping
    let files = vec!["src/components/Button.tsx"];
    assert_eq!(resolve_import("@/src/components/Button", &files), Some(0));
}

#[test]
fn resolve_import_dotdot_prefix() {
    // Kills: removing ../ prefix stripping
    let files = vec!["src/utils/helper.ts"];
    assert_eq!(resolve_import("../src/utils/helper", &files), Some(0));
}

#[test]
fn resolve_import_with_extension() {
    let files = vec!["src/component.tsx"];
    assert_eq!(resolve_import("component", &files), Some(0));
}

#[test]
fn resolve_import_index_file() {
    let files = vec!["src/components/index.ts"];
    assert_eq!(resolve_import("src/components", &files), Some(0));
}

// --- classify_file_role mutations ---

#[test]
fn fixture_detection_all_markers() {
    assert_eq!(
        classify_file_role("path/__fixtures__/data.json"),
        FileRole::Fixture
    );
    assert_eq!(
        classify_file_role("path/fixtures/sample.ts"),
        FileRole::Fixture
    );
    assert_eq!(
        classify_file_role("path/fixture/sample.ts"),
        FileRole::Fixture
    );
    assert_eq!(
        classify_file_role("path/fixtures-baseline/x.ts"),
        FileRole::Fixture
    );
    assert_eq!(
        classify_file_role("test/cases/e2e/case1.ts"),
        FileRole::Fixture
    );
}

#[test]
fn test_detection_all_markers() {
    assert_eq!(classify_file_role("src/__tests__/foo.ts"), FileRole::Test);
    assert_eq!(classify_file_role("src/tests/foo.ts"), FileRole::Test);
    assert_eq!(classify_file_role("src/test/foo.ts"), FileRole::Test);
    assert_eq!(classify_file_role("src/e2e/foo.ts"), FileRole::Test);
    assert_eq!(classify_file_role("foo.test.ts"), FileRole::Test);
    assert_eq!(classify_file_role("foo_test.go"), FileRole::Test);
    assert_eq!(classify_file_role("foo.spec.ts"), FileRole::Test);
    assert_eq!(classify_file_role("foo-test.js"), FileRole::Test);
    assert_eq!(classify_file_role("foo-spec.js"), FileRole::Test);
    assert_eq!(classify_file_role("test-d.ts"), FileRole::Test);
}

#[test]
fn fixture_takes_priority_over_test() {
    // Kills: swapping fixture/test check order
    assert_eq!(
        classify_file_role("tests/__fixtures__/data.json"),
        FileRole::Fixture
    );
}

// --- semantic_path_tokens ---

#[test]
fn semantic_tokens_camel_case_split() {
    let tokens = semantic_path_tokens("src/MyComponent.tsx");
    assert!(tokens.contains(&"component".to_string()));
}

#[test]
fn semantic_tokens_deduplicated_and_sorted() {
    let tokens = semantic_path_tokens("src/foo/foo.ts");
    assert_eq!(tokens.iter().filter(|t| *t == "foo").count(), 1,);
}

#[test]
fn semantic_tokens_min_length_3() {
    // Kills: >= 3 → >= 2
    let tokens = semantic_path_tokens("src/ab.ts");
    assert!(!tokens.contains(&"ab".to_string()), "2-char token excluded");
    assert!(tokens.contains(&"src".to_string()), "3-char token included");
}

// --- common_prefix_len ---

#[test]
fn common_prefix_len_basic() {
    assert_eq!(common_prefix_len("abcdef", "abcxyz"), 3);
    assert_eq!(common_prefix_len("abc", "abc"), 3);
    assert_eq!(common_prefix_len("abc", "xyz"), 0);
    assert_eq!(common_prefix_len("", "abc"), 0);
}

// --- has_token_overlap ---

#[test]
fn token_overlap_min_length_check() {
    let a = vec!["abc".to_string()];
    let b = vec!["abc".to_string()];
    assert!(!has_token_overlap(&a, &b, 5, false), "3 < 5 threshold");
    assert!(has_token_overlap(&a, &b, 3, false), "3 >= 3 threshold");
}

#[test]
fn token_overlap_generic_filter() {
    // Kills: removing require_non_generic check
    let a = vec!["tests".to_string()];
    let b = vec!["tests".to_string()];
    assert!(
        !has_token_overlap(&a, &b, 3, true),
        "generic token should be rejected"
    );
    assert!(
        has_token_overlap(&a, &b, 3, false),
        "generic allowed when filter off"
    );
}

// --- is_generic_token comprehensive ---

#[test]
fn generic_tokens_all_covered() {
    let generics = vec![
        "test", "tests", "spec", "fixture", "fixtures", "runtime", "source", "types", "type",
        "index", "core", "src", "lib", "util", "utils", "package", "packages", "private",
        "compiler",
    ];
    for token in &generics {
        assert!(is_generic_token(token), "{token} should be generic");
    }
}

// --- package_root ---

#[test]
fn package_root_with_src_boundary() {
    assert_eq!(package_root("packages/foo/src/bar.ts"), "packages/foo");
}

#[test]
fn package_root_with_tests_boundary() {
    assert_eq!(
        package_root("packages/foo/tests/bar.spec.ts"),
        "packages/foo"
    );
}

#[test]
fn package_root_at_repo_root() {
    assert_eq!(package_root("src/main.rs"), "src");
    assert_eq!(package_root("tests/foo.rs"), "tests");
}

#[test]
fn package_root_no_boundary_falls_back_to_parent() {
    assert_eq!(package_root("packages/foo/bar.ts"), "packages/foo");
}

// --- normalized_file_stem ---

#[test]
fn normalized_file_stem_strips_extension_and_lowercases() {
    assert_eq!(normalized_file_stem("src/FooBar.tsx"), "foobar");
    assert_eq!(normalized_file_stem("MyFile.test.ts"), "myfile");
}

// --- should_bridge_colocated_sources mutations ---

#[test]
fn colocated_bridge_different_parents_rejected() {
    assert!(!should_bridge_colocated_sources(
        "packages/a/src/LongFeatureName.ts",
        "packages/b/src/LongFeatureName.ts"
    ));
}

#[test]
fn colocated_bridge_non_source_rejected() {
    assert!(!should_bridge_colocated_sources(
        "packages/a/src/Foo.ts",
        "packages/a/__tests__/FooTest.spec.ts"
    ));
}

// --- should_bridge_aux_to_source mutations ---

#[test]
fn aux_bridge_aux_count_boundary_6_vs_7() {
    // Kills: > 6 → >= 6 or > 6 → > 7
    assert!(should_bridge_aux_to_source(
        "packages/compiler/src/expression.ts",
        "packages/compiler/__tests__/expression.spec.ts",
        1,
        6,
    ));
    assert!(!should_bridge_aux_to_source(
        "packages/compiler/src/expression.ts",
        "packages/compiler/__tests__/expression.spec.ts",
        1,
        7,
    ));
}

#[test]
fn aux_bridge_source_count_boundary_2_vs_3() {
    // Kills: source_count > 2 → > 3 (when aux_count == 1)
    assert!(should_bridge_aux_to_source(
        "packages/compiler/src/expression.ts",
        "packages/compiler/__tests__/expression.spec.ts",
        2,
        1,
    ));
    assert!(!should_bridge_aux_to_source(
        "packages/compiler/src/expression.ts",
        "packages/compiler/__tests__/expression.spec.ts",
        3,
        1,
    ));
}

// --- should_bridge_fork_variants mutations ---

#[test]
fn fork_variant_must_contain_forks_path() {
    assert!(!should_bridge_fork_variants(
        "packages/shared/ReactFeatureFlags.js",
        "packages/shared/ReactFeatureFlags.web.js"
    ));
}

#[test]
fn fork_variant_stem_too_short_rejected() {
    // Kills: stem_a.len() < 8 → < 4
    assert!(!should_bridge_fork_variants(
        "packages/shared/Foo.js",
        "packages/shared/forks/Foo.web.js"
    ));
}

#[test]
fn fork_variant_generic_stem_rejected() {
    assert!(!should_bridge_fork_variants(
        "packages/shared/compiler.js",
        "packages/shared/forks/compiler.web.js"
    ));
}

// --- should_bridge_test_fixture_pair mutations ---

#[test]
fn test_fixture_bridge_wrong_roles_rejected() {
    assert!(!should_bridge_test_fixture_pair(
        "src/alpha.ts",
        "src/alpha_helper.ts"
    ));
    assert!(!should_bridge_test_fixture_pair(
        "test/alpha.spec.ts",
        "test/alpha.test.ts"
    ));
}

// --- should_bridge_patch_semantic_tokens mutations ---

#[test]
fn patch_semantic_source_source_requires_same_package_root() {
    let tokens = vec!["setinssrsetupstate".to_string()];
    assert!(!should_bridge_patch_semantic_tokens(
        "packages/core/src/component.ts",
        "packages/other/src/helper.ts",
        &tokens,
        &tokens,
        2,
        1,
    ));
}

#[test]
fn patch_semantic_source_test_same_parent_rejected() {
    let tokens = vec!["setinssrsetupstate".to_string()];
    assert!(!should_bridge_patch_semantic_tokens(
        "packages/core/src/component.ts",
        "packages/core/src/component.test.ts",
        &tokens,
        &tokens,
        1,
        1,
    ));
}

#[test]
fn patch_semantic_test_fixture_allowed_within_aux_limit() {
    let tokens = vec!["setinssrsetupstate".to_string()];
    assert!(should_bridge_patch_semantic_tokens(
        "tests/integration/component.spec.ts",
        "tests/__fixtures__/component.json",
        &tokens,
        &tokens,
        0,
        2,
    ));
}

#[test]
fn patch_semantic_test_fixture_rejects_aux_0() {
    let tokens = vec!["setinssrsetupstate".to_string()];
    assert!(!should_bridge_patch_semantic_tokens(
        "tests/integration/component.spec.ts",
        "tests/__fixtures__/component.json",
        &tokens,
        &tokens,
        0,
        0,
    ));
}

#[test]
fn patch_semantic_no_token_overlap_rejected() {
    let a = vec!["alpha".to_string()];
    let b = vec!["bravo".to_string()];
    assert!(!should_bridge_patch_semantic_tokens(
        "packages/core/src/a.ts",
        "packages/core/__tests__/b.spec.ts",
        &a,
        &b,
        1,
        1,
    ));
}

// --- extract_feature_namespace upper_bound mutation ---

#[test]
fn feature_namespace_rejects_ubiquitous_token_in_large_pr() {
    let paths: Vec<&str> = (0..10)
        .map(|i| match i % 3 {
            0 => "src/feature/frobnicator-alpha.ts",
            1 => "test/feature/frobnicator-beta.ts",
            _ => "lib/feature/frobnicator-gamma.ts",
        })
        .collect();
    let ns = extract_feature_namespace(&paths);
    if let Some(ns) = &ns {
        assert_ne!(
            ns.member_indices.len(),
            10,
            "token appearing in all files of large PR should be rejected"
        );
    }
}
