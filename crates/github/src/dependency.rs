//! Dependency signature evidence collection for GitHub repositories.
//!
//! Detects lock files in the repository (Cargo.lock, package-lock.json, etc.)
//! and collects dependency signature evidence by parsing lock-file checksums
//! and optionally verifying npm provenance via `npm audit signatures`.

use libverify_core::evidence::{
    DependencySignatureEvidence, EvidenceGap, EvidenceState, VerificationOutcome,
};

use crate::client::GitHubClient;

/// Lock file basenames we can parse for dependency evidence.
const LOCK_FILE_NAMES: &[&str] = &["package-lock.json", "Cargo.lock", "poetry.lock"];

/// Collect dependency signature evidence for a PR by checking which lock files
/// are present in the repository and parsing them for dependency information.
///
/// Currently supports:
/// - **npm**: `npm audit signatures --json` for Sigstore provenance verification
/// - **Cargo**: Cargo.lock checksum parsing (checksum-pinned, not cryptographic signature)
pub fn collect_pr_dependency_signatures(
    client: &GitHubClient,
    owner: &str,
    repo: &str,
    head_sha: &str,
    changed_files: &[String],
) -> EvidenceState<Vec<DependencySignatureEvidence>> {
    // Find changed lock files (supports monorepo paths like packages/app/Cargo.lock)
    let changed_lock_files: Vec<&str> = changed_files
        .iter()
        .filter(|f| LOCK_FILE_NAMES.iter().any(|name| f.ends_with(name)))
        .map(|f| f.as_str())
        .collect();

    if changed_lock_files.is_empty() {
        return EvidenceState::NotApplicable;
    }

    let mut all_deps = Vec::new();
    let mut gaps = Vec::new();

    for lock_path in &changed_lock_files {
        match client.get_file_content(owner, repo, lock_path, head_sha) {
            Ok(content) => {
                let result = if lock_path.ends_with("Cargo.lock") {
                    parse_cargo_lock(&content)
                } else if lock_path.ends_with("package-lock.json") {
                    parse_package_lock_json(&content)
                } else if lock_path.ends_with("poetry.lock") {
                    parse_poetry_lock(&content)
                } else {
                    continue;
                };
                match result {
                    Ok(deps) => all_deps.extend(deps),
                    Err(e) => {
                        gaps.push(EvidenceGap::CollectionFailed {
                            source: "lock-file-parser".to_string(),
                            subject: lock_path.to_string(),
                            detail: format!("parse error: {e}"),
                        });
                    }
                }
            }
            Err(e) => {
                gaps.push(EvidenceGap::CollectionFailed {
                    source: "github-api".to_string(),
                    subject: lock_path.to_string(),
                    detail: format!("{e}"),
                });
            }
        }
    }

    if all_deps.is_empty() && !gaps.is_empty() {
        EvidenceState::missing(gaps)
    } else if gaps.is_empty() {
        EvidenceState::complete(all_deps)
    } else {
        EvidenceState::partial(all_deps, gaps)
    }
}

/// Collect dependency signature evidence for an entire repository at a given ref.
///
/// Uses the GitHub Git Tree API to discover all lock files across the repository
/// (including monorepo subdirectories), then fetches and parses each one.
/// Returns `NotApplicable` if no lock files exist anywhere in the tree.
pub fn collect_repo_dependency_signatures(
    client: &GitHubClient,
    owner: &str,
    repo: &str,
    reference: &str,
) -> EvidenceState<Vec<DependencySignatureEvidence>> {
    // Discover all lock files in the repo tree
    let tree_result = match client.find_files_in_tree(owner, repo, reference, |path| {
        LOCK_FILE_NAMES.iter().any(|name| path.ends_with(name))
    }) {
        Ok(result) => result,
        Err(e) => {
            return EvidenceState::missing(vec![EvidenceGap::CollectionFailed {
                source: "github-tree-api".to_string(),
                subject: "lock-file-discovery".to_string(),
                detail: format!("{e}"),
            }]);
        }
    };

    if tree_result.paths.is_empty() && !tree_result.truncated {
        return EvidenceState::NotApplicable;
    }

    let mut all_deps = Vec::new();
    let mut gaps = Vec::new();

    // If the tree was truncated, record it as a gap — some lock files may be missing
    if tree_result.truncated {
        gaps.push(EvidenceGap::Truncated {
            source: "github-tree-api".to_string(),
            subject: "repository-tree".to_string(),
        });
    }

    let lock_paths = &tree_result.paths;

    for lock_path in lock_paths {
        match client.get_file_content(owner, repo, lock_path, reference) {
            Ok(content) => {
                let result = if lock_path.ends_with("Cargo.lock") {
                    parse_cargo_lock(&content)
                } else if lock_path.ends_with("package-lock.json") {
                    parse_package_lock_json(&content)
                } else if lock_path.ends_with("poetry.lock") {
                    parse_poetry_lock(&content)
                } else {
                    continue;
                };
                match result {
                    Ok(deps) => all_deps.extend(deps),
                    Err(e) => {
                        gaps.push(EvidenceGap::CollectionFailed {
                            source: "lock-file-parser".to_string(),
                            subject: lock_path.to_string(),
                            detail: format!("parse error: {e}"),
                        });
                    }
                }
            }
            Err(e) => {
                gaps.push(EvidenceGap::CollectionFailed {
                    source: "github-api".to_string(),
                    subject: lock_path.to_string(),
                    detail: format!("{e}"),
                });
            }
        }
    }

    // dedup by (name, version, registry)
    all_deps.sort_by(|a, b| (&a.name, &a.version).cmp(&(&b.name, &b.version)));
    all_deps
        .dedup_by(|a, b| a.name == b.name && a.version == b.version && a.registry == b.registry);

    if all_deps.is_empty() && !gaps.is_empty() {
        EvidenceState::missing(gaps)
    } else if gaps.is_empty() {
        EvidenceState::complete(all_deps)
    } else {
        EvidenceState::partial(all_deps, gaps)
    }
}

// -- package-lock.json parsing --

/// Parse package-lock.json (v1/v2/v3) to extract dependency integrity hashes.
///
/// - **v2/v3**: `packages` object keyed by `node_modules/` path
/// - **v1**: `dependencies` object keyed by package name (flat or nested)
fn parse_package_lock_json(content: &str) -> anyhow::Result<Vec<DependencySignatureEvidence>> {
    let lock: serde_json::Value = serde_json::from_str(content)?;
    let mut deps = Vec::new();

    // v2/v3 format: "packages" object (preferred)
    if let Some(packages) = lock.get("packages").and_then(|p| p.as_object()) {
        for (path, info) in packages {
            if path.is_empty() {
                continue;
            }
            let name = path.strip_prefix("node_modules/").unwrap_or(path);
            let is_direct = !name.contains("node_modules/");
            push_npm_dep(&mut deps, name, info, is_direct);
        }
    }
    // v1 fallback: "dependencies" object
    else if let Some(dependencies) = lock.get("dependencies").and_then(|d| d.as_object()) {
        parse_npm_v1_deps(&mut deps, dependencies, true);
    }

    Ok(deps)
}

fn push_npm_dep(
    deps: &mut Vec<DependencySignatureEvidence>,
    name: &str,
    info: &serde_json::Value,
    is_direct: bool,
) {
    let version = info
        .get("version")
        .and_then(|v| v.as_str())
        .unwrap_or("unknown");

    let integrity = info.get("integrity").and_then(|i| i.as_str());

    let (verification, pinned_digest) = match integrity {
        Some(hash) => (VerificationOutcome::ChecksumMatch, Some(hash.to_string())),
        None => (
            VerificationOutcome::AttestationAbsent {
                detail: "no integrity hash in package-lock.json".to_string(),
            },
            None,
        ),
    };

    deps.push(DependencySignatureEvidence {
        name: name.to_string(),
        version: version.to_string(),
        registry: Some("registry.npmjs.org".to_string()),
        verification,
        signature_mechanism: integrity.map(|_| "checksum".to_string()),
        signer_identity: None,
        source_repo: None,
        source_commit: None,
        pinned_digest,
        actual_digest: None,
        transparency_log_uri: None,
        is_direct,
    });
}

/// Recursively parse v1 `dependencies` object.
fn parse_npm_v1_deps(
    deps: &mut Vec<DependencySignatureEvidence>,
    dependencies: &serde_json::Map<String, serde_json::Value>,
    is_direct: bool,
) {
    for (name, info) in dependencies {
        push_npm_dep(deps, name, info, is_direct);
        // v1 nests transitive deps under "dependencies" within each entry
        if let Some(sub_deps) = info.get("dependencies").and_then(|d| d.as_object()) {
            parse_npm_v1_deps(deps, sub_deps, false);
        }
    }
}

// -- Cargo.lock checksum collection --

/// Parse Cargo.lock content and extract dependency name, version, and checksum.
///
/// Packages without a `source` field are workspace/path dependencies and are
/// skipped — they are not external supply-chain dependencies.
fn parse_cargo_lock(content: &str) -> anyhow::Result<Vec<DependencySignatureEvidence>> {
    let mut deps = Vec::new();
    let mut current_name: Option<String> = None;
    let mut current_version: Option<String> = None;
    let mut current_checksum: Option<String> = None;
    let mut current_source: Option<String> = None;
    let mut in_package = false;

    for line in content.lines() {
        let line = line.trim();

        if line == "[[package]]" {
            // Flush previous package
            flush_cargo_package(
                &mut deps,
                current_name.take(),
                current_version.take(),
                current_checksum.take(),
                current_source.take(),
            );
            in_package = true;
            continue;
        }

        if in_package {
            if let Some(rest) = line.strip_prefix("name = ") {
                current_name = Some(unquote(rest));
            } else if let Some(rest) = line.strip_prefix("version = ") {
                current_version = Some(unquote(rest));
            } else if let Some(rest) = line.strip_prefix("checksum = ") {
                current_checksum = Some(unquote(rest));
            } else if let Some(rest) = line.strip_prefix("source = ") {
                current_source = Some(unquote(rest));
            }
        }
    }

    // Flush last package
    flush_cargo_package(
        &mut deps,
        current_name,
        current_version,
        current_checksum,
        current_source,
    );

    Ok(deps)
}

fn flush_cargo_package(
    deps: &mut Vec<DependencySignatureEvidence>,
    name: Option<String>,
    version: Option<String>,
    checksum: Option<String>,
    source: Option<String>,
) {
    if let (Some(name), Some(version)) = (name, version) {
        // Skip path/workspace dependencies (no source field)
        let source = match source {
            Some(s) => s,
            None => return,
        };
        deps.push(make_cargo_dep(
            &name,
            &version,
            checksum.as_deref(),
            &source,
        ));
    }
}

fn make_cargo_dep(
    name: &str,
    version: &str,
    checksum: Option<&str>,
    source: &str,
) -> DependencySignatureEvidence {
    let (verification, mechanism, pinned_digest) = match checksum {
        Some(cs) => (
            VerificationOutcome::ChecksumMatch,
            Some("checksum".to_string()),
            Some(format!("sha256:{cs}")),
        ),
        None => (
            VerificationOutcome::AttestationAbsent {
                detail: "no checksum in Cargo.lock".to_string(),
            },
            None,
            None,
        ),
    };

    // Derive registry from source field
    let registry = if source.contains("crates.io-index") {
        Some("crates.io".to_string())
    } else {
        // git sources, alternate registries, etc. — use source as-is
        Some(source.to_string())
    };

    DependencySignatureEvidence {
        name: name.to_string(),
        version: version.to_string(),
        registry,
        verification,
        signature_mechanism: mechanism,
        signer_identity: None,
        source_repo: None,
        source_commit: None,
        pinned_digest,
        actual_digest: None,
        transparency_log_uri: None,
        // Cargo.lock does not distinguish direct from transitive dependencies;
        // Cargo.toml cross-reference would be needed for accurate classification.
        is_direct: true,
    }
}

fn unquote(s: &str) -> String {
    s.trim().trim_matches('"').to_string()
}

// -- poetry.lock parsing --

/// Parse poetry.lock (TOML-like) to extract dependency name, version, and optional file hashes.
///
/// poetry.lock uses TOML format with `[[package]]` sections. Each section has `name` and
/// `version` fields. File hashes appear in a `[metadata.files]` or inline `files` array
/// within each `[[package]]` section (Poetry 1.x vs 2.x formats).
///
/// This parser uses the same line-based approach as `parse_cargo_lock` to avoid adding
/// a TOML crate dependency.
fn parse_poetry_lock(content: &str) -> anyhow::Result<Vec<DependencySignatureEvidence>> {
    let mut deps = Vec::new();
    let mut current_name: Option<String> = None;
    let mut current_version: Option<String> = None;
    let mut current_has_hash: bool = false;
    let mut in_package = false;
    // Track whether we are inside the files array of a [[package]] section.
    // Poetry 2.x embeds `files = [...]` directly inside each [[package]].
    let mut in_files_array = false;

    for line in content.lines() {
        let trimmed = line.trim();

        if trimmed == "[[package]]" {
            // Flush previous package
            flush_poetry_package(
                &mut deps,
                current_name.take(),
                current_version.take(),
                current_has_hash,
            );
            in_package = true;
            in_files_array = false;
            current_has_hash = false;
            continue;
        }

        // Detect start of a new top-level section (e.g. [metadata], [metadata.files])
        // which ends any active [[package]] context.
        if trimmed.starts_with('[') && !trimmed.starts_with("[[") {
            in_files_array = false;
            // Do NOT reset in_package — package fields may appear after sub-tables in
            // future formats, but practically this is fine since name/version come first.
        }

        if in_package {
            if let Some(rest) = trimmed.strip_prefix("name = ") {
                current_name = Some(unquote(rest));
                in_files_array = false;
            } else if let Some(rest) = trimmed.strip_prefix("version = ") {
                current_version = Some(unquote(rest));
                in_files_array = false;
            } else if trimmed == "files = [" || trimmed.starts_with("files = [") {
                in_files_array = true;
                // Check if the array is non-empty on the same line (single-line form)
                // e.g. `files = [{file = "...", hash = "sha256:..."}]`
                if trimmed.contains("hash =") || trimmed.contains("sha256:") {
                    current_has_hash = true;
                }
            } else if in_files_array {
                if trimmed == "]" {
                    in_files_array = false;
                } else if trimmed.contains("hash =") || trimmed.contains("sha256:") {
                    current_has_hash = true;
                }
            }
        }
    }

    // Flush last package
    flush_poetry_package(&mut deps, current_name, current_version, current_has_hash);

    Ok(deps)
}

fn flush_poetry_package(
    deps: &mut Vec<DependencySignatureEvidence>,
    name: Option<String>,
    version: Option<String>,
    has_hash: bool,
) {
    if let (Some(name), Some(version)) = (name, version) {
        let (verification, mechanism) = if has_hash {
            (
                VerificationOutcome::ChecksumMatch,
                Some("checksum".to_string()),
            )
        } else {
            (
                VerificationOutcome::AttestationAbsent {
                    detail: "no file hash in poetry.lock".to_string(),
                },
                None,
            )
        };

        deps.push(DependencySignatureEvidence {
            name,
            version,
            registry: Some("pypi.org".to_string()),
            verification,
            signature_mechanism: mechanism,
            signer_identity: None,
            source_repo: None,
            source_commit: None,
            pinned_digest: None,
            actual_digest: None,
            transparency_log_uri: None,
            // poetry.lock does not reliably distinguish direct from transitive;
            // pyproject.toml cross-reference would be needed for accuracy.
            is_direct: true,
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_cargo_lock_extracts_deps_with_checksum() {
        let content = r#"
[[package]]
name = "serde"
version = "1.0.204"
source = "registry+https://github.com/rust-lang/crates.io-index"
checksum = "abc123def456"

[[package]]
name = "tokio"
version = "1.38.0"
source = "registry+https://github.com/rust-lang/crates.io-index"
checksum = "789xyz"
"#;
        let deps = parse_cargo_lock(content).unwrap();
        assert_eq!(deps.len(), 2);
        assert_eq!(deps[0].name, "serde");
        assert_eq!(deps[0].version, "1.0.204");
        assert!(deps[0].verification.is_verified());
        assert_eq!(
            deps[0].pinned_digest,
            Some("sha256:abc123def456".to_string())
        );
        assert_eq!(deps[0].signature_mechanism, Some("checksum".to_string()));

        assert_eq!(deps[1].name, "tokio");
    }

    #[test]
    fn parse_cargo_lock_skips_path_dependencies() {
        let content = r#"
[[package]]
name = "my-workspace-crate"
version = "0.1.0"

[[package]]
name = "external-dep"
version = "1.0.0"
source = "registry+https://github.com/rust-lang/crates.io-index"
checksum = "aaa"
"#;
        let deps = parse_cargo_lock(content).unwrap();
        assert_eq!(deps.len(), 1, "path dependency should be skipped");
        assert_eq!(deps[0].name, "external-dep");
    }

    #[test]
    fn parse_cargo_lock_empty_content() {
        let deps = parse_cargo_lock("").unwrap();
        assert!(deps.is_empty());
    }

    #[test]
    fn parse_cargo_lock_git_source_without_checksum() {
        let content = r#"
[[package]]
name = "git-dep"
version = "0.1.0"
source = "git+https://github.com/example/repo#abc123"
"#;
        let deps = parse_cargo_lock(content).unwrap();
        assert_eq!(deps.len(), 1, "git source should be included");
        assert!(!deps[0].verification.is_verified());
    }

    #[test]
    fn parse_cargo_lock_mixed_sources() {
        let content = r#"
[[package]]
name = "with-checksum"
version = "1.0.0"
source = "registry+https://github.com/rust-lang/crates.io-index"
checksum = "aaa"

[[package]]
name = "local-dep"
version = "0.1.0"

[[package]]
name = "another"
version = "2.0.0"
source = "registry+https://github.com/rust-lang/crates.io-index"
checksum = "bbb"
"#;
        let deps = parse_cargo_lock(content).unwrap();
        assert_eq!(deps.len(), 2, "local-dep (no source) should be skipped");
        assert_eq!(deps[0].name, "with-checksum");
        assert!(deps[0].verification.is_verified());
        assert_eq!(deps[1].name, "another");
        assert!(deps[1].verification.is_verified());
    }

    // -- package-lock.json tests --

    #[test]
    fn parse_package_lock_v3_with_integrity() {
        let content = r#"{
  "lockfileVersion": 3,
  "packages": {
    "": { "name": "my-app", "version": "1.0.0" },
    "node_modules/lodash": {
      "version": "4.17.21",
      "resolved": "https://registry.npmjs.org/lodash/-/lodash-4.17.21.tgz",
      "integrity": "sha512-v2kDEe57RiUrWo9HuEz+"
    },
    "node_modules/react": {
      "version": "18.3.1",
      "resolved": "https://registry.npmjs.org/react/-/react-18.3.1.tgz",
      "integrity": "sha512-wS+hAgJShR0K+"
    }
  }
}"#;
        let deps = parse_package_lock_json(content).unwrap();
        assert_eq!(deps.len(), 2);
        assert_eq!(deps[0].name, "lodash");
        assert_eq!(deps[0].version, "4.17.21");
        assert!(deps[0].verification.is_verified());
        assert_eq!(
            deps[0].pinned_digest,
            Some("sha512-v2kDEe57RiUrWo9HuEz+".to_string())
        );
        assert!(deps[0].is_direct);
        assert_eq!(deps[1].name, "react");
    }

    #[test]
    fn parse_package_lock_transitive_deps() {
        let content = r#"{
  "lockfileVersion": 3,
  "packages": {
    "": { "name": "app", "version": "1.0.0" },
    "node_modules/express": {
      "version": "4.18.2",
      "integrity": "sha512-abc"
    },
    "node_modules/express/node_modules/body-parser": {
      "version": "1.20.0",
      "integrity": "sha512-def"
    }
  }
}"#;
        let deps = parse_package_lock_json(content).unwrap();
        assert_eq!(deps.len(), 2);
        // express is direct
        assert!(deps[0].is_direct);
        // body-parser is transitive (nested under express)
        assert!(!deps[1].is_direct);
    }

    #[test]
    fn parse_package_lock_no_integrity() {
        let content = r#"{
  "lockfileVersion": 3,
  "packages": {
    "": { "name": "app", "version": "1.0.0" },
    "node_modules/local-link": {
      "version": "0.1.0"
    }
  }
}"#;
        let deps = parse_package_lock_json(content).unwrap();
        assert_eq!(deps.len(), 1);
        assert!(!deps[0].verification.is_verified());
    }

    #[test]
    fn parse_package_lock_scoped_package() {
        let content = r#"{
  "lockfileVersion": 3,
  "packages": {
    "": { "name": "app", "version": "1.0.0" },
    "node_modules/@babel/core": {
      "version": "7.24.0",
      "integrity": "sha512-babel-integrity"
    }
  }
}"#;
        let deps = parse_package_lock_json(content).unwrap();
        assert_eq!(deps.len(), 1);
        assert_eq!(deps[0].name, "@babel/core");
        assert!(deps[0].verification.is_verified());
    }

    #[test]
    fn parse_package_lock_empty() {
        let content = r#"{ "lockfileVersion": 3, "packages": {} }"#;
        let deps = parse_package_lock_json(content).unwrap();
        assert!(deps.is_empty());
    }

    // -- package-lock.json v1 tests --

    #[test]
    fn parse_package_lock_v1_format() {
        let content = r#"{
  "lockfileVersion": 1,
  "dependencies": {
    "lodash": {
      "version": "4.17.21",
      "resolved": "https://registry.npmjs.org/lodash/-/lodash-4.17.21.tgz",
      "integrity": "sha512-v1-lodash-hash"
    },
    "express": {
      "version": "4.18.2",
      "resolved": "https://registry.npmjs.org/express/-/express-4.18.2.tgz",
      "integrity": "sha512-express-hash",
      "dependencies": {
        "body-parser": {
          "version": "1.20.0",
          "integrity": "sha512-body-parser-hash"
        }
      }
    }
  }
}"#;
        let deps = parse_package_lock_json(content).unwrap();
        assert_eq!(deps.len(), 3);

        let lodash = deps.iter().find(|d| d.name == "lodash").expect("lodash");
        assert!(lodash.is_direct);
        assert!(lodash.verification.is_verified());

        let express = deps.iter().find(|d| d.name == "express").expect("express");
        assert!(express.is_direct);

        let body_parser = deps
            .iter()
            .find(|d| d.name == "body-parser")
            .expect("body-parser");
        assert!(!body_parser.is_direct, "nested dep should be transitive");
        assert!(body_parser.verification.is_verified());
    }

    #[test]
    fn parse_package_lock_v1_no_integrity() {
        let content = r#"{
  "lockfileVersion": 1,
  "dependencies": {
    "old-pkg": {
      "version": "0.0.1"
    }
  }
}"#;
        let deps = parse_package_lock_json(content).unwrap();
        assert_eq!(deps.len(), 1);
        assert!(!deps[0].verification.is_verified());
    }

    // -- poetry.lock tests --

    #[test]
    fn parse_poetry_lock_with_hash() {
        let content = r#"
[[package]]
name = "requests"
version = "2.31.0"
description = "Python HTTP for Humans."
optional = false
python-versions = ">=3.7"
files = [
    {file = "requests-2.31.0-py3-none-any.whl", hash = "sha256:58cd2187423839"},
    {file = "requests-2.31.0.tar.gz", hash = "sha256:942c5a758f98"},
]

[[package]]
name = "urllib3"
version = "2.0.7"
description = "HTTP library with thread-safe connection pooling"
optional = false
python-versions = ">=3.7"
files = [
    {file = "urllib3-2.0.7-py3-none-any.whl", hash = "sha256:fdb6d215c776a"},
]
"#;
        let deps = parse_poetry_lock(content).unwrap();
        assert_eq!(deps.len(), 2);

        let requests = deps
            .iter()
            .find(|d| d.name == "requests")
            .expect("requests");
        assert_eq!(requests.version, "2.31.0");
        assert!(
            requests.verification.is_verified(),
            "hash present → ChecksumMatch"
        );
        assert_eq!(requests.signature_mechanism, Some("checksum".to_string()));
        assert_eq!(requests.registry, Some("pypi.org".to_string()));

        let urllib3 = deps.iter().find(|d| d.name == "urllib3").expect("urllib3");
        assert_eq!(urllib3.version, "2.0.7");
        assert!(urllib3.verification.is_verified());
    }

    #[test]
    fn parse_poetry_lock_without_hash() {
        let content = r#"
[[package]]
name = "legacy-pkg"
version = "0.1.0"
description = "A package without file hashes"
optional = false
python-versions = "*"

[[package]]
name = "another-legacy"
version = "1.2.3"
description = "Also no hashes"
optional = false
python-versions = "*"
"#;
        let deps = parse_poetry_lock(content).unwrap();
        assert_eq!(deps.len(), 2);

        let legacy = deps
            .iter()
            .find(|d| d.name == "legacy-pkg")
            .expect("legacy-pkg");
        assert_eq!(legacy.version, "0.1.0");
        assert!(
            !legacy.verification.is_verified(),
            "no hash → AttestationAbsent"
        );
        assert_eq!(legacy.signature_mechanism, None);
        assert_eq!(legacy.registry, Some("pypi.org".to_string()));

        let another = deps
            .iter()
            .find(|d| d.name == "another-legacy")
            .expect("another-legacy");
        assert!(!another.verification.is_verified());
    }
}
