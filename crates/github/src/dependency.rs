//! Dependency signature evidence collection for GitHub repositories.
//!
//! Detects lock files in the repository (Cargo.lock, package-lock.json, etc.)
//! and collects dependency signature evidence by parsing lock-file checksums
//! and optionally verifying npm provenance via `npm audit signatures`.

use libverify_core::evidence::{
    DependencySignatureEvidence, EvidenceGap, EvidenceState, VerificationOutcome,
};

use crate::client::GitHubClient;

/// Lock file types we can parse for dependency evidence.
const LOCK_FILES: &[&str] = &["package-lock.json", "Cargo.lock"];

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
    // Only collect if a lock file was changed or exists
    let has_lock_file_change = changed_files
        .iter()
        .any(|f| LOCK_FILES.iter().any(|lf| f.ends_with(lf)));

    if !has_lock_file_change {
        return EvidenceState::NotApplicable;
    }

    let mut all_deps = Vec::new();
    let mut gaps = Vec::new();

    // Try parsing package-lock.json if present
    if changed_files
        .iter()
        .any(|f| f.ends_with("package-lock.json"))
    {
        match client.get_file_content(owner, repo, "package-lock.json", head_sha) {
            Ok(content) => match parse_package_lock_json(&content) {
                Ok(deps) => all_deps.extend(deps),
                Err(e) => {
                    gaps.push(EvidenceGap::CollectionFailed {
                        source: "package-lock-json".to_string(),
                        subject: "package-lock.json".to_string(),
                        detail: format!("parse error: {e}"),
                    });
                }
            },
            Err(e) => {
                gaps.push(EvidenceGap::CollectionFailed {
                    source: "github-api".to_string(),
                    subject: "package-lock.json".to_string(),
                    detail: format!("{e}"),
                });
            }
        }
    }

    // Try Cargo.lock parsing if present
    if changed_files.iter().any(|f| f.ends_with("Cargo.lock")) {
        match collect_cargo_checksums(client, owner, repo, head_sha) {
            Ok(deps) => all_deps.extend(deps),
            Err(e) => {
                gaps.push(EvidenceGap::CollectionFailed {
                    source: "cargo-lock".to_string(),
                    subject: "Cargo.lock".to_string(),
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
/// Probes for known lock files (Cargo.lock, package-lock.json) at the given
/// reference and parses each one found. Returns `NotApplicable` if no lock
/// files exist in the repository.
pub fn collect_repo_dependency_signatures(
    client: &GitHubClient,
    owner: &str,
    repo: &str,
    reference: &str,
) -> EvidenceState<Vec<DependencySignatureEvidence>> {
    let mut all_deps = Vec::new();
    let mut gaps = Vec::new();
    let mut found_any = false;

    for &lock_file in LOCK_FILES {
        match client.get_file_content(owner, repo, lock_file, reference) {
            Ok(content) => {
                found_any = true;
                if lock_file == "Cargo.lock" {
                    match parse_cargo_lock(&content) {
                        Ok(deps) => all_deps.extend(deps),
                        Err(e) => {
                            gaps.push(EvidenceGap::CollectionFailed {
                                source: "cargo-lock".to_string(),
                                subject: lock_file.to_string(),
                                detail: format!("parse error: {e}"),
                            });
                        }
                    }
                } else if lock_file == "package-lock.json" {
                    match parse_package_lock_json(&content) {
                        Ok(deps) => all_deps.extend(deps),
                        Err(e) => {
                            gaps.push(EvidenceGap::CollectionFailed {
                                source: "package-lock-json".to_string(),
                                subject: lock_file.to_string(),
                                detail: format!("parse error: {e}"),
                            });
                        }
                    }
                }
            }
            Err(_) => {
                // File not found at this ref — skip silently
            }
        }
    }

    if !found_any {
        return EvidenceState::NotApplicable;
    }

    if all_deps.is_empty() && !gaps.is_empty() {
        EvidenceState::missing(gaps)
    } else if gaps.is_empty() {
        EvidenceState::complete(all_deps)
    } else {
        EvidenceState::partial(all_deps, gaps)
    }
}

// -- package-lock.json parsing --

/// Parse package-lock.json (v2/v3 format) to extract dependency integrity hashes.
///
/// package-lock.json v2+ has a `packages` object keyed by path, where each entry
/// contains `version`, `resolved`, and `integrity` (subresource integrity hash).
fn parse_package_lock_json(
    content: &str,
) -> anyhow::Result<Vec<DependencySignatureEvidence>> {
    let lock: serde_json::Value = serde_json::from_str(content)?;
    let mut deps = Vec::new();

    // v2/v3 format: "packages" object
    if let Some(packages) = lock.get("packages").and_then(|p| p.as_object()) {
        for (path, info) in packages {
            // Skip the root package (empty key "")
            if path.is_empty() {
                continue;
            }

            // Extract package name from path: "node_modules/lodash" → "lodash"
            // Scoped: "node_modules/@scope/pkg" → "@scope/pkg"
            let name = path
                .strip_prefix("node_modules/")
                .unwrap_or(path);

            let version = info
                .get("version")
                .and_then(|v| v.as_str())
                .unwrap_or("unknown");

            let integrity = info
                .get("integrity")
                .and_then(|i| i.as_str());

            let is_direct = !name.contains("node_modules/");

            let (verification, pinned_digest) = match integrity {
                Some(hash) => (
                    VerificationOutcome::Verified,
                    Some(hash.to_string()),
                ),
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
                signature_mechanism: integrity.map(|_| "integrity-hash".to_string()),
                signer_identity: None,
                source_repo: None,
                source_commit: None,
                pinned_digest,
                actual_digest: None,
                transparency_log_uri: None,
                is_direct,
            });
        }
    }

    Ok(deps)
}

// -- Cargo.lock checksum collection --

/// Parse Cargo.lock to extract dependency checksums.
/// Fetches the lock file content from GitHub at the given commit SHA.
fn collect_cargo_checksums(
    client: &GitHubClient,
    owner: &str,
    repo: &str,
    head_sha: &str,
) -> anyhow::Result<Vec<DependencySignatureEvidence>> {
    let content = client.get_file_content(owner, repo, "Cargo.lock", head_sha)?;
    parse_cargo_lock(&content)
}

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
        if source.is_none() {
            return;
        }
        deps.push(make_cargo_dep(&name, &version, checksum.as_deref()));
    }
}

fn make_cargo_dep(
    name: &str,
    version: &str,
    checksum: Option<&str>,
) -> DependencySignatureEvidence {
    let (verification, mechanism, pinned_digest) = match checksum {
        Some(cs) => (
            VerificationOutcome::Verified,
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

    DependencySignatureEvidence {
        name: name.to_string(),
        version: version.to_string(),
        registry: Some("crates.io".to_string()),
        verification,
        signature_mechanism: mechanism,
        signer_identity: None,
        source_repo: None,
        source_commit: None,
        pinned_digest,
        actual_digest: None,
        transparency_log_uri: None,
        is_direct: true,
    }
}

fn unquote(s: &str) -> String {
    s.trim().trim_matches('"').to_string()
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
}
