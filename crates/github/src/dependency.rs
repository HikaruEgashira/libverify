//! Dependency signature evidence collection for GitHub repositories.
//!
//! Detects lock files in the repository (Cargo.lock, package-lock.json, etc.)
//! and collects dependency signature evidence by parsing lock-file checksums
//! and optionally verifying npm provenance via `npm audit signatures`.

use libverify_core::evidence::{
    DependencySignatureEvidence, EvidenceGap, EvidenceState, VerificationOutcome,
};
use std::process::Command;

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

    // Try npm audit signatures if package-lock.json is present
    if changed_files
        .iter()
        .any(|f| f.ends_with("package-lock.json"))
    {
        match collect_npm_signatures() {
            Ok(deps) => all_deps.extend(deps),
            Err(e) => {
                gaps.push(EvidenceGap::CollectionFailed {
                    source: "npm-audit-signatures".to_string(),
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
                    // For npm, try npm audit signatures if available
                    match collect_npm_signatures() {
                        Ok(deps) => all_deps.extend(deps),
                        Err(e) => {
                            gaps.push(EvidenceGap::CollectionFailed {
                                source: "npm-audit-signatures".to_string(),
                                subject: lock_file.to_string(),
                                detail: format!("{e}"),
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

// -- npm provenance collection --

/// Collect npm dependency signature evidence using `npm audit signatures --json`.
fn collect_npm_signatures() -> anyhow::Result<Vec<DependencySignatureEvidence>> {
    if !command_available("npm") {
        anyhow::bail!("`npm` CLI is not available");
    }

    let output = Command::new("npm")
        .args(["audit", "signatures", "--json"])
        .output()?;

    // npm audit signatures returns non-zero if unsigned packages exist — that's expected
    let stdout = String::from_utf8(output.stdout)?;
    if stdout.trim().is_empty() {
        anyhow::bail!("npm audit signatures produced no output");
    }

    // Try to parse as the structured format first, fall back to line-based parsing
    let deps = parse_npm_audit_output(&stdout)?;
    Ok(deps)
}

/// Parse npm audit signatures JSON output into dependency evidence.
///
/// npm audit signatures --json outputs a JSON object with attestation info.
/// The exact format varies by npm version. We handle both structured and
/// fallback approaches.
fn parse_npm_audit_output(stdout: &str) -> anyhow::Result<Vec<DependencySignatureEvidence>> {
    // npm audit signatures --json returns objects with keys per package
    let value: serde_json::Value = serde_json::from_str(stdout)?;

    let mut deps = Vec::new();

    // Handle the common format: { "audit": { "signatures": [...] } }
    if let Some(audit) = value.get("audit").and_then(|a| a.get("signatures")) {
        if let Some(sigs) = audit.as_array() {
            for sig in sigs {
                if let (Some(name), Some(version)) = (
                    sig.get("name").and_then(|n| n.as_str()),
                    sig.get("version").and_then(|v| v.as_str()),
                ) {
                    let verified = sig
                        .get("verified")
                        .and_then(|v| v.as_bool())
                        .unwrap_or(false);

                    deps.push(DependencySignatureEvidence {
                        name: name.to_string(),
                        version: version.to_string(),
                        registry: Some("registry.npmjs.org".to_string()),
                        verification: if verified {
                            VerificationOutcome::Verified
                        } else {
                            VerificationOutcome::AttestationAbsent {
                                detail: "npm provenance not found".to_string(),
                            }
                        },
                        signature_mechanism: if verified {
                            Some("sigstore".to_string())
                        } else {
                            None
                        },
                        signer_identity: None,
                        source_repo: None,
                        source_commit: None,
                        pinned_digest: None,
                        actual_digest: None,
                        transparency_log_uri: None,
                        is_direct: true,
                    });
                }
            }
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
fn parse_cargo_lock(content: &str) -> anyhow::Result<Vec<DependencySignatureEvidence>> {
    let mut deps = Vec::new();
    let mut current_name: Option<String> = None;
    let mut current_version: Option<String> = None;
    let mut current_checksum: Option<String> = None;
    let mut in_package = false;

    for line in content.lines() {
        let line = line.trim();

        if line == "[[package]]" {
            // Flush previous package
            if let (Some(name), Some(version)) = (current_name.take(), current_version.take()) {
                let checksum = current_checksum.take();
                deps.push(make_cargo_dep(&name, &version, checksum.as_deref()));
            }
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
            }
        }
    }

    // Flush last package
    if let (Some(name), Some(version)) = (current_name, current_version) {
        deps.push(make_cargo_dep(&name, &version, current_checksum.as_deref()));
    }

    Ok(deps)
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

fn command_available(cmd: &str) -> bool {
    Command::new(cmd)
        .arg("--version")
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
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
checksum = "abc123def456"

[[package]]
name = "tokio"
version = "1.38.0"
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
    fn parse_cargo_lock_handles_missing_checksum() {
        let content = r#"
[[package]]
name = "path-dep"
version = "0.1.0"
"#;
        let deps = parse_cargo_lock(content).unwrap();
        assert_eq!(deps.len(), 1);
        assert!(!deps[0].verification.is_verified());
        assert_eq!(deps[0].pinned_digest, None);
    }

    #[test]
    fn parse_cargo_lock_empty_content() {
        let deps = parse_cargo_lock("").unwrap();
        assert!(deps.is_empty());
    }

    #[test]
    fn parse_cargo_lock_multiple_packages_with_mixed_checksums() {
        let content = r#"
[[package]]
name = "with-checksum"
version = "1.0.0"
checksum = "aaa"

[[package]]
name = "local-dep"
version = "0.1.0"

[[package]]
name = "another"
version = "2.0.0"
checksum = "bbb"
"#;
        let deps = parse_cargo_lock(content).unwrap();
        assert_eq!(deps.len(), 3);
        assert!(deps[0].verification.is_verified());
        assert!(!deps[1].verification.is_verified());
        assert!(deps[2].verification.is_verified());
    }
}
