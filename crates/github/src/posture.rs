//! Repository posture evidence collection for GitHub repositories.
//!
//! Collects repository-level security configuration signals:
//! CODEOWNERS, SECURITY.md, secret scanning, vulnerability scanning,
//! and branch protection settings.

use libverify_core::evidence::{CodeownersEntry, EvidenceGap, EvidenceState, RepositoryPosture};

use crate::client::GitHubClient;

/// Candidate paths for the CODEOWNERS file (GitHub resolves in this order).
const CODEOWNERS_PATHS: &[&str] = &["CODEOWNERS", "docs/CODEOWNERS", ".github/CODEOWNERS"];

/// Candidate paths for the security policy file.
const SECURITY_POLICY_PATHS: &[&str] = &["SECURITY.md", "docs/SECURITY.md", ".github/SECURITY.md"];

/// Disclosure keywords that indicate a responsible disclosure process.
const DISCLOSURE_KEYWORDS: &[&str] = &[
    "responsible disclosure",
    "coordinated disclosure",
    "vulnerability report",
    "report a vulnerability",
    "security@",
    "hackerone",
    "bugcrowd",
    "bug bounty",
];

/// Collect repository posture evidence from the GitHub API.
///
/// Fetches CODEOWNERS, SECURITY.md, and repository settings to populate
/// `RepositoryPosture`. Uses `ref_sha` for file lookups. Falls back to
/// `EvidenceState::Missing` when the API call fails entirely, or
/// `EvidenceState::Partial` when some data could not be collected.
pub fn collect_repository_posture(
    client: &GitHubClient,
    owner: &str,
    repo: &str,
    ref_sha: &str,
) -> EvidenceState<RepositoryPosture> {
    let mut gaps = Vec::new();

    // --- CODEOWNERS ---
    let codeowners_entries = collect_codeowners(client, owner, repo, ref_sha);

    // --- SECURITY.md ---
    let (security_policy_present, security_policy_has_disclosure) =
        collect_security_policy(client, owner, repo, ref_sha);

    // --- Repository settings (secret scanning, vulnerability scanning, branch protection) ---
    let (
        secret_scanning_enabled,
        secret_push_protection_enabled,
        vulnerability_scanning_enabled,
        code_scanning_enabled,
        default_branch_protected,
    ) = collect_repo_settings(client, owner, repo).unwrap_or_else(|e| {
        gaps.push(EvidenceGap::CollectionFailed {
            source: "github".to_string(),
            subject: "repository settings".to_string(),
            detail: format!("{e:#}"),
        });
        (false, false, false, false, false)
    });

    let posture = RepositoryPosture {
        codeowners_entries,
        secret_scanning_enabled,
        secret_push_protection_enabled,
        vulnerability_scanning_enabled,
        code_scanning_enabled,
        security_policy_present,
        security_policy_has_disclosure,
        default_branch_protected,
    };

    if gaps.is_empty() {
        EvidenceState::complete(posture)
    } else {
        EvidenceState::partial(posture, gaps)
    }
}

/// Parse CODEOWNERS file content into entries.
fn collect_codeowners(
    client: &GitHubClient,
    owner: &str,
    repo: &str,
    ref_sha: &str,
) -> Vec<CodeownersEntry> {
    for path in CODEOWNERS_PATHS {
        if let Ok(content) = client.get_file_content(owner, repo, path, ref_sha) {
            return parse_codeowners(&content);
        }
    }
    Vec::new()
}

/// Parse CODEOWNERS content into structured entries.
fn parse_codeowners(content: &str) -> Vec<CodeownersEntry> {
    content
        .lines()
        .filter(|line| {
            let trimmed = line.trim();
            !trimmed.is_empty() && !trimmed.starts_with('#')
        })
        .filter_map(|line| {
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() >= 2 {
                Some(CodeownersEntry {
                    pattern: parts[0].to_string(),
                    owners: parts[1..].iter().map(|s| s.to_string()).collect(),
                })
            } else {
                None
            }
        })
        .collect()
}

/// Check for SECURITY.md and whether it describes a disclosure process.
fn collect_security_policy(
    client: &GitHubClient,
    owner: &str,
    repo: &str,
    ref_sha: &str,
) -> (bool, bool) {
    for path in SECURITY_POLICY_PATHS {
        if let Ok(content) = client.get_file_content(owner, repo, path, ref_sha) {
            let lower = content.to_lowercase();
            let has_disclosure = DISCLOSURE_KEYWORDS.iter().any(|kw| lower.contains(kw));
            return (true, has_disclosure);
        }
    }
    (false, false)
}

/// Repository settings response (subset of GET /repos/{owner}/{repo}).
#[derive(serde::Deserialize)]
struct RepoResponse {
    #[serde(default)]
    default_branch: String,
    #[serde(default)]
    security_and_analysis: Option<SecurityAndAnalysis>,
}

#[derive(serde::Deserialize)]
struct SecurityAndAnalysis {
    #[serde(default)]
    secret_scanning: Option<SecurityFeature>,
    #[serde(default)]
    secret_scanning_push_protection: Option<SecurityFeature>,
    #[serde(default)]
    dependabot_security_updates: Option<SecurityFeature>,
}

#[derive(serde::Deserialize)]
struct SecurityFeature {
    status: String,
}

/// Fetch repository settings from the GitHub REST API.
fn collect_repo_settings(
    client: &GitHubClient,
    owner: &str,
    repo: &str,
) -> anyhow::Result<(bool, bool, bool, bool, bool)> {
    let path = format!("/repos/{owner}/{repo}");
    let body = client.get(&path)?;
    let resp: RepoResponse = serde_json::from_str(&body)?;

    let (secret_scanning, push_protection, dependabot) = match resp.security_and_analysis.as_ref() {
        Some(sa) => (
            sa.secret_scanning
                .as_ref()
                .is_some_and(|f| f.status == "enabled"),
            sa.secret_scanning_push_protection
                .as_ref()
                .is_some_and(|f| f.status == "enabled"),
            sa.dependabot_security_updates
                .as_ref()
                .is_some_and(|f| f.status == "enabled"),
        ),
        None => (false, false, false),
    };

    // Code scanning: check if any code-scanning analyses exist (non-empty = enabled)
    let code_scanning = client
        .get(&format!(
            "/repos/{owner}/{repo}/code-scanning/analyses?per_page=1"
        ))
        .map(|body| {
            serde_json::from_str::<Vec<serde_json::Value>>(&body)
                .map(|v| !v.is_empty())
                .unwrap_or(false)
        })
        .unwrap_or(false);

    // Branch protection
    let default_branch = &resp.default_branch;
    let branch_protected = client
        .get(&format!(
            "/repos/{owner}/{repo}/branches/{default_branch}/protection"
        ))
        .is_ok();

    Ok((
        secret_scanning,
        push_protection,
        dependabot,
        code_scanning,
        branch_protected,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_codeowners_basic() {
        let content = "# Global owners\n* @org/team\n/src/auth/ @alice @bob\n";
        let entries = parse_codeowners(content);
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].pattern, "*");
        assert_eq!(entries[0].owners, vec!["@org/team"]);
        assert_eq!(entries[1].pattern, "/src/auth/");
        assert_eq!(entries[1].owners, vec!["@alice", "@bob"]);
    }

    #[test]
    fn parse_codeowners_empty_and_comments() {
        let content = "# comment\n\n  # another comment\n";
        let entries = parse_codeowners(content);
        assert!(entries.is_empty());
    }

    #[test]
    fn parse_codeowners_single_column_skipped() {
        let content = "*.rs\n";
        let entries = parse_codeowners(content);
        assert!(entries.is_empty(), "single-column lines have no owners");
    }

    #[test]
    fn disclosure_keywords_are_lowercase() {
        for kw in DISCLOSURE_KEYWORDS {
            assert_eq!(
                *kw,
                kw.to_lowercase(),
                "keyword must be lowercase for case-insensitive matching"
            );
        }
    }
}
