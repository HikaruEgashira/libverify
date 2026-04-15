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

    // Run independent API calls concurrently using scoped threads.
    // Each call hits different endpoints so there's no contention.
    let (
        codeowners_entries,
        security_policy,
        settings_result,
        dep_tool,
        permissions_result,
        tag_protection,
    ) = std::thread::scope(|s| {
        let h_codeowners = s.spawn(|| collect_codeowners(client, owner, repo, ref_sha));
        let h_security = s.spawn(|| collect_security_policy(client, owner, repo, ref_sha));
        let h_settings = s.spawn(|| collect_repo_settings(client, owner, repo));
        let h_dep_tool = s.spawn(|| collect_dependency_update_tool(client, owner, repo, ref_sha));
        let h_permissions = s.spawn(|| collect_permissions_info(client, owner, repo));
        let h_tag = s.spawn(|| collect_tag_protection(client, owner, repo));

        (
            h_codeowners.join().unwrap(),
            h_security.join().unwrap(),
            h_settings.join().unwrap(),
            h_dep_tool.join().unwrap(),
            h_permissions.join().unwrap(),
            h_tag.join().unwrap(),
        )
    });

    let (security_policy_present, security_policy_has_disclosure) = security_policy;

    let (
        security_analysis_available,
        secret_scanning_enabled,
        secret_push_protection_enabled,
        vulnerability_scanning_enabled,
        code_scanning_enabled,
        default_branch_protected,
        enforce_admins,
        dismiss_stale_reviews,
    ) = match settings_result {
        Ok(settings) => (
            settings.security_analysis_available,
            settings.secret_scanning,
            settings.push_protection,
            settings.dependabot,
            settings.code_scanning,
            settings.branch_protected,
            settings.enforce_admins,
            settings.dismiss_stale_reviews,
        ),
        Err(e) => {
            gaps.push(EvidenceGap::CollectionFailed {
                source: "github".to_string(),
                subject: "repository settings".to_string(),
                detail: format!("{e:#}"),
            });
            (false, false, false, false, false, false, false, false)
        }
    };

    let (default_workflow_permissions, admin_count, direct_collaborator_count) =
        match permissions_result {
            Ok(info) => (
                info.default_workflow_permissions,
                info.admin_count,
                info.direct_collaborator_count,
            ),
            Err(e) => {
                gaps.push(EvidenceGap::CollectionFailed {
                    source: "github".to_string(),
                    subject: "permissions info".to_string(),
                    detail: format!("{e:#}"),
                });
                (String::new(), 0, 0)
            }
        };

    // TODO: Populate copyleft_dependencies from GitHub License API or SBOM parser.
    // The license-compliance control evaluates this field against known copyleft SPDX IDs.
    // Until integrated, the field defaults to empty (no copyleft deps detected).

    // TODO: Populate release_has_sbom from release assets (detect *.spdx.json, *.cdx.json, *sbom*).
    // The sbom-completeness control checks this field. Until integrated with the release API,
    // the field defaults to false.

    let posture = RepositoryPosture {
        codeowners_entries,
        security_analysis_available,
        secret_scanning_enabled,
        secret_push_protection_enabled,
        vulnerability_scanning_enabled,
        code_scanning_enabled,
        security_policy_present,
        security_policy_has_disclosure,
        default_branch_protected,
        enforce_admins,
        dismiss_stale_reviews,
        dependency_update_tool_configured: dep_tool,
        default_workflow_permissions,
        admin_count,
        direct_collaborator_count,
        tag_protection_enabled: tag_protection,
        ..Default::default()
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

/// Branch protection API response (subset).
#[derive(serde::Deserialize)]
struct BranchProtectionResponse {
    #[serde(default)]
    enforce_admins: Option<EnforceAdmins>,
    #[serde(default)]
    required_pull_request_reviews: Option<RequiredPullRequestReviews>,
}

#[derive(serde::Deserialize)]
struct EnforceAdmins {
    enabled: bool,
}

#[derive(serde::Deserialize)]
struct RequiredPullRequestReviews {
    #[serde(default)]
    dismiss_stale_reviews: bool,
}

/// Result of collecting repository settings, including any evidence gaps
/// that occurred during collection (e.g. insufficient API permissions).
struct RepoSettingsResult {
    security_analysis_available: bool,
    secret_scanning: bool,
    push_protection: bool,
    dependabot: bool,
    code_scanning: bool,
    branch_protected: bool,
    enforce_admins: bool,
    dismiss_stale_reviews: bool,
}

/// Fetch repository settings from the GitHub REST API.
fn collect_repo_settings(
    client: &GitHubClient,
    owner: &str,
    repo: &str,
) -> anyhow::Result<RepoSettingsResult> {
    let path = format!("/repos/{owner}/{repo}");
    let body = client.get(&path)?;
    let resp: RepoResponse = serde_json::from_str(&body)?;
    let security_analysis_available = resp.security_and_analysis.is_some();

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

    // Branch protection: parse response for detailed fields
    let default_branch = &resp.default_branch;
    let protection_url = format!("/repos/{owner}/{repo}/branches/{default_branch}/protection");
    let (branch_protected, enforce_admins, dismiss_stale_reviews) =
        match client.get(&protection_url) {
            Ok(bp_body) => {
                let bp: BranchProtectionResponse =
                    serde_json::from_str(&bp_body).unwrap_or(BranchProtectionResponse {
                        enforce_admins: None,
                        required_pull_request_reviews: None,
                    });
                let enforce = bp.enforce_admins.as_ref().is_some_and(|ea| ea.enabled);
                let dismiss = bp
                    .required_pull_request_reviews
                    .as_ref()
                    .is_some_and(|pr| pr.dismiss_stale_reviews);
                (true, enforce, dismiss)
            }
            Err(_) => (false, false, false),
        };

    Ok(RepoSettingsResult {
        security_analysis_available,
        secret_scanning,
        push_protection,
        dependabot,
        code_scanning,
        branch_protected,
        enforce_admins,
        dismiss_stale_reviews,
    })
}

/// Dependency update tool config file paths to check.
const DEPENDABOT_PATH: &str = ".github/dependabot.yml";
const RENOVATE_PATHS: &[&str] = &[
    "renovate.json",
    "renovate.json5",
    ".renovaterc",
    ".renovaterc.json",
];

/// Check whether a dependency update tool is configured.
fn collect_dependency_update_tool(
    client: &GitHubClient,
    owner: &str,
    repo: &str,
    ref_sha: &str,
) -> bool {
    // Check Dependabot
    if client
        .get_file_content(owner, repo, DEPENDABOT_PATH, ref_sha)
        .is_ok()
    {
        return true;
    }
    // Check Renovate
    for path in RENOVATE_PATHS {
        if client.get_file_content(owner, repo, path, ref_sha).is_ok() {
            return true;
        }
    }
    false
}

/// Permissions info collected from the GitHub API.
struct PermissionsInfo {
    default_workflow_permissions: String,
    admin_count: u32,
    direct_collaborator_count: u32,
}

/// Collect workflow permissions and collaborator info.
fn collect_permissions_info(
    client: &GitHubClient,
    owner: &str,
    repo: &str,
) -> anyhow::Result<PermissionsInfo> {
    // GET /repos/{owner}/{repo} includes default_branch_permissions in some API versions
    // For workflow permissions, we use the Actions permissions endpoint
    let default_workflow_permissions = client
        .get(&format!(
            "/repos/{owner}/{repo}/actions/permissions/workflow"
        ))
        .ok()
        .and_then(|body| {
            serde_json::from_str::<serde_json::Value>(&body)
                .ok()
                .and_then(|v| v["default_workflow_permissions"].as_str().map(String::from))
        })
        .unwrap_or_default();

    // GET /repos/{owner}/{repo}/collaborators?affiliation=direct
    let (admin_count, direct_collaborator_count) = client
        .get(&format!(
            "/repos/{owner}/{repo}/collaborators?affiliation=direct&per_page=100"
        ))
        .ok()
        .and_then(|body| serde_json::from_str::<Vec<serde_json::Value>>(&body).ok())
        .map(|collabs| {
            let admins = collabs
                .iter()
                .filter(|c| c["permissions"]["admin"].as_bool().unwrap_or(false))
                .count() as u32;
            let direct = collabs.len() as u32;
            (admins, direct)
        })
        .unwrap_or((0, 0));

    Ok(PermissionsInfo {
        default_workflow_permissions,
        admin_count,
        direct_collaborator_count,
    })
}

/// Check whether tag protection rules exist.
fn collect_tag_protection(client: &GitHubClient, owner: &str, repo: &str) -> bool {
    // Tag protection rules API requires admin access; returns 404 if no rules or no permission
    client
        .get(&format!("/repos/{owner}/{repo}/tags/protection"))
        .ok()
        .and_then(|body| serde_json::from_str::<Vec<serde_json::Value>>(&body).ok())
        .is_some_and(|rules| !rules.is_empty())
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
