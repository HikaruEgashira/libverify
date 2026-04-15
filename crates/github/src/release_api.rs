use anyhow::{Context, Result};

use crate::client::GitHubClient;
use crate::types::{
    CompareCommit, CompareResponse, PullRequestSummary, Release, ReleaseAsset, Tag,
};

/// Fetch repository tags (reverse chronological).
pub fn get_tags(client: &GitHubClient, owner: &str, repo: &str) -> Result<Vec<Tag>> {
    client.paginate(&format!("/repos/{owner}/{repo}/tags?per_page=100"))
}

/// Compare two refs and return commits between them.
pub fn compare_refs(
    client: &GitHubClient,
    owner: &str,
    repo: &str,
    base: &str,
    head: &str,
) -> Result<Vec<CompareCommit>> {
    let path = format!("/repos/{owner}/{repo}/compare/{base}...{head}");
    let body = client.get(&path)?;
    let response: CompareResponse =
        serde_json::from_str(&body).context("failed to parse compare response")?;
    Ok(response.commits)
}

/// SBOM asset filename patterns. A release is considered to have an SBOM
/// if any asset name matches one of these patterns (case-insensitive).
const SBOM_PATTERNS: &[&str] = &[".spdx.json", ".cdx.json", "sbom"];

/// Returns true if any release asset matches known SBOM filename patterns.
pub fn has_sbom_asset(assets: &[ReleaseAsset]) -> bool {
    assets.iter().any(|asset| {
        let lower = asset.name.to_ascii_lowercase();
        SBOM_PATTERNS.iter().any(|pattern| lower.contains(pattern))
    })
}

/// Fetch release assets for a given tag.
///
/// Returns an empty vec if the tag has no associated release (e.g. lightweight tag).
pub fn get_release_assets(
    client: &GitHubClient,
    owner: &str,
    repo: &str,
    tag: &str,
) -> Result<Vec<ReleaseAsset>> {
    let path = format!("/repos/{owner}/{repo}/releases/tags/{tag}");
    match client.get(&path) {
        Ok(body) => {
            let release: Release =
                serde_json::from_str(&body).context("failed to parse release response")?;
            Ok(release.assets)
        }
        Err(_) => {
            // Tag may exist without a release object (lightweight tag)
            Ok(vec![])
        }
    }
}

/// Fetch PRs associated with a commit.
pub fn get_commit_pulls(
    client: &GitHubClient,
    owner: &str,
    repo: &str,
    sha: &str,
) -> Result<Vec<PullRequestSummary>> {
    let path = format!("/repos/{owner}/{repo}/commits/{sha}/pulls");
    let body = client.get(&path)?;
    serde_json::from_str(&body).context("failed to parse commit pulls")
}
