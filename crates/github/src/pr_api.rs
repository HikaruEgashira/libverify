use anyhow::{Context, Result};

use crate::client::GitHubClient;
use crate::types::{
    CheckRunsResponse, CombinedStatusResponse, PrCommit, PrFile, PrMetadata, PullRequestListItem,
    Review, SearchPrItem,
};

/// Fetch the list of changed files for a PR.
pub fn get_pr_files(
    client: &GitHubClient,
    owner: &str,
    repo: &str,
    pr_number: u32,
) -> Result<Vec<PrFile>> {
    client.paginate(&format!(
        "/repos/{owner}/{repo}/pulls/{pr_number}/files?per_page=100"
    ))
}

/// Fetch PR metadata.
pub fn get_pr_metadata(
    client: &GitHubClient,
    owner: &str,
    repo: &str,
    pr_number: u32,
) -> Result<PrMetadata> {
    let path = format!("/repos/{owner}/{repo}/pulls/{pr_number}");
    let body = client.get(&path)?;
    serde_json::from_str(&body).context("failed to parse PR metadata")
}

/// Fetch recent merged PRs for a repository from the closed PR listing.
pub fn list_recent_merged_prs(
    client: &GitHubClient,
    owner: &str,
    repo: &str,
    limit: usize,
) -> Result<Vec<PullRequestListItem>> {
    let all: Vec<PullRequestListItem> = client.paginate(&format!(
        "/repos/{owner}/{repo}/pulls?state=closed&sort=updated&direction=desc&per_page=100"
    ))?;
    Ok(all
        .into_iter()
        .filter(|pr| pr.merged_at.is_some())
        .take(limit)
        .collect())
}

/// Fetch reviews for a PR (paginated).
pub fn get_pr_reviews(
    client: &GitHubClient,
    owner: &str,
    repo: &str,
    pr_number: u32,
) -> Result<Vec<Review>> {
    client.paginate(&format!(
        "/repos/{owner}/{repo}/pulls/{pr_number}/reviews?per_page=100"
    ))
}

/// Fetch commits for a PR.
pub fn get_pr_commits(
    client: &GitHubClient,
    owner: &str,
    repo: &str,
    pr_number: u32,
) -> Result<Vec<PrCommit>> {
    client.paginate(&format!(
        "/repos/{owner}/{repo}/pulls/{pr_number}/commits?per_page=100"
    ))
}

/// Fetch check runs for a specific commit ref.
pub fn get_commit_check_runs(
    client: &GitHubClient,
    owner: &str,
    repo: &str,
    git_ref: &str,
) -> Result<CheckRunsResponse> {
    let path = format!("/repos/{owner}/{repo}/commits/{git_ref}/check-runs?per_page=100");
    let body = client
        .get(&path)
        .context("failed to fetch commit check runs")?;
    serde_json::from_str(&body).context("failed to parse check runs response")
}

/// Fetch the combined commit status for a specific commit ref.
pub fn get_commit_status(
    client: &GitHubClient,
    owner: &str,
    repo: &str,
    git_ref: &str,
) -> Result<CombinedStatusResponse> {
    let path = format!("/repos/{owner}/{repo}/commits/{git_ref}/status");
    let body = client.get(&path).context("failed to fetch commit status")?;
    serde_json::from_str(&body).context("failed to parse combined status response")
}

/// Search for merged PRs within a date range using GitHub Search API.
pub fn search_merged_prs(
    client: &GitHubClient,
    owner: &str,
    repo: &str,
    since: &str,
    until: &str,
) -> Result<Vec<u32>> {
    let path = format!(
        "/search/issues?q=repo:{owner}/{repo}+is:pr+is:merged+merged:{since}..{until}&sort=created&per_page=100"
    );
    let items: Vec<SearchPrItem> = client
        .paginate_search(&path)
        .context("failed to search merged PRs by date")?;
    Ok(items.into_iter().map(|item| item.number).collect())
}

/// Search for merged PRs within a PR number range using GitHub Search API.
pub fn search_merged_prs_in_range(
    client: &GitHubClient,
    owner: &str,
    repo: &str,
    start: u32,
    end: u32,
) -> Result<Vec<u32>> {
    let path = format!(
        "/search/issues?q=repo:{owner}/{repo}+is:pr+is:merged+number:{start}..{end}&sort=created&per_page=100"
    );
    let items: Vec<SearchPrItem> = client
        .paginate_search(&path)
        .context("failed to search merged PRs by number range")?;
    Ok(items.into_iter().map(|item| item.number).collect())
}
