use anyhow::{Context, Result};

use crate::client::GitHubClient;
use crate::types::SearchPrItem;

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
