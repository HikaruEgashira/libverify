use serde::Deserialize;

/// GitHub API response type for PR changed files.
#[derive(Debug, Clone, Deserialize)]
pub struct PrFile {
    pub filename: String,
    pub patch: Option<String>,
    #[serde(default)]
    pub additions: u32,
    #[serde(default)]
    pub deletions: u32,
    #[serde(default)]
    pub status: String,
}

/// GitHub API response type for PR metadata.
#[derive(Debug, Clone, Deserialize)]
pub struct PrMetadata {
    pub number: u32,
    pub title: String,
    pub body: Option<String>,
    pub user: Option<PrUser>,
    pub head: PrHead,
    pub base: PrBase,
}

/// The head branch/commit info from a PR.
#[derive(Debug, Clone, Deserialize)]
pub struct PrHead {
    pub sha: String,
}

/// The base branch info from a PR.
#[derive(Debug, Clone, Deserialize)]
pub struct PrBase {
    /// The branch name (e.g. "main").
    #[serde(rename = "ref")]
    pub ref_name: String,
}

/// GitHub API response type for a tag.
#[derive(Debug, Clone, Deserialize)]
pub struct Tag {
    pub name: String,
    pub commit: TagCommit,
}

#[derive(Debug, Clone, Deserialize)]
pub struct TagCommit {
    pub sha: String,
}

/// Commit verification info from GitHub API.
#[derive(Debug, Clone, Deserialize)]
pub struct CommitVerification {
    pub verified: bool,
    pub reason: String,
}

/// Commit author info (top-level, optional).
#[derive(Debug, Clone, Deserialize)]
pub struct CommitAuthor {
    pub login: String,
}

/// Inner commit data.
#[derive(Debug, Clone, Deserialize)]
pub struct CompareCommitInner {
    pub message: String,
    pub verification: CommitVerification,
}

/// Parent commit reference from the GitHub API.
#[derive(Debug, Clone, Deserialize)]
pub struct CommitParent {
    pub sha: String,
}

/// A commit from the compare API.
#[derive(Debug, Clone, Deserialize)]
pub struct CompareCommit {
    pub sha: String,
    pub commit: CompareCommitInner,
    pub author: Option<CommitAuthor>,
    #[serde(default)]
    pub parents: Vec<CommitParent>,
}

/// Response from the compare API.
#[derive(Debug, Clone, Deserialize)]
pub struct CompareResponse {
    pub commits: Vec<CompareCommit>,
}

/// A pull request summary (from commits/{sha}/pulls).
#[derive(Debug, Clone, Deserialize)]
pub struct PullRequestSummary {
    pub number: u32,
    pub merged_at: Option<String>,
    pub user: PrUser,
}

/// Pull request user.
#[derive(Debug, Clone, Deserialize)]
pub struct PrUser {
    pub login: String,
}

/// A release from the GitHub Releases API.
#[derive(Debug, Clone, Deserialize)]
pub struct Release {
    pub tag_name: String,
    pub assets: Vec<ReleaseAsset>,
}

/// An asset attached to a GitHub release.
#[derive(Debug, Clone, Deserialize)]
pub struct ReleaseAsset {
    pub name: String,
    pub browser_download_url: String,
}

/// A PR review.
#[derive(Debug, Clone, Deserialize)]
pub struct Review {
    pub user: PrUser,
    pub state: String,
    pub submitted_at: Option<String>,
    /// Review body text. Used to detect bot-mediated approvals
    /// (e.g., Prow `/lgtm`, `/approve` commands).
    #[serde(default)]
    pub body: Option<String>,
}

/// A commit on a PR (from the pulls/{number}/commits endpoint).
#[derive(Debug, Clone, Deserialize)]
pub struct PrCommit {
    pub sha: String,
    pub commit: PrCommitInner,
    pub author: Option<PrUser>,
}

/// Inner commit data for a PR commit.
#[derive(Debug, Clone, Deserialize)]
pub struct PrCommitInner {
    pub committer: Option<PrCommitAuthor>,
    pub verification: Option<CommitVerification>,
}

/// Committer info with timestamp.
#[derive(Debug, Clone, Deserialize)]
pub struct PrCommitAuthor {
    pub date: Option<String>,
}

/// Minimal app info from a check run.
#[derive(Debug, Clone, Deserialize)]
pub struct CheckRunApp {
    pub slug: String,
}

/// A single check run from the GitHub Check Runs API.
#[derive(Debug, Clone, Deserialize)]
pub struct CheckRunItem {
    pub name: String,
    /// "completed", "in_progress", "queued", etc.
    pub status: String,
    /// "success", "failure", "neutral", "cancelled", "skipped", "timed_out", "action_required", or null if not completed.
    pub conclusion: Option<String>,
    /// The GitHub App that created this check run (e.g. "github-actions").
    pub app: Option<CheckRunApp>,
}

/// Response from GET /repos/{owner}/{repo}/commits/{ref}/status.
#[derive(Debug, Clone, Deserialize)]
pub struct CombinedStatusResponse {
    pub state: String,
    pub statuses: Vec<CommitStatusItem>,
}

/// A single status from the combined status API.
#[derive(Debug, Clone, Deserialize)]
pub struct CommitStatusItem {
    pub context: String,
    pub state: String,
}

/// Wrapper for GitHub Search API responses.
#[derive(Debug, Clone, Deserialize)]
pub struct SearchResponse<T> {
    pub total_count: u32,
    pub items: Vec<T>,
}

/// A PR item from the GitHub Search API (issues endpoint).
#[derive(Debug, Clone, Deserialize)]
pub struct SearchPrItem {
    pub number: u32,
    pub pull_request: Option<SearchPrMeta>,
}

/// Pull request metadata within a search result.
#[derive(Debug, Clone, Deserialize)]
pub struct SearchPrMeta {
    pub merged_at: Option<String>,
}
