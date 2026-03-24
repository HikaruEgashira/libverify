use std::collections::HashMap;

use anyhow::{Context, Result, bail};
use serde::Deserialize;

use crate::client::GitHubClient;
use crate::types::*;

// -- Batch sizes --

const PR_BATCH_SIZE: usize = 20;
const COMMIT_PR_BATCH_SIZE: usize = 100;

// -- GraphQL response wrapper --

#[derive(Deserialize)]
struct GqlResponse {
    data: Option<serde_json::Value>,
    errors: Option<Vec<GqlError>>,
}

#[derive(Deserialize)]
struct GqlError {
    message: String,
}

// -- PR data types (GraphQL-specific) --

#[derive(Deserialize)]
struct GqlPullRequest {
    number: u32,
    title: String,
    body: Option<String>,
    author: Option<GqlActor>,
    #[serde(rename = "headRefOid")]
    head_ref_oid: String,
    #[serde(rename = "baseRefName")]
    base_ref_name: String,
    files: Option<GqlConnection<GqlChangedFile>>,
    reviews: Option<GqlConnection<GqlReview>>,
    commits: Option<GqlConnection<GqlPrCommitNode>>,
    #[serde(rename = "statusChecks")]
    status_checks: Option<GqlConnection<GqlStatusCheckNode>>,
}

#[derive(Deserialize)]
struct GqlActor {
    login: String,
}

#[derive(Deserialize)]
struct GqlConnection<T> {
    nodes: Vec<T>,
}

#[derive(Deserialize)]
struct GqlChangedFile {
    path: String,
    additions: u32,
    deletions: u32,
    #[serde(rename = "changeType")]
    change_type: String,
}

#[derive(Deserialize)]
struct GqlReview {
    author: Option<GqlActor>,
    state: String,
    #[serde(rename = "submittedAt")]
    submitted_at: Option<String>,
}

#[derive(Deserialize)]
struct GqlPrCommitNode {
    commit: GqlPrCommit,
}

#[derive(Deserialize)]
struct GqlPrCommit {
    oid: String,
    author: Option<GqlCommitAuthor>,
    committer: Option<GqlCommitDate>,
    signature: Option<GqlSignature>,
}

#[derive(Deserialize)]
struct GqlCommitAuthor {
    user: Option<GqlActor>,
}

#[derive(Deserialize)]
struct GqlCommitDate {
    date: Option<String>,
}

#[derive(Deserialize)]
struct GqlSignature {
    #[serde(rename = "isValid")]
    is_valid: bool,
    state: String,
}

#[derive(Deserialize)]
struct GqlStatusCheckNode {
    commit: GqlStatusCheckCommit,
}

#[derive(Deserialize)]
struct GqlStatusCheckCommit {
    #[serde(rename = "statusCheckRollup")]
    status_check_rollup: Option<GqlStatusCheckRollup>,
}

#[derive(Deserialize)]
struct GqlStatusCheckRollup {
    contexts: GqlConnection<serde_json::Value>,
}

// -- Commit -> PR resolution types --

#[derive(Deserialize)]
struct GqlCommitWithPrs {
    #[serde(rename = "associatedPullRequests")]
    associated_pull_requests: GqlConnection<GqlAssociatedPr>,
}

#[derive(Deserialize)]
struct GqlAssociatedPr {
    number: u32,
    #[serde(rename = "mergedAt")]
    merged_at: Option<String>,
    author: Option<GqlActor>,
}

// -- Public data type --

pub struct PrData {
    pub metadata: PrMetadata,
    pub files: Vec<PrFile>,
    pub reviews: Vec<Review>,
    pub commits: Vec<PrCommit>,
    pub check_runs: Vec<CheckRunItem>,
    pub commit_statuses: Vec<CommitStatusItem>,
}

// -- Query fragment --

fn pr_fields_fragment() -> &'static str {
    r#"fragment PrFields on PullRequest {
  number title body
  author { login }
  headRefOid baseRefName
  files(first: 100) {
    nodes { path additions deletions changeType }
  }
  reviews(first: 100) {
    nodes { author { login } state submittedAt }
  }
  commits(first: 250) {
    nodes {
      commit {
        oid
        author { user { login } }
        committer { date }
        signature { isValid state }
      }
    }
  }
  statusChecks: commits(last: 1) {
    nodes {
      commit {
        statusCheckRollup {
          contexts(first: 100) {
            nodes {
              __typename
              ... on CheckRun {
                name status conclusion
                checkSuite { app { slug } }
              }
              ... on StatusContext {
                context state
              }
            }
          }
        }
      }
    }
  }
}"#
}

// -- Query builders --

fn single_pr_query(owner: &str, repo: &str, number: u32) -> String {
    let fragment = pr_fields_fragment();
    format!(
        r#"query {{
  repository(owner: "{owner}", name: "{repo}") {{
    pullRequest(number: {number}) {{ ...PrFields }}
  }}
}}
{fragment}"#
    )
}

fn batch_pr_query(owner: &str, repo: &str, numbers: &[u32]) -> String {
    let aliases: Vec<String> = numbers
        .iter()
        .enumerate()
        .map(|(i, n)| format!("    pr{i}: pullRequest(number: {n}) {{ ...PrFields }}"))
        .collect();

    let aliases_str = aliases.join("\n");
    let fragment = pr_fields_fragment();
    format!(
        r#"query {{
  repository(owner: "{owner}", name: "{repo}") {{
{aliases_str}
  }}
}}
{fragment}"#
    )
}

fn commit_prs_query(owner: &str, repo: &str, shas: &[&str]) -> String {
    let aliases: Vec<String> = shas
        .iter()
        .enumerate()
        .map(|(i, sha)| {
            format!(
                r#"    c{i}: object(expression: "{sha}") {{
      ... on Commit {{
        associatedPullRequests(first: 10) {{
          nodes {{ number mergedAt author {{ login }} }}
        }}
      }}
    }}"#
            )
        })
        .collect();

    format!(
        r#"query {{
  repository(owner: "{owner}", name: "{repo}") {{
{aliases}
  }}
}}"#,
        aliases = aliases.join("\n")
    )
}

// -- Conversion functions --

fn convert_pr(pr: GqlPullRequest) -> PrData {
    let metadata = PrMetadata {
        number: pr.number,
        title: pr.title,
        body: pr.body,
        user: pr.author.map(|a| PrUser { login: a.login }),
        head: PrHead {
            sha: pr.head_ref_oid,
        },
        base: PrBase {
            ref_name: pr.base_ref_name,
        },
    };

    let files = pr
        .files
        .map(|f| f.nodes)
        .unwrap_or_default()
        .into_iter()
        .map(|f| PrFile {
            filename: f.path,
            patch: None, // GraphQL does not expose patch content
            additions: f.additions,
            deletions: f.deletions,
            status: convert_change_type(&f.change_type),
        })
        .collect();

    let reviews = pr
        .reviews
        .map(|r| r.nodes)
        .unwrap_or_default()
        .into_iter()
        .map(|r| Review {
            user: PrUser {
                login: r.author.map(|a| a.login).unwrap_or_default(),
            },
            state: r.state,
            submitted_at: r.submitted_at,
        })
        .collect();

    let commits = pr
        .commits
        .map(|c| c.nodes)
        .unwrap_or_default()
        .into_iter()
        .map(convert_commit_node)
        .collect();

    let (check_runs, commit_statuses) =
        extract_status_checks(pr.status_checks.and_then(|sc| sc.nodes.into_iter().next()));

    PrData {
        metadata,
        files,
        reviews,
        commits,
        check_runs,
        commit_statuses,
    }
}

fn convert_commit_node(node: GqlPrCommitNode) -> PrCommit {
    let c = node.commit;
    PrCommit {
        sha: c.oid,
        commit: PrCommitInner {
            committer: c.committer.map(|ct| PrCommitAuthor { date: ct.date }),
            verification: Some(match c.signature {
                Some(sig) => CommitVerification {
                    verified: sig.is_valid,
                    reason: sig.state.to_lowercase(),
                },
                None => CommitVerification {
                    verified: false,
                    reason: "unsigned".to_string(),
                },
            }),
        },
        author: c
            .author
            .and_then(|a| a.user)
            .map(|u| PrUser { login: u.login }),
    }
}

fn convert_change_type(change_type: &str) -> String {
    match change_type {
        "ADDED" => "added",
        "DELETED" => "removed",
        "MODIFIED" => "modified",
        "RENAMED" => "renamed",
        "COPIED" => "copied",
        "CHANGED" => "changed",
        _ => "modified",
    }
    .to_string()
}

fn extract_status_checks(
    head_commit: Option<GqlStatusCheckNode>,
) -> (Vec<CheckRunItem>, Vec<CommitStatusItem>) {
    let mut check_runs = Vec::new();
    let mut statuses = Vec::new();

    let Some(node) = head_commit else {
        return (check_runs, statuses);
    };
    let Some(rollup) = node.commit.status_check_rollup else {
        return (check_runs, statuses);
    };

    for ctx in rollup.contexts.nodes {
        let typename = ctx.get("__typename").and_then(|v| v.as_str()).unwrap_or("");
        match typename {
            "CheckRun" => {
                check_runs.push(CheckRunItem {
                    name: ctx
                        .get("name")
                        .and_then(|v| v.as_str())
                        .unwrap_or("")
                        .to_string(),
                    status: ctx
                        .get("status")
                        .and_then(|v| v.as_str())
                        .unwrap_or("")
                        .to_lowercase(),
                    conclusion: ctx
                        .get("conclusion")
                        .and_then(|v| v.as_str())
                        .map(|s| s.to_lowercase()),
                    app: ctx
                        .get("checkSuite")
                        .and_then(|cs| cs.get("app"))
                        .and_then(|app| app.get("slug"))
                        .and_then(|s| s.as_str())
                        .map(|slug| CheckRunApp {
                            slug: slug.to_string(),
                        }),
                });
            }
            "StatusContext" => {
                statuses.push(CommitStatusItem {
                    context: ctx
                        .get("context")
                        .and_then(|v| v.as_str())
                        .unwrap_or("")
                        .to_string(),
                    state: ctx
                        .get("state")
                        .and_then(|v| v.as_str())
                        .unwrap_or("")
                        .to_lowercase(),
                });
            }
            _ => {}
        }
    }

    (check_runs, statuses)
}

fn check_errors(resp: &GqlResponse) -> Result<()> {
    if let Some(errors) = &resp.errors {
        if resp.data.is_none() {
            let msgs: Vec<&str> = errors.iter().map(|e| e.message.as_str()).collect();
            bail!("GraphQL errors: {}", msgs.join(", "));
        }
    }
    Ok(())
}

// -- Public API --

/// Fetch all data for a single PR in one GraphQL call.
pub fn fetch_pr(client: &GitHubClient, owner: &str, repo: &str, number: u32) -> Result<PrData> {
    let query = single_pr_query(owner, repo, number);
    let body = client.post_graphql(&query, None)?;

    let resp: GqlResponse =
        serde_json::from_str(&body).context("failed to parse GraphQL response")?;
    check_errors(&resp)?;

    let data = resp.data.context("no data in GraphQL response")?;
    let pr_value = data
        .get("repository")
        .and_then(|r| r.get("pullRequest"))
        .context("pullRequest not found in response")?;

    if pr_value.is_null() {
        bail!("PR #{number} not found");
    }

    let pr: GqlPullRequest =
        serde_json::from_value(pr_value.clone()).context("failed to deserialize pull request")?;

    Ok(convert_pr(pr))
}

/// Fetch data for multiple PRs in batched GraphQL calls (up to 20 PRs per query).
pub fn fetch_prs(
    client: &GitHubClient,
    owner: &str,
    repo: &str,
    numbers: &[u32],
) -> Vec<(u32, Result<PrData>)> {
    let mut results = Vec::new();

    for chunk in numbers.chunks(PR_BATCH_SIZE) {
        let query = batch_pr_query(owner, repo, chunk);
        match client.post_graphql(&query, None) {
            Err(e) => {
                let msg = format!("{e:#}");
                for &n in chunk {
                    results.push((n, Err(anyhow::anyhow!("GraphQL batch failed: {msg}"))));
                }
                continue;
            }
            Ok(body) => {
                let resp: GqlResponse = match serde_json::from_str(&body) {
                    Ok(r) => r,
                    Err(e) => {
                        let msg = format!("{e:#}");
                        for &n in chunk {
                            results
                                .push((n, Err(anyhow::anyhow!("failed to parse response: {msg}"))));
                        }
                        continue;
                    }
                };

                if resp.data.is_none() {
                    let msg = resp
                        .errors
                        .as_ref()
                        .map(|errs| {
                            errs.iter()
                                .map(|e| e.message.as_str())
                                .collect::<Vec<_>>()
                                .join(", ")
                        })
                        .unwrap_or_else(|| "unknown error".to_string());
                    for &n in chunk {
                        results.push((n, Err(anyhow::anyhow!("GraphQL error: {msg}"))));
                    }
                    continue;
                }

                let data = resp.data.unwrap();
                let repo_data = data.get("repository");

                for (i, &number) in chunk.iter().enumerate() {
                    let key = format!("pr{i}");
                    let pr_result = repo_data
                        .and_then(|r| r.get(&key))
                        .map(|v| {
                            if v.is_null() {
                                Err(anyhow::anyhow!("PR #{number} not found"))
                            } else {
                                serde_json::from_value::<GqlPullRequest>(v.clone())
                                    .map(convert_pr)
                                    .context("failed to parse PR data")
                            }
                        })
                        .unwrap_or_else(|| {
                            Err(anyhow::anyhow!("PR #{number} missing from response"))
                        });

                    results.push((number, pr_result));
                }
            }
        }
    }

    results
}

/// Resolve commits to their associated PRs in batched GraphQL calls.
pub fn resolve_commit_prs(
    client: &GitHubClient,
    owner: &str,
    repo: &str,
    shas: &[&str],
) -> Result<HashMap<String, Vec<PullRequestSummary>>> {
    let mut result = HashMap::new();

    for chunk in shas.chunks(COMMIT_PR_BATCH_SIZE) {
        let query = commit_prs_query(owner, repo, chunk);
        let body = client.post_graphql(&query, None)?;
        let resp: GqlResponse =
            serde_json::from_str(&body).context("failed to parse GraphQL response")?;
        check_errors(&resp)?;

        let data = resp.data.context("no data in GraphQL response")?;
        let repo_data = data.get("repository").context("repository not found")?;

        for (i, sha) in chunk.iter().enumerate() {
            let key = format!("c{i}");
            if let Some(obj) = repo_data.get(&key) {
                if !obj.is_null() {
                    if let Ok(commit) = serde_json::from_value::<GqlCommitWithPrs>(obj.clone()) {
                        let prs = commit
                            .associated_pull_requests
                            .nodes
                            .into_iter()
                            .map(|pr| PullRequestSummary {
                                number: pr.number,
                                merged_at: pr.merged_at,
                                user: PrUser {
                                    login: pr.author.map(|a| a.login).unwrap_or_default(),
                                },
                            })
                            .collect();
                        result.insert(sha.to_string(), prs);
                    }
                }
            }
        }
    }

    Ok(result)
}
