use std::collections::HashSet;

use anyhow::{Context, Result, bail};

use crate::client::GitHubClient;
use crate::{graphql, pr_api, release_api};

/// Specification for a range of PRs to verify.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RangeSpec {
    /// `#100..#200` -- PR numbers in a range
    PrRange { start: u32, end: u32 },
    /// `SHA..SHA` or `TAG..TAG` -- commits between two refs
    RefRange { base: String, head: String },
    /// `2024-01-01..2024-02-01` -- PRs merged within a date window
    DateRange { since: String, until: String },
}

/// Try to parse a range specification from a CLI argument.
/// Returns `None` if the argument is not a range (e.g., a plain PR number).
pub fn parse_range(arg: &str) -> Option<RangeSpec> {
    let sep_idx = arg.find("..")?;
    let left = &arg[..sep_idx];
    let right = &arg[sep_idx + 2..];

    if left.is_empty() || right.is_empty() {
        return None;
    }

    // #N..#M -- PR number range
    if let (Some(l), Some(r)) = (left.strip_prefix('#'), right.strip_prefix('#')) {
        if let (Ok(start), Ok(end)) = (l.parse::<u32>(), r.parse::<u32>()) {
            return Some(RangeSpec::PrRange { start, end });
        }
    }

    // YYYY-MM-DD..YYYY-MM-DD -- date range
    if is_date(left) && is_date(right) {
        return Some(RangeSpec::DateRange {
            since: left.to_string(),
            until: right.to_string(),
        });
    }

    // Fallback: ref range (SHA or tag)
    Some(RangeSpec::RefRange {
        base: left.to_string(),
        head: right.to_string(),
    })
}

fn is_date(s: &str) -> bool {
    let bytes = s.as_bytes();
    bytes.len() == 10
        && bytes[4] == b'-'
        && bytes[7] == b'-'
        && bytes[..4].iter().all(|b| b.is_ascii_digit())
        && bytes[5..7].iter().all(|b| b.is_ascii_digit())
        && bytes[8..10].iter().all(|b| b.is_ascii_digit())
}

/// Resolve a range specification into a list of merged PR numbers.
pub fn resolve_pr_numbers(
    spec: &RangeSpec,
    client: &GitHubClient,
    owner: &str,
    repo: &str,
) -> Result<Vec<u32>> {
    match spec {
        RangeSpec::PrRange { start, end } => {
            pr_api::search_merged_prs_in_range(client, owner, repo, *start, *end)
        }
        RangeSpec::RefRange { base, head } => {
            let commits = release_api::compare_refs(client, owner, repo, base, head)
                .context("failed to compare refs")?;

            if commits.len() >= 250 {
                eprintln!(
                    "Warning: GitHub API returned {} commits (max 250). Some PRs may be missing.",
                    commits.len()
                );
            }

            let shas: Vec<&str> = commits.iter().map(|c| c.sha.as_str()).collect();
            let commit_pr_map = graphql::resolve_commit_prs(client, owner, repo, &shas)
                .unwrap_or_else(|err| {
                    eprintln!("Warning: failed to resolve commit PRs via GraphQL: {err}");
                    std::collections::HashMap::new()
                });

            let mut pr_numbers = HashSet::new();
            for prs in commit_pr_map.values() {
                for pr in prs {
                    if pr.merged_at.is_some() {
                        pr_numbers.insert(pr.number);
                    }
                }
            }

            let mut sorted: Vec<u32> = pr_numbers.into_iter().collect();
            sorted.sort_unstable();
            Ok(sorted)
        }
        RangeSpec::DateRange { since, until } => {
            pr_api::search_merged_prs(client, owner, repo, since, until)
        }
    }
}

/// Parse a release argument into (base_tag, head_tag).
///
/// If the argument contains `..`, it is treated as an explicit range.
/// Otherwise, the previous tag is detected automatically.
pub fn parse_release_arg(
    arg: &str,
    client: &GitHubClient,
    owner: &str,
    repo: &str,
) -> Result<(String, String)> {
    if let Some(sep_idx) = arg.find("..") {
        let base = arg[..sep_idx].to_string();
        let head = arg[sep_idx + 2..].to_string();
        return Ok((base, head));
    }

    let head_tag = arg.to_string();
    let tags = release_api::get_tags(client, owner, repo)?;

    for (idx, t) in tags.iter().enumerate() {
        if t.name == head_tag {
            if idx + 1 < tags.len() {
                return Ok((tags[idx + 1].name.clone(), head_tag));
            } else {
                bail!("no previous tag found before {head_tag}");
            }
        }
    }
    bail!("tag not found: {head_tag}");
}

/// Detect the latest release tag from repository tags.
pub fn detect_latest_release_tag(
    client: &GitHubClient,
    owner: &str,
    repo: &str,
) -> Result<String> {
    let tags = release_api::get_tags(client, owner, repo)?;
    tags.into_iter()
        .next()
        .map(|t| t.name)
        .context("no tags found in repository")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_pr_range() {
        assert_eq!(
            parse_range("#100..#200"),
            Some(RangeSpec::PrRange {
                start: 100,
                end: 200
            })
        );
    }

    #[test]
    fn parse_date_range() {
        assert_eq!(
            parse_range("2024-01-01..2024-06-01"),
            Some(RangeSpec::DateRange {
                since: "2024-01-01".to_string(),
                until: "2024-06-01".to_string()
            })
        );
    }

    #[test]
    fn parse_ref_range_tags() {
        assert_eq!(
            parse_range("v1.0..v2.0"),
            Some(RangeSpec::RefRange {
                base: "v1.0".to_string(),
                head: "v2.0".to_string()
            })
        );
    }

    #[test]
    fn parse_ref_range_shas() {
        assert_eq!(
            parse_range("abc123..def456"),
            Some(RangeSpec::RefRange {
                base: "abc123".to_string(),
                head: "def456".to_string()
            })
        );
    }

    #[test]
    fn parse_single_number_returns_none() {
        assert_eq!(parse_range("42"), None);
    }

    #[test]
    fn parse_empty_sides_returns_none() {
        assert_eq!(parse_range(".."), None);
        assert_eq!(parse_range("abc.."), None);
        assert_eq!(parse_range("..abc"), None);
    }

    #[test]
    fn is_date_valid() {
        assert!(is_date("2024-01-01"));
        assert!(is_date("2024-12-31"));
    }

    #[test]
    fn is_date_invalid() {
        assert!(!is_date("2024-1-1"));
        assert!(!is_date("not-a-date"));
        assert!(!is_date("20240101"));
    }
}
