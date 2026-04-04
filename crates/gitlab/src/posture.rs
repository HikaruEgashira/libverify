//! Repository posture evidence collection for GitLab projects.
//!
//! Collects project-level security configuration signals:
//! CODEOWNERS, SECURITY.md, branch protection, tag protection,
//! and member access levels.

use libverify_core::evidence::{CodeownersEntry, EvidenceGap, EvidenceState, RepositoryPosture};

use crate::client::GitLabClient;
use crate::types::{ProjectMember, ProtectedBranch, ProtectedTag};

/// Candidate paths for the CODEOWNERS file (GitLab resolves in this order).
const CODEOWNERS_PATHS: &[&str] = &["CODEOWNERS", "docs/CODEOWNERS", ".gitlab/CODEOWNERS"];

/// Candidate paths for the security policy file.
const SECURITY_POLICY_PATHS: &[&str] = &["SECURITY.md", "docs/SECURITY.md", ".gitlab/SECURITY.md"];

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

/// Collect repository posture evidence from the GitLab API.
///
/// Fetches CODEOWNERS, SECURITY.md, branch/tag protection, and member counts.
/// Falls back to `EvidenceState::Partial` when some data could not be collected.
pub fn collect_repository_posture(
    client: &GitLabClient,
    owner: &str,
    repo: &str,
    reference: &str,
) -> EvidenceState<RepositoryPosture> {
    let project = GitLabClient::encode_project(owner, repo);
    let mut gaps = Vec::new();

    // Run independent API calls concurrently using scoped threads.
    let (codeowners_entries, security_policy, branch_protection, tag_protection, members) =
        std::thread::scope(|s| {
            let h_codeowners = s.spawn(|| collect_codeowners(client, &project, reference));
            let h_security = s.spawn(|| collect_security_policy(client, &project, reference));
            let h_branch = s.spawn(|| collect_branch_protection(client, &project));
            let h_tag = s.spawn(|| collect_tag_protection(client, &project));
            let h_members = s.spawn(|| collect_members(client, &project));

            (
                h_codeowners.join().unwrap(),
                h_security.join().unwrap(),
                h_branch.join().unwrap(),
                h_tag.join().unwrap(),
                h_members.join().unwrap(),
            )
        });

    let (security_policy_present, security_policy_has_disclosure) = security_policy;

    let default_branch_protected = match branch_protection {
        Ok(protected) => protected,
        Err(e) => {
            gaps.push(EvidenceGap::CollectionFailed {
                source: "gitlab".to_string(),
                subject: "branch protection".to_string(),
                detail: format!("{e:#}"),
            });
            false
        }
    };

    let tag_protection_enabled = match tag_protection {
        Ok(enabled) => enabled,
        Err(e) => {
            gaps.push(EvidenceGap::CollectionFailed {
                source: "gitlab".to_string(),
                subject: "tag protection".to_string(),
                detail: format!("{e:#}"),
            });
            false
        }
    };

    let (admin_count, direct_collaborator_count) = match members {
        Ok((admins, maintainers)) => (admins, maintainers),
        Err(e) => {
            gaps.push(EvidenceGap::CollectionFailed {
                source: "gitlab".to_string(),
                subject: "project members".to_string(),
                detail: format!("{e:#}"),
            });
            (0, 0)
        }
    };

    let posture = RepositoryPosture {
        codeowners_entries,
        security_policy_present,
        security_policy_has_disclosure,
        default_branch_protected,
        tag_protection_enabled,
        admin_count,
        direct_collaborator_count,
        // GitLab-specific: these features don't have direct API equivalents
        // or require different API calls not yet implemented.
        security_analysis_available: false,
        secret_scanning_enabled: false,
        secret_push_protection_enabled: false,
        vulnerability_scanning_enabled: false,
        code_scanning_enabled: false,
        default_workflow_permissions: String::new(),
        unpinned_action_refs: Vec::new(),
        privileged_workflows: Vec::new(),
        release_has_sbom: false,
        release_assets_attested: false,
        ..Default::default()
    };

    if gaps.is_empty() {
        EvidenceState::complete(posture)
    } else {
        EvidenceState::partial(posture, gaps)
    }
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

/// Parse CODEOWNERS file content into entries.
fn collect_codeowners(client: &GitLabClient, project: &str, ref_sha: &str) -> Vec<CodeownersEntry> {
    for path in CODEOWNERS_PATHS {
        if let Ok(content) = client.get_file_content(project, path, ref_sha) {
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
fn collect_security_policy(client: &GitLabClient, project: &str, ref_sha: &str) -> (bool, bool) {
    for path in SECURITY_POLICY_PATHS {
        if let Ok(content) = client.get_file_content(project, path, ref_sha) {
            let lower = content.to_lowercase();
            let has_disclosure = DISCLOSURE_KEYWORDS.iter().any(|kw| lower.contains(kw));
            return (true, has_disclosure);
        }
    }
    (false, false)
}

/// Check if the default branch is listed among protected branches.
fn collect_branch_protection(client: &GitLabClient, project: &str) -> anyhow::Result<bool> {
    let branches: Vec<ProtectedBranch> =
        client.get_json(&format!("/projects/{project}/protected_branches"))?;
    // Consider the default branch protected if any protected branch rule
    // matches common default branch names.
    Ok(branches
        .iter()
        .any(|b| b.name == "main" || b.name == "master" || b.name == "*"))
}

/// Check whether tag protection rules exist.
fn collect_tag_protection(client: &GitLabClient, project: &str) -> anyhow::Result<bool> {
    let tags: Vec<ProtectedTag> =
        client.get_json(&format!("/projects/{project}/protected_tags"))?;
    Ok(!tags.is_empty())
}

/// Count members by access level.
/// Returns (admin_count, direct_collaborator_count).
/// GitLab access levels: 50 = Owner, 40 = Maintainer, 30 = Developer.
fn collect_members(client: &GitLabClient, project: &str) -> anyhow::Result<(u32, u32)> {
    let members: Vec<ProjectMember> = client.paginate(&format!("/projects/{project}/members"))?;
    let admin_count = members.iter().filter(|m| m.access_level >= 50).count() as u32;
    let maintainer_plus = members.iter().filter(|m| m.access_level >= 40).count() as u32;
    Ok((admin_count, maintainer_plus))
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
