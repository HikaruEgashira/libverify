use std::collections::HashSet;

use libverify_core::evidence::{
    ApprovalDecision, ApprovalDisposition, ArtifactAttestation, AuthenticityEvidence,
    ChangeRequestId, ChangedAsset, EvidenceBundle, EvidenceGap, EvidenceState, GovernedChange,
    PromotionBatch, SourceRevision, WorkItemRef,
};

use libverify_core::evidence::{BuildPlatformEvidence, CheckConclusion, CheckRunEvidence};

use crate::types::{
    CheckRunItem, CombinedStatusResponse, CompareCommit, PrCommit, PrFile, PrMetadata,
    PullRequestSummary, Review,
};

/// Associates a commit SHA with the pull requests that introduced it.
pub struct GitHubCommitPullAssociation {
    pub commit_sha: String,
    pub pull_requests: Vec<PullRequestSummary>,
}

/// Builds an evidence bundle from a single pull request's metadata and reviews.
pub fn build_pull_request_bundle(
    repo: &str,
    pr_number: u32,
    pr_metadata: &PrMetadata,
    pr_files: &[PrFile],
    pr_reviews: &[Review],
    pr_commits: &[PrCommit],
) -> EvidenceBundle {
    EvidenceBundle {
        change_requests: vec![map_pull_request_evidence(
            repo,
            pr_number,
            pr_metadata,
            pr_files,
            pr_reviews,
            pr_commits,
        )],
        promotion_batches: Vec::new(),
        ..Default::default()
    }
}

/// Builds an evidence bundle from a release tag comparison and associated commits.
pub fn build_release_bundle(
    repo: &str,
    base_tag: &str,
    head_tag: &str,
    commits: &[CompareCommit],
    commit_pulls: &[GitHubCommitPullAssociation],
    artifact_attestations: EvidenceState<Vec<ArtifactAttestation>>,
) -> EvidenceBundle {
    EvidenceBundle {
        change_requests: Vec::new(),
        promotion_batches: vec![map_promotion_batch_evidence(
            repo,
            base_tag,
            head_tag,
            commits,
            commit_pulls,
        )],
        artifact_attestations,
        ..Default::default()
    }
}

/// Converts GitHub PR data into a platform-neutral `GovernedChange`.
pub fn map_pull_request_evidence(
    repo: &str,
    pr_number: u32,
    pr_metadata: &PrMetadata,
    pr_files: &[PrFile],
    pr_reviews: &[Review],
    pr_commits: &[PrCommit],
) -> GovernedChange {
    let changed_assets = map_changed_assets(pr_files);
    let approval_decisions = EvidenceState::complete(
        pr_reviews
            .iter()
            .map(|review| ApprovalDecision {
                actor: review.user.login.clone(),
                disposition: map_review_disposition(&review.state, review.body.as_deref()),
                submitted_at: review.submitted_at.clone(),
            })
            .collect(),
    );

    let source_revisions = EvidenceState::complete(
        pr_commits
            .iter()
            .map(|commit| SourceRevision {
                id: commit.sha.clone(),
                authored_by: commit.author.as_ref().map(|a| a.login.clone()),
                committed_at: commit
                    .commit
                    .committer
                    .as_ref()
                    .and_then(|committer| committer.date.clone()),
                merge: false,
                authenticity: match &commit.commit.verification {
                    Some(v) => EvidenceState::complete(AuthenticityEvidence::new(
                        v.verified,
                        Some(v.reason.clone()),
                    )),
                    None => EvidenceState::not_applicable(),
                },
            })
            .collect(),
    );

    let work_item_refs = EvidenceState::complete(
        libverify_core::linkage::extract_issue_references(
            pr_metadata.body.as_deref().unwrap_or(""),
            &[],
        )
        .into_iter()
        .map(|reference| WorkItemRef {
            system: map_issue_ref_kind(&reference.kind).to_string(),
            value: reference.value,
        })
        .collect(),
    );

    GovernedChange {
        id: ChangeRequestId::new("github_pr", format!("{repo}#{pr_number}")),
        title: pr_metadata.title.clone(),
        summary: pr_metadata.body.clone(),
        submitted_by: pr_metadata.user.as_ref().map(|u| u.login.clone()),
        changed_assets,
        approval_decisions,
        source_revisions,
        work_item_refs,
    }
}

/// Converts a GitHub tag comparison into a platform-neutral `PromotionBatch`.
pub fn map_promotion_batch_evidence(
    repo: &str,
    base_tag: &str,
    head_tag: &str,
    commits: &[CompareCommit],
    commit_pulls: &[GitHubCommitPullAssociation],
) -> PromotionBatch {
    let commit_shas: HashSet<&str> = commits.iter().map(|c| c.sha.as_str()).collect();
    let mut seen_prs = HashSet::new();
    let linked_change_requests: Vec<ChangeRequestId> = commit_pulls
        .iter()
        .filter(|assoc| commit_shas.contains(assoc.commit_sha.as_str()))
        .flat_map(|assoc| assoc.pull_requests.iter())
        .filter(|pr| seen_prs.insert(pr.number))
        .map(|pr| ChangeRequestId::new("github_pr", format!("{repo}#{}", pr.number)))
        .collect();

    PromotionBatch {
        id: format!("github_release:{repo}:{base_tag}..{head_tag}"),
        source_revisions: EvidenceState::complete(
            commits
                .iter()
                .map(|commit| SourceRevision {
                    id: commit.sha.clone(),
                    authored_by: commit.author.as_ref().map(|author| author.login.clone()),
                    committed_at: None,
                    merge: commit.parents.len() >= 2,
                    authenticity: EvidenceState::complete(AuthenticityEvidence::new(
                        commit.commit.verification.verified,
                        Some(commit.commit.verification.reason.clone()),
                    )),
                })
                .collect(),
        ),
        linked_change_requests: EvidenceState::complete(linked_change_requests),
    }
}

/// Maps GitHub check run items and combined commit statuses into platform-neutral evidence.
pub fn map_check_runs_evidence(
    check_runs: &[CheckRunItem],
    combined_status: Option<&CombinedStatusResponse>,
) -> Vec<CheckRunEvidence> {
    let mut evidence: Vec<CheckRunEvidence> = check_runs
        .iter()
        .map(|cr| CheckRunEvidence {
            name: cr.name.clone(),
            conclusion: map_check_run_conclusion(cr.status.as_str(), cr.conclusion.as_deref()),
            app_slug: cr.app.as_ref().map(|a| a.slug.clone()),
        })
        .collect();

    // Merge legacy commit statuses (reported via the Status API, not Check Runs API)
    if let Some(status_resp) = combined_status {
        for s in &status_resp.statuses {
            // Avoid duplicates if a check run already covers this context
            if evidence.iter().any(|e| e.name == s.context) {
                continue;
            }
            evidence.push(CheckRunEvidence {
                name: s.context.clone(),
                conclusion: map_commit_status_state(&s.state),
                app_slug: None,
            });
        }
    }

    evidence
}

fn map_check_run_conclusion(status: &str, conclusion: Option<&str>) -> CheckConclusion {
    if status != "completed" {
        return CheckConclusion::Pending;
    }
    match conclusion {
        Some("success") => CheckConclusion::Success,
        Some("failure") => CheckConclusion::Failure,
        Some("neutral") => CheckConclusion::Neutral,
        Some("cancelled") => CheckConclusion::Cancelled,
        Some("skipped") => CheckConclusion::Skipped,
        Some("timed_out") => CheckConclusion::TimedOut,
        Some("action_required") => CheckConclusion::ActionRequired,
        _ => CheckConclusion::Unknown,
    }
}

fn map_commit_status_state(state: &str) -> CheckConclusion {
    match state {
        "success" => CheckConclusion::Success,
        "failure" | "error" => CheckConclusion::Failure,
        "pending" => CheckConclusion::Pending,
        _ => CheckConclusion::Unknown,
    }
}

fn map_changed_assets(pr_files: &[PrFile]) -> EvidenceState<Vec<ChangedAsset>> {
    let assets: Vec<ChangedAsset> = pr_files
        .iter()
        .map(|file| ChangedAsset {
            path: file.filename.clone(),
            diff_available: file.patch.is_some(),
            additions: file.additions,
            deletions: file.deletions,
            status: file.status.clone(),
            diff: file.patch.clone(),
        })
        .collect();

    let gaps: Vec<EvidenceGap> = pr_files
        .iter()
        .filter(|file| file.patch.is_none())
        .map(|file| EvidenceGap::DiffUnavailable {
            subject: file.filename.clone(),
        })
        .collect();

    if gaps.is_empty() {
        EvidenceState::complete(assets)
    } else {
        EvidenceState::partial(assets, gaps)
    }
}

/// Maps a GitHub review state + body to an approval disposition.
///
/// Handles bot-mediated approvals (Prow, GitLab-style bots) where the review
/// state is `COMMENTED` but the body contains approval commands like `/lgtm`
/// or `/approve`. This is critical for Kubernetes, Istio, and other CNCF projects.
fn map_review_disposition(state: &str, body: Option<&str>) -> ApprovalDisposition {
    match state {
        "APPROVED" => ApprovalDisposition::Approved,
        "CHANGES_REQUESTED" => ApprovalDisposition::Rejected,
        "COMMENTED" => {
            if is_bot_approval_command(body) {
                ApprovalDisposition::Approved
            } else {
                ApprovalDisposition::Commented
            }
        }
        "DISMISSED" => ApprovalDisposition::Dismissed,
        _ => ApprovalDisposition::Unknown,
    }
}

/// Detects bot-mediated approval commands in review body text.
/// Recognizes Prow (`/lgtm`, `/approve`), GitLab (`/merge`), and similar patterns.
fn is_bot_approval_command(body: Option<&str>) -> bool {
    let Some(body) = body else { return false };
    // Check each line for approval commands (commands are line-start anchored)
    body.lines().any(|line| {
        let trimmed = line.trim();
        trimmed == "/lgtm"
            || trimmed == "/approve"
            || trimmed.starts_with("/lgtm ")
            || trimmed.starts_with("/approve ")
    })
}

/// Known hosted CI platforms and their isolation characteristics.
/// (hosted, ephemeral, isolated, signing_key_isolated)
fn classify_ci_platform(slug: &str) -> (bool, bool, bool, bool) {
    match slug {
        // Fully hosted + isolated platforms
        "github-actions" => (true, true, true, true),
        "cirrus-ci" => (true, true, true, false),
        "travis-ci" => (true, true, true, false),
        "azure-pipelines" => (true, true, true, false),
        "google-cloud-build" => (true, true, true, true),
        "aws-codebuild" => (true, true, true, false),
        "buildkite" => (true, true, true, false),

        // Hosted but not fully isolated (preview deploys, shared runners)
        "netlify" => (true, false, false, false),
        "vercel" => (true, false, false, false),
        "render" => (true, false, false, false),

        // Bot/meta platforms (not build platforms — treat as hosted to avoid FP)
        "prow" | "tide" => (true, true, true, false),
        "codecov" | "codspeed-hq" | "codecov-commenter" => (true, false, false, false),
        "sonarcloud" | "snyk" => (true, false, false, false),
        "dependabot" | "renovate" => (true, false, false, false),
        "buildomat" => (true, true, true, false),

        // Code scanning / security analysis (hosted SaaS)
        "github-advanced-security" => (true, true, true, false),

        // Package preview / deploy bots (hosted)
        "pkg-pr-new" => (true, false, false, false),

        // DCO (Developer Certificate of Origin) check
        "dco" => (true, false, false, false),

        // ReadTheDocs (documentation build)
        "readthedocs" => (true, false, false, false),

        // Enterprise GitHub Apps (Microsoft, etc.)
        "vs-code-engineering" | "microsoft-github-policy-service" => (true, false, false, false),

        // Unknown — if a check run was reported to GitHub, *something* hosted
        // ran it. Mark as hosted but not isolated (we cannot verify isolation).
        _ => (true, false, false, false),
    }
}

/// Maps check run evidence into build platform evidence.
///
/// Recognizes a wide range of hosted CI platforms beyond GitHub Actions,
/// including Cirrus CI, Buildkite, Netlify, Prow, Codecov, etc.
pub fn map_build_platform_evidence(check_runs: &[CheckRunEvidence]) -> Vec<BuildPlatformEvidence> {
    check_runs
        .iter()
        .filter(|cr| cr.conclusion != CheckConclusion::Pending)
        .map(|cr| {
            let slug = cr.app_slug.as_deref().unwrap_or("unknown");
            let (hosted, ephemeral, isolated, signing_key_isolated) = classify_ci_platform(slug);

            // Fallback: if app_slug is unknown, try to infer from check run name.
            // Prow check runs (pull-kubernetes-*, tide) have no app_slug.
            let (platform, hosted, ephemeral, isolated, signing_key_isolated) = if slug == "unknown"
            {
                let inferred = infer_platform_from_name(&cr.name);
                let (h, e, i, s) = classify_ci_platform(inferred);
                (inferred.to_string(), h, e, i, s)
            } else {
                (
                    slug.to_string(),
                    hosted,
                    ephemeral,
                    isolated,
                    signing_key_isolated,
                )
            };

            BuildPlatformEvidence {
                platform,
                hosted,
                ephemeral,
                isolated,
                runner_labels: vec![cr.app_slug.as_deref().unwrap_or("unknown").to_string()],
                signing_key_isolated,
            }
        })
        .collect()
}

/// Infer CI platform from check run name when app_slug is missing.
/// Common patterns: Prow jobs start with "pull-" or "ci-", Tide is k8s merge bot,
/// EasyCLA is a compliance check.
fn infer_platform_from_name(name: &str) -> &'static str {
    let lower = name.to_ascii_lowercase();
    // Prow (Kubernetes, CNCF): "pull-kubernetes-*", "ci-*", "tide"
    if lower.starts_with("pull-") || lower.starts_with("ci-") || lower == "tide" {
        return "prow";
    }
    // Bors (Rust, Servo): "Bors auto build", "bors try"
    if lower.starts_with("bors") {
        return "github-actions"; // bors runs via GitHub, treat as hosted
    }
    // CLA checks
    if lower.contains("easycla") || lower.contains("cla") {
        return "github-actions";
    }
    // Codecov/coverage reporting
    if lower.contains("codecov") || lower.contains("coverage") {
        return "codecov";
    }
    // Netlify (deploy previews reported as status checks without app_slug)
    if lower.contains("netlify") {
        return "netlify";
    }
    // Cirrus CI
    if lower.contains("cirrus") {
        return "cirrus-ci";
    }
    // Buildkite
    if lower.starts_with("buildkite/") || lower.contains("buildkite") {
        return "buildkite";
    }
    // ReadTheDocs
    if lower.contains("readthedocs") {
        return "readthedocs";
    }
    // External CI reported via GitHub Status API (Jenkins, Buildbot, etc.)
    // Pattern: "pull-requests-*", "pr-*" are common Jenkins job names
    if lower.starts_with("pull-requests-") || lower.starts_with("pr-") {
        return "github-actions"; // external CI, treat as hosted
    }
    // Vercel/preview deployments
    if lower.contains("preview deploy") || lower.contains("vercel") {
        return "vercel";
    }
    // Ecosystem CI (cross-project compatibility testing)
    if lower.contains("ecosystem-ci") {
        return "github-actions";
    }
    "unknown"
}

fn map_issue_ref_kind(kind: &libverify_core::linkage::IssueRefKind) -> &'static str {
    match kind {
        libverify_core::linkage::IssueRefKind::NumericIssue => "numeric_issue",
        libverify_core::linkage::IssueRefKind::ProjectTicket => "project_ticket",
        libverify_core::linkage::IssueRefKind::Url => "url",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{
        CommitParent, CommitVerification, CompareCommitInner, PrBase, PrCommitAuthor,
        PrCommitInner, PrHead, PrUser,
    };

    #[test]
    fn pull_request_mapping_marks_missing_patch_as_partial() {
        let evidence = map_pull_request_evidence(
            "owner/repo",
            42,
            &PrMetadata {
                number: 42,
                title: "feat: add abstraction layer".to_string(),
                body: Some("fixes #10".to_string()),
                user: Some(PrUser {
                    login: "author".to_string(),
                }),
                head: PrHead {
                    sha: "abc123".to_string(),
                },
                base: PrBase {
                    ref_name: "main".to_string(),
                },
            },
            &[PrFile {
                filename: "src/lib.rs".to_string(),
                patch: None,
                additions: 0,
                deletions: 0,
                status: "modified".to_string(),
            }],
            &[Review {
                user: PrUser {
                    login: "reviewer".to_string(),
                },
                state: "APPROVED".to_string(),
                submitted_at: Some("2026-03-15T00:00:00Z".to_string()),
                body: None,
            }],
            &[PrCommit {
                sha: "abc123".to_string(),
                commit: PrCommitInner {
                    committer: Some(PrCommitAuthor {
                        date: Some("2026-03-15T00:00:00Z".to_string()),
                    }),
                    verification: None,
                },
                author: Some(PrUser {
                    login: "author".to_string(),
                }),
            }],
        );

        assert!(matches!(
            evidence.changed_assets,
            EvidenceState::Partial { .. }
        ));
        assert!(matches!(
            evidence.source_revisions,
            EvidenceState::Complete { .. }
        ));
    }

    #[test]
    fn promotion_batch_mapping_preserves_signature_state() {
        let batch = map_promotion_batch_evidence(
            "owner/repo",
            "v0.1.0",
            "v0.2.0",
            &[CompareCommit {
                sha: "deadbeef".to_string(),
                commit: CompareCommitInner {
                    message: "feat: ship control layer".to_string(),
                    verification: CommitVerification {
                        verified: false,
                        reason: "unsigned".to_string(),
                    },
                },
                author: None,
                parents: vec![CommitParent {
                    sha: "parent".to_string(),
                }],
            }],
            &[GitHubCommitPullAssociation {
                commit_sha: "deadbeef".to_string(),
                pull_requests: vec![],
            }],
        );

        let revisions = match &batch.source_revisions {
            EvidenceState::Complete { value } => value,
            _ => panic!("source revisions should be complete"),
        };
        assert_eq!(revisions.len(), 1);
        assert!(matches!(
            revisions[0].authenticity,
            EvidenceState::Complete { .. }
        ));
    }

    #[test]
    fn promotion_batch_filters_unrelated_commits_and_deduplicates_prs() {
        let commits = vec![CompareCommit {
            sha: "aaa111".to_string(),
            commit: CompareCommitInner {
                message: "feat: in-range commit".to_string(),
                verification: CommitVerification {
                    verified: true,
                    reason: "valid".to_string(),
                },
            },
            author: None,
            parents: vec![],
        }];

        let commit_pulls = vec![
            GitHubCommitPullAssociation {
                commit_sha: "aaa111".to_string(),
                pull_requests: vec![PullRequestSummary {
                    number: 1,
                    merged_at: Some("2026-03-15T00:00:00Z".to_string()),
                    user: PrUser {
                        login: "dev".to_string(),
                    },
                }],
            },
            GitHubCommitPullAssociation {
                commit_sha: "bbb222".to_string(),
                pull_requests: vec![PullRequestSummary {
                    number: 99,
                    merged_at: Some("2026-03-15T00:00:00Z".to_string()),
                    user: PrUser {
                        login: "other".to_string(),
                    },
                }],
            },
            GitHubCommitPullAssociation {
                commit_sha: "aaa111".to_string(),
                pull_requests: vec![PullRequestSummary {
                    number: 1,
                    merged_at: Some("2026-03-15T00:00:00Z".to_string()),
                    user: PrUser {
                        login: "dev".to_string(),
                    },
                }],
            },
        ];

        let batch =
            map_promotion_batch_evidence("owner/repo", "v0.1.0", "v0.2.0", &commits, &commit_pulls);

        let crs = match &batch.linked_change_requests {
            EvidenceState::Complete { value } => value,
            _ => panic!("linked_change_requests should be complete"),
        };
        assert_eq!(crs.len(), 1, "expected exactly 1 CR after filter+dedup");
        assert_eq!(crs[0].value, "owner/repo#1");
    }

    #[test]
    fn pull_request_bundle_uses_new_evidence_entrypoint() {
        let bundle = build_pull_request_bundle(
            "owner/repo",
            42,
            &PrMetadata {
                number: 42,
                title: "feat: add abstraction layer".to_string(),
                body: Some("fixes #10".to_string()),
                user: Some(PrUser {
                    login: "author".to_string(),
                }),
                head: PrHead {
                    sha: "abc123".to_string(),
                },
                base: PrBase {
                    ref_name: "main".to_string(),
                },
            },
            &[],
            &[],
            &[],
        );

        assert_eq!(bundle.change_requests.len(), 1);
        assert!(bundle.promotion_batches.is_empty());
    }

    #[test]
    fn submitted_by_populated_from_pr_user() {
        let evidence = map_pull_request_evidence(
            "owner/repo",
            1,
            &PrMetadata {
                number: 1,
                title: "feat: wire user".to_string(),
                body: None,
                user: Some(PrUser {
                    login: "octocat".to_string(),
                }),
                head: PrHead {
                    sha: "def456".to_string(),
                },
                base: PrBase {
                    ref_name: "main".to_string(),
                },
            },
            &[],
            &[],
            &[],
        );

        assert_eq!(evidence.submitted_by, Some("octocat".to_string()));
    }

    #[test]
    fn submitted_by_none_when_user_absent() {
        let evidence = map_pull_request_evidence(
            "owner/repo",
            1,
            &PrMetadata {
                number: 1,
                title: "feat: anonymous".to_string(),
                body: None,
                user: None,
                head: PrHead {
                    sha: "ghi789".to_string(),
                },
                base: PrBase {
                    ref_name: "main".to_string(),
                },
            },
            &[],
            &[],
            &[],
        );

        assert_eq!(evidence.submitted_by, None);
    }

    #[test]
    fn release_bundle_includes_artifact_attestations() {
        let attestations =
            EvidenceState::complete(vec![libverify_core::evidence::ArtifactAttestation {
                subject: "binary-linux-amd64".to_string(),
                subject_digest: None,
                predicate_type: "https://slsa.dev/provenance/v1".to_string(),
                signer_workflow: Some(".github/workflows/release.yml".to_string()),
                source_repo: Some("owner/repo".to_string()),
                verification: libverify_core::evidence::VerificationOutcome::Verified,
            }]);

        let bundle = build_release_bundle(
            "owner/repo",
            "v0.1.0",
            "v0.2.0",
            &[CompareCommit {
                sha: "abc123".to_string(),
                commit: CompareCommitInner {
                    message: "feat: ship".to_string(),
                    verification: CommitVerification {
                        verified: true,
                        reason: "valid".to_string(),
                    },
                },
                author: None,
                parents: vec![],
            }],
            &[],
            attestations,
        );

        match &bundle.artifact_attestations {
            EvidenceState::Complete { value } => {
                assert_eq!(value.len(), 1);
                assert!(value[0].verification.is_verified());
                assert_eq!(value[0].subject, "binary-linux-amd64");
            }
            other => panic!("expected Complete, got {other:?}"),
        }
    }

    #[test]
    fn release_bundle_not_applicable_without_attestations() {
        let bundle = build_release_bundle(
            "owner/repo",
            "v0.1.0",
            "v0.2.0",
            &[CompareCommit {
                sha: "abc123".to_string(),
                commit: CompareCommitInner {
                    message: "feat: ship".to_string(),
                    verification: CommitVerification {
                        verified: true,
                        reason: "valid".to_string(),
                    },
                },
                author: None,
                parents: vec![],
            }],
            &[],
            EvidenceState::not_applicable(),
        );

        assert!(matches!(
            bundle.artifact_attestations,
            EvidenceState::NotApplicable
        ));
    }

    #[test]
    fn prow_lgtm_comment_treated_as_approval() {
        let disposition = map_review_disposition("COMMENTED", Some("/lgtm\n/approve"));
        assert_eq!(disposition, ApprovalDisposition::Approved);
    }

    #[test]
    fn prow_lgtm_with_text_treated_as_approval() {
        let disposition = map_review_disposition("COMMENTED", Some("/lgtm looks good"));
        assert_eq!(disposition, ApprovalDisposition::Approved);
    }

    #[test]
    fn plain_comment_stays_commented() {
        let disposition =
            map_review_disposition("COMMENTED", Some("this looks good, but needs a fix"));
        assert_eq!(disposition, ApprovalDisposition::Commented);
    }

    #[test]
    fn approved_state_unchanged() {
        let disposition = map_review_disposition("APPROVED", None);
        assert_eq!(disposition, ApprovalDisposition::Approved);
    }

    #[test]
    fn empty_body_stays_commented() {
        let disposition = map_review_disposition("COMMENTED", None);
        assert_eq!(disposition, ApprovalDisposition::Commented);
    }
}
