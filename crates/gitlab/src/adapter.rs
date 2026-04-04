use std::collections::HashSet;

use libverify_core::evidence::{
    ApprovalDecision, ApprovalDisposition, BuildPlatformEvidence, ChangeRequestId, ChangedAsset,
    CheckConclusion, CheckRunEvidence, EvidenceBundle, EvidenceGap, EvidenceState, GovernedChange,
    PromotionBatch, SourceRevision, WorkItemRef,
};

use crate::types::{
    CompareCommit, MrApprovals, MrChange, MrCommit, MrMetadata, PipelineJob,
};

/// Maps a GitLab merge request to a platform-neutral `GovernedChange`.
pub fn map_merge_request_evidence(
    repo: &str,
    mr: &MrMetadata,
    changes: &[MrChange],
    approvals: &MrApprovals,
    commits: &[MrCommit],
) -> GovernedChange {
    let changed_assets = map_changed_assets(changes);

    let approval_decisions = EvidenceState::complete(
        approvals
            .approved_by
            .iter()
            .map(|entry| ApprovalDecision {
                actor: entry.user.username.clone(),
                disposition: ApprovalDisposition::Approved,
                submitted_at: None,
            })
            .collect(),
    );

    let source_revisions = EvidenceState::complete(
        commits
            .iter()
            .map(|commit| SourceRevision {
                id: commit.id.clone(),
                authored_by: Some(commit.author_name.clone()),
                committed_at: commit.authored_date.clone(),
                merge: commit.parent_ids.len() >= 2,
                authenticity: EvidenceState::not_applicable(),
            })
            .collect(),
    );

    let description = mr.description.as_deref().unwrap_or("");
    let work_item_refs = EvidenceState::complete(
        libverify_core::linkage::extract_issue_references(description, &[])
            .into_iter()
            .map(|reference| WorkItemRef {
                system: map_issue_ref_kind(&reference.kind).to_string(),
                value: reference.value,
            })
            .collect(),
    );

    GovernedChange {
        id: ChangeRequestId::new("gitlab_mr", format!("{repo}!{}", mr.iid)),
        title: mr.title.clone(),
        summary: mr.description.clone(),
        submitted_by: mr.author.as_ref().map(|a| a.username.clone()),
        changed_assets,
        approval_decisions,
        source_revisions,
        work_item_refs,
    }
}

/// Maps GitLab pipeline jobs to platform-neutral check run evidence.
pub fn map_pipeline_jobs_evidence(jobs: &[PipelineJob]) -> Vec<CheckRunEvidence> {
    jobs.iter()
        .map(|job| CheckRunEvidence {
            name: job.name.clone(),
            conclusion: map_job_conclusion(&job.status),
            app_slug: Some("gitlab-ci".to_string()),
        })
        .collect()
}

/// Maps check run evidence to build platform evidence for GitLab CI.
pub fn map_build_platform_evidence(check_runs: &[CheckRunEvidence]) -> Vec<BuildPlatformEvidence> {
    check_runs
        .iter()
        .filter(|cr| cr.conclusion != CheckConclusion::Pending)
        .map(|cr| BuildPlatformEvidence {
            platform: "gitlab-ci".to_string(),
            hosted: true,
            ephemeral: true,
            isolated: true,
            runner_labels: vec![cr.app_slug.as_deref().unwrap_or("gitlab-ci").to_string()],
            signing_key_isolated: false,
        })
        .collect()
}

/// Construct an evidence bundle from a single merge request's data.
pub fn build_merge_request_bundle(
    repo: &str,
    mr: &MrMetadata,
    changes: &[MrChange],
    approvals: &MrApprovals,
    commits: &[MrCommit],
) -> EvidenceBundle {
    EvidenceBundle {
        change_requests: vec![map_merge_request_evidence(
            repo, mr, changes, approvals, commits,
        )],
        promotion_batches: Vec::new(),
        ..Default::default()
    }
}

/// Construct an evidence bundle for release verification with promotion batches.
pub fn build_release_bundle(
    repo: &str,
    base_tag: &str,
    head_tag: &str,
    commits: &[CompareCommit],
    commit_mr_iids: &[(String, Vec<u32>)],
) -> EvidenceBundle {
    let commit_shas: HashSet<&str> = commits.iter().map(|c| c.id.as_str()).collect();
    let mut seen_mrs = HashSet::new();
    let linked_change_requests: Vec<ChangeRequestId> = commit_mr_iids
        .iter()
        .filter(|(sha, _)| commit_shas.contains(sha.as_str()))
        .flat_map(|(_, iids)| iids.iter())
        .filter(|iid| seen_mrs.insert(**iid))
        .map(|iid| ChangeRequestId::new("gitlab_mr", format!("{repo}!{iid}")))
        .collect();

    let batch = PromotionBatch {
        id: format!("gitlab_release:{repo}:{base_tag}..{head_tag}"),
        source_revisions: EvidenceState::complete(
            commits
                .iter()
                .map(|commit| SourceRevision {
                    id: commit.id.clone(),
                    authored_by: Some(commit.author_name.clone()),
                    committed_at: None,
                    merge: commit.parent_ids.len() >= 2,
                    authenticity: EvidenceState::not_applicable(),
                })
                .collect(),
        ),
        linked_change_requests: EvidenceState::complete(linked_change_requests),
    };

    EvidenceBundle {
        change_requests: Vec::new(),
        promotion_batches: vec![batch],
        ..Default::default()
    }
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

fn map_changed_assets(changes: &[MrChange]) -> EvidenceState<Vec<ChangedAsset>> {
    let assets: Vec<ChangedAsset> = changes
        .iter()
        .map(|change| {
            let status = if change.new_file {
                "added"
            } else if change.deleted_file {
                "removed"
            } else if change.renamed_file {
                "renamed"
            } else {
                "modified"
            };

            ChangedAsset {
                path: change.new_path.clone(),
                diff_available: change.diff.is_some(),
                additions: 0,
                deletions: 0,
                status: status.to_string(),
                diff: change.diff.clone(),
            }
        })
        .collect();

    let gaps: Vec<EvidenceGap> = changes
        .iter()
        .filter(|c| c.diff.is_none())
        .map(|c| EvidenceGap::DiffUnavailable {
            subject: c.new_path.clone(),
        })
        .collect();

    if gaps.is_empty() {
        EvidenceState::complete(assets)
    } else {
        EvidenceState::partial(assets, gaps)
    }
}

fn map_job_conclusion(status: &str) -> CheckConclusion {
    match status {
        "success" => CheckConclusion::Success,
        "failed" => CheckConclusion::Failure,
        "canceled" => CheckConclusion::Cancelled,
        "skipped" => CheckConclusion::Skipped,
        "pending" | "running" => CheckConclusion::Pending,
        _ => CheckConclusion::Unknown,
    }
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
    use crate::types::{ApprovalEntry, MrAuthor};

    fn sample_mr() -> MrMetadata {
        MrMetadata {
            iid: 42,
            title: "feat: add GitLab adapter".to_string(),
            description: Some("Closes #10\nRelated to PROJ-123".to_string()),
            author: Some(MrAuthor {
                username: "dev".to_string(),
            }),
            sha: "abc123".to_string(),
            target_branch: "main".to_string(),
            source_branch: "feature/gitlab".to_string(),
        }
    }

    fn sample_changes() -> Vec<MrChange> {
        vec![
            MrChange {
                old_path: "src/lib.rs".to_string(),
                new_path: "src/lib.rs".to_string(),
                diff: Some("@@ -1 +1,2 @@\n+use foo;".to_string()),
                new_file: false,
                renamed_file: false,
                deleted_file: false,
            },
            MrChange {
                old_path: "src/new.rs".to_string(),
                new_path: "src/new.rs".to_string(),
                diff: None,
                new_file: true,
                renamed_file: false,
                deleted_file: false,
            },
        ]
    }

    fn sample_approvals() -> MrApprovals {
        MrApprovals {
            approved_by: vec![ApprovalEntry {
                user: MrAuthor {
                    username: "reviewer".to_string(),
                },
            }],
        }
    }

    fn sample_commits() -> Vec<MrCommit> {
        vec![MrCommit {
            id: "abc123".to_string(),
            author_name: "dev".to_string(),
            authored_date: Some("2026-04-01T00:00:00Z".to_string()),
            parent_ids: vec!["parent1".to_string()],
        }]
    }

    #[test]
    fn merge_request_mapping_basic() {
        let evidence = map_merge_request_evidence(
            "owner/repo",
            &sample_mr(),
            &sample_changes(),
            &sample_approvals(),
            &sample_commits(),
        );

        assert_eq!(evidence.id.system, "gitlab_mr");
        assert_eq!(evidence.id.value, "owner/repo!42");
        assert_eq!(evidence.title, "feat: add GitLab adapter");
        assert_eq!(evidence.submitted_by, Some("dev".to_string()));
    }

    #[test]
    fn merge_request_missing_diff_produces_partial() {
        let evidence = map_merge_request_evidence(
            "owner/repo",
            &sample_mr(),
            &sample_changes(),
            &sample_approvals(),
            &sample_commits(),
        );

        // Second change has no diff
        assert!(matches!(
            evidence.changed_assets,
            EvidenceState::Partial { .. }
        ));
    }

    #[test]
    fn changed_asset_status_mapping() {
        let changes = vec![
            MrChange {
                old_path: "a.rs".to_string(),
                new_path: "a.rs".to_string(),
                diff: Some(String::new()),
                new_file: true,
                renamed_file: false,
                deleted_file: false,
            },
            MrChange {
                old_path: "b.rs".to_string(),
                new_path: "b.rs".to_string(),
                diff: Some(String::new()),
                new_file: false,
                renamed_file: false,
                deleted_file: true,
            },
            MrChange {
                old_path: "c.rs".to_string(),
                new_path: "d.rs".to_string(),
                diff: Some(String::new()),
                new_file: false,
                renamed_file: true,
                deleted_file: false,
            },
            MrChange {
                old_path: "e.rs".to_string(),
                new_path: "e.rs".to_string(),
                diff: Some(String::new()),
                new_file: false,
                renamed_file: false,
                deleted_file: false,
            },
        ];

        if let EvidenceState::Complete { value } = map_changed_assets(&changes) {
            assert_eq!(value[0].status, "added");
            assert_eq!(value[1].status, "removed");
            assert_eq!(value[2].status, "renamed");
            assert_eq!(value[3].status, "modified");
        } else {
            panic!("expected Complete");
        }
    }

    #[test]
    fn approval_decisions_mapped() {
        let evidence = map_merge_request_evidence(
            "owner/repo",
            &sample_mr(),
            &[],
            &sample_approvals(),
            &[],
        );

        if let EvidenceState::Complete { value } = &evidence.approval_decisions {
            assert_eq!(value.len(), 1);
            assert_eq!(value[0].actor, "reviewer");
            assert_eq!(value[0].disposition, ApprovalDisposition::Approved);
            assert!(value[0].submitted_at.is_none());
        } else {
            panic!("expected Complete");
        }
    }

    #[test]
    fn source_revisions_merge_detection() {
        let commits = vec![
            MrCommit {
                id: "single".to_string(),
                author_name: "dev".to_string(),
                authored_date: None,
                parent_ids: vec!["p1".to_string()],
            },
            MrCommit {
                id: "merge".to_string(),
                author_name: "dev".to_string(),
                authored_date: None,
                parent_ids: vec!["p1".to_string(), "p2".to_string()],
            },
        ];

        let evidence = map_merge_request_evidence(
            "owner/repo",
            &sample_mr(),
            &[],
            &MrApprovals {
                approved_by: vec![],
            },
            &commits,
        );

        if let EvidenceState::Complete { value } = &evidence.source_revisions {
            assert!(!value[0].merge);
            assert!(value[1].merge);
        } else {
            panic!("expected Complete");
        }
    }

    #[test]
    fn work_item_refs_extracted() {
        let evidence = map_merge_request_evidence(
            "owner/repo",
            &sample_mr(),
            &[],
            &MrApprovals {
                approved_by: vec![],
            },
            &[],
        );

        if let EvidenceState::Complete { value } = &evidence.work_item_refs {
            assert!(!value.is_empty(), "should extract issue references from description");
        } else {
            panic!("expected Complete");
        }
    }

    #[test]
    fn pipeline_jobs_mapping() {
        let jobs = vec![
            PipelineJob {
                name: "build".to_string(),
                status: "success".to_string(),
            },
            PipelineJob {
                name: "test".to_string(),
                status: "failed".to_string(),
            },
            PipelineJob {
                name: "lint".to_string(),
                status: "canceled".to_string(),
            },
            PipelineJob {
                name: "deploy".to_string(),
                status: "skipped".to_string(),
            },
            PipelineJob {
                name: "pending-job".to_string(),
                status: "pending".to_string(),
            },
            PipelineJob {
                name: "unknown-job".to_string(),
                status: "manual".to_string(),
            },
        ];

        let evidence = map_pipeline_jobs_evidence(&jobs);
        assert_eq!(evidence.len(), 6);
        assert_eq!(evidence[0].conclusion, CheckConclusion::Success);
        assert_eq!(evidence[1].conclusion, CheckConclusion::Failure);
        assert_eq!(evidence[2].conclusion, CheckConclusion::Cancelled);
        assert_eq!(evidence[3].conclusion, CheckConclusion::Skipped);
        assert_eq!(evidence[4].conclusion, CheckConclusion::Pending);
        assert_eq!(evidence[5].conclusion, CheckConclusion::Unknown);
        assert_eq!(evidence[0].app_slug, Some("gitlab-ci".to_string()));
    }

    #[test]
    fn build_platform_evidence_filters_pending() {
        let check_runs = vec![
            CheckRunEvidence {
                name: "build".to_string(),
                conclusion: CheckConclusion::Success,
                app_slug: Some("gitlab-ci".to_string()),
            },
            CheckRunEvidence {
                name: "pending-job".to_string(),
                conclusion: CheckConclusion::Pending,
                app_slug: Some("gitlab-ci".to_string()),
            },
        ];

        let platforms = map_build_platform_evidence(&check_runs);
        assert_eq!(platforms.len(), 1);
        assert_eq!(platforms[0].platform, "gitlab-ci");
        assert!(platforms[0].hosted);
        assert!(platforms[0].ephemeral);
        assert!(platforms[0].isolated);
        assert!(!platforms[0].signing_key_isolated);
    }

    #[test]
    fn build_merge_request_bundle_structure() {
        let bundle = build_merge_request_bundle(
            "owner/repo",
            &sample_mr(),
            &[],
            &MrApprovals {
                approved_by: vec![],
            },
            &[],
        );

        assert_eq!(bundle.change_requests.len(), 1);
        assert!(bundle.promotion_batches.is_empty());
    }

    #[test]
    fn build_release_bundle_deduplicates_mrs() {
        let commits = vec![CompareCommit {
            id: "aaa".to_string(),
            message: "feat: something".to_string(),
            author_name: "dev".to_string(),
            parent_ids: vec![],
        }];

        let commit_mr_iids = vec![
            ("aaa".to_string(), vec![1, 2]),
            ("aaa".to_string(), vec![1, 3]), // MR !1 appears twice
        ];

        let bundle = build_release_bundle("owner/repo", "v0.1.0", "v0.2.0", &commits, &commit_mr_iids);

        assert_eq!(bundle.promotion_batches.len(), 1);
        let batch = &bundle.promotion_batches[0];
        assert_eq!(batch.id, "gitlab_release:owner/repo:v0.1.0..v0.2.0");

        if let EvidenceState::Complete { value } = &batch.linked_change_requests {
            assert_eq!(value.len(), 3, "MR !1 should be deduplicated");
            let values: Vec<&str> = value.iter().map(|cr| cr.value.as_str()).collect();
            assert!(values.contains(&"owner/repo!1"));
            assert!(values.contains(&"owner/repo!2"));
            assert!(values.contains(&"owner/repo!3"));
        } else {
            panic!("expected Complete");
        }
    }

    #[test]
    fn release_bundle_filters_unrelated_commits() {
        let commits = vec![CompareCommit {
            id: "in_range".to_string(),
            message: "feat".to_string(),
            author_name: "dev".to_string(),
            parent_ids: vec![],
        }];

        let commit_mr_iids = vec![
            ("in_range".to_string(), vec![1]),
            ("out_of_range".to_string(), vec![99]),
        ];

        let bundle = build_release_bundle("owner/repo", "v1", "v2", &commits, &commit_mr_iids);

        if let EvidenceState::Complete { value } = &bundle.promotion_batches[0].linked_change_requests {
            assert_eq!(value.len(), 1);
            assert_eq!(value[0].value, "owner/repo!1");
        } else {
            panic!("expected Complete");
        }
    }
}
