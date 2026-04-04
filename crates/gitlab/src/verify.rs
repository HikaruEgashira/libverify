use std::collections::HashSet;

use libverify_core::adapter::{AdapterResult, PlatformAdapter};
use libverify_core::evidence::{EvidenceBundle, EvidenceState};

use crate::adapter;
use crate::client::GitLabClient;
use crate::types::{
    CommitMr, CompareResponse, MrApprovals, MrChangesResponse, MrCommit, MrMetadata, MrPipeline,
    PipelineJob,
};

/// GitLab implementation of [`PlatformAdapter`].
///
/// Wraps a [`GitLabClient`] and translates GitLab REST API responses into
/// platform-neutral evidence bundles.
pub struct GitLabAdapter<'a> {
    client: &'a GitLabClient,
}

impl<'a> GitLabAdapter<'a> {
    pub fn new(client: &'a GitLabClient) -> Self {
        Self { client }
    }

    /// Access the underlying GitLab client for platform-specific operations.
    pub fn client(&self) -> &GitLabClient {
        self.client
    }
}

impl PlatformAdapter for GitLabAdapter<'_> {
    fn collect_pr_evidence(
        &self,
        owner: &str,
        repo: &str,
        pr_number: u32,
    ) -> AdapterResult<EvidenceBundle> {
        collect_mr_evidence(self.client, owner, repo, pr_number).map_err(Into::into)
    }

    fn collect_release_evidence(
        &self,
        owner: &str,
        repo: &str,
        base_tag: &str,
        head_tag: &str,
    ) -> AdapterResult<EvidenceBundle> {
        collect_release_evidence(self.client, owner, repo, base_tag, head_tag).map_err(Into::into)
    }

    fn collect_repo_evidence(
        &self,
        owner: &str,
        repo: &str,
        reference: &str,
    ) -> AdapterResult<EvidenceBundle> {
        collect_repo_evidence(self.client, owner, repo, reference).map_err(Into::into)
    }
}

// ---------------------------------------------------------------------------
// Evidence collection
// ---------------------------------------------------------------------------

/// Collect evidence for a single merge request.
fn collect_mr_evidence(
    client: &GitLabClient,
    owner: &str,
    repo: &str,
    mr_iid: u32,
) -> anyhow::Result<EvidenceBundle> {
    let project = GitLabClient::encode_project(owner, repo);
    let repo_full = format!("{owner}/{repo}");

    // Fetch MR data concurrently.
    let (metadata, changes_resp, approvals, commits, pipelines) = std::thread::scope(|s| {
        let h_meta = s.spawn(|| {
            client.get_json::<MrMetadata>(&format!("/projects/{project}/merge_requests/{mr_iid}"))
        });
        let h_changes = s.spawn(|| {
            client.get_json::<MrChangesResponse>(&format!(
                "/projects/{project}/merge_requests/{mr_iid}/changes"
            ))
        });
        let h_approvals = s.spawn(|| {
            client.get_json::<MrApprovals>(&format!(
                "/projects/{project}/merge_requests/{mr_iid}/approvals"
            ))
        });
        let h_commits = s.spawn(|| {
            client.paginate::<MrCommit>(&format!(
                "/projects/{project}/merge_requests/{mr_iid}/commits"
            ))
        });
        let h_pipelines = s.spawn(|| {
            client.get_json::<Vec<MrPipeline>>(&format!(
                "/projects/{project}/merge_requests/{mr_iid}/pipelines"
            ))
        });

        (
            h_meta.join().unwrap(),
            h_changes.join().unwrap(),
            h_approvals.join().unwrap(),
            h_commits.join().unwrap(),
            h_pipelines.join().unwrap(),
        )
    });

    let metadata = metadata?;
    let changes = changes_resp.map(|r| r.changes).unwrap_or_default();
    let approvals = approvals.unwrap_or(MrApprovals {
        approved_by: Vec::new(),
    });
    let commits = commits.unwrap_or_default();

    let mut bundle =
        adapter::build_merge_request_bundle(&repo_full, &metadata, &changes, &approvals, &commits);

    // Fetch pipeline jobs for the latest pipeline.
    if let Ok(pipelines) = pipelines
        && let Some(latest) = pipelines.first()
    {
        let pipeline_id = latest.id;
        if let Ok(jobs) = client
            .paginate::<PipelineJob>(&format!("/projects/{project}/pipelines/{pipeline_id}/jobs"))
        {
            let check_run_evidence = adapter::map_pipeline_jobs_evidence(&jobs);
            let build_platforms = adapter::map_build_platform_evidence(&check_run_evidence);
            bundle.check_runs = EvidenceState::complete(check_run_evidence);
            if !build_platforms.is_empty() {
                bundle.build_platform = EvidenceState::complete(build_platforms);
            }
        }
    }

    // Collect repository posture.
    bundle.repository_posture =
        crate::posture::collect_repository_posture(client, owner, repo, &metadata.sha);

    Ok(bundle)
}

/// Collect evidence for a release (tag range).
fn collect_release_evidence(
    client: &GitLabClient,
    owner: &str,
    repo: &str,
    base_tag: &str,
    head_tag: &str,
) -> anyhow::Result<EvidenceBundle> {
    let project = GitLabClient::encode_project(owner, repo);
    let repo_full = format!("{owner}/{repo}");

    // Compare tags to get commits in range.
    let compare: CompareResponse = client.get_json(&format!(
        "/projects/{project}/repository/compare?from={base_tag}&to={head_tag}"
    ))?;

    if compare.commits.is_empty() {
        anyhow::bail!("no commits found between {base_tag} and {head_tag}");
    }

    // For each commit, find associated MRs.
    let mut commit_mr_iids: Vec<(String, Vec<u32>)> = Vec::new();
    let mut unique_mr_iids = HashSet::new();

    for commit in &compare.commits {
        let mrs: Vec<CommitMr> = client
            .get_json(&format!(
                "/projects/{project}/repository/commits/{}/merge_requests",
                commit.id
            ))
            .unwrap_or_default();

        let iids: Vec<u32> = mrs.iter().map(|mr| mr.iid).collect();
        for &iid in &iids {
            unique_mr_iids.insert(iid);
        }
        commit_mr_iids.push((commit.id.clone(), iids));
    }

    let mut bundle = adapter::build_release_bundle(
        &repo_full,
        base_tag,
        head_tag,
        &compare.commits,
        &commit_mr_iids,
    );

    // Fetch full MR details for all unique MRs in the range.
    let mut change_requests = Vec::new();
    for iid in &unique_mr_iids {
        let mr_result: anyhow::Result<_> = (|| {
            let metadata: MrMetadata =
                client.get_json(&format!("/projects/{project}/merge_requests/{iid}"))?;
            let changes = client
                .get_json::<MrChangesResponse>(&format!(
                    "/projects/{project}/merge_requests/{iid}/changes"
                ))
                .map(|r| r.changes)
                .unwrap_or_default();
            let approvals = client
                .get_json::<MrApprovals>(&format!(
                    "/projects/{project}/merge_requests/{iid}/approvals"
                ))
                .unwrap_or(MrApprovals {
                    approved_by: Vec::new(),
                });
            let commits = client
                .paginate::<MrCommit>(&format!("/projects/{project}/merge_requests/{iid}/commits"))
                .unwrap_or_default();

            Ok(adapter::map_merge_request_evidence(
                &repo_full, &metadata, &changes, &approvals, &commits,
            ))
        })();

        match mr_result {
            Ok(governed_change) => change_requests.push(governed_change),
            Err(e) => {
                eprintln!("Warning: failed to fetch MR !{iid} for release verification: {e:#}");
            }
        }
    }
    bundle.change_requests = change_requests;

    // Collect repository posture.
    bundle.repository_posture =
        crate::posture::collect_repository_posture(client, owner, repo, head_tag);

    Ok(bundle)
}

/// Collect evidence for repository-level posture at a given ref.
fn collect_repo_evidence(
    client: &GitLabClient,
    owner: &str,
    repo: &str,
    reference: &str,
) -> anyhow::Result<EvidenceBundle> {
    let repository_posture =
        crate::posture::collect_repository_posture(client, owner, repo, reference);

    Ok(EvidenceBundle {
        dependency_signatures: EvidenceState::not_applicable(),
        repository_posture,
        check_runs: EvidenceState::not_applicable(),
        build_platform: EvidenceState::not_applicable(),
        artifact_attestations: EvidenceState::not_applicable(),
        ..Default::default()
    })
}
