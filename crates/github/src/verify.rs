use std::process;

use anyhow::{Context, Result, bail};

use libverify_core::adapter::PlatformAdapter;
use libverify_core::assessment::{
    AssessmentReport, BatchEntry, BatchReport, SkippedEntry, VerificationResult,
};
use libverify_core::control::Control;
use libverify_core::evidence::EvidenceState;
use libverify_core::profile::GateDecision;
use libverify_core::registry::ControlRegistry;
use libverify_policy::OpaProfile;

use crate::adapter;
use crate::client::GitHubClient;
use crate::dependency;
use crate::graphql::{self, PrData};
use crate::types::{CombinedStatusResponse, CommitStatusItem};

// ---------------------------------------------------------------------------
// GitHubAdapter — PlatformAdapter implementation for GitHub
// ---------------------------------------------------------------------------

/// GitHub implementation of [`PlatformAdapter`].
///
/// Wraps a [`GitHubClient`] and delegates to the existing evidence-collection
/// functions. Platform-specific optimisations (batch GraphQL, phased release)
/// are preserved internally.
pub struct GitHubAdapter<'a> {
    client: &'a GitHubClient,
}

impl<'a> GitHubAdapter<'a> {
    pub fn new(client: &'a GitHubClient) -> Self {
        Self { client }
    }

    /// Access the underlying GitHub client for platform-specific operations
    /// (e.g. phased release evidence collection, range utilities).
    pub fn client(&self) -> &GitHubClient {
        self.client
    }
}

impl PlatformAdapter for GitHubAdapter<'_> {
    fn collect_pr_evidence(
        &self,
        owner: &str,
        repo: &str,
        pr_number: u32,
    ) -> libverify_core::adapter::AdapterResult<libverify_core::evidence::EvidenceBundle> {
        collect_pr_evidence(self.client, owner, repo, pr_number).map_err(Into::into)
    }

    fn collect_pr_batch_evidence(
        &self,
        owner: &str,
        repo: &str,
        pr_numbers: &[u32],
    ) -> Vec<(
        String,
        libverify_core::adapter::AdapterResult<libverify_core::evidence::EvidenceBundle>,
    )> {
        collect_pr_batch_evidence(self.client, owner, repo, pr_numbers)
            .into_iter()
            .map(|(id, r)| (id, r.map_err(Into::into)))
            .collect()
    }

    fn collect_release_evidence(
        &self,
        owner: &str,
        repo: &str,
        base_tag: &str,
        head_tag: &str,
    ) -> libverify_core::adapter::AdapterResult<libverify_core::evidence::EvidenceBundle> {
        collect_release_evidence(self.client, owner, repo, base_tag, head_tag).map_err(Into::into)
    }

    fn collect_repo_evidence(
        &self,
        owner: &str,
        repo: &str,
        reference: &str,
    ) -> libverify_core::adapter::AdapterResult<libverify_core::evidence::EvidenceBundle> {
        collect_repo_evidence(self.client, owner, repo, reference).map_err(Into::into)
    }
}

// ---------------------------------------------------------------------------
// Evidence collection (API calls happen here — expensive, cacheable)
// ---------------------------------------------------------------------------

/// Collect evidence for a single pull request without evaluating any policy.
///
/// Returns an [`EvidenceBundle`] that can be assessed multiple times with
/// different policies via [`assess_bundle`].
pub fn collect_pr_evidence(
    client: &GitHubClient,
    owner: &str,
    repo: &str,
    pr_number: u32,
) -> Result<libverify_core::evidence::EvidenceBundle> {
    let pr_data =
        graphql::fetch_pr(client, owner, repo, pr_number).context("failed to fetch PR data")?;
    let posture =
        crate::posture::collect_repository_posture(client, owner, repo, &pr_data.metadata.head.sha);
    collect_pr_evidence_from_data(client, &pr_data, owner, repo, pr_number, posture)
}

/// Collect evidence for a batch of PRs.
///
/// Returns `(subject_id, Result<EvidenceBundle>)` per PR, preserving order.
/// Repository posture is collected once and shared across all PRs.
pub fn collect_pr_batch_evidence(
    client: &GitHubClient,
    owner: &str,
    repo: &str,
    pr_numbers: &[u32],
) -> Vec<(String, Result<libverify_core::evidence::EvidenceBundle>)> {
    let all_data = graphql::fetch_prs(client, owner, repo, pr_numbers);

    // Collect repository posture once for the entire batch (same repo)
    let head_sha = all_data
        .iter()
        .find_map(|(_, r)| r.as_ref().ok().map(|d| d.metadata.head.sha.as_str()))
        .unwrap_or("HEAD");
    let posture = crate::posture::collect_repository_posture(client, owner, repo, head_sha);

    all_data
        .into_iter()
        .map(|(pr_number, result)| {
            let subject_id = format!("#{pr_number}");
            let bundle = result.and_then(|pr_data| {
                collect_pr_evidence_from_data(
                    client,
                    &pr_data,
                    owner,
                    repo,
                    pr_number,
                    posture.clone(),
                )
            });
            (subject_id, bundle)
        })
        .collect()
}

/// Phase 1: Collect PR and commit evidence for a release range.
///
/// Resolves commits between tags, maps them to PRs via GraphQL, and fetches
/// full PR data (reviews, files, check runs). Returns a bundle with
/// `change_requests`, `promotion_batches`, `check_runs`, and `build_platform`
/// populated. Other fields (`repository_posture`, `artifact_attestations`)
/// are left as defaults for subsequent phases.
pub fn collect_release_pr_evidence(
    client: &GitHubClient,
    owner: &str,
    repo: &str,
    base_tag: &str,
    head_tag: &str,
) -> Result<libverify_core::evidence::EvidenceBundle> {
    let commits = crate::release_api::compare_refs(client, owner, repo, base_tag, head_tag)
        .context("failed to compare refs")?;

    if commits.is_empty() {
        bail!("no commits found between {base_tag} and {head_tag}");
    }

    let shas: Vec<&str> = commits.iter().map(|c| c.sha.as_str()).collect();
    let commit_pr_map =
        graphql::resolve_commit_prs(client, owner, repo, &shas).unwrap_or_else(|err| {
            eprintln!("Warning: failed to resolve commit PRs via GraphQL: {err}");
            std::collections::HashMap::new()
        });

    let commit_prs: Vec<_> = commits
        .iter()
        .map(|c| adapter::GitHubCommitPullAssociation {
            commit_sha: c.sha.clone(),
            pull_requests: commit_pr_map.get(&c.sha).cloned().unwrap_or_default(),
        })
        .collect();

    let unique_pr_numbers: Vec<u32> = {
        let mut seen = std::collections::HashSet::new();
        commit_pr_map
            .values()
            .flatten()
            .filter(|pr| seen.insert(pr.number))
            .map(|pr| pr.number)
            .collect()
    };

    let repo_full = format!("{owner}/{repo}");
    let mut change_requests = Vec::new();
    let mut all_check_runs = Vec::new();

    if !unique_pr_numbers.is_empty() {
        for (pr_number, result) in graphql::fetch_prs(client, owner, repo, &unique_pr_numbers) {
            match result {
                Ok(pr_data) => {
                    change_requests.push(adapter::map_pull_request_evidence(
                        &repo_full,
                        pr_number,
                        &pr_data.metadata,
                        &pr_data.files,
                        &pr_data.reviews,
                        &pr_data.commits,
                    ));
                    all_check_runs.extend(pr_data.check_runs);
                }
                Err(e) => {
                    eprintln!(
                        "Warning: failed to fetch PR #{pr_number} for release verification: {e:#}"
                    );
                }
            }
        }
    }

    let mut bundle = adapter::build_release_bundle(
        &repo_full,
        base_tag,
        head_tag,
        &commits,
        &commit_prs,
        EvidenceState::default(),
    );
    bundle.change_requests = change_requests;

    let check_run_evidence = adapter::map_check_runs_evidence(&all_check_runs, None);
    bundle.check_runs = EvidenceState::complete(check_run_evidence);
    if let Some(cr_list) = bundle.check_runs.value() {
        let build_platforms = adapter::map_build_platform_evidence(cr_list);
        if !build_platforms.is_empty() {
            bundle.build_platform = EvidenceState::complete(build_platforms);
        }
        bundle.harness_results = EvidenceState::complete(adapter::map_harness_results(cr_list));
    }

    Ok(bundle)
}

/// Phase 2: Collect repository security posture and merge into the bundle.
///
/// Queries branch protection, secret scanning, code scanning, CODEOWNERS,
/// workflow permissions, tag protection rules, etc.
/// Also checks release assets for SBOM files and updates the posture.
pub fn collect_release_repo_evidence(
    client: &GitHubClient,
    owner: &str,
    repo: &str,
    head_tag: &str,
    bundle: &mut libverify_core::evidence::EvidenceBundle,
) {
    bundle.repository_posture =
        crate::posture::collect_repository_posture(client, owner, repo, head_tag);

    // Check release assets for SBOM and update the posture field.
    let release_assets =
        crate::release_api::get_release_assets(client, owner, repo, head_tag).unwrap_or_default();
    if let Some(posture) = bundle.repository_posture.value_mut() {
        posture.release_has_sbom = crate::release_api::has_sbom_asset(&release_assets);
    }
}

/// Phase 3: Check release asset attestations via the GitHub API and merge
/// into the bundle.
///
/// Downloads only `.sha256` sidecar files (a few KB), then queries the
/// Attestations REST API for each asset digest. No binary downloads needed.
pub fn collect_release_attestation_evidence(
    client: &GitHubClient,
    owner: &str,
    repo: &str,
    head_tag: &str,
    bundle: &mut libverify_core::evidence::EvidenceBundle,
) {
    let release_assets = crate::release_api::get_release_assets(client, owner, repo, head_tag)
        .unwrap_or_else(|err| {
            eprintln!("Warning: failed to fetch release assets: {err}");
            vec![]
        });

    bundle.artifact_attestations = crate::attestation::collect_release_attestations(
        owner,
        repo,
        head_tag,
        &release_assets,
        client,
    );
}

/// Collect all evidence for a release (backward-compatible convenience wrapper).
///
/// Calls all three phases sequentially. Prefer the individual phase functions
/// when progressive output is desired.
pub fn collect_release_evidence(
    client: &GitHubClient,
    owner: &str,
    repo: &str,
    base_tag: &str,
    head_tag: &str,
) -> Result<libverify_core::evidence::EvidenceBundle> {
    let mut bundle = collect_release_pr_evidence(client, owner, repo, base_tag, head_tag)?;
    collect_release_repo_evidence(client, owner, repo, head_tag, &mut bundle);
    collect_release_attestation_evidence(client, owner, repo, head_tag, &mut bundle);
    Ok(bundle)
}

/// Collect evidence for repository-level posture and dependencies at a given ref.
pub fn collect_repo_evidence(
    client: &GitHubClient,
    owner: &str,
    repo: &str,
    reference: &str,
) -> Result<libverify_core::evidence::EvidenceBundle> {
    let dep_sigs = dependency::collect_repo_dependency_signatures(client, owner, repo, reference);

    // Enrich npm dependencies with provenance from the npm attestation API
    let dep_sigs = enrich_npm_attestations(dep_sigs);

    let repository_posture =
        crate::posture::collect_repository_posture(client, owner, repo, reference);

    Ok(libverify_core::evidence::EvidenceBundle {
        dependency_signatures: dep_sigs,
        repository_posture,
        check_runs: EvidenceState::not_applicable(),
        build_platform: EvidenceState::not_applicable(),
        artifact_attestations: EvidenceState::not_applicable(),
        ..Default::default()
    })
}

// ---------------------------------------------------------------------------
// Assessment (CPU-only, no API calls — fast, re-runnable with different policies)
// ---------------------------------------------------------------------------

/// Assess an evidence bundle against all built-in controls using the given policy.
///
/// Extra controls are appended to the built-in registry, enabling callers to
/// inject platform-specific checks (e.g. Jira linkage, Bitbucket pipeline status).
pub fn assess_bundle(
    bundle: &libverify_core::evidence::EvidenceBundle,
    policy: Option<&str>,
    extra_controls: Vec<Box<dyn Control>>,
) -> Result<AssessmentReport> {
    let mut registry = ControlRegistry::builtin();
    for c in extra_controls {
        registry.register(c);
    }
    let profile = OpaProfile::from_preset_or_file(policy.unwrap_or("default"))?;
    Ok(libverify_core::assessment::assess(
        bundle,
        registry.controls(),
        &profile,
    ))
}

/// Assess an evidence bundle using repo-scoped controls (dependencies + posture).
///
/// This mirrors the control selection logic of [`verify_repo`] but operates
/// on a pre-collected bundle. Extra controls are appended after the built-in
/// dependency + posture controls.
pub fn assess_repo_bundle(
    bundle: &libverify_core::evidence::EvidenceBundle,
    policy: Option<&str>,
    extra_controls: Vec<Box<dyn Control>>,
) -> Result<AssessmentReport> {
    use libverify_core::slsa::SlsaTrack;
    let policy_str = policy.unwrap_or("default");
    let dep_level = match policy_str {
        "slsa-l1" => libverify_core::slsa::SlsaLevel::L1,
        "slsa-l2" => libverify_core::slsa::SlsaLevel::L2,
        "slsa-l3" => libverify_core::slsa::SlsaLevel::L3,
        "slsa-l4" => libverify_core::slsa::SlsaLevel::L4,
        _ => libverify_core::slsa::SlsaLevel::L4,
    };
    let dep_controls =
        libverify_core::controls::slsa_controls_for_level(SlsaTrack::Dependencies, dep_level);
    let mut registry = ControlRegistry::new();
    for control in dep_controls {
        registry.register(control);
    }
    for control in libverify_core::controls::posture_controls() {
        registry.register(control);
    }
    for c in extra_controls {
        registry.register(c);
    }
    let profile = OpaProfile::from_preset_or_file(policy_str)?;
    Ok(libverify_core::assessment::assess(
        bundle,
        registry.controls(),
        &profile,
    ))
}

// ---------------------------------------------------------------------------
// Convenience wrappers (collect + assess in one call — backward compatible)
// ---------------------------------------------------------------------------

/// Verify a single pull request and return a verification result.
pub fn verify_pr(
    client: &GitHubClient,
    owner: &str,
    repo: &str,
    pr_number: u32,
    policy: Option<&str>,
    with_evidence: bool,
    extra_controls: Vec<Box<dyn Control>>,
) -> Result<VerificationResult> {
    let bundle = collect_pr_evidence(client, owner, repo, pr_number)?;
    let report = assess_bundle(&bundle, policy, extra_controls)?;
    let evidence_bundle = if with_evidence { Some(bundle) } else { None };
    Ok(VerificationResult::new(report, evidence_bundle))
}

/// Verify a batch of PRs and aggregate results.
pub fn verify_pr_batch(
    client: &GitHubClient,
    owner: &str,
    repo: &str,
    pr_numbers: &[u32],
    policy: Option<&str>,
    with_evidence: bool,
    extra_controls_fn: impl Fn() -> Vec<Box<dyn Control>>,
) -> Result<BatchReport> {
    let mut reports = Vec::new();
    let mut skipped = Vec::new();
    let mut total_pass = 0usize;
    let mut total_review = 0usize;
    let mut total_fail = 0usize;
    let total = pr_numbers.len();

    let evidence_items = collect_pr_batch_evidence(client, owner, repo, pr_numbers);

    for (i, (subject_id, result)) in evidence_items.into_iter().enumerate() {
        eprintln!("Verifying {subject_id} ({}/{})", i + 1, total);

        match result.and_then(|bundle| {
            let report = assess_bundle(&bundle, policy, extra_controls_fn())?;
            let evidence_bundle = if with_evidence { Some(bundle) } else { None };
            Ok(VerificationResult::new(report, evidence_bundle))
        }) {
            Ok(vr) => {
                for outcome in &vr.report.outcomes {
                    match outcome.decision {
                        GateDecision::Pass => total_pass += 1,
                        GateDecision::Review => total_review += 1,
                        GateDecision::Fail => total_fail += 1,
                    }
                }
                reports.push(BatchEntry {
                    subject_id,
                    result: vr,
                });
            }
            Err(e) => {
                eprintln!("Warning: skipping {subject_id}: {e:#}");
                skipped.push(SkippedEntry {
                    subject_id,
                    reason: format!("{e:#}"),
                });
            }
        }
    }

    Ok(BatchReport {
        reports,
        total_pass,
        total_review,
        total_fail,
        skipped,
    })
}

/// Verify a release (tag range) and return a verification result.
#[allow(clippy::too_many_arguments)]
pub fn verify_release(
    client: &GitHubClient,
    owner: &str,
    repo: &str,
    base_tag: &str,
    head_tag: &str,
    policy: Option<&str>,
    with_evidence: bool,
    extra_controls: Vec<Box<dyn Control>>,
) -> Result<VerificationResult> {
    let bundle = collect_release_evidence(client, owner, repo, base_tag, head_tag)?;
    let report = assess_bundle(&bundle, policy, extra_controls)?;
    let evidence_bundle = if with_evidence { Some(bundle) } else { None };
    Ok(VerificationResult::new(report, evidence_bundle))
}

/// Verify repository-level dependency signatures at a given ref.
pub fn verify_repo(
    client: &GitHubClient,
    owner: &str,
    repo: &str,
    reference: &str,
    policy: Option<&str>,
    with_evidence: bool,
    extra_controls: Vec<Box<dyn Control>>,
) -> Result<VerificationResult> {
    let bundle = collect_repo_evidence(client, owner, repo, reference)?;
    let report = assess_repo_bundle(&bundle, policy, extra_controls)?;
    let evidence_bundle = if with_evidence { Some(bundle) } else { None };
    Ok(VerificationResult::new(report, evidence_bundle))
}

pub fn exit_if_assessment_fails(result: &VerificationResult) {
    if result
        .report
        .outcomes
        .iter()
        .any(|o| o.decision == GateDecision::Fail)
    {
        process::exit(1);
    }
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

fn collect_pr_evidence_from_data(
    client: &GitHubClient,
    pr_data: &PrData,
    owner: &str,
    repo: &str,
    pr_number: u32,
    repository_posture: EvidenceState<libverify_core::evidence::RepositoryPosture>,
) -> Result<libverify_core::evidence::EvidenceBundle> {
    let repo_full = format!("{owner}/{repo}");
    let mut bundle = adapter::build_pull_request_bundle(
        &repo_full,
        pr_number,
        &pr_data.metadata,
        &pr_data.files,
        &pr_data.reviews,
        &pr_data.commits,
    );

    let combined_status = if pr_data.commit_statuses.is_empty() {
        None
    } else {
        Some(CombinedStatusResponse {
            state: String::new(),
            statuses: pr_data
                .commit_statuses
                .iter()
                .map(|s| CommitStatusItem {
                    context: s.context.clone(),
                    state: s.state.clone(),
                })
                .collect(),
        })
    };
    let evidence = adapter::map_check_runs_evidence(&pr_data.check_runs, combined_status.as_ref());
    bundle.check_runs = EvidenceState::complete(evidence);

    if let Some(cr_list) = bundle.check_runs.value() {
        let build_platforms = adapter::map_build_platform_evidence(cr_list);
        if !build_platforms.is_empty() {
            bundle.build_platform = EvidenceState::complete(build_platforms);
        }
        bundle.harness_results = EvidenceState::complete(adapter::map_harness_results(cr_list));
    }

    bundle.repository_posture = repository_posture;

    // Collect dependency signature evidence from lock files
    let changed_files: Vec<String> = pr_data.files.iter().map(|f| f.filename.clone()).collect();
    let dep_sigs = dependency::collect_pr_dependency_signatures(
        client,
        owner,
        repo,
        &pr_data.metadata.head.sha,
        &changed_files,
    );
    bundle.dependency_signatures = enrich_npm_attestations(dep_sigs);

    Ok(bundle)
}

/// Enrich dependencies with provenance from registry attestation APIs.
/// Supports npm (Sigstore) and PyPI (PEP 740).
fn enrich_npm_attestations(
    state: EvidenceState<Vec<libverify_core::evidence::DependencySignatureEvidence>>,
) -> EvidenceState<Vec<libverify_core::evidence::DependencySignatureEvidence>> {
    use crate::npm_attestation::NpmAttestationClient;
    use crate::pypi_attestation::PypiAttestationClient;

    fn enrich(deps: &mut [libverify_core::evidence::DependencySignatureEvidence]) {
        let has_npm = deps
            .iter()
            .any(|d| d.registry.as_deref() == Some("registry.npmjs.org"));
        let has_pypi = deps
            .iter()
            .any(|d| d.registry.as_deref() == Some("pypi.org"));

        if has_npm && let Ok(client) = NpmAttestationClient::new() {
            client.enrich_npm_deps(deps);
        }
        if has_pypi && let Ok(client) = PypiAttestationClient::new() {
            client.enrich_pypi_deps(deps);
        }
    }

    match state {
        EvidenceState::Complete { mut value } => {
            enrich(&mut value);
            EvidenceState::Complete { value }
        }
        EvidenceState::Partial { mut value, gaps } => {
            enrich(&mut value);
            EvidenceState::Partial { value, gaps }
        }
        other => other,
    }
}
