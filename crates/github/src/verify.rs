use std::process;

use anyhow::{Context, Result, bail};

use libverify_core::assessment::{
    AssessmentReport, BatchEntry, BatchReport, SkippedEntry, VerificationResult,
};
use libverify_core::evidence::EvidenceState;
use libverify_core::profile::GateDecision;
use libverify_core::registry::ControlRegistry;
use libverify_policy::OpaProfile;

use crate::adapter;
use crate::client::GitHubClient;
use crate::dependency;
use crate::graphql::{self, PrData};
use crate::types::{CombinedStatusResponse, CommitStatusItem};

/// Verify a single pull request and return a verification result.
pub fn verify_pr(
    client: &GitHubClient,
    owner: &str,
    repo: &str,
    pr_number: u32,
    policy: Option<&str>,
    with_evidence: bool,
) -> Result<VerificationResult> {
    let pr_data =
        graphql::fetch_pr(client, owner, repo, pr_number).context("failed to fetch PR data")?;
    assess_from_pr_data(
        client,
        &pr_data,
        owner,
        repo,
        pr_number,
        policy,
        with_evidence,
    )
}

fn assess_from_pr_data(
    client: &GitHubClient,
    pr_data: &PrData,
    owner: &str,
    repo: &str,
    pr_number: u32,
    policy: Option<&str>,
    with_evidence: bool,
) -> Result<VerificationResult> {
    let posture =
        crate::posture::collect_repository_posture(client, owner, repo, &pr_data.metadata.head.sha);
    assess_from_pr_data_with_posture(
        client,
        pr_data,
        owner,
        repo,
        pr_number,
        policy,
        with_evidence,
        posture,
    )
}

#[allow(clippy::too_many_arguments)]
fn assess_from_pr_data_with_posture(
    client: &GitHubClient,
    pr_data: &PrData,
    owner: &str,
    repo: &str,
    pr_number: u32,
    policy: Option<&str>,
    with_evidence: bool,
    repository_posture: EvidenceState<libverify_core::evidence::RepositoryPosture>,
) -> Result<VerificationResult> {
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

    let report = assess_bundle(&bundle, policy)?;
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
) -> Result<BatchReport> {
    let mut reports = Vec::new();
    let mut skipped = Vec::new();
    let mut total_pass = 0usize;
    let mut total_review = 0usize;
    let mut total_fail = 0usize;
    let total = pr_numbers.len();

    let all_data = graphql::fetch_prs(client, owner, repo, pr_numbers);

    // Collect repository posture once for the entire batch (same repo)
    let head_sha = all_data
        .iter()
        .find_map(|(_, r)| r.as_ref().ok().map(|d| d.metadata.head.sha.as_str()))
        .unwrap_or("HEAD");
    let posture = crate::posture::collect_repository_posture(client, owner, repo, head_sha);

    for (i, (pr_number, result)) in all_data.into_iter().enumerate() {
        eprintln!("Verifying PR #{pr_number} ({}/{})", i + 1, total);

        match result.and_then(|pr_data| {
            assess_from_pr_data_with_posture(
                client,
                &pr_data,
                owner,
                repo,
                pr_number,
                policy,
                with_evidence,
                posture.clone(),
            )
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
                    subject_id: format!("#{pr_number}"),
                    result: vr,
                });
            }
            Err(e) => {
                eprintln!("Warning: skipping PR #{pr_number}: {e:#}");
                skipped.push(SkippedEntry {
                    subject_id: format!("#{pr_number}"),
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
///
/// This encapsulates the full release verification flow:
/// compare refs, resolve commit PRs, collect attestations, build bundle, assess.
pub fn verify_release(
    client: &GitHubClient,
    owner: &str,
    repo: &str,
    base_tag: &str,
    head_tag: &str,
    policy: Option<&str>,
    with_evidence: bool,
) -> Result<VerificationResult> {
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

    // Collect build-provenance attestations for release assets
    let release_assets = crate::release_api::get_release_assets(client, owner, repo, head_tag)
        .unwrap_or_else(|err| {
            eprintln!("Warning: failed to fetch release assets: {err}");
            vec![]
        });

    let artifact_attestations =
        crate::attestation::collect_release_attestations(owner, repo, head_tag, &release_assets);

    // Deduplicate PRs and fetch full evidence for each
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
        artifact_attestations,
    );
    bundle.change_requests = change_requests;
    bundle.repository_posture =
        crate::posture::collect_repository_posture(client, owner, repo, head_tag);

    // Aggregate check runs from all PRs for build platform evidence
    let check_run_evidence = adapter::map_check_runs_evidence(&all_check_runs, None);
    bundle.check_runs = EvidenceState::complete(check_run_evidence);
    if let Some(cr_list) = bundle.check_runs.value() {
        let build_platforms = adapter::map_build_platform_evidence(cr_list);
        if !build_platforms.is_empty() {
            bundle.build_platform = EvidenceState::complete(build_platforms);
        }
    }

    let report = assess_bundle(&bundle, policy)?;
    let evidence_bundle = if with_evidence { Some(bundle) } else { None };
    Ok(VerificationResult::new(report, evidence_bundle))
}

/// Verify repository-level dependency signatures at a given ref.
///
/// Scans for lock files (Cargo.lock, package-lock.json) at the specified
/// reference and evaluates dependency signature evidence.
///
/// Only evaluates dependency-related controls (not PR or build controls)
/// to avoid noisy NotApplicable results.
pub fn verify_repo(
    client: &GitHubClient,
    owner: &str,
    repo: &str,
    reference: &str,
    policy: Option<&str>,
    with_evidence: bool,
) -> Result<VerificationResult> {
    let dep_sigs = dependency::collect_repo_dependency_signatures(client, owner, repo, reference);

    // Enrich npm dependencies with provenance from the npm attestation API
    let dep_sigs = enrich_npm_attestations(dep_sigs);

    let repository_posture =
        crate::posture::collect_repository_posture(client, owner, repo, reference);

    let bundle = libverify_core::evidence::EvidenceBundle {
        dependency_signatures: dep_sigs,
        repository_posture,
        check_runs: EvidenceState::not_applicable(),
        build_platform: EvidenceState::not_applicable(),
        artifact_attestations: EvidenceState::not_applicable(),
        ..Default::default()
    };

    // Use dependency-scoped controls matching the requested policy level
    use libverify_core::slsa::SlsaTrack;
    let policy_str = policy.unwrap_or("default");
    let dep_level = match policy_str {
        "slsa-l1" => libverify_core::slsa::SlsaLevel::L1,
        "slsa-l2" => libverify_core::slsa::SlsaLevel::L2,
        "slsa-l3" => libverify_core::slsa::SlsaLevel::L3,
        "slsa-l4" => libverify_core::slsa::SlsaLevel::L4,
        _ => libverify_core::slsa::SlsaLevel::L4, // default/oss/soc2: evaluate all
    };
    let dep_controls =
        libverify_core::controls::slsa_controls_for_level(SlsaTrack::Dependencies, dep_level);
    let mut registry = ControlRegistry::new();
    for control in dep_controls {
        registry.register(control);
    }
    // Repository-level posture controls (not PR-scoped compliance controls)
    for control in libverify_core::controls::posture_controls() {
        registry.register(control);
    }
    let profile = OpaProfile::from_preset_or_file(policy_str)?;
    let report = libverify_core::assessment::assess(&bundle, registry.controls(), &profile);
    let evidence_bundle = if with_evidence { Some(bundle) } else { None };
    Ok(VerificationResult::new(report, evidence_bundle))
}

pub fn assess_bundle(
    bundle: &libverify_core::evidence::EvidenceBundle,
    policy: Option<&str>,
) -> Result<AssessmentReport> {
    let registry = ControlRegistry::builtin();
    let profile = OpaProfile::from_preset_or_file(policy.unwrap_or("default"))?;
    Ok(libverify_core::assessment::assess(
        bundle,
        registry.controls(),
        &profile,
    ))
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
