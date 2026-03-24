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
    assess_from_pr_data(client, &pr_data, owner, repo, pr_number, policy, with_evidence)
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

    // Collect dependency signature evidence from lock files
    let changed_files: Vec<String> = pr_data
        .files
        .iter()
        .map(|f| f.filename.clone())
        .collect();
    bundle.dependency_signatures = dependency::collect_pr_dependency_signatures(
        client,
        owner,
        repo,
        &pr_data.metadata.head.sha,
        &changed_files,
    );

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

    for (i, (pr_number, result)) in all_data.into_iter().enumerate() {
        eprintln!("Verifying PR #{pr_number} ({}/{})", i + 1, total);

        match result.and_then(|pr_data| {
            assess_from_pr_data(client, &pr_data, owner, repo, pr_number, policy, with_evidence)
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

    let repo_full = format!("{owner}/{repo}");
    let mut bundle = adapter::build_release_bundle(
        &repo_full,
        base_tag,
        head_tag,
        &commits,
        &commit_prs,
        artifact_attestations,
    );
    // Check runs are PR-scoped; not applicable for release verification.
    bundle.check_runs = EvidenceState::not_applicable();

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
    let dep_sigs =
        dependency::collect_repo_dependency_signatures(client, owner, repo, reference);

    let bundle = libverify_core::evidence::EvidenceBundle {
        dependency_signatures: dep_sigs,
        check_runs: EvidenceState::not_applicable(),
        build_platform: EvidenceState::not_applicable(),
        artifact_attestations: EvidenceState::not_applicable(),
        ..Default::default()
    };

    // Use only dependency-scoped controls (L1-L4) to avoid NotApplicable noise
    let mut registry = ControlRegistry::new();
    registry.register(Box::new(
        libverify_core::controls::dependency_signature::DependencySignatureControl,
    ));
    registry.register(Box::new(
        libverify_core::controls::dependency_provenance::DependencyProvenanceControl,
    ));
    registry.register(Box::new(
        libverify_core::controls::dependency_signer_verified::DependencySignerVerifiedControl,
    ));
    registry.register(Box::new(
        libverify_core::controls::dependency_completeness::DependencyCompletenessControl,
    ));
    let profile = OpaProfile::from_preset_or_file(policy.unwrap_or("default"))?;
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
