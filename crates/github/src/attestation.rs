use anyhow::{Context, Result, bail};
use serde::Deserialize;
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::process::Command;

use libverify_core::evidence::{
    ArtifactAttestation, EvidenceGap, EvidenceState, VerificationOutcome,
};

use crate::types::ReleaseAsset;

// -- gh CLI attestation types --

/// Raw JSON structure from `gh attestation verify --format json`
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct GhAttestationOutput {
    pub verification_result: GhVerificationResult,
}

#[derive(Debug, Deserialize)]
pub struct GhVerificationResult {
    pub statement: Statement,
    pub signature: Option<SignatureInfo>,
}

#[derive(Debug, Deserialize)]
pub struct Statement {
    #[serde(rename = "predicateType")]
    pub predicate_type: String,
    /// In-toto statement subjects: artifacts with their digests.
    #[serde(default)]
    pub subject: Vec<StatementSubject>,
}

/// An in-toto statement subject entry.
#[derive(Debug, Deserialize)]
pub struct StatementSubject {
    pub name: String,
    /// Map of algorithm -> hex digest (e.g. {"sha256": "abcd..."}).
    #[serde(default)]
    pub digest: HashMap<String, String>,
}

#[derive(Debug, Deserialize)]
pub struct SignatureInfo {
    pub certificate: Option<CertificateInfo>,
}

#[derive(Debug, Deserialize)]
pub struct CertificateInfo {
    #[serde(rename = "sourceRepositoryURI")]
    pub source_repository_uri: Option<String>,
    #[serde(rename = "buildSignerURI")]
    pub build_signer_uri: Option<String>,
}

// -- gh CLI verification --

/// Verify an artifact using `gh attestation verify` and return parsed results.
pub fn verify_artifact(
    artifact: &str,
    owner: Option<&str>,
    repo: Option<&str>,
) -> Result<Vec<GhAttestationOutput>> {
    let mut cmd = Command::new("gh");
    cmd.args(["attestation", "verify", artifact, "--format", "json"]);

    if let Some(r) = repo {
        cmd.args(["--repo", r]);
    } else if let Some(o) = owner {
        cmd.args(["--owner", o]);
    } else {
        bail!("either --owner or --repo is required for attestation verification");
    }

    let output = cmd
        .output()
        .context("failed to execute `gh attestation verify`")?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        bail!("gh attestation verify failed: {stderr}");
    }

    let stdout = String::from_utf8(output.stdout).context("invalid UTF-8 in gh output")?;
    let results: Vec<GhAttestationOutput> =
        serde_json::from_str(&stdout).context("failed to parse gh attestation verify output")?;

    Ok(results)
}

/// Convert parsed `gh attestation verify` results into core evidence types.
///
/// When both a local digest and an attestation-claimed digest are available,
/// the two are compared. A mismatch overrides the `Verified` outcome with
/// `SignatureInvalid` (the attestation does not cover the actual artifact).
pub fn to_artifact_attestations(
    artifact: &str,
    results: &[GhAttestationOutput],
    subject_digest: Option<String>,
) -> Vec<ArtifactAttestation> {
    results
        .iter()
        .map(|r| {
            let cert = r
                .verification_result
                .signature
                .as_ref()
                .and_then(|s| s.certificate.as_ref());

            let claimed_digest = r
                .verification_result
                .statement
                .subject
                .iter()
                .find(|s| s.name == artifact)
                .and_then(|s| s.digest.get("sha256"))
                .map(|hex| format!("sha256:{hex}"));

            let verification = match (&subject_digest, &claimed_digest) {
                (Some(local), Some(claimed)) if local != claimed => {
                    VerificationOutcome::SignatureInvalid {
                        detail: format!("digest mismatch: local={local}, attestation={claimed}"),
                    }
                }
                _ => VerificationOutcome::Verified,
            };

            ArtifactAttestation {
                subject: artifact.to_string(),
                subject_digest: subject_digest.clone(),
                predicate_type: r.verification_result.statement.predicate_type.clone(),
                signer_workflow: cert.and_then(|c| c.build_signer_uri.clone()),
                source_repo: cert.and_then(|c| c.source_repository_uri.clone()),
                verification,
            }
        })
        .collect()
}

// -- Release attestation collection --

/// Compute SHA256 digest of a file, returning the hex string.
fn sha256_file(path: &std::path::Path) -> Result<String> {
    let bytes = std::fs::read(path)?;
    let hash = Sha256::digest(&bytes);
    Ok(format!("sha256:{hash:x}"))
}

/// Download release assets to a temporary directory, verify attestations for each,
/// and return an `EvidenceState` suitable for `EvidenceBundle.artifact_attestations`.
///
/// Assets that lack attestations are recorded as unverified rather than causing
/// an error, so the overall assessment can still proceed.
pub fn collect_release_attestations(
    owner: &str,
    repo: &str,
    tag: &str,
    assets: &[ReleaseAsset],
) -> EvidenceState<Vec<ArtifactAttestation>> {
    if assets.is_empty() {
        return EvidenceState::not_applicable();
    }

    let repo_full = format!("{owner}/{repo}");

    // Check whether `gh` CLI is available before doing any work.
    if !gh_cli_available() {
        return EvidenceState::missing(vec![EvidenceGap::CollectionFailed {
            source: "gh-attestation".to_string(),
            subject: "release-assets".to_string(),
            detail: "`gh` CLI is not available".to_string(),
        }]);
    }

    let tmp_dir = match tempfile::tempdir() {
        Ok(d) => d,
        Err(e) => {
            return EvidenceState::missing(vec![EvidenceGap::CollectionFailed {
                source: "gh-attestation".to_string(),
                subject: "release-assets".to_string(),
                detail: format!("failed to create temporary directory: {e}"),
            }]);
        }
    };

    // Download and verify all assets concurrently — each asset writes to a
    // unique path in the same tmp_dir and spawns independent subprocesses.
    let tmp_path = tmp_dir.path();
    let per_asset_results: Vec<(Vec<ArtifactAttestation>, Vec<EvidenceGap>)> =
        std::thread::scope(|s| {
            let handles: Vec<_> = assets
                .iter()
                .map(|asset| {
                    s.spawn(|| {
                        let mut atts = Vec::new();
                        let mut g = Vec::new();
                        let asset_path = tmp_path.join(&asset.name);

                        match download_asset(owner, repo, tag, &asset.name, &asset_path) {
                            Ok(()) => {}
                            Err(e) => {
                                g.push(EvidenceGap::CollectionFailed {
                                    source: "gh-release-download".to_string(),
                                    subject: asset.name.clone(),
                                    detail: format!("failed to download asset: {e}"),
                                });
                                atts.push(ArtifactAttestation {
                                    subject: asset.name.clone(),
                                    subject_digest: None,
                                    predicate_type: String::new(),
                                    signer_workflow: None,
                                    source_repo: None,
                                    verification: VerificationOutcome::Failed {
                                        detail: format!("download failed: {e}"),
                                    },
                                });
                                return (atts, g);
                            }
                        }

                        let digest = sha256_file(&asset_path).ok();
                        let path_str = asset_path.to_string_lossy().to_string();
                        match verify_artifact(&path_str, None, Some(&repo_full)) {
                            Ok(results) if !results.is_empty() => {
                                atts.extend(to_artifact_attestations(
                                    &asset.name, &results, digest,
                                ));
                            }
                            Ok(_) => {
                                atts.push(ArtifactAttestation {
                                    subject: asset.name.clone(),
                                    subject_digest: digest,
                                    predicate_type: String::new(),
                                    signer_workflow: None,
                                    source_repo: None,
                                    verification: VerificationOutcome::AttestationAbsent {
                                        detail: "no attestation found".to_string(),
                                    },
                                });
                            }
                            Err(e) => {
                                let detail = format!("{e}");
                                let outcome = classify_verification_error(&detail);
                                atts.push(ArtifactAttestation {
                                    subject: asset.name.clone(),
                                    subject_digest: digest,
                                    predicate_type: String::new(),
                                    signer_workflow: None,
                                    source_repo: None,
                                    verification: outcome,
                                });
                            }
                        }
                        (atts, g)
                    })
                })
                .collect();
            handles.into_iter().map(|h| h.join().unwrap()).collect()
        });

    let mut attestations: Vec<ArtifactAttestation> = Vec::new();
    let mut gaps: Vec<EvidenceGap> = Vec::new();
    for (atts, g) in per_asset_results {
        attestations.extend(atts);
        gaps.extend(g);
    }

    if gaps.is_empty() {
        EvidenceState::complete(attestations)
    } else {
        EvidenceState::partial(attestations, gaps)
    }
}

/// Download a single release asset using `gh release download`.
fn download_asset(
    owner: &str,
    repo: &str,
    tag: &str,
    asset_name: &str,
    dest: &std::path::Path,
) -> Result<()> {
    let repo_full = format!("{owner}/{repo}");
    let output = Command::new("gh")
        .args([
            "release",
            "download",
            tag,
            "--repo",
            &repo_full,
            "--pattern",
            asset_name,
            "--dir",
            &dest.parent().unwrap().to_string_lossy(),
            "--clobber",
        ])
        .output()?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        anyhow::bail!("{stderr}");
    }

    if !dest.exists() {
        anyhow::bail!("asset file not found after download");
    }

    Ok(())
}

/// Classify the error message from `gh attestation verify` into a structured outcome.
fn classify_verification_error(detail: &str) -> VerificationOutcome {
    let lower = detail.to_lowercase();
    if lower.contains("no attestation") || lower.contains("not found") {
        VerificationOutcome::AttestationAbsent {
            detail: detail.to_string(),
        }
    } else if lower.contains("signature") || lower.contains("cosign") {
        VerificationOutcome::SignatureInvalid {
            detail: detail.to_string(),
        }
    } else if lower.contains("transparency") || lower.contains("rekor") || lower.contains("tlog") {
        VerificationOutcome::TransparencyLogMissing {
            detail: detail.to_string(),
        }
    } else if lower.contains("signer") || lower.contains("identity") || lower.contains("issuer") {
        VerificationOutcome::SignerMismatch {
            detail: detail.to_string(),
        }
    } else {
        VerificationOutcome::Failed {
            detail: detail.to_string(),
        }
    }
}

/// Check whether the `gh` CLI is available on PATH.
fn gh_cli_available() -> bool {
    Command::new("gh")
        .arg("--version")
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_assets_returns_not_applicable() {
        let result = collect_release_attestations("owner", "repo", "v1.0.0", &[]);
        assert!(matches!(result, EvidenceState::NotApplicable));
    }
}
