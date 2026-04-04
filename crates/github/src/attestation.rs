use anyhow::{Context, Result, bail};
use base64::Engine;
use base64::engine::general_purpose::STANDARD as BASE64;
use p256::ecdsa::{Signature, VerifyingKey, signature::Verifier};
use serde::Deserialize;
use std::collections::HashMap;
use std::process::Command;
use x509_cert::Certificate;
use x509_cert::der::Decode;

use libverify_core::evidence::{
    ArtifactAttestation, EvidenceGap, EvidenceState, VerificationOutcome,
};

use crate::client::GitHubClient;
use crate::types::ReleaseAsset;

// -- gh CLI attestation types (kept for verify_artifact) --

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
    #[serde(default)]
    pub subject: Vec<StatementSubject>,
}

#[derive(Debug, Deserialize)]
pub struct StatementSubject {
    #[serde(default)]
    pub name: String,
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

// -- GitHub Attestations REST API types --

#[derive(Debug, Deserialize)]
struct AttestationsApiResponse {
    #[serde(default)]
    attestations: Vec<ApiAttestation>,
}

#[derive(Debug, Deserialize)]
struct ApiAttestation {
    bundle: Option<ApiBundle>,
}

#[derive(Debug, Clone, Deserialize)]
struct ApiBundle {
    #[serde(rename = "dsseEnvelope")]
    dsse_envelope: Option<DsseEnvelope>,
    #[serde(rename = "verificationMaterial")]
    verification_material: Option<VerificationMaterial>,
}

#[derive(Debug, Clone, Deserialize)]
struct DsseEnvelope {
    payload: String,
    #[serde(rename = "payloadType")]
    payload_type: String,
    #[serde(default)]
    signatures: Vec<DsseSignature>,
}

#[derive(Debug, Clone, Deserialize)]
struct DsseSignature {
    sig: String,
}

#[derive(Debug, Clone, Deserialize)]
struct VerificationMaterial {
    certificate: Option<CertificateRaw>,
}

#[derive(Debug, Clone, Deserialize)]
struct CertificateRaw {
    #[serde(rename = "rawBytes")]
    raw_bytes: String,
}

// -- gh CLI verification (kept for backward compat) --

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

// -- DSSE cryptographic verification (no binary download) --

/// Compute the DSSE Pre-Authentication Encoding (PAE).
///
/// PAE = "DSSEv1" + SP + len(payloadType) + SP + payloadType + SP + len(payload) + SP + payload
fn dsse_pae(payload_type: &str, payload: &[u8]) -> Vec<u8> {
    let mut pae = Vec::new();
    pae.extend_from_slice(b"DSSEv1 ");
    pae.extend_from_slice(payload_type.len().to_string().as_bytes());
    pae.push(b' ');
    pae.extend_from_slice(payload_type.as_bytes());
    pae.push(b' ');
    pae.extend_from_slice(payload.len().to_string().as_bytes());
    pae.push(b' ');
    pae.extend_from_slice(payload);
    pae
}

/// Verify a DSSE envelope's signature using the certificate's public key.
///
/// Returns Ok(()) if the signature is cryptographically valid.
fn verify_dsse_signature(envelope: &DsseEnvelope, cert_der: &[u8]) -> Result<()> {
    let sig_b64 = &envelope
        .signatures
        .first()
        .context("no signatures in DSSE envelope")?
        .sig;

    let sig_bytes = BASE64
        .decode(sig_b64)
        .context("invalid base64 in signature")?;

    let payload_bytes = BASE64
        .decode(&envelope.payload)
        .context("invalid base64 in payload")?;

    let pae = dsse_pae(&envelope.payload_type, &payload_bytes);

    // Parse the X.509 certificate and extract the ECDSA P-256 public key
    let cert = Certificate::from_der(cert_der).context("failed to parse X.509 certificate")?;
    let spki = cert
        .tbs_certificate
        .subject_public_key_info
        .subject_public_key
        .as_bytes()
        .context("missing public key bytes")?;

    let verifying_key =
        VerifyingKey::from_sec1_bytes(spki).context("failed to parse ECDSA P-256 public key")?;

    let signature =
        Signature::from_der(&sig_bytes).context("failed to parse ECDSA DER signature")?;

    verifying_key
        .verify(&pae, &signature)
        .map_err(|e| anyhow::anyhow!("DSSE signature verification failed: {e}"))?;

    Ok(())
}

/// Extract subject digests and predicate type from a DSSE payload.
fn parse_dsse_payload(envelope: &DsseEnvelope) -> Result<Statement> {
    let payload_bytes = BASE64
        .decode(&envelope.payload)
        .context("invalid base64 in payload")?;
    let stmt: Statement =
        serde_json::from_slice(&payload_bytes).context("failed to parse in-toto statement")?;
    Ok(stmt)
}

// -- Release attestation collection --

const SKIP_EXTENSIONS: &[&str] = &[".sha256", ".sha512", ".md5", ".sig", ".asc", ".pem"];
const SKIP_NAMES: &[&str] = &["sha256.sum", "sha512.sum", "checksums.txt"];

fn is_attestation_irrelevant(name: &str) -> bool {
    let lower = name.to_lowercase();
    SKIP_EXTENSIONS.iter().any(|ext| lower.ends_with(ext))
        || SKIP_NAMES.iter().any(|n| lower == *n)
        || lower.ends_with(".sh")
        || lower.ends_with(".ps1")
}

fn parse_sha256_line(line: &str) -> Option<&str> {
    let hex = line.split_whitespace().next()?;
    if hex.len() == 64 && hex.chars().all(|c| c.is_ascii_hexdigit()) {
        Some(hex)
    } else {
        None
    }
}

/// Fetch attestation bundles for a given digest via the GitHub REST API.
fn fetch_attestation_bundles(
    client: &GitHubClient,
    owner: &str,
    repo: &str,
    digest: &str,
) -> Result<Vec<ApiBundle>> {
    let path = format!("/repos/{owner}/{repo}/attestations/sha256:{digest}");
    let body = client.get(&path)?;
    let resp: AttestationsApiResponse =
        serde_json::from_str(&body).context("failed to parse attestations API response")?;
    Ok(resp
        .attestations
        .into_iter()
        .filter_map(|a| a.bundle)
        .collect())
}

/// Verify a single attestation bundle against an expected digest.
///
/// Performs:
/// 1. DSSE signature verification using the certificate's public key
/// 2. Subject digest matching against the expected digest
fn verify_bundle(
    bundle: &ApiBundle,
    asset_name: &str,
    expected_digest: &str,
) -> (ArtifactAttestation, Option<String>) {
    let envelope = match &bundle.dsse_envelope {
        Some(e) => e,
        None => {
            return (
                ArtifactAttestation {
                    subject: asset_name.to_string(),
                    subject_digest: Some(format!("sha256:{expected_digest}")),
                    predicate_type: String::new(),
                    signer_workflow: None,
                    source_repo: None,
                    verification: VerificationOutcome::Failed {
                        detail: "attestation bundle missing DSSE envelope".to_string(),
                    },
                },
                None,
            );
        }
    };

    // 1. Parse the payload to get predicate type and subject digests
    let stmt = match parse_dsse_payload(envelope) {
        Ok(s) => s,
        Err(e) => {
            return (
                ArtifactAttestation {
                    subject: asset_name.to_string(),
                    subject_digest: Some(format!("sha256:{expected_digest}")),
                    predicate_type: String::new(),
                    signer_workflow: None,
                    source_repo: None,
                    verification: VerificationOutcome::Failed {
                        detail: format!("failed to parse DSSE payload: {e}"),
                    },
                },
                None,
            );
        }
    };

    // 2. Check that the expected digest appears in the attestation subjects
    let digest_matched = stmt
        .subject
        .iter()
        .any(|s| s.digest.get("sha256").is_some_and(|d| d == expected_digest));

    if !digest_matched {
        return (
            ArtifactAttestation {
                subject: asset_name.to_string(),
                subject_digest: Some(format!("sha256:{expected_digest}")),
                predicate_type: stmt.predicate_type,
                signer_workflow: None,
                source_repo: None,
                verification: VerificationOutcome::SignatureInvalid {
                    detail: format!(
                        "digest sha256:{expected_digest} not found in attestation subjects"
                    ),
                },
            },
            None,
        );
    }

    // 3. Verify DSSE signature using the certificate
    let sig_result = bundle
        .verification_material
        .as_ref()
        .and_then(|vm| vm.certificate.as_ref())
        .map(|cert_raw| {
            let cert_der = BASE64
                .decode(&cert_raw.raw_bytes)
                .context("invalid base64 in certificate")?;
            verify_dsse_signature(envelope, &cert_der)
        });

    let verification = match sig_result {
        Some(Ok(())) => VerificationOutcome::Verified,
        Some(Err(e)) => VerificationOutcome::SignatureInvalid {
            detail: format!("{e}"),
        },
        None => VerificationOutcome::Failed {
            detail: "no certificate in verification material".to_string(),
        },
    };

    let error_detail = match &verification {
        VerificationOutcome::Verified => None,
        VerificationOutcome::SignatureInvalid { detail }
        | VerificationOutcome::Failed { detail } => Some(detail.clone()),
        _ => None,
    };

    (
        ArtifactAttestation {
            subject: asset_name.to_string(),
            subject_digest: Some(format!("sha256:{expected_digest}")),
            predicate_type: stmt.predicate_type,
            signer_workflow: None,
            source_repo: None,
            verification,
        },
        error_detail,
    )
}

/// Collect and cryptographically verify attestations for release assets.
///
/// 1. Downloads `.sha256` sidecar files (a few KB) to obtain digests
/// 2. Fetches attestation bundles from the GitHub Attestations REST API
/// 3. Verifies DSSE signatures using the certificate's public key
/// 4. Confirms subject digests match the expected sidecar digests
///
/// No release binaries are downloaded.
pub fn collect_release_attestations(
    owner: &str,
    repo: &str,
    tag: &str,
    assets: &[ReleaseAsset],
    client: &GitHubClient,
) -> EvidenceState<Vec<ArtifactAttestation>> {
    if assets.is_empty() {
        return EvidenceState::not_applicable();
    }

    let verifiable: Vec<&ReleaseAsset> = assets
        .iter()
        .filter(|a| !is_attestation_irrelevant(&a.name))
        .collect();

    if verifiable.is_empty() {
        return EvidenceState::not_applicable();
    }

    let digest_map = collect_sidecar_digests(owner, repo, tag, assets);

    let mut attestations = Vec::new();
    let mut gaps: Vec<EvidenceGap> = Vec::new();

    for asset in &verifiable {
        let digest = match digest_map.get(asset.name.as_str()) {
            Some(d) => d.clone(),
            None => {
                gaps.push(EvidenceGap::CollectionFailed {
                    source: "gh-attestation-api".to_string(),
                    subject: asset.name.clone(),
                    detail: "no .sha256 sidecar file found for digest lookup".to_string(),
                });
                attestations.push(ArtifactAttestation {
                    subject: asset.name.clone(),
                    subject_digest: None,
                    predicate_type: String::new(),
                    signer_workflow: None,
                    source_repo: None,
                    verification: VerificationOutcome::Failed {
                        detail: "cannot verify without digest".to_string(),
                    },
                });
                continue;
            }
        };

        match fetch_attestation_bundles(client, owner, repo, &digest) {
            Ok(bundles) if !bundles.is_empty() => {
                for bundle in &bundles {
                    let (att, err) = verify_bundle(bundle, &asset.name, &digest);
                    if let Some(detail) = err {
                        gaps.push(EvidenceGap::CollectionFailed {
                            source: "dsse-verification".to_string(),
                            subject: asset.name.clone(),
                            detail,
                        });
                    }
                    attestations.push(att);
                }
            }
            Ok(_) => {
                attestations.push(ArtifactAttestation {
                    subject: asset.name.clone(),
                    subject_digest: Some(format!("sha256:{digest}")),
                    predicate_type: String::new(),
                    signer_workflow: None,
                    source_repo: None,
                    verification: VerificationOutcome::AttestationAbsent {
                        detail: "no attestation found via API".to_string(),
                    },
                });
            }
            Err(e) => {
                let detail = format!("{e}");
                attestations.push(ArtifactAttestation {
                    subject: asset.name.clone(),
                    subject_digest: Some(format!("sha256:{digest}")),
                    predicate_type: String::new(),
                    signer_workflow: None,
                    source_repo: None,
                    verification: classify_verification_error(&detail),
                });
            }
        }
    }

    if gaps.is_empty() {
        EvidenceState::complete(attestations)
    } else {
        EvidenceState::partial(attestations, gaps)
    }
}

/// Download `.sha256` sidecar files and build a map of asset_name -> hex_digest.
fn collect_sidecar_digests(
    owner: &str,
    repo: &str,
    tag: &str,
    assets: &[ReleaseAsset],
) -> HashMap<String, String> {
    let sidecar_names: Vec<&str> = assets
        .iter()
        .filter(|a| a.name.ends_with(".sha256"))
        .map(|a| a.name.as_str())
        .collect();

    if sidecar_names.is_empty() {
        return HashMap::new();
    }

    let tmp_dir = match tempfile::tempdir() {
        Ok(d) => d,
        Err(_) => return HashMap::new(),
    };

    let repo_full = format!("{owner}/{repo}");
    let mut cmd = Command::new("gh");
    cmd.args(["release", "download", tag, "--repo", &repo_full]);
    for name in &sidecar_names {
        cmd.args(["--pattern", name]);
    }
    cmd.args(["--dir", &tmp_dir.path().to_string_lossy(), "--clobber"]);

    if cmd.output().map(|o| o.status.success()).unwrap_or(false) {
        let mut map = HashMap::new();
        for name in &sidecar_names {
            let path = tmp_dir.path().join(name);
            if let Ok(content) = std::fs::read_to_string(&path)
                && let Some(line) = content.lines().next()
                && let Some(hex) = parse_sha256_line(line)
            {
                let asset_name = name.trim_end_matches(".sha256");
                map.insert(asset_name.to_string(), hex.to_string());
            }
        }
        map
    } else {
        HashMap::new()
    }
}

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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_assets_returns_not_applicable() {
        let client = mock_client();
        let result = collect_release_attestations("owner", "repo", "v1.0.0", &[], &client);
        assert!(matches!(result, EvidenceState::NotApplicable));
    }

    #[test]
    fn filter_skips_checksums_and_scripts() {
        assert!(is_attestation_irrelevant("ruff-x86_64.tar.gz.sha256"));
        assert!(is_attestation_irrelevant("binary.sig"));
        assert!(is_attestation_irrelevant("sha256.sum"));
        assert!(is_attestation_irrelevant("installer.sh"));
        assert!(is_attestation_irrelevant("installer.ps1"));
        assert!(!is_attestation_irrelevant("ruff-x86_64-linux.tar.gz"));
        assert!(!is_attestation_irrelevant("dist-manifest.json"));
    }

    #[test]
    fn only_checksums_returns_not_applicable() {
        let client = mock_client();
        let assets = vec![
            ReleaseAsset {
                name: "file.sha256".to_string(),
                browser_download_url: String::new(),
            },
            ReleaseAsset {
                name: "sha256.sum".to_string(),
                browser_download_url: String::new(),
            },
        ];
        let result = collect_release_attestations("owner", "repo", "v1.0.0", &assets, &client);
        assert!(matches!(result, EvidenceState::NotApplicable));
    }

    #[test]
    fn parse_sha256_line_formats() {
        assert_eq!(
            parse_sha256_line(
                "e573cdb504fce521af501cc16b7018fb6560ac0e7af5d05056c942b3a1ad5a79  ruff-aarch64-apple-darwin.tar.gz"
            ),
            Some("e573cdb504fce521af501cc16b7018fb6560ac0e7af5d05056c942b3a1ad5a79")
        );
        assert_eq!(
            parse_sha256_line(
                "beb2eb063e52f197694fb79045cef276735a7becbbd8f8f79e1c99613a12d7e7 *ruff-aarch64-pc-windows-msvc.zip"
            ),
            Some("beb2eb063e52f197694fb79045cef276735a7becbbd8f8f79e1c99613a12d7e7")
        );
        assert_eq!(parse_sha256_line("not-a-hash  file.txt"), None);
    }

    #[test]
    fn dsse_pae_encoding() {
        let pae = dsse_pae("application/vnd.in-toto+json", b"{}");
        let expected = b"DSSEv1 28 application/vnd.in-toto+json 2 {}";
        assert_eq!(pae, expected);
    }

    fn mock_client() -> GitHubClient {
        let cfg = crate::config::GitHubConfig {
            token: String::new(),
            repo: String::new(),
            host: "https://api.github.com".to_string(),
        };
        GitHubClient::new(&cfg).unwrap()
    }
}
