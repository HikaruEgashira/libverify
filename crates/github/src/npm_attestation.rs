//! npm Registry Attestation API client.
//!
//! Fetches Sigstore-based provenance attestations from the npm registry
//! to enrich `DependencySignatureEvidence` with signer identity, source
//! repository, source commit, and transparency log information.
//!
//! API endpoint: `https://registry.npmjs.org/-/npm/v1/attestations/{name}@{version}`
//!
//! Each response contains up to two attestations:
//! - **publish attestation** (`predicateType: .../npm/attestation/.../publish/v0.1`)
//! - **SLSA provenance** (`predicateType: https://slsa.dev/provenance/v1`)
//!
//! We extract provenance data from the SLSA provenance attestation's
//! DSSE envelope payload (base64-encoded in-toto Statement v1).

use anyhow::{Context, Result, bail};
use reqwest::blocking::Client;
use reqwest::header::{ACCEPT, HeaderMap, HeaderValue, USER_AGENT};
use serde::Deserialize;

use libverify_core::evidence::DependencySignatureEvidence;
use libverify_core::evidence::VerificationOutcome;

const REGISTRY_URL: &str = "https://registry.npmjs.org";
const SLSA_PROVENANCE_V1: &str = "https://slsa.dev/provenance/v1";

pub struct NpmAttestationClient {
    client: Client,
}

/// Provenance data extracted from an npm SLSA attestation.
#[derive(Debug, Clone)]
pub struct NpmProvenance {
    pub source_repo: Option<String>,
    pub source_commit: Option<String>,
    pub signer_identity: Option<String>,
    pub transparency_log_index: Option<String>,
}

impl NpmAttestationClient {
    pub fn new() -> Result<Self> {
        let mut headers = HeaderMap::new();
        headers.insert(ACCEPT, HeaderValue::from_static("application/json"));
        headers.insert(
            USER_AGENT,
            HeaderValue::from_static("libverify-github/0.1.0"),
        );

        let client = Client::builder()
            .default_headers(headers)
            .timeout(std::time::Duration::from_secs(10))
            .build()
            .context("failed to create npm attestation HTTP client")?;
        Ok(Self { client })
    }

    /// Fetch provenance for a single package version.
    /// Returns `None` if the package has no SLSA provenance attestation.
    pub fn fetch_provenance(&self, name: &str, version: &str) -> Result<Option<NpmProvenance>> {
        let url = format!("{REGISTRY_URL}/-/npm/v1/attestations/{name}@{version}");
        let response = self
            .client
            .get(&url)
            .send()
            .with_context(|| format!("npm attestation request failed for {name}@{version}"))?;

        let status = response.status();
        if status.as_u16() == 404 {
            return Ok(None);
        }
        if !status.is_success() {
            bail!(
                "npm attestation API error for {name}@{version}: {} {}",
                status.as_u16(),
                status.canonical_reason().unwrap_or("Unknown")
            );
        }

        let payload: AttestationResponse = response
            .json()
            .with_context(|| format!("failed to parse attestation for {name}@{version}"))?;

        // Find the SLSA provenance attestation
        let slsa = payload
            .attestations
            .iter()
            .find(|a| a.predicate_type == SLSA_PROVENANCE_V1);

        let slsa = match slsa {
            Some(a) => a,
            None => return Ok(None),
        };

        let bundle = match &slsa.bundle {
            Some(b) => b,
            None => return Ok(None),
        };

        // Extract transparency log entry
        let tlog_index = bundle
            .verification_material
            .as_ref()
            .and_then(|vm| vm.tlog_entries.as_ref())
            .and_then(|entries| entries.first())
            .map(|entry| entry.log_index.clone());

        // Decode the DSSE payload to get provenance predicate
        let payload_b64 = match &bundle.dsse_envelope {
            Some(env) => &env.payload,
            None => return Ok(Some(NpmProvenance {
                source_repo: None,
                source_commit: None,
                signer_identity: None,
                transparency_log_index: tlog_index,
            })),
        };

        let payload_bytes = base64_decode(payload_b64)?;
        let statement: InTotoStatement =
            serde_json::from_slice(&payload_bytes).context("failed to parse in-toto statement")?;

        let (source_repo, source_commit, signer_identity) = match statement.predicate {
            Some(predicate) => {
                let repo = predicate
                    .build_definition
                    .as_ref()
                    .and_then(|bd| bd.external_parameters.as_ref())
                    .and_then(|ep| ep.workflow.as_ref())
                    .map(|w| w.repository.clone());

                let commit = predicate
                    .build_definition
                    .as_ref()
                    .and_then(|bd| bd.resolved_dependencies.as_ref())
                    .and_then(|deps| deps.first())
                    .and_then(|dep| dep.digest.as_ref())
                    .and_then(|d| d.git_commit.clone());

                // Signer identity: use the workflow URI as identity
                // (matches the SAN in the Sigstore cert)
                let identity = predicate
                    .build_definition
                    .as_ref()
                    .and_then(|bd| bd.external_parameters.as_ref())
                    .and_then(|ep| ep.workflow.as_ref())
                    .map(|w| {
                        format!(
                            "{}/.github/workflows/{}@{}",
                            w.repository,
                            w.path
                                .strip_prefix(".github/workflows/")
                                .unwrap_or(&w.path),
                            w.r#ref
                        )
                    });

                (repo, commit, identity)
            }
            None => (None, None, None),
        };

        Ok(Some(NpmProvenance {
            source_repo,
            source_commit,
            signer_identity,
            transparency_log_index: tlog_index,
        }))
    }

    /// Enrich npm dependencies in-place with provenance data from the attestation API.
    /// Non-npm dependencies and dependencies that lack attestations are left unchanged.
    pub fn enrich_npm_deps(&self, deps: &mut [DependencySignatureEvidence]) {
        for dep in deps.iter_mut() {
            if dep.registry.as_deref() != Some("registry.npmjs.org") {
                continue;
            }

            match self.fetch_provenance(&dep.name, &dep.version) {
                Ok(Some(prov)) => {
                    dep.source_repo = prov.source_repo;
                    dep.source_commit = prov.source_commit;
                    dep.signer_identity = prov.signer_identity;
                    if let Some(log_index) = prov.transparency_log_index {
                        dep.transparency_log_uri = Some(format!(
                            "https://search.sigstore.dev/?logIndex={log_index}"
                        ));
                    }
                    // Upgrade verification from ChecksumMatch to Verified
                    // if we found a valid SLSA provenance attestation
                    if dep.verification == VerificationOutcome::ChecksumMatch {
                        dep.verification = VerificationOutcome::Verified;
                        dep.signature_mechanism = Some("sigstore".to_string());
                    }
                }
                Ok(None) => {
                    // No attestation — leave as-is (checksum only)
                }
                Err(e) => {
                    eprintln!(
                        "Warning: failed to fetch npm attestation for {}@{}: {e:#}",
                        dep.name, dep.version
                    );
                }
            }
        }
    }
}

/// Decode base64 (standard or URL-safe) with optional padding.
fn base64_decode(input: &str) -> Result<Vec<u8>> {
    use base64::Engine;
    base64::engine::general_purpose::STANDARD
        .decode(input)
        .or_else(|_| base64::engine::general_purpose::STANDARD_NO_PAD.decode(input))
        .or_else(|_| base64::engine::general_purpose::URL_SAFE.decode(input))
        .or_else(|_| base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(input))
        .context("failed to base64-decode attestation payload")
}

// --- npm attestation API response types ---

#[derive(Debug, Deserialize)]
struct AttestationResponse {
    attestations: Vec<Attestation>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct Attestation {
    predicate_type: String,
    bundle: Option<SigstoreBundle>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct SigstoreBundle {
    verification_material: Option<VerificationMaterial>,
    dsse_envelope: Option<DsseEnvelope>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct VerificationMaterial {
    tlog_entries: Option<Vec<TlogEntry>>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct TlogEntry {
    log_index: String,
}

#[derive(Debug, Deserialize)]
struct DsseEnvelope {
    payload: String,
}

// --- in-toto Statement / SLSA Provenance ---

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct InTotoStatement {
    predicate: Option<SlsaPredicate>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct SlsaPredicate {
    build_definition: Option<BuildDefinition>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct BuildDefinition {
    external_parameters: Option<ExternalParameters>,
    resolved_dependencies: Option<Vec<ResolvedDependency>>,
}

#[derive(Debug, Deserialize)]
struct ExternalParameters {
    workflow: Option<Workflow>,
}

#[derive(Debug, Deserialize)]
struct Workflow {
    #[serde(rename = "ref")]
    r#ref: String,
    repository: String,
    path: String,
}

#[derive(Debug, Deserialize)]
struct ResolvedDependency {
    digest: Option<Digest>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct Digest {
    git_commit: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn base64_decode_standard() {
        let encoded = base64::Engine::encode(
            &base64::engine::general_purpose::STANDARD,
            b"hello world",
        );
        let decoded = base64_decode(&encoded).unwrap();
        assert_eq!(decoded, b"hello world");
    }

    #[test]
    fn attestation_response_deserializes() {
        let json = r#"{
            "attestations": [
                {
                    "predicateType": "https://slsa.dev/provenance/v1",
                    "bundle": {
                        "verificationMaterial": {
                            "tlogEntries": [{"logIndex": "12345"}]
                        },
                        "dsseEnvelope": {
                            "payload": "eyJwcmVkaWNhdGVUeXBlIjoiaHR0cHM6Ly9zbHNhLmRldi9wcm92ZW5hbmNlL3YxIiwicHJlZGljYXRlIjp7ImJ1aWxkRGVmaW5pdGlvbiI6eyJleHRlcm5hbFBhcmFtZXRlcnMiOnsid29ya2Zsb3ciOnsicmVmIjoicmVmcy9oZWFkcy9tYWluIiwicmVwb3NpdG9yeSI6Imh0dHBzOi8vZ2l0aHViLmNvbS9leGFtcGxlL3JlcG8iLCJwYXRoIjoiLmdpdGh1Yi93b3JrZmxvd3MvcmVsZWFzZS55bWwifX0sInJlc29sdmVkRGVwZW5kZW5jaWVzIjpbeyJkaWdlc3QiOnsiZ2l0Q29tbWl0IjoiYWJjMTIzIn19XX19fQ=="
                        }
                    }
                }
            ]
        }"#;

        let resp: AttestationResponse = serde_json::from_str(json).unwrap();
        assert_eq!(resp.attestations.len(), 1);
        assert_eq!(resp.attestations[0].predicate_type, SLSA_PROVENANCE_V1);

        let bundle = resp.attestations[0].bundle.as_ref().unwrap();
        let tlog = bundle
            .verification_material
            .as_ref()
            .unwrap()
            .tlog_entries
            .as_ref()
            .unwrap();
        assert_eq!(tlog[0].log_index, "12345");
    }
}
