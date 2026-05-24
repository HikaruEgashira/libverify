//! PyPI Attestation API client (PEP 740).
//!
//! Fetches Sigstore-based provenance attestations from PyPI's Integrity API
//! to enrich `DependencySignatureEvidence` with publisher identity, source
//! repository, and transparency log information.
//!
//! Two-phase approach:
//! 1. Simple API (`/simple/{project}/`) → find provenance URL for the version's sdist
//! 2. Integrity API (provenance URL) → fetch attestation with publisher + Rekor entry
//!
//! API docs: https://docs.pypi.org/api/integrity/

use anyhow::{Context, Result, bail};
use reqwest::blocking::Client;
use reqwest::header::{ACCEPT, HeaderMap, HeaderValue, USER_AGENT};
use serde::Deserialize;

use libverify_core::evidence::DependencySignatureEvidence;
use libverify_core::evidence::VerificationOutcome;

const PYPI_SIMPLE_URL: &str = "https://pypi.org/simple";

pub struct PypiAttestationClient {
    client: Client,
}

/// Provenance data extracted from a PyPI attestation.
#[derive(Debug, Clone)]
pub struct PypiProvenance {
    pub source_repo: Option<String>,
    pub signer_identity: Option<String>,
    pub transparency_log_index: Option<String>,
}

impl PypiAttestationClient {
    pub fn new() -> Result<Self> {
        let mut headers = HeaderMap::new();
        headers.insert(
            USER_AGENT,
            HeaderValue::from_static("libverify-github/0.1.0"),
        );

        let mut builder = Client::builder()
            .default_headers(headers)
            .timeout(std::time::Duration::from_secs(10))
            .no_proxy();
        if let Some(proxy_url) = std::env::var("HTTPS_PROXY")
            .or_else(|_| std::env::var("https_proxy"))
            .ok()
        {
            if let Ok(proxy) = reqwest::Proxy::https(&proxy_url) {
                let no_proxy = std::env::var("NO_PROXY")
                    .or_else(|_| std::env::var("no_proxy"))
                    .ok()
                    .and_then(|s| reqwest::NoProxy::from_string(&s));
                builder = builder.proxy(proxy.no_proxy(no_proxy));
            }
        }
        let client = builder
            .build()
            .context("failed to create PyPI attestation HTTP client")?;
        Ok(Self { client })
    }

    /// Fetch provenance for a single package version.
    /// Returns `None` if the package has no attestation.
    pub fn fetch_provenance(&self, name: &str, version: &str) -> Result<Option<PypiProvenance>> {
        // Phase 1: Get provenance URL from Simple API
        let provenance_url = self.find_provenance_url(name, version)?;
        let provenance_url = match provenance_url {
            Some(url) => url,
            None => return Ok(None),
        };

        // Phase 2: Fetch provenance
        let response = self
            .client
            .get(&provenance_url)
            .header(ACCEPT, "application/vnd.pypi.integrity.v1+json")
            .send()
            .with_context(|| format!("PyPI provenance request failed for {name}@{version}"))?;

        let status = response.status();
        if status.as_u16() == 404 {
            return Ok(None);
        }
        if !status.is_success() {
            bail!(
                "PyPI provenance API error for {name}@{version}: {}",
                status.as_u16()
            );
        }

        let payload: ProvenanceResponse = response
            .json()
            .with_context(|| format!("failed to parse PyPI provenance for {name}@{version}"))?;

        let bundle = match payload.attestation_bundles.into_iter().next() {
            Some(b) => b,
            None => return Ok(None),
        };

        let source_repo = bundle.publisher.as_ref().map(|p| {
            // Normalize to full URL if it's just owner/repo
            if p.repository.starts_with("http") {
                p.repository.clone()
            } else {
                format!("https://github.com/{}", p.repository)
            }
        });

        let signer_identity = bundle.publisher.as_ref().map(|p| match &p.workflow {
            Some(wf) => format!("{}@{}", p.repository, wf),
            None => p.repository.clone(),
        });

        let tlog_index = bundle
            .attestations
            .into_iter()
            .next()
            .and_then(|a| a.verification_material)
            .and_then(|vm| vm.transparency_entries)
            .and_then(|entries| entries.into_iter().next())
            .map(|entry| entry.log_index);

        Ok(Some(PypiProvenance {
            source_repo,
            signer_identity,
            transparency_log_index: tlog_index,
        }))
    }

    /// Find the provenance URL for a package version from the Simple API.
    /// Prefers sdist (.tar.gz), falls back to first wheel.
    fn find_provenance_url(&self, name: &str, version: &str) -> Result<Option<String>> {
        // PyPI normalizes names: underscores → hyphens, lowercase
        let normalized = name.to_lowercase().replace('_', "-");
        let url = format!("{PYPI_SIMPLE_URL}/{normalized}/");

        let response = self
            .client
            .get(&url)
            .header(ACCEPT, "application/vnd.pypi.simple.v1+json")
            .send()
            .with_context(|| format!("PyPI Simple API request failed for {name}"))?;

        if !response.status().is_success() {
            return Ok(None);
        }

        let listing: SimpleApiResponse = response
            .json()
            .with_context(|| format!("failed to parse PyPI Simple API for {name}"))?;

        // Filter to files matching this version
        let version_prefix = format!("{normalized}-{version}");
        let matching: Vec<&SimpleFile> = listing
            .files
            .iter()
            .filter(|f| {
                let fname = f.filename.to_lowercase().replace('_', "-");
                fname.starts_with(&version_prefix) && f.provenance.is_some()
            })
            .collect();

        // Prefer sdist, then any file with provenance
        let chosen = matching
            .iter()
            .find(|f| f.filename.ends_with(".tar.gz"))
            .or_else(|| matching.first());

        Ok(chosen.and_then(|f| f.provenance.clone()))
    }

    /// Enrich PyPI dependencies in-place with provenance from the attestation API.
    /// Uses bounded parallel fetching.
    pub fn enrich_pypi_deps(&self, deps: &mut [DependencySignatureEvidence]) {
        const CONCURRENCY: usize = 16;

        let pypi_indices: Vec<usize> = deps
            .iter()
            .enumerate()
            .filter(|(_, d)| d.registry.as_deref() == Some("pypi.org"))
            .map(|(i, _)| i)
            .collect();

        if pypi_indices.is_empty() {
            return;
        }

        let total = pypi_indices.len();
        eprintln!("Fetching PyPI provenance for {total} packages ({CONCURRENCY} concurrent)...");

        let queries: Vec<(usize, String, String)> = pypi_indices
            .iter()
            .map(|&i| (i, deps[i].name.clone(), deps[i].version.clone()))
            .collect();

        let results: Vec<(usize, Option<PypiProvenance>)> = std::thread::scope(|scope| {
            let (tx, rx) = std::sync::mpsc::channel::<(usize, String, String)>();
            let rx = std::sync::Arc::new(std::sync::Mutex::new(rx));
            let (result_tx, result_rx) =
                std::sync::mpsc::channel::<(usize, Option<PypiProvenance>)>();
            let done = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));

            let workers: Vec<_> = (0..CONCURRENCY.min(total))
                .map(|_| {
                    let rx = rx.clone();
                    let result_tx = result_tx.clone();
                    let done = done.clone();
                    let client = &self;
                    scope.spawn(move || {
                        loop {
                            let work = {
                                let guard = rx.lock().unwrap();
                                guard.recv().ok()
                            };
                            match work {
                                Some((idx, name, version)) => {
                                    let prov = match client.fetch_provenance(&name, &version) {
                                        Ok(p) => p,
                                        Err(e) => {
                                            eprintln!(
                                                "Warning: PyPI attestation for {name}@{version}: {e:#}"
                                            );
                                            None
                                        }
                                    };
                                    let count = done.fetch_add(1, std::sync::atomic::Ordering::Relaxed) + 1;
                                    if count.is_multiple_of(50) || count == total {
                                        eprint!("\r  [{count}/{total}]");
                                    }
                                    let _ = result_tx.send((idx, prov));
                                }
                                None => break,
                            }
                        }
                    })
                })
                .collect();

            drop(result_tx);

            for q in queries {
                let _ = tx.send(q);
            }
            drop(tx);

            let results: Vec<_> = result_rx.iter().collect();

            for w in workers {
                let _ = w.join();
            }

            results
        });

        eprintln!();

        let mut enriched = 0usize;
        for (idx, prov) in results {
            if let Some(prov) = prov {
                let dep = &mut deps[idx];
                dep.source_repo = prov.source_repo;
                dep.signer_identity = prov.signer_identity;
                if let Some(log_index) = prov.transparency_log_index {
                    dep.transparency_log_uri =
                        Some(format!("https://search.sigstore.dev/?logIndex={log_index}"));
                }
                if dep.verification == VerificationOutcome::ChecksumMatch {
                    dep.verification = VerificationOutcome::Verified;
                    dep.signature_mechanism = Some("sigstore".to_string());
                }
                enriched += 1;
            }
        }

        eprintln!("  {enriched}/{total} PyPI packages have provenance attestations");
    }
}

// --- PyPI Simple API response types ---

#[derive(Debug, Deserialize)]
struct SimpleApiResponse {
    files: Vec<SimpleFile>,
}

#[derive(Debug, Deserialize)]
struct SimpleFile {
    filename: String,
    provenance: Option<String>,
}

// --- PyPI Integrity API response types ---

#[derive(Debug, Deserialize)]
struct ProvenanceResponse {
    attestation_bundles: Vec<AttestationBundle>,
}

#[derive(Debug, Deserialize)]
struct AttestationBundle {
    publisher: Option<Publisher>,
    attestations: Vec<PypiAttestation>,
}

#[derive(Debug, Deserialize)]
struct Publisher {
    repository: String,
    workflow: Option<String>,
}

#[derive(Debug, Deserialize)]
struct PypiAttestation {
    verification_material: Option<PypiVerificationMaterial>,
}

#[derive(Debug, Deserialize)]
struct PypiVerificationMaterial {
    transparency_entries: Option<Vec<TransparencyEntry>>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct TransparencyEntry {
    log_index: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pypi_attestation_client_builds_without_proxy() {
        // Exercises the .no_proxy() + env-var bypass path without any HTTPS_PROXY set.
        PypiAttestationClient::new().unwrap();
    }

    #[test]
    fn simple_api_response_deserializes() {
        let json = r#"{
            "files": [
                {
                    "filename": "foo-1.0.0.tar.gz",
                    "provenance": "https://pypi.org/integrity/foo/1.0.0/foo-1.0.0.tar.gz/provenance"
                },
                {
                    "filename": "foo-1.0.0-py3-none-any.whl",
                    "provenance": null
                }
            ]
        }"#;
        let resp: SimpleApiResponse = serde_json::from_str(json).unwrap();
        assert_eq!(resp.files.len(), 2);
        assert!(resp.files[0].provenance.is_some());
        assert!(resp.files[1].provenance.is_none());
    }

    #[test]
    fn provenance_response_deserializes() {
        let json = r#"{
            "attestation_bundles": [{
                "publisher": {
                    "kind": "GitHub",
                    "repository": "pyca/cryptography",
                    "workflow": "pypi-publish.yml",
                    "environment": null
                },
                "attestations": [{
                    "version": 1,
                    "verification_material": {
                        "transparency_entries": [{
                            "logIndex": "152047507",
                            "logId": {"keyId": "test"}
                        }]
                    }
                }]
            }]
        }"#;
        let resp: ProvenanceResponse = serde_json::from_str(json).unwrap();
        let bundle = &resp.attestation_bundles[0];
        assert_eq!(
            bundle.publisher.as_ref().unwrap().repository,
            "pyca/cryptography"
        );
        let tlog = &bundle.attestations[0]
            .verification_material
            .as_ref()
            .unwrap()
            .transparency_entries
            .as_ref()
            .unwrap()[0];
        assert_eq!(tlog.log_index, "152047507");
    }
}
