//! Drata API client.
//!
//! Handles API key authentication and test result submission to the Drata
//! Public API v2.
//!
//! See <https://developers.drata.com/>.

use anyhow::{Context, Result};
use reqwest::blocking::Client;

use crate::model::{DrataTestResult, DrataTestResultBatch};

const DRATA_API_BASE: &str = "https://public-api.drata.com";

/// Configuration for the Drata API client.
pub struct DrataConfig {
    /// API key (Bearer token).
    pub token: String,
    /// API base URL. Defaults to `https://public-api.drata.com`.
    pub base_url: Option<String>,
}

/// Client for the Drata Public API v2.
pub struct DrataClient {
    http: Client,
    base_url: String,
    token: String,
}

impl DrataClient {
    pub fn new(config: DrataConfig) -> Result<Self> {
        let http = Client::builder()
            .user_agent("libverify-drata")
            .build()
            .context("failed to create HTTP client")?;
        Ok(Self {
            http,
            base_url: config
                .base_url
                .unwrap_or_else(|| DRATA_API_BASE.to_string()),
            token: config.token,
        })
    }

    /// Push test results to Drata.
    pub fn push_results(&self, results: &[DrataTestResult]) -> Result<()> {
        let url = format!("{}/v2/controls/external-test-results", self.base_url);
        let resp = self
            .http
            .post(&url)
            .bearer_auth(&self.token)
            .json(results)
            .send()
            .with_context(|| format!("failed to POST to {url}"))?;

        let status = resp.status();
        if !status.is_success() {
            let body = resp.text().unwrap_or_default();
            anyhow::bail!("Drata API returned {status}: {body}");
        }
        Ok(())
    }

    /// Push a batch payload to Drata.
    pub fn push_batch(&self, batch: &DrataTestResultBatch) -> Result<()> {
        self.push_results(&batch.results)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_base_url() {
        let client = DrataClient::new(DrataConfig {
            token: "test-token".to_string(),
            base_url: None,
        })
        .unwrap();
        assert_eq!(client.base_url, "https://public-api.drata.com");
    }

    #[test]
    fn custom_base_url() {
        let client = DrataClient::new(DrataConfig {
            token: "test-token".to_string(),
            base_url: Some("https://staging.drata.com".to_string()),
        })
        .unwrap();
        assert_eq!(client.base_url, "https://staging.drata.com");
    }
}
