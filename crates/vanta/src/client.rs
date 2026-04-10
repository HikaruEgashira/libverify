//! Vanta API client.
//!
//! Handles OAuth 2.0 authentication and resource push to
//! `POST /v1/resources/custom`.
//!
//! See <https://developer.vanta.com/docs/build-integrations>.

use anyhow::{Context, Result};
use reqwest::blocking::Client;

use crate::model::VantaResource;

const VANTA_API_BASE: &str = "https://api.vanta.com";
const CUSTOM_RESOURCE_PATH: &str = "/v1/resources/custom";

/// Configuration for the Vanta API client.
pub struct VantaConfig {
    /// OAuth 2.0 Bearer token.
    pub token: String,
    /// API base URL. Defaults to `https://api.vanta.com`.
    pub base_url: Option<String>,
}

/// Client for the Vanta Build Integrations API.
pub struct VantaClient {
    http: Client,
    base_url: String,
    token: String,
}

impl VantaClient {
    pub fn new(config: VantaConfig) -> Result<Self> {
        let http = Client::builder()
            .user_agent("libverify-vanta")
            .build()
            .context("failed to create HTTP client")?;
        Ok(Self {
            http,
            base_url: config
                .base_url
                .unwrap_or_else(|| VANTA_API_BASE.to_string()),
            token: config.token,
        })
    }

    /// Push a single custom resource to Vanta.
    pub fn push_resource(&self, resource: &VantaResource) -> Result<()> {
        let url = format!("{}{}", self.base_url, CUSTOM_RESOURCE_PATH);
        let resp = self
            .http
            .post(&url)
            .bearer_auth(&self.token)
            .json(resource)
            .send()
            .with_context(|| format!("failed to POST to {url}"))?;

        let status = resp.status();
        if !status.is_success() {
            let body = resp.text().unwrap_or_default();
            anyhow::bail!("Vanta API returned {status}: {body}");
        }
        Ok(())
    }

    /// Push multiple resources to Vanta (one request per resource).
    pub fn push_resources(&self, resources: &[VantaResource]) -> Result<()> {
        for resource in resources {
            self.push_resource(resource)
                .with_context(|| format!("failed to push resource {}", resource.resource_id))?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_base_url() {
        let client = VantaClient::new(VantaConfig {
            token: "test-token".to_string(),
            base_url: None,
        })
        .unwrap();
        assert_eq!(client.base_url, "https://api.vanta.com");
    }

    #[test]
    fn custom_base_url() {
        let client = VantaClient::new(VantaConfig {
            token: "test-token".to_string(),
            base_url: Some("https://staging.api.vanta.com".to_string()),
        })
        .unwrap();
        assert_eq!(client.base_url, "https://staging.api.vanta.com");
    }
}
