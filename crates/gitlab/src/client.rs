use std::thread;
use std::time::Duration;

use anyhow::{bail, Context, Result};
use reqwest::blocking::Client;
use reqwest::header::{HeaderMap, HeaderValue, USER_AGENT};
use reqwest::StatusCode;
use serde::de::DeserializeOwned;

use crate::config::GitLabConfig;

const MAX_BODY_SIZE: usize = 10 * 1024 * 1024;
const MAX_PAGES: usize = 10;
const MAX_HTTP_ATTEMPTS: usize = 3;
const INITIAL_RETRY_DELAY_MS: u64 = 250;

pub struct GitLabClient {
    client: Client,
    base_url: String,
}

impl GitLabClient {
    pub fn new(cfg: &GitLabConfig) -> Result<Self> {
        let mut headers = HeaderMap::new();
        headers.insert(
            "PRIVATE-TOKEN",
            HeaderValue::from_str(&cfg.token).context("invalid token")?,
        );
        headers.insert(
            USER_AGENT,
            HeaderValue::from_static("libverify-gitlab/0.1.0"),
        );

        let client = Client::builder()
            .default_headers(headers)
            .build()
            .context("failed to create HTTP client")?;

        Ok(Self {
            client,
            base_url: format!("https://{}/api/v4", cfg.host),
        })
    }

    /// URL-encode a project path (`owner/repo` → `owner%2Frepo`).
    pub fn encode_project(owner: &str, repo: &str) -> String {
        format!("{}%2F{}", owner, repo)
    }

    /// GET request returning body as string. `path` is relative to `base_url`.
    pub fn get(&self, path: &str) -> Result<String> {
        let url = format!("{}{}", self.base_url, path);
        let mut delay = Duration::from_millis(INITIAL_RETRY_DELAY_MS);

        for attempt in 1..=MAX_HTTP_ATTEMPTS {
            let resp = self
                .client
                .get(&url)
                .send()
                .context("HTTP request failed")?;

            if resp.status() == StatusCode::TOO_MANY_REQUESTS {
                if attempt < MAX_HTTP_ATTEMPTS {
                    let wait = resp
                        .headers()
                        .get("retry-after")
                        .and_then(|v| v.to_str().ok())
                        .and_then(|v| v.parse::<u64>().ok())
                        .map(Duration::from_secs)
                        .unwrap_or(delay);
                    thread::sleep(wait);
                    delay *= 2;
                    continue;
                }
                bail!("rate limited after {MAX_HTTP_ATTEMPTS} attempts");
            }

            if resp.status().is_server_error() && attempt < MAX_HTTP_ATTEMPTS {
                thread::sleep(delay);
                delay *= 2;
                continue;
            }

            if !resp.status().is_success() {
                bail!(
                    "GitLab API error: {} {}",
                    resp.status().as_u16(),
                    resp.status().canonical_reason().unwrap_or("Unknown")
                );
            }

            let body = resp.text().context("failed to read response body")?;
            if body.len() > MAX_BODY_SIZE {
                bail!("response body exceeds {MAX_BODY_SIZE} bytes");
            }
            return Ok(body);
        }
        bail!("request failed after {MAX_HTTP_ATTEMPTS} attempts")
    }

    /// GET and deserialize JSON.
    pub fn get_json<T: DeserializeOwned>(&self, path: &str) -> Result<T> {
        let body = self.get(path)?;
        serde_json::from_str(&body).context("failed to parse JSON response")
    }

    /// Auto-paginate using GitLab's `x-next-page` header.
    pub fn paginate<T: DeserializeOwned>(&self, path: &str) -> Result<Vec<T>> {
        let mut all: Vec<T> = Vec::new();
        let separator = if path.contains('?') { "&" } else { "?" };
        let mut current_page = 1u32;

        for _ in 0..MAX_PAGES {
            let paged_path =
                format!("{path}{separator}per_page=100&page={current_page}");
            let url = format!("{}{}", self.base_url, paged_path);

            let mut delay = Duration::from_millis(INITIAL_RETRY_DELAY_MS);
            let resp = 'retry: {
                for attempt in 1..=MAX_HTTP_ATTEMPTS {
                    let r = self
                        .client
                        .get(&url)
                        .send()
                        .context("HTTP request failed")?;

                    if r.status() == StatusCode::TOO_MANY_REQUESTS
                        && attempt < MAX_HTTP_ATTEMPTS
                    {
                        let wait = r
                            .headers()
                            .get("retry-after")
                            .and_then(|v| v.to_str().ok())
                            .and_then(|v| v.parse::<u64>().ok())
                            .map(Duration::from_secs)
                            .unwrap_or(delay);
                        thread::sleep(wait);
                        delay *= 2;
                        continue;
                    }

                    if r.status().is_server_error() && attempt < MAX_HTTP_ATTEMPTS {
                        thread::sleep(delay);
                        delay *= 2;
                        continue;
                    }

                    break 'retry r;
                }
                bail!(
                    "paginate request failed after {MAX_HTTP_ATTEMPTS} attempts"
                );
            };

            if !resp.status().is_success() {
                bail!(
                    "GitLab API error: {} {}",
                    resp.status().as_u16(),
                    resp.status().canonical_reason().unwrap_or("Unknown")
                );
            }

            let next_page = resp
                .headers()
                .get("x-next-page")
                .and_then(|v| v.to_str().ok())
                .and_then(|v| v.parse::<u32>().ok());

            let body = resp.text().context("failed to read response body")?;
            if body.len() > MAX_BODY_SIZE {
                bail!("response body exceeds {MAX_BODY_SIZE} bytes");
            }

            let page: Vec<T> =
                serde_json::from_str(&body).context("failed to parse paginated JSON")?;

            if page.is_empty() {
                break;
            }
            all.extend(page);

            match next_page {
                Some(np) if np > current_page => current_page = np,
                _ => break,
            }
        }

        Ok(all)
    }

    /// Fetch raw file content from a repository at a specific ref.
    ///
    /// `project` must already be URL-encoded (e.g. `owner%2Frepo`).
    pub fn get_file_content(
        &self,
        project: &str,
        file_path: &str,
        ref_sha: &str,
    ) -> Result<String> {
        let encoded_path = file_path.replace('/', "%2F");
        let api_path = format!(
            "/projects/{project}/repository/files/{encoded_path}/raw?ref={ref_sha}"
        );
        self.get(&api_path)
    }
}
