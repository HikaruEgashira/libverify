use std::thread;
use std::time::Duration;

use anyhow::{Context, Result, bail};
use reqwest::blocking::Client;
use reqwest::header::{ACCEPT, AUTHORIZATION, HeaderMap, HeaderValue, RETRY_AFTER, USER_AGENT};
use reqwest::{StatusCode, blocking::Response};
use serde::de::DeserializeOwned;

use crate::config::GitHubConfig;

const MAX_BODY_SIZE: usize = 10 * 1024 * 1024; // 10MB
const MAX_PAGES: usize = 10;
const MAX_HTTP_ATTEMPTS: usize = 3;
const INITIAL_RETRY_DELAY_MS: u64 = 250;

pub struct GitHubClient {
    client: Client,
    base_url: String,
}

impl GitHubClient {
    pub fn new(cfg: &GitHubConfig) -> Result<Self> {
        Self::with_user_agent(cfg, "libverify-github/0.1.0")
    }

    pub fn with_user_agent(cfg: &GitHubConfig, user_agent: &str) -> Result<Self> {
        let mut headers = HeaderMap::new();
        headers.insert(
            AUTHORIZATION,
            HeaderValue::from_str(&format!("Bearer {}", cfg.token)).context("invalid token")?,
        );
        headers.insert(
            ACCEPT,
            HeaderValue::from_static("application/vnd.github.v3+json"),
        );
        headers.insert(
            "X-GitHub-Api-Version",
            HeaderValue::from_static("2022-11-28"),
        );
        headers.insert(
            USER_AGENT,
            HeaderValue::from_str(user_agent).context("invalid User-Agent")?,
        );

        let client = Client::builder()
            .default_headers(headers)
            .build()
            .context("failed to create HTTP client")?;

        Ok(Self {
            client,
            base_url: format!("https://{}", cfg.host),
        })
    }

    /// Fetch raw file content from a repository at a specific ref.
    ///
    /// Uses the GitHub raw content media type to avoid base64 encoding.
    pub fn get_file_content(
        &self,
        owner: &str,
        repo: &str,
        path: &str,
        ref_sha: &str,
    ) -> Result<String> {
        let url = format!(
            "{}/repos/{owner}/{repo}/contents/{path}?ref={ref_sha}",
            self.base_url
        );
        let resp = self
            .client
            .get(&url)
            .header("Accept", "application/vnd.github.raw+json")
            .send()
            .context("failed to fetch file content")?;

        if !resp.status().is_success() {
            bail!(
                "failed to fetch {path}: {} {}",
                resp.status().as_u16(),
                resp.status().canonical_reason().unwrap_or("Unknown"),
            );
        }

        resp.text().context("failed to read file content")
    }

    /// GET request returning body as string.
    pub fn get(&self, path: &str) -> Result<String> {
        let (body, _) = self.get_internal(path)?;
        Ok(body)
    }

    /// GET request with pagination support. Returns (body, next_url).
    pub fn get_with_link(&self, path: &str) -> Result<(String, Option<String>)> {
        self.get_internal(path)
    }

    /// Paginate a GitHub API endpoint, collecting all items across pages.
    pub fn paginate<T: DeserializeOwned>(&self, initial_path: &str) -> Result<Vec<T>> {
        let mut all_items: Vec<T> = Vec::new();
        let mut current_path = initial_path.to_string();

        for _ in 0..MAX_PAGES {
            let (body, next_path) = self.get_with_link(&current_path)?;
            let items: Vec<T> =
                serde_json::from_str(&body).context("failed to parse paginated response")?;
            all_items.extend(items);

            match next_path {
                Some(next) => current_path = next,
                None => break,
            }
        }

        Ok(all_items)
    }

    /// Paginate a GitHub Search API endpoint whose response wraps items in `{ items: [...] }`.
    pub fn paginate_search<T: DeserializeOwned>(&self, initial_path: &str) -> Result<Vec<T>> {
        use crate::types::SearchResponse;

        let mut all_items: Vec<T> = Vec::new();
        let mut current_path = initial_path.to_string();

        for _ in 0..MAX_PAGES {
            let (body, next_path) = self.get_with_link(&current_path)?;
            let resp: SearchResponse<T> =
                serde_json::from_str(&body).context("failed to parse search response")?;
            all_items.extend(resp.items);

            match next_path {
                Some(next) => current_path = next,
                None => break,
            }
        }

        Ok(all_items)
    }

    /// POST a GraphQL query and return the response body.
    pub fn post_graphql(
        &self,
        query: &str,
        variables: Option<&serde_json::Value>,
    ) -> Result<String> {
        let url = format!("{}/graphql", self.base_url);
        let body = match variables {
            Some(vars) => serde_json::json!({ "query": query, "variables": vars }),
            None => serde_json::json!({ "query": query }),
        };

        for attempt in 0..MAX_HTTP_ATTEMPTS {
            match self.client.post(&url).json(&body).send() {
                Ok(resp) => {
                    let status = resp.status();
                    let retry_after_secs = parse_retry_after_secs(resp.headers().get(RETRY_AFTER));

                    if !status.is_success() {
                        if should_retry_status(status) && attempt + 1 < MAX_HTTP_ATTEMPTS {
                            thread::sleep(retry_delay_for(attempt, retry_after_secs));
                            continue;
                        }
                        bail!(
                            "GitHub GraphQL error: {} {}",
                            status.as_u16(),
                            status.canonical_reason().unwrap_or("Unknown")
                        );
                    }

                    let text = resp.text().context("failed to read GraphQL response")?;
                    if text.len() > MAX_BODY_SIZE {
                        bail!("GraphQL response too large: {} bytes", text.len());
                    }
                    return Ok(text);
                }
                Err(_err) if attempt + 1 < MAX_HTTP_ATTEMPTS => {
                    thread::sleep(retry_delay_for(attempt, None));
                }
                Err(err) => return Err(err).context("GraphQL request failed"),
            }
        }

        bail!("GraphQL request exhausted retry attempts")
    }

    fn get_internal(&self, path: &str) -> Result<(String, Option<String>)> {
        let url = format!("{}{}", self.base_url, path);
        for attempt in 0..MAX_HTTP_ATTEMPTS {
            match self.client.get(&url).send() {
                Ok(resp) => {
                    let status = resp.status();
                    let retry_after_secs = parse_retry_after_secs(resp.headers().get(RETRY_AFTER));

                    if !status.is_success() {
                        if should_retry_status(status) && attempt + 1 < MAX_HTTP_ATTEMPTS {
                            thread::sleep(retry_delay_for(attempt, retry_after_secs));
                            continue;
                        }

                        bail!(
                            "GitHub API error: {} {}",
                            status.as_u16(),
                            status.canonical_reason().unwrap_or("Unknown")
                        );
                    }

                    return parse_success_response(resp, &self.base_url);
                }
                Err(_err) if attempt + 1 < MAX_HTTP_ATTEMPTS => {
                    thread::sleep(retry_delay_for(attempt, None));
                }
                Err(err) => return Err(err).context("HTTP request failed"),
            }
        }

        bail!("GitHub API request exhausted retry attempts")
    }
}

fn parse_success_response(resp: Response, base_url: &str) -> Result<(String, Option<String>)> {
    let next_url = resp
        .headers()
        .get("link")
        .and_then(|v| v.to_str().ok())
        .and_then(|link| parse_link_next(link, base_url));

    let body = resp.text().context("failed to read response body")?;
    if body.len() > MAX_BODY_SIZE {
        bail!("response too large: {} bytes", body.len());
    }

    Ok((body, next_url))
}

fn should_retry_status(status: StatusCode) -> bool {
    status == StatusCode::TOO_MANY_REQUESTS || status.is_server_error()
}

fn parse_retry_after_secs(value: Option<&HeaderValue>) -> Option<u64> {
    value?.to_str().ok()?.parse::<u64>().ok()
}

fn retry_delay_for(attempt: usize, retry_after_secs: Option<u64>) -> Duration {
    if let Some(seconds) = retry_after_secs {
        return Duration::from_secs(seconds);
    }

    let multiplier = 1u64 << attempt.min(10);
    Duration::from_millis(INITIAL_RETRY_DELAY_MS.saturating_mul(multiplier))
}

/// Extract the path for rel="next" from a Link header.
fn parse_link_next(link_header: &str, base_prefix: &str) -> Option<String> {
    for part in link_header.split(',') {
        let part = part.trim();
        if !part.contains("rel=\"next\"") {
            continue;
        }
        let lt = part.find('<')?;
        let gt = part.find('>')?;
        let url = &part[lt + 1..gt];
        if let Some(path) = url.strip_prefix(base_prefix) {
            return Some(path.to_string());
        }
        return Some(url.to_string());
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_link_next_extracts_path() {
        let header = r#"<https://api.github.com/repos/o/r/pulls/1/files?page=2>; rel="next", <https://api.github.com/repos/o/r/pulls/1/files?page=5>; rel="last""#;
        let result = parse_link_next(header, "https://api.github.com");
        assert_eq!(result, Some("/repos/o/r/pulls/1/files?page=2".to_string()));
    }

    #[test]
    fn parse_link_next_returns_none_without_next() {
        let header = r#"<https://api.github.com/repos/o/r/pulls/1/files?page=5>; rel="last""#;
        let result = parse_link_next(header, "https://api.github.com");
        assert!(result.is_none());
    }

    #[test]
    fn should_retry_server_errors_and_rate_limits() {
        assert!(should_retry_status(StatusCode::INTERNAL_SERVER_ERROR));
        assert!(should_retry_status(StatusCode::SERVICE_UNAVAILABLE));
        assert!(should_retry_status(StatusCode::TOO_MANY_REQUESTS));
        assert!(!should_retry_status(StatusCode::NOT_FOUND));
    }

    #[test]
    fn parse_retry_after_secs_reads_integer_seconds() {
        let value = HeaderValue::from_static("7");
        assert_eq!(parse_retry_after_secs(Some(&value)), Some(7));
    }

    #[test]
    fn retry_delay_for_uses_exponential_backoff() {
        assert_eq!(retry_delay_for(0, None), Duration::from_millis(250));
        assert_eq!(retry_delay_for(1, None), Duration::from_millis(500));
        assert_eq!(retry_delay_for(2, None), Duration::from_millis(1000));
    }

    #[test]
    fn retry_delay_for_prefers_retry_after() {
        assert_eq!(retry_delay_for(2, Some(7)), Duration::from_secs(7));
    }
}
