use anyhow::{Context, Result, bail};
use reqwest::blocking::Client;
use reqwest::header::{ACCEPT, HeaderMap, HeaderValue, USER_AGENT};
use serde::{Deserialize, Serialize};

const BASE_URL: &str = "https://api.ossinsight.io/v1";

pub struct OssInsightClient {
    client: Client,
}

impl OssInsightClient {
    pub fn new() -> Result<Self> {
        Self::with_user_agent("libverify-github/0.1.0")
    }

    pub fn with_user_agent(user_agent: &str) -> Result<Self> {
        let mut headers = HeaderMap::new();
        headers.insert(ACCEPT, HeaderValue::from_static("application/json"));
        headers.insert(
            USER_AGENT,
            HeaderValue::from_str(user_agent).context("invalid User-Agent")?,
        );

        let client = Client::builder()
            .default_headers(headers)
            .build()
            .context("failed to create OSS Insight HTTP client")?;
        Ok(Self { client })
    }

    pub fn ranking_by_prs(
        &self,
        collection_id: u64,
        period: &str,
    ) -> Result<Vec<CollectionRepoRank>> {
        self.get_rows(&format!(
            "{BASE_URL}/collections/{collection_id}/ranking_by_prs/?period={period}"
        ))
    }

    pub fn pull_request_creators(
        &self,
        owner: &str,
        repo: &str,
        page_size: u32,
    ) -> Result<Vec<PullRequestCreator>> {
        self.get_rows(&format!(
            "{BASE_URL}/repos/{owner}/{repo}/pull_request_creators/?sort=prs-desc&exclude_bots=true&page=1&page_size={page_size}"
        ))
    }

    fn get_rows<T: for<'de> Deserialize<'de>>(&self, url: &str) -> Result<Vec<T>> {
        let response = self
            .client
            .get(url)
            .send()
            .context("OSS Insight request failed")?;
        let status = response.status();
        if !status.is_success() {
            bail!(
                "OSS Insight API error: {} {}",
                status.as_u16(),
                status.canonical_reason().unwrap_or("Unknown")
            );
        }

        let payload: SqlRowsResponse<T> = response
            .json()
            .context("failed to parse OSS Insight response")?;
        Ok(payload.data.rows)
    }
}

#[derive(Debug, Clone, Deserialize)]
struct SqlRowsResponse<T> {
    data: SqlRows<T>,
}

#[derive(Debug, Clone, Deserialize)]
struct SqlRows<T> {
    rows: Vec<T>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct CollectionRepoRank {
    pub repo_id: String,
    pub repo_name: String,
    pub current_period_growth: String,
    pub past_period_growth: String,
    pub growth_pop: String,
    pub rank_pop: String,
    pub total: String,
    pub current_period_rank: String,
    pub past_period_rank: String,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct PullRequestCreator {
    pub id: String,
    pub login: String,
    pub name: String,
    pub prs: String,
    pub first_pr_opened_at: String,
    pub first_pr_merged_at: String,
}
