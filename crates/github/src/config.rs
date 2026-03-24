use anyhow::{Context, Result, bail};
use std::process::Command;

pub struct GitHubConfig {
    pub token: String,
    pub repo: String,
    pub host: String,
}

impl GitHubConfig {
    pub fn load() -> Result<Self> {
        let token = resolve_token()?;
        let repo = std::env::var("GH_REPO").unwrap_or_default();
        let host = std::env::var("GH_HOST").unwrap_or_else(|_| "api.github.com".to_string());
        validate_host(&host)?;
        Ok(Self { token, repo, host })
    }
}

fn validate_host(host: &str) -> Result<()> {
    if host.is_empty() {
        bail!("invalid host: empty");
    }
    if host.starts_with("localhost") {
        bail!("invalid host: localhost not allowed");
    }
    if host.as_bytes()[0].is_ascii_digit() {
        bail!("invalid host: IP addresses not allowed");
    }
    // Block IMDS and special-purpose IP addresses (SSRF mitigation)
    if host.starts_with("169.254.169.254") {
        bail!("invalid host: IMDS endpoint not allowed");
    }
    if host.starts_with("fd00::") {
        bail!("invalid host: ULA IPv6 address not allowed");
    }
    if host.starts_with("fe80::") {
        bail!("invalid host: link-local IPv6 address not allowed");
    }
    if host.starts_with("0.0.0.0") {
        bail!("invalid host: 0.0.0.0 not allowed");
    }
    if host.starts_with("[::") {
        bail!("invalid host: unspecified IPv6 address not allowed");
    }
    if !host.contains('.') {
        bail!("invalid host: must contain a dot");
    }
    Ok(())
}

fn normalize_secret(value: &str) -> Option<String> {
    let trimmed = value.trim();
    (!trimmed.is_empty()).then(|| trimmed.to_string())
}

fn non_empty_env_var(name: &str) -> Option<String> {
    std::env::var(name)
        .ok()
        .and_then(|value| normalize_secret(&value))
}

fn resolve_token() -> Result<String> {
    if let Some(token) = non_empty_env_var("GH_TOKEN") {
        return Ok(token);
    }
    if let Some(token) = non_empty_env_var("GH_ENTERPRISE_TOKEN") {
        return Ok(token);
    }
    // Fallback: run `gh auth token`
    let output = Command::new("gh")
        .args(["auth", "token"])
        .output()
        .context("failed to run `gh auth token`")?;
    let token = String::from_utf8(output.stdout)
        .context("invalid UTF-8 in gh auth token output")?
        .trim()
        .to_string();
    if token.is_empty() {
        bail!("no GitHub token found. Set GH_TOKEN or run `gh auth login`");
    }
    Ok(token)
}

#[cfg(test)]
mod tests {
    use super::{non_empty_env_var, normalize_secret};

    #[test]
    fn normalize_secret_rejects_empty_and_whitespace() {
        assert_eq!(normalize_secret(""), None);
        assert_eq!(normalize_secret("   \n\t "), None);
    }

    #[test]
    fn normalize_secret_trims_valid_token() {
        assert_eq!(
            normalize_secret("  gho_test  "),
            Some("gho_test".to_string())
        );
    }

    #[test]
    fn non_empty_env_var_returns_none_when_not_set() {
        assert!(non_empty_env_var("GH_VERIFY_TEST_TOKEN__NOT_SET").is_none());
    }
}
