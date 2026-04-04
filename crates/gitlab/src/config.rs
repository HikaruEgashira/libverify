use anyhow::{Result, bail};

pub struct GitLabConfig {
    pub token: String,
    pub host: String,
}

impl GitLabConfig {
    pub fn load() -> Result<Self> {
        let token = resolve_token()?;
        let host = std::env::var("GITLAB_HOST").unwrap_or_else(|_| "gitlab.com".to_string());
        validate_host(&host)?;
        Ok(Self { token, host })
    }
}

/// Try GITLAB_TOKEN, then GL_TOKEN, then CI_JOB_TOKEN.
fn resolve_token() -> Result<String> {
    for var in ["GITLAB_TOKEN", "GL_TOKEN", "CI_JOB_TOKEN"] {
        if let Some(val) = non_empty_env_var(var) {
            return Ok(normalize_secret(&val));
        }
    }
    bail!("GitLab token not found. Set one of: GITLAB_TOKEN, GL_TOKEN, CI_JOB_TOKEN")
}

/// Strip surrounding whitespace and remove common copy-paste artifacts.
fn normalize_secret(raw: &str) -> String {
    raw.trim()
        .trim_start_matches('"')
        .trim_end_matches('"')
        .trim_start_matches('\'')
        .trim_end_matches('\'')
        .to_string()
}

/// Return `Some(value)` only when the env var exists and is non-empty after trimming.
fn non_empty_env_var(name: &str) -> Option<String> {
    std::env::var(name)
        .ok()
        .map(|v| v.trim().to_string())
        .filter(|v| !v.is_empty())
}

/// SSRF protection: reject localhost, IP literals, IMDS endpoints, and bare
/// hostnames (no dots).
fn validate_host(host: &str) -> Result<()> {
    let lower = host.to_lowercase();

    // Reject hosts without a dot (e.g. "localhost", single-label names).
    if !lower.contains('.') {
        bail!("invalid GitLab host (no dot): {host}");
    }

    // Reject well-known loopback / localhost names.
    if lower == "localhost"
        || lower.ends_with(".localhost")
        || lower == "127.0.0.1"
        || lower == "[::1]"
        || lower == "::1"
    {
        bail!("GitLab host must not be localhost: {host}");
    }

    // Reject raw IPv4 addresses (simple heuristic: all chars are digits or dots).
    if lower.chars().all(|c| c.is_ascii_digit() || c == '.') {
        bail!("GitLab host must not be an IP address: {host}");
    }

    // Reject IPv6 bracket notation.
    if lower.starts_with('[') {
        bail!("GitLab host must not be an IP address: {host}");
    }

    // Reject AWS IMDS endpoint.
    if lower == "169.254.169.254" || lower.starts_with("169.254.169.254") {
        bail!("GitLab host must not be an IMDS endpoint: {host}");
    }

    // Reject GCP / Azure metadata endpoints.
    if lower == "metadata.google.internal" || lower == "metadata.azure.com" {
        bail!("GitLab host must not be a cloud metadata endpoint: {host}");
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    // ---- normalize_secret ----

    #[test]
    fn normalize_trims_whitespace() {
        assert_eq!(normalize_secret("  glpat-abc  "), "glpat-abc");
    }

    #[test]
    fn normalize_strips_double_quotes() {
        assert_eq!(normalize_secret("\"glpat-abc\""), "glpat-abc");
    }

    #[test]
    fn normalize_strips_single_quotes() {
        assert_eq!(normalize_secret("'glpat-abc'"), "glpat-abc");
    }

    #[test]
    fn normalize_noop_for_clean_value() {
        assert_eq!(normalize_secret("glpat-abc"), "glpat-abc");
    }

    // ---- non_empty_env_var ----

    #[test]
    fn non_empty_returns_none_when_unset() {
        // Use a key that is extremely unlikely to exist.
        assert!(non_empty_env_var("__LIBVERIFY_TEST_NONEXISTENT_VAR__").is_none());
    }

    #[test]
    fn non_empty_returns_none_for_blank() {
        unsafe { std::env::set_var("__LIBVERIFY_TEST_BLANK__", "   ") };
        assert!(non_empty_env_var("__LIBVERIFY_TEST_BLANK__").is_none());
        unsafe { std::env::remove_var("__LIBVERIFY_TEST_BLANK__") };
    }

    #[test]
    fn non_empty_returns_trimmed_value() {
        unsafe { std::env::set_var("__LIBVERIFY_TEST_OK__", "  hello  ") };
        assert_eq!(
            non_empty_env_var("__LIBVERIFY_TEST_OK__"),
            Some("hello".to_string())
        );
        unsafe { std::env::remove_var("__LIBVERIFY_TEST_OK__") };
    }

    // ---- validate_host ----

    #[test]
    fn validate_rejects_localhost() {
        assert!(validate_host("localhost").is_err());
    }

    #[test]
    fn validate_rejects_ip_address() {
        assert!(validate_host("192.168.1.1").is_err());
    }

    #[test]
    fn validate_rejects_ipv6_bracket() {
        assert!(validate_host("[::1]").is_err());
    }

    #[test]
    fn validate_accepts_gitlab_com() {
        assert!(validate_host("gitlab.com").is_ok());
    }

    #[test]
    fn validate_accepts_self_hosted() {
        assert!(validate_host("gitlab.example.com").is_ok());
    }
}
