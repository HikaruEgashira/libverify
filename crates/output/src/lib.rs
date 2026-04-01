pub mod json;
pub mod sarif;

pub use sarif::utc_now_rfc3339;

use anyhow::Result;
use libverify_core::assessment::{BatchReport, VerificationResult};

#[derive(Debug, Clone, Copy)]
pub enum Format {
    Json,
    Sarif,
}

pub struct OutputOptions {
    pub format: Format,
    pub only_failures: bool,
    /// Tool name for SARIF output (e.g. "gh-verify", "atlassian-verify").
    pub tool_name: String,
    /// Tool version for SARIF output.
    pub tool_version: String,
}

pub fn parse_format(s: &str) -> Result<Format> {
    match s {
        "json" => Ok(Format::Json),
        "sarif" => Ok(Format::Sarif),
        _ => anyhow::bail!("invalid format: {s} (use 'json' or 'sarif')"),
    }
}

pub fn render(opts: &OutputOptions, result: &VerificationResult) -> Result<String> {
    match opts.format {
        Format::Json => json::render(result, opts.only_failures),
        Format::Sarif => sarif::render(
            result,
            opts.only_failures,
            &opts.tool_name,
            &opts.tool_version,
        ),
    }
}

pub fn render_batch(opts: &OutputOptions, batch: &BatchReport) -> Result<String> {
    match opts.format {
        Format::Json => json::render_batch(batch, opts.only_failures),
        Format::Sarif => sarif::render_batch(
            batch,
            opts.only_failures,
            &opts.tool_name,
            &opts.tool_version,
        ),
    }
}
