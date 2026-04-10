pub mod json;
pub mod matrix;
pub mod sarif;
pub mod vanta;

pub use sarif::utc_now_rfc3339;

use anyhow::Result;
use libverify_core::assessment::{BatchReport, VerificationResult};

#[derive(Debug, Clone, Copy)]
pub enum Format {
    Json,
    Matrix,
    Sarif,
    Vanta,
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
        "matrix" => Ok(Format::Matrix),
        "sarif" => Ok(Format::Sarif),
        "vanta" => Ok(Format::Vanta),
        _ => anyhow::bail!("invalid format: {s} (use 'json', 'matrix', 'sarif', or 'vanta')"),
    }
}

pub fn render(opts: &OutputOptions, result: &VerificationResult) -> Result<String> {
    match opts.format {
        Format::Json => json::render(result, opts.only_failures),
        Format::Matrix => matrix::render(result, opts.only_failures),
        Format::Sarif => sarif::render(
            result,
            opts.only_failures,
            &opts.tool_name,
            &opts.tool_version,
        ),
        Format::Vanta => vanta::render(result, opts.only_failures),
    }
}

pub fn render_batch(opts: &OutputOptions, batch: &BatchReport) -> Result<String> {
    match opts.format {
        Format::Json => json::render_batch(batch, opts.only_failures),
        Format::Matrix => matrix::render_batch(batch, opts.only_failures),
        Format::Sarif => sarif::render_batch(
            batch,
            opts.only_failures,
            &opts.tool_name,
            &opts.tool_version,
        ),
        Format::Vanta => vanta::render_batch(batch, opts.only_failures),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use libverify_core::assessment::AssessmentReport;
    use libverify_core::control::{ControlFinding, builtin};
    use libverify_core::profile::{FindingSeverity, GateDecision, ProfileOutcome};

    fn opts(format: Format) -> OutputOptions {
        OutputOptions {
            format,
            only_failures: false,
            tool_name: "test".to_string(),
            tool_version: "0.1".to_string(),
        }
    }

    fn sample_result() -> VerificationResult {
        VerificationResult {
            report: AssessmentReport {
                profile_name: "test".to_string(),
                findings: vec![ControlFinding::satisfied(
                    builtin::id(builtin::REVIEW_INDEPENDENCE),
                    "ok",
                    vec![],
                )],
                outcomes: vec![ProfileOutcome {
                    control_id: builtin::id(builtin::REVIEW_INDEPENDENCE),
                    severity: FindingSeverity::Info,
                    decision: GateDecision::Pass,
                    rationale: "ok".to_string(),
                    annotations: Default::default(),
                }],
                severity_labels: Default::default(),
            },
            evidence: None,
        }
    }

    #[test]
    fn parse_format_valid() {
        assert!(matches!(parse_format("json").unwrap(), Format::Json));
        assert!(matches!(parse_format("matrix").unwrap(), Format::Matrix));
        assert!(matches!(parse_format("sarif").unwrap(), Format::Sarif));
        assert!(matches!(parse_format("vanta").unwrap(), Format::Vanta));
    }

    #[test]
    fn parse_format_invalid() {
        assert!(parse_format("xml").is_err());
        assert!(parse_format("").is_err());
    }

    #[test]
    fn render_json_format() {
        let output = render(&opts(Format::Json), &sample_result()).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&output).unwrap();
        assert_eq!(parsed["profile_name"], "test");
    }

    #[test]
    fn render_sarif_format() {
        let output = render(&opts(Format::Sarif), &sample_result()).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&output).unwrap();
        assert_eq!(parsed["version"], "2.1.0");
    }

    #[test]
    fn render_batch_json_format() {
        let batch = BatchReport {
            reports: vec![],
            total_pass: 0,
            total_review: 0,
            total_fail: 0,
            skipped: vec![],
        };
        let output = render_batch(&opts(Format::Json), &batch).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&output).unwrap();
        assert!(parsed["reports"].as_array().unwrap().is_empty());
    }

    #[test]
    fn render_batch_sarif_format() {
        let batch = BatchReport {
            reports: vec![],
            total_pass: 0,
            total_review: 0,
            total_fail: 0,
            skipped: vec![],
        };
        let output = render_batch(&opts(Format::Sarif), &batch).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&output).unwrap();
        assert_eq!(parsed["version"], "2.1.0");
    }
}
