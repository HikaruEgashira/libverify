//! Drata API data model.
//!
//! Structs target the Drata Public API v2 custom test results schema.
//! See <https://developers.drata.com/>.

use serde::{Deserialize, Serialize};

/// A test result payload for Drata's compliance monitoring API.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct DrataTestResult {
    /// Unique identifier for this test execution.
    pub external_id: String,
    /// Control identifier mapped to Drata's control library.
    pub control_id: String,
    /// Whether the test passed.
    pub passed: bool,
    /// Human-readable description of what was tested.
    pub description: String,
    /// Detailed evidence or rationale for the result.
    pub evidence: String,
    /// Timestamp of when the test was executed (ISO 8601).
    pub tested_at: String,
    /// Additional metadata about the verification.
    pub metadata: DrataMetadata,
}

/// Metadata attached to a Drata test result.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct DrataMetadata {
    /// The libverify profile used for verification.
    pub profile: String,
    /// Severity level: `"info"`, `"warning"`, or `"error"`.
    pub severity: String,
    /// Gate decision: `"pass"`, `"review"`, or `"fail"`.
    pub decision: String,
    /// Subject identifiers (PR numbers, commit SHAs, etc.).
    pub subjects: Vec<String>,
    /// Framework reference if available (e.g. "CC8.1").
    #[serde(skip_serializing_if = "Option::is_none")]
    pub framework_ref: Option<String>,
}

/// Wrapper for batch submission to Drata.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct DrataTestResultBatch {
    /// Source tool identifier.
    pub source: String,
    /// Source tool version.
    pub source_version: String,
    /// Individual test results.
    pub results: Vec<DrataTestResult>,
    /// Summary counts.
    pub summary: DrataSummary,
}

/// Summary statistics for a batch of test results.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct DrataSummary {
    pub total: usize,
    pub passed: usize,
    pub failed: usize,
    pub review: usize,
}
