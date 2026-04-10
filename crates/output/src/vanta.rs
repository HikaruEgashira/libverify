//! Vanta-compatible JSON output format.
//!
//! Delegates to [`libverify_vanta::adapter`] for the actual conversion.

use anyhow::Result;
use libverify_core::assessment::{BatchReport, VerificationResult};

pub fn render(result: &VerificationResult, only_failures: bool) -> Result<String> {
    libverify_vanta::render(result, only_failures)
}

pub fn render_batch(batch: &BatchReport, only_failures: bool) -> Result<String> {
    libverify_vanta::render_batch(batch, only_failures)
}
