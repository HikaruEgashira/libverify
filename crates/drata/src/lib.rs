//! Drata compliance platform adapter for libverify.
//!
//! This crate provides:
//! - [`model`] — Drata API data types matching the Public API v2 schema
//! - [`adapter`] — Conversion from libverify [`VerificationResult`] / [`BatchReport`]
//!   to Drata test results
//! - [`client`] — HTTP client for pushing results to the Drata API
//!
//! # Usage
//!
//! ```no_run
//! use libverify_drata::{adapter, client::DrataClient, client::DrataConfig};
//! # fn example(result: &libverify_core::assessment::VerificationResult) -> anyhow::Result<()> {
//! let results = adapter::to_test_results(result, false);
//! let client = DrataClient::new(DrataConfig {
//!     token: "your-api-key".to_string(),
//!     base_url: None,
//! })?;
//! client.push_results(&results)?;
//! # Ok(())
//! # }
//! ```

pub mod adapter;
pub mod client;
pub mod model;

pub use adapter::{render, render_batch, to_batch, to_test_results};
pub use model::{DrataMetadata, DrataSummary, DrataTestResult, DrataTestResultBatch};
