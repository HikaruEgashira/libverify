//! Vanta compliance platform adapter for libverify.
//!
//! This crate provides:
//! - [`model`] — Vanta API data types matching the Build Integrations schema
//! - [`adapter`] — Conversion from libverify [`VerificationResult`] / [`BatchReport`]
//!   to Vanta custom resources
//! - [`client`] — HTTP client for pushing resources to the Vanta API
//!
//! # Usage
//!
//! ```no_run
//! use libverify_vanta::{adapter, client::VantaClient, client::VantaConfig};
//! # fn example(result: &libverify_core::assessment::VerificationResult) -> anyhow::Result<()> {
//! let resource = adapter::to_resource(result, false);
//! let client = VantaClient::new(VantaConfig {
//!     token: "your-oauth-token".to_string(),
//!     base_url: None,
//! })?;
//! client.push_resource(&resource)?;
//! # Ok(())
//! # }
//! ```

pub mod adapter;
pub mod client;
pub mod model;

pub use adapter::{render, render_batch, to_resource, to_resources};
pub use model::{VantaControl, VantaProperties, VantaResource};
