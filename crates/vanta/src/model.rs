//! Vanta API data model.
//!
//! Structs match the Vanta Build Integrations API custom resource schema
//! (`POST /v1/resources/custom`). See <https://developer.vanta.com/docs/build-integrations>.

use serde::{Deserialize, Serialize};

/// A custom resource to be pushed to Vanta via their Build Integrations API.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct VantaResource {
    pub resource_id: String,
    pub resource_type: String,
    pub display_name: String,
    pub description: String,
    /// Overall status: `"PASS"`, `"WARN"`, or `"FAIL"`.
    pub status: String,
    pub status_description: String,
    pub properties: VantaProperties,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct VantaProperties {
    pub profile: String,
    pub controls: Vec<VantaControl>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct VantaControl {
    pub control_id: String,
    pub status: String,
    pub decision: String,
    pub severity: String,
    pub rationale: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub framework_ref: Option<String>,
}
