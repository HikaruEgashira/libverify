pub mod adapter;
pub mod attestation;
pub mod client;
pub mod config;
pub mod dependency;
pub mod graphql;
pub mod npm_attestation;
pub mod ossinsight;
pub mod posture;
pub mod pr_api;
pub mod pypi_attestation;
pub mod range;
pub mod release_api;
pub mod types;
pub mod verify;

pub use client::GitHubClient;
pub use config::GitHubConfig;
pub use verify::GitHubAdapter;
pub use verify::{
    // Assessment (cheap, re-runnable with different policies)
    assess_bundle,
    assess_repo_bundle,
    collect_pr_batch_evidence,
    // Evidence collection (expensive, cacheable)
    collect_pr_evidence,
    // Phased release evidence collection (for progressive output)
    collect_release_attestation_evidence,
    collect_release_evidence,
    collect_release_pr_evidence,
    collect_release_repo_evidence,
    collect_repo_evidence,
    // Utilities
    exit_if_assessment_fails,
    // Convenience wrappers (collect + assess)
    verify_pr,
    verify_pr_batch,
    verify_release,
    verify_repo,
};
