pub mod adapter;
pub mod client;
pub mod config;
pub mod posture;
pub mod types;
pub mod verify;

pub use client::GitLabClient;
pub use config::GitLabConfig;
pub use verify::GitLabAdapter;
