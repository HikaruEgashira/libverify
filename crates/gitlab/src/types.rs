use serde::Deserialize;

#[derive(Debug, Clone, Deserialize)]
pub struct MrMetadata {
    pub iid: u32,
    pub title: String,
    #[serde(default)]
    pub description: Option<String>,
    #[serde(default)]
    pub author: Option<MrAuthor>,
    pub sha: String,
    pub target_branch: String,
    pub source_branch: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct MrAuthor {
    pub username: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct MrChangesResponse {
    #[serde(default)]
    pub changes: Vec<MrChange>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct MrChange {
    pub old_path: String,
    pub new_path: String,
    #[serde(default)]
    pub diff: Option<String>,
    #[serde(default)]
    pub new_file: bool,
    #[serde(default)]
    pub renamed_file: bool,
    #[serde(default)]
    pub deleted_file: bool,
}

#[derive(Debug, Clone, Deserialize)]
pub struct MrApprovals {
    #[serde(default)]
    pub approved_by: Vec<ApprovalEntry>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct ApprovalEntry {
    pub user: MrAuthor,
}

#[derive(Debug, Clone, Deserialize)]
pub struct MrCommit {
    pub id: String,
    pub author_name: String,
    #[serde(default)]
    pub authored_date: Option<String>,
    #[serde(default)]
    pub parent_ids: Vec<String>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct MrPipeline {
    pub id: u64,
    pub status: String,
    pub sha: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct PipelineJob {
    pub name: String,
    pub status: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct ProtectedBranch {
    pub name: String,
    #[serde(default)]
    pub push_access_levels: Vec<AccessLevel>,
    #[serde(default)]
    pub merge_access_levels: Vec<AccessLevel>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct AccessLevel {
    pub access_level: u32,
}

#[derive(Debug, Clone, Deserialize)]
pub struct CompareResponse {
    #[serde(default)]
    pub commits: Vec<CompareCommit>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct CompareCommit {
    pub id: String,
    pub message: String,
    pub author_name: String,
    #[serde(default)]
    pub parent_ids: Vec<String>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct CommitMr {
    pub iid: u32,
}

#[derive(Debug, Clone, Deserialize)]
pub struct ProjectMember {
    pub access_level: u32,
}

#[derive(Debug, Clone, Deserialize)]
pub struct ProtectedTag {
    pub name: String,
}
