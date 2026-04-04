use crate::evidence::EvidenceBundle;

/// Error type for platform adapter operations.
pub type AdapterResult<T> = Result<T, Box<dyn std::error::Error + Send + Sync>>;

/// Platform-agnostic evidence collection interface.
///
/// Implementations translate platform-specific APIs (GitHub, GitLab, Bitbucket, etc.)
/// into the platform-neutral [`EvidenceBundle`] that controls evaluate.
///
/// The trait covers the "expensive" evidence collection layer only.
/// Assessment (policy evaluation) is platform-independent and handled separately
/// by functions like `assess_bundle` / `assess_repo_bundle`.
pub trait PlatformAdapter: Send + Sync {
    /// Collect evidence for a single change request (PR / MR).
    fn collect_pr_evidence(
        &self,
        owner: &str,
        repo: &str,
        pr_number: u32,
    ) -> AdapterResult<EvidenceBundle>;

    /// Collect evidence for a batch of change requests.
    ///
    /// Returns `(subject_id, AdapterResult<EvidenceBundle>)` per item, preserving order.
    /// The default implementation calls [`collect_pr_evidence`] sequentially;
    /// platform adapters may override for batch-optimised API calls.
    fn collect_pr_batch_evidence(
        &self,
        owner: &str,
        repo: &str,
        pr_numbers: &[u32],
    ) -> Vec<(String, AdapterResult<EvidenceBundle>)> {
        pr_numbers
            .iter()
            .map(|&n| {
                let subject = format!("#{n}");
                let bundle = self.collect_pr_evidence(owner, repo, n);
                (subject, bundle)
            })
            .collect()
    }

    /// Collect evidence for a release (tag range).
    fn collect_release_evidence(
        &self,
        owner: &str,
        repo: &str,
        base_tag: &str,
        head_tag: &str,
    ) -> AdapterResult<EvidenceBundle>;

    /// Collect evidence for repository-level posture and dependencies at a given ref.
    fn collect_repo_evidence(
        &self,
        owner: &str,
        repo: &str,
        reference: &str,
    ) -> AdapterResult<EvidenceBundle>;
}
