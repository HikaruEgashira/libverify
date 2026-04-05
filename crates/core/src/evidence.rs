use std::fmt;

use serde::{Deserialize, Serialize};

/// Represents the completeness of a collected evidence value.
///
/// Controls use this to distinguish between a verified absence and an
/// evidence-collection failure, which maps to different control statuses.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(tag = "state", rename_all = "snake_case")]
pub enum EvidenceState<T> {
    /// All expected data was collected successfully.
    Complete { value: T },
    /// Data was collected but some aspects are missing or degraded.
    Partial { value: T, gaps: Vec<EvidenceGap> },
    /// No usable data could be collected; only gap descriptions remain.
    Missing { gaps: Vec<EvidenceGap> },
    /// The evidence category does not apply to this context.
    #[default]
    NotApplicable,
}

impl<T> EvidenceState<T> {
    pub fn complete(value: T) -> Self {
        Self::Complete { value }
    }

    pub fn partial(value: T, gaps: Vec<EvidenceGap>) -> Self {
        Self::Partial { value, gaps }
    }

    pub fn missing(gaps: Vec<EvidenceGap>) -> Self {
        Self::Missing { gaps }
    }

    pub fn not_applicable() -> Self {
        Self::NotApplicable
    }

    pub fn value(&self) -> Option<&T> {
        match self {
            Self::Complete { value } | Self::Partial { value, .. } => Some(value),
            Self::Missing { .. } | Self::NotApplicable => None,
        }
    }

    pub fn gaps(&self) -> &[EvidenceGap] {
        match self {
            Self::Partial { gaps, .. } | Self::Missing { gaps } => gaps,
            Self::Complete { .. } | Self::NotApplicable => &[],
        }
    }

    pub fn has_gaps(&self) -> bool {
        !self.gaps().is_empty()
    }
}

/// Describes why a piece of evidence is incomplete or absent.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum EvidenceGap {
    CollectionFailed {
        source: String,
        subject: String,
        detail: String,
    },
    Truncated {
        source: String,
        subject: String,
    },
    MissingField {
        source: String,
        subject: String,
        field: String,
    },
    DiffUnavailable {
        subject: String,
    },
    Unsupported {
        source: String,
        capability: String,
    },
}

impl fmt::Display for EvidenceGap {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::CollectionFailed {
                source,
                subject,
                detail,
            } => write!(f, "collection failed: {source}/{subject}: {detail}"),
            Self::Truncated { source, subject } => write!(f, "truncated: {source}/{subject}"),
            Self::MissingField {
                source,
                subject,
                field,
            } => write!(f, "missing field: {source}/{subject}.{field}"),
            Self::DiffUnavailable { subject } => write!(f, "diff unavailable: {subject}"),
            Self::Unsupported { source, capability } => {
                write!(f, "unsupported: {source}/{capability}")
            }
        }
    }
}

/// Platform-independent identifier for a change request (e.g. a pull request).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChangeRequestId {
    pub system: String,
    pub value: String,
}

impl ChangeRequestId {
    pub fn new(system: impl Into<String>, value: impl Into<String>) -> Self {
        Self {
            system: system.into(),
            value: value.into(),
        }
    }
}

impl fmt::Display for ChangeRequestId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}:{}", self.system, self.value)
    }
}

/// Reference to an external work item (issue, Jira ticket, etc.).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WorkItemRef {
    pub system: String,
    pub value: String,
}

/// A file or artifact that was modified in a change request.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChangedAsset {
    pub path: String,
    pub diff_available: bool,
    #[serde(default)]
    pub additions: u32,
    #[serde(default)]
    pub deletions: u32,
    #[serde(default)]
    pub status: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub diff: Option<String>,
}

/// Normalized outcome of a review action, independent of platform terminology.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ApprovalDisposition {
    Approved,
    Rejected,
    Commented,
    Dismissed,
    Unknown,
}

/// A single review decision recorded against a change request.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ApprovalDecision {
    pub actor: String,
    pub disposition: ApprovalDisposition,
    pub submitted_at: Option<String>,
}

/// Cryptographic verification state for a source revision.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuthenticityEvidence {
    pub verified: bool,
    pub mechanism: Option<String>,
}

impl AuthenticityEvidence {
    pub fn new(verified: bool, mechanism: Option<String>) -> Self {
        Self {
            verified,
            mechanism,
        }
    }
}

/// A single commit or source revision associated with a change request.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SourceRevision {
    pub id: String,
    pub authored_by: Option<String>,
    pub committed_at: Option<String>,
    pub merge: bool,
    pub authenticity: EvidenceState<AuthenticityEvidence>,
}

/// Normalized representation of a governed change request (e.g. a pull request).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GovernedChange {
    pub id: ChangeRequestId,
    pub title: String,
    pub summary: Option<String>,
    pub submitted_by: Option<String>,
    pub changed_assets: EvidenceState<Vec<ChangedAsset>>,
    pub approval_decisions: EvidenceState<Vec<ApprovalDecision>>,
    pub source_revisions: EvidenceState<Vec<SourceRevision>>,
    pub work_item_refs: EvidenceState<Vec<WorkItemRef>>,
}

impl GovernedChange {
    /// Returns true if this change was submitted by a known merge/rollup bot.
    /// Bot-submitted PRs aggregate already-reviewed changes and should not
    /// be individually evaluated for review controls.
    pub fn is_bot_submitted(&self) -> bool {
        let Some(author) = self.submitted_by.as_deref() else {
            return false;
        };
        let lower = author.to_ascii_lowercase();
        const BOT_SUBMITTERS: &[&str] = &[
            "bors",
            "bors[bot]",
            "mergify[bot]",
            "mergify",
            "dependabot[bot]",
            "dependabot",
            "renovate[bot]",
            "renovate",
            "k8s-ci-robot",
            "github-actions[bot]",
            "copybara-service[bot]",
        ];
        BOT_SUBMITTERS.contains(&lower.as_str()) || lower.ends_with("[bot]")
    }
}

/// A release or deployment batch that promotes one or more source revisions.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PromotionBatch {
    pub id: String,
    pub source_revisions: EvidenceState<Vec<SourceRevision>>,
    pub linked_change_requests: EvidenceState<Vec<ChangeRequestId>>,
}

/// Structured outcome of attestation verification.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "outcome", rename_all = "snake_case")]
pub enum VerificationOutcome {
    /// Cryptographic signature verified (Sigstore, PGP, cosign, etc.).
    Verified,
    /// Checksum/integrity hash matched but no cryptographic signature was verified.
    /// This confirms download integrity but NOT authenticity.
    ChecksumMatch,
    SignatureInvalid {
        detail: String,
    },
    SignerMismatch {
        detail: String,
    },
    TransparencyLogMissing {
        detail: String,
    },
    AttestationAbsent {
        detail: String,
    },
    DigestMismatch {
        detail: String,
    },
    Failed {
        detail: String,
    },
}

impl VerificationOutcome {
    /// Returns true for both `Verified` (signature) and `ChecksumMatch` (integrity).
    pub fn is_verified(&self) -> bool {
        matches!(self, Self::Verified | Self::ChecksumMatch)
    }

    /// Returns true only for cryptographic signature verification.
    pub fn is_cryptographically_signed(&self) -> bool {
        matches!(self, Self::Verified)
    }

    pub fn failure_detail(&self) -> Option<&str> {
        match self {
            Self::Verified | Self::ChecksumMatch => None,
            Self::SignatureInvalid { detail }
            | Self::SignerMismatch { detail }
            | Self::TransparencyLogMissing { detail }
            | Self::AttestationAbsent { detail }
            | Self::DigestMismatch { detail }
            | Self::Failed { detail } => Some(detail),
        }
    }

    pub fn failure_kind(&self) -> Option<&'static str> {
        match self {
            Self::Verified | Self::ChecksumMatch => None,
            Self::SignatureInvalid { .. } => Some("signature_invalid"),
            Self::SignerMismatch { .. } => Some("signer_mismatch"),
            Self::TransparencyLogMissing { .. } => Some("transparency_log_missing"),
            Self::AttestationAbsent { .. } => Some("attestation_absent"),
            Self::DigestMismatch { .. } => Some("digest_mismatch"),
            Self::Failed { .. } => Some("failed"),
        }
    }
}

/// Result of verifying an artifact's build provenance attestation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ArtifactAttestation {
    pub subject: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub subject_digest: Option<String>,
    pub predicate_type: String,
    pub signer_workflow: Option<String>,
    pub source_repo: Option<String>,
    pub verification: VerificationOutcome,
}

/// Conclusion of a CI check run, normalized across platforms.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CheckConclusion {
    Success,
    Failure,
    Neutral,
    Cancelled,
    Skipped,
    TimedOut,
    ActionRequired,
    Pending,
    Unknown,
}

/// Evidence for a single CI check run executed against a commit.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CheckRunEvidence {
    pub name: String,
    pub conclusion: CheckConclusion,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub app_slug: Option<String>,
}

/// Provenance and signature verification evidence for a single dependency.
///
/// Supports multiple verification mechanisms including:
/// - **npm provenance**: Sigstore-signed SLSA provenance via `npm audit signatures`
/// - **Sigstore/cosign**: General Sigstore verification with Rekor transparency log
/// - **PGP signatures**: Traditional GPG/PGP package signatures
/// - **Checksum pinning**: Lock-file checksum verification (e.g. Cargo.lock, package-lock.json)
///
/// The `verification` field uses `VerificationOutcome` for structured failure reasons,
/// matching the pattern used by `ArtifactAttestation`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DependencySignatureEvidence {
    /// Package name (e.g. "serde", "lodash").
    pub name: String,
    /// Package version (e.g. "1.0.204", "4.17.21").
    pub version: String,
    /// Registry origin (e.g. "crates.io", "registry.npmjs.org").
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub registry: Option<String>,
    /// Structured verification outcome, reusing `VerificationOutcome` for consistency
    /// with `ArtifactAttestation`. `Verified` = signature valid, otherwise structured failure.
    pub verification: VerificationOutcome,
    /// Signing mechanism (e.g. "sigstore", "pgp", "checksum").
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signature_mechanism: Option<String>,
    /// Signer identity: OIDC issuer URI, public key fingerprint, or email.
    /// For npm provenance this is the GitHub Actions OIDC token subject.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signer_identity: Option<String>,
    /// Source repository that built the package (from SLSA provenance predicate).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source_repo: Option<String>,
    /// Source commit SHA at which the package was built.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source_commit: Option<String>,
    /// Expected artifact digest from lock file (e.g. "sha512:..." from Cargo.lock/package-lock.json).
    /// Populated by lock-file parsers. Compare with `actual_digest` to detect artifact replacement.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pinned_digest: Option<String>,
    /// Actual artifact digest computed from downloaded artifact at install/build time.
    /// Populated by build-time adapters (not lock-file parsers). When both `pinned_digest`
    /// and `actual_digest` are present, `has_digest_mismatch()` in the control detects
    /// registry-side artifact replacement attacks.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub actual_digest: Option<String>,
    /// Transparency log entry URL (e.g. Rekor log index for Sigstore).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub transparency_log_uri: Option<String>,
    /// Whether this is a direct dependency (true) or transitive (false).
    /// Transitive dependencies are more susceptible to typosquatting attacks.
    #[serde(default = "default_true")]
    pub is_direct: bool,
}

fn default_true() -> bool {
    true
}

/// Provenance capability levels supported by a package registry.
///
/// Registries evolve at different speeds. This enum captures the highest
/// SLSA Dependencies level a registry's infrastructure can currently support,
/// allowing controls to skip dependencies from registries that lack the
/// required infrastructure rather than producing false positives.
///
/// Current ecosystem status (as of March 2026):
/// - **npm** (`registry.npmjs.org`): L3 — Sigstore keyless signing + Rekor.
///   GA since Oct 2023, 134+ high-impact projects adopted.
/// - **PyPI** (`pypi.org`): L3 — Trusted Publishers + Sigstore attestations
///   (Fulcio + Rekor, same stack as npm). 17% of uploads include attestations.
///   Packages with attestations provide full L3: signer identity
///   (publisher.repository + Fulcio cert SAN) and Rekor transparency log.
/// - **Maven Central**: L3 capability — Sigstore `.sigstore.json` validation
///   added Jan 2025 (opt-in). PGP `.asc` still mandatory. Very low Sigstore
///   adoption. No dedicated query API (URL convention only).
/// - **crates.io**: L1 only — SHA-256 checksums in Cargo.lock.
///   Trusted Publishing (RFC #3691) covers auth only; Sigstore RFC #3403
///   proposed but not merged.
/// - **Go** (`proxy.golang.org`): L1 only — `sum.golang.org` provides
///   tamper-evident checksum log but no provenance/signing.
/// - **NuGet** (`nuget.org`): L1 — X.509 signing exists but no
///   Sigstore/attestation API at registry level.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum RegistryProvenanceCapability {
    /// L1: integrity only (checksum). No cryptographic signing infrastructure.
    ChecksumOnly,
    /// L2: cryptographic signature + source provenance available.
    CryptographicProvenance,
    /// L3: signature + signer identity + transparency log available.
    FullTrustChain,
}

impl DependencySignatureEvidence {
    /// Returns the provenance capability level of this dependency's registry.
    ///
    /// This determines whether higher-level controls (L2 provenance, L3 signer
    /// verification) are meaningful for this dependency. Dependencies from
    /// registries that lack the required infrastructure are excluded from
    /// evaluation rather than producing false positives.
    pub fn registry_provenance_capability(&self) -> RegistryProvenanceCapability {
        match self.registry.as_deref() {
            Some(r) if r.contains("npmjs.org") => RegistryProvenanceCapability::FullTrustChain,
            Some("pypi.org") => RegistryProvenanceCapability::FullTrustChain,
            _ => RegistryProvenanceCapability::ChecksumOnly,
        }
    }
}

/// A single CODEOWNERS entry mapping a file pattern to its designated owners.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CodeownersEntry {
    /// File pattern (e.g. "*.rs", "/src/auth/", "*").
    pub pattern: String,
    /// Designated owners (e.g. "@org/security-team", "alice@example.com").
    pub owners: Vec<String>,
}

/// Repository-level security posture evidence for ASPM controls.
///
/// Captures configuration-level signals that are independent of any single
/// change request: code ownership, scanning settings, and security policy.
/// Designed to be populated from GitHub REST API, GitLab API, or other platform adapters.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct RepositoryPosture {
    /// Parsed CODEOWNERS entries. Empty vec means no CODEOWNERS file found.
    pub codeowners_entries: Vec<CodeownersEntry>,

    // --- Security analysis availability ---
    /// Whether the security_and_analysis API field was available.
    /// `false` means the API token lacked permission to read security settings,
    /// so `secret_scanning_enabled` / `vulnerability_scanning_enabled` etc. may be inaccurate.
    #[serde(default = "default_true")]
    pub security_analysis_available: bool,

    // --- Secret scanning (CC6.1 / CC6.6) ---
    /// Whether secret scanning is enabled (detection).
    pub secret_scanning_enabled: bool,
    /// Whether push protection is enabled (prevention). Requires GHAS on private repos.
    #[serde(default)]
    pub secret_push_protection_enabled: bool,

    // --- Vulnerability scanning (CC7.1) ---
    /// Whether dependency vulnerability scanning (Dependabot, Snyk, etc.) is enabled.
    pub vulnerability_scanning_enabled: bool,
    /// Whether code scanning / SAST (CodeQL, Semgrep, etc.) is enabled.
    #[serde(default)]
    pub code_scanning_enabled: bool,

    // --- Security policy (CC7.3 / CC7.4) ---
    /// Whether a SECURITY.md or equivalent security policy file exists.
    pub security_policy_present: bool,
    /// Whether the security policy describes a responsible disclosure process.
    pub security_policy_has_disclosure: bool,

    // --- Branch protection (CC6.1 / CC8.1) ---
    /// Whether the default branch has protection rules configured.
    #[serde(default)]
    pub default_branch_protected: bool,

    // --- Branch protection detail (enterprise controls) ---
    /// Whether branch protection rules are enforced for admins (no bypass).
    #[serde(default)]
    pub enforce_admins: bool,
    /// Whether stale pull request reviews are automatically dismissed on new push.
    #[serde(default)]
    pub dismiss_stale_reviews: bool,
    #[serde(default)]
    pub unpinned_action_refs: Vec<UnpinnedActionRef>,
    #[serde(default)]
    pub production_environment_protected: bool,
    #[serde(default)]
    pub open_high_severity_alerts: u32,
    #[serde(default)]
    pub copyleft_dependencies: Vec<CopyleftDependency>,
    #[serde(default)]
    pub release_has_sbom: bool,
    #[serde(default)]
    pub release_assets_attested: bool,
    #[serde(default)]
    pub privileged_workflows: Vec<PrivilegedWorkflow>,

    // --- Workflow permissions (CC6.8 / least privilege) ---
    /// Default workflow permissions for the repository ("read" or "write").
    /// Empty string means the field could not be collected.
    #[serde(default)]
    pub default_workflow_permissions: String,

    // --- Dependency update tool (Scorecard Dependency-Update-Tool) ---
    /// Whether a dependency update tool config exists (Dependabot or Renovate).
    #[serde(default)]
    pub dependency_update_tool_configured: bool,

    // --- Repository permissions audit (CC6.1 / least privilege) ---
    /// Number of users with admin access to the repository.
    #[serde(default)]
    pub admin_count: u32,
    /// Number of direct (non-team) collaborators with write or admin access.
    #[serde(default)]
    pub direct_collaborator_count: u32,

    // --- Tag protection (SA-10 / release integrity) ---
    /// Whether at least one tag protection rule exists.
    #[serde(default)]
    pub tag_protection_enabled: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UnpinnedActionRef {
    pub workflow_file: String,
    pub action_ref: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CopyleftDependency {
    pub name: String,
    pub license: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PrivilegedWorkflow {
    pub file: String,
    pub trigger: String,
    pub risk: String,
}

/// Build platform evidence for Build Track L2+.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BuildPlatformEvidence {
    pub platform: String,
    pub hosted: bool,
    pub ephemeral: bool,
    pub isolated: bool,
    pub runner_labels: Vec<String>,
    pub signing_key_isolated: bool,
}

// ---------------------------------------------------------------------------
// Dark Factory evidence types (Layers 1, 4)
// ---------------------------------------------------------------------------

/// A single action performed by an AI agent.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AgentAction {
    pub tool: String,
    pub command: String,
    #[serde(default)]
    pub timestamp: Option<String>,
    #[serde(default)]
    pub required_permission: Option<String>,
}

/// Log of all actions an agent performed in a session (Layer 4).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AgentActionLog {
    pub agent_id: String,
    pub session_id: String,
    pub actions: Vec<AgentAction>,
}

/// Spec constraining what an agent is allowed to do (Layer 1).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AgentSpec {
    #[serde(default)]
    pub allowed_paths: Vec<String>,
    #[serde(default)]
    pub forbidden_paths: Vec<String>,
    #[serde(default)]
    pub allowed_tools: Vec<String>,
    #[serde(default)]
    pub granted_permissions: Vec<String>,
    #[serde(default)]
    pub max_steps: Option<u32>,
    #[serde(default)]
    pub budget_cents: Option<u32>,
}

/// Record of what an agent actually did (Layer 1).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AgentExecution {
    pub agent_id: String,
    pub session_id: String,
    #[serde(default)]
    pub files_touched: Vec<String>,
    #[serde(default)]
    pub tools_used: Vec<String>,
    #[serde(default)]
    pub steps_taken: u32,
    #[serde(default)]
    pub cost_cents: u32,
}

/// Top-level container for all evidence collected from adapters.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct EvidenceBundle {
    pub change_requests: Vec<GovernedChange>,
    pub promotion_batches: Vec<PromotionBatch>,
    pub artifact_attestations: EvidenceState<Vec<ArtifactAttestation>>,
    pub check_runs: EvidenceState<Vec<CheckRunEvidence>>,
    pub build_platform: EvidenceState<Vec<BuildPlatformEvidence>>,
    pub dependency_signatures: EvidenceState<Vec<DependencySignatureEvidence>>,
    #[serde(default)]
    pub repository_posture: EvidenceState<RepositoryPosture>,
    // Dark Factory evidence (Layers 1, 4)
    #[serde(default)]
    pub agent_action_log: EvidenceState<AgentActionLog>,
    #[serde(default)]
    pub agent_spec: EvidenceState<AgentSpec>,
    #[serde(default)]
    pub agent_execution: EvidenceState<AgentExecution>,
}
