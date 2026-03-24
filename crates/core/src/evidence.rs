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
    SignatureInvalid { detail: String },
    SignerMismatch { detail: String },
    TransparencyLogMissing { detail: String },
    AttestationAbsent { detail: String },
    DigestMismatch { detail: String },
    Failed { detail: String },
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

/// Top-level container for all evidence collected from adapters.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct EvidenceBundle {
    pub change_requests: Vec<GovernedChange>,
    pub promotion_batches: Vec<PromotionBatch>,
    pub artifact_attestations: EvidenceState<Vec<ArtifactAttestation>>,
    pub check_runs: EvidenceState<Vec<CheckRunEvidence>>,
    pub build_platform: EvidenceState<Vec<BuildPlatformEvidence>>,
    pub dependency_signatures: EvidenceState<Vec<DependencySignatureEvidence>>,
}
