//! Creusot verification targets for gh-verify.
//!
//! This crate contains only pure functions with `#[ensures]` specifications.
//! It is compiled exclusively with `cargo creusot` and verified by SMT solvers.
//! No I/O, no `format!`, no String operations — only primitive-type logic.
//!
//! The corresponding runtime implementations in `gh-verify-core` delegate
//! to these predicates, so proving them correct ensures the core decision
//! logic is sound.

use creusot_std::macros::{ensures, requires};

/// Severity levels mirroring `gh-verify-core::verdict::Severity`.
/// Duplicated here to avoid pulling in serde and format! via the core crate.
#[derive(Debug, Clone, Copy, creusot_std::prelude::DeepModel)]
pub enum Severity {
    Pass,
    Warning,
    Error,
}

/// Core predicate for the four-eyes principle (SLSA mutual approval).
///
/// An approver is independent iff they are **neither** a commit author
/// **nor** the PR author. Both conditions must hold (AND).
#[ensures(result == (!is_commit_author && !is_pr_author))]
pub fn is_approver_independent(is_commit_author: bool, is_pr_author: bool) -> bool {
    !is_commit_author && !is_pr_author
}

/// Signature check severity.
///
/// Pass iff zero unsigned commits; Error otherwise.
#[ensures(unsigned_count == 0usize ==> result == Severity::Pass)]
#[ensures(unsigned_count > 0usize ==> result == Severity::Error)]
pub fn signature_severity(unsigned_count: usize) -> Severity {
    if unsigned_count == 0 {
        Severity::Pass
    } else {
        Severity::Error
    }
}

/// Scope classification.
///
/// Exhaustive postconditions covering all input combinations.
///
/// Precondition: union-find produces at most as many connected components
/// as there are code files (each file starts as its own component).
#[requires(components <= code_files_count)]
#[ensures(code_files_count <= 1usize ==> result == Severity::Pass)]
#[ensures(code_files_count > 1usize && components <= 1usize ==> result == Severity::Pass)]
#[ensures(code_files_count > 1usize && components == 2usize ==> result == Severity::Warning)]
#[ensures(code_files_count > 1usize && components >= 3usize ==> result == Severity::Error)]
pub fn classify_scope(code_files_count: usize, components: usize) -> Severity {
    if code_files_count <= 1 {
        return Severity::Pass;
    }
    match components {
        0 | 1 => Severity::Pass,
        2 => Severity::Warning,
        _ => Severity::Error,
    }
}

/// Build provenance severity.
///
/// Pass iff zero unverified attestations; Error otherwise.
/// Empty attestation lists are handled at control level (NotApplicable).
#[ensures(unverified_count == 0usize ==> result == Severity::Pass)]
#[ensures(unverified_count >= 1usize ==> result == Severity::Error)]
pub fn build_provenance_severity(unverified_count: usize) -> Severity {
    if unverified_count == 0 {
        Severity::Pass
    } else {
        Severity::Error
    }
}

/// Required status checks severity.
///
/// Pass iff zero check runs have a failing conclusion.
#[ensures(fail_count == 0usize ==> result == Severity::Pass)]
#[ensures(fail_count >= 1usize ==> result == Severity::Error)]
pub fn required_status_checks_severity(fail_count: usize) -> Severity {
    if fail_count == 0 {
        Severity::Pass
    } else {
        Severity::Error
    }
}

// --- SLSA v1.2 Source Track predicates ---

/// Branch history integrity severity (Source L2).
///
/// Pass iff zero merge commits found in the change request (linear history).
#[ensures(unprotected_count == 0usize ==> result == Severity::Pass)]
#[ensures(unprotected_count >= 1usize ==> result == Severity::Error)]
pub fn branch_history_severity(unprotected_count: usize) -> Severity {
    if unprotected_count == 0 {
        Severity::Pass
    } else {
        Severity::Error
    }
}

/// Technical enforcement severity (Source L3).
///
/// Pass iff zero change requests lack factual enforcement (CI checks passed + independent review).
#[ensures(non_enforced_count == 0usize ==> result == Severity::Pass)]
#[ensures(non_enforced_count >= 1usize ==> result == Severity::Error)]
pub fn branch_protection_enforcement_severity(non_enforced_count: usize) -> Severity {
    if non_enforced_count == 0 {
        Severity::Pass
    } else {
        Severity::Error
    }
}

/// Two-party review severity (Source L4).
///
/// Pass iff at least 2 independent reviewers approved.
#[ensures(independent_count >= 2usize ==> result == Severity::Pass)]
#[ensures(independent_count < 2usize ==> result == Severity::Error)]
pub fn two_party_review_severity(independent_count: usize) -> Severity {
    if independent_count >= 2 {
        Severity::Pass
    } else {
        Severity::Error
    }
}

// --- SLSA v1.2 Build Track predicates ---

/// Hosted build platform severity (Build L2).
///
/// Pass iff zero build runs are on non-hosted platforms.
#[ensures(non_hosted_count == 0usize ==> result == Severity::Pass)]
#[ensures(non_hosted_count >= 1usize ==> result == Severity::Error)]
pub fn hosted_build_severity(non_hosted_count: usize) -> Severity {
    if non_hosted_count == 0 {
        Severity::Pass
    } else {
        Severity::Error
    }
}

/// Provenance authenticity severity (Build L2).
///
/// Pass iff zero attestations lack cryptographic authentication.
#[ensures(unauthenticated_count == 0usize ==> result == Severity::Pass)]
#[ensures(unauthenticated_count >= 1usize ==> result == Severity::Error)]
pub fn provenance_authenticity_severity(unauthenticated_count: usize) -> Severity {
    if unauthenticated_count == 0 {
        Severity::Pass
    } else {
        Severity::Error
    }
}

/// Build isolation severity (Build L3).
///
/// Pass iff zero builds lack isolation, ephemerality, or signing key isolation.
#[ensures(non_isolated_count == 0usize ==> result == Severity::Pass)]
#[ensures(non_isolated_count >= 1usize ==> result == Severity::Error)]
pub fn build_isolation_severity(non_isolated_count: usize) -> Severity {
    if non_isolated_count == 0 {
        Severity::Pass
    } else {
        Severity::Error
    }
}

// --- Compliance control predicates (SOC2 CC7/CC8) ---

/// Stale review severity (CC7.2).
///
/// Pass iff zero approval decisions predate the latest source revision.
#[ensures(stale_count == 0usize ==> result == Severity::Pass)]
#[ensures(stale_count >= 1usize ==> result == Severity::Error)]
pub fn stale_review_severity(stale_count: usize) -> Severity {
    if stale_count == 0 {
        Severity::Pass
    } else {
        Severity::Error
    }
}

/// Description quality severity (CC8.1).
///
/// Pass iff body length meets or exceeds the minimum threshold.
#[ensures(body_length >= min_length ==> result == Severity::Pass)]
#[ensures(body_length < min_length ==> result == Severity::Error)]
pub fn description_quality_severity(body_length: usize, min_length: usize) -> Severity {
    if body_length >= min_length {
        Severity::Pass
    } else {
        Severity::Error
    }
}

/// Merge commit policy severity (CC8.1).
///
/// Pass iff zero merge commits are present in the change request.
#[ensures(merge_count == 0usize ==> result == Severity::Pass)]
#[ensures(merge_count >= 1usize ==> result == Severity::Error)]
pub fn merge_commit_policy_severity(merge_count: usize) -> Severity {
    if merge_count == 0 {
        Severity::Pass
    } else {
        Severity::Error
    }
}

/// Conventional title severity (CC8.1).
///
/// Pass iff the title follows the Conventional Commits format.
#[ensures(is_conventional == true ==> result == Severity::Pass)]
#[ensures(is_conventional == false ==> result == Severity::Error)]
pub fn conventional_title_severity(is_conventional: bool) -> Severity {
    if is_conventional {
        Severity::Pass
    } else {
        Severity::Error
    }
}

/// Security file change severity (CC7.2).
///
/// Pass iff zero security-sensitive files are changed.
#[ensures(sensitive_count == 0usize ==> result == Severity::Pass)]
#[ensures(sensitive_count >= 1usize ==> result == Severity::Error)]
pub fn security_file_change_severity(sensitive_count: usize) -> Severity {
    if sensitive_count == 0 {
        Severity::Pass
    } else {
        Severity::Error
    }
}

/// Release traceability severity (CC7.1).
///
/// Pass iff at least one linked change request exists.
#[ensures(linked_cr_count >= 1usize ==> result == Severity::Pass)]
#[ensures(linked_cr_count == 0usize ==> result == Severity::Error)]
pub fn release_traceability_severity(linked_cr_count: usize) -> Severity {
    if linked_cr_count > 0 {
        Severity::Pass
    } else {
        Severity::Error
    }
}
