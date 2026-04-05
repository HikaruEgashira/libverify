pub mod actions_pinned_dependencies;
pub mod agent_spec_conformance;
pub mod branch_history_integrity;
pub mod branch_protection_admin_enforcement;
pub mod branch_protection_enforcement;
pub mod build_isolation;
pub mod build_provenance;
pub mod change_request_size;
pub mod code_scanning_alerts_resolved;
pub mod codeowners_coverage;
pub mod conventional_title;
pub mod default_branch_settings_baseline;
pub mod dependency_completeness;
pub mod dependency_license_compliance;
pub mod dependency_provenance;
pub mod dependency_signature;
pub mod dependency_signer_verified;
pub mod dependency_update_tool;
pub mod description_quality;
pub mod dismiss_stale_reviews_on_push;
pub mod environment_protection_rules;
pub mod hosted_build_platform;
pub mod issue_linkage;
pub mod merge_commit_policy;
pub mod privileged_operation_audit;
pub mod privileged_workflow_detection;
pub mod protected_tags;
pub mod provenance_authenticity;
pub mod release_asset_attestation;
pub mod release_traceability;
pub mod repository_permissions_audit;
pub mod required_status_checks;
pub mod review_independence;
pub mod sbom_attestation;
pub mod scoped_change;
pub mod secret_scanning;
pub mod secret_scanning_push_protection;
pub mod security_file_change;
pub mod security_policy;
pub mod security_test_in_ci;
pub mod source_authenticity;
pub mod stale_review;
pub mod test_coverage;
pub mod two_party_review;
pub mod vulnerability_scanning;
pub mod workflow_permissions_restricted;

use crate::control::{Control, builtin};
use crate::slsa::{SlsaLevel, SlsaTrack};

use self::actions_pinned_dependencies::ActionsPinnedDependenciesControl;
use self::agent_spec_conformance::AgentSpecConformanceControl;
use self::branch_history_integrity::BranchHistoryIntegrityControl;
use self::branch_protection_admin_enforcement::BranchProtectionAdminEnforcementControl;
use self::branch_protection_enforcement::BranchProtectionEnforcementControl;
use self::build_isolation::BuildIsolationControl;
use self::build_provenance::BuildProvenanceControl;
use self::change_request_size::ChangeRequestSizeControl;
use self::code_scanning_alerts_resolved::CodeScanningAlertsResolvedControl;
use self::codeowners_coverage::CodeownersCoverageControl;
use self::conventional_title::ConventionalTitleControl;
use self::default_branch_settings_baseline::DefaultBranchSettingsBaselineControl;
use self::dependency_completeness::DependencyCompletenessControl;
use self::dependency_license_compliance::DependencyLicenseComplianceControl;
use self::dependency_provenance::DependencyProvenanceControl;
use self::dependency_signature::DependencySignatureControl;
use self::dependency_signer_verified::DependencySignerVerifiedControl;
use self::dependency_update_tool::DependencyUpdateToolControl;
use self::description_quality::DescriptionQualityControl;
use self::dismiss_stale_reviews_on_push::DismissStaleReviewsOnPushControl;
use self::environment_protection_rules::EnvironmentProtectionRulesControl;
use self::hosted_build_platform::HostedBuildPlatformControl;
use self::issue_linkage::IssueLinkageControl;
use self::merge_commit_policy::MergeCommitPolicyControl;
use self::privileged_operation_audit::PrivilegedOperationAuditControl;
use self::privileged_workflow_detection::PrivilegedWorkflowDetectionControl;
use self::protected_tags::ProtectedTagsControl;
use self::provenance_authenticity::ProvenanceAuthenticityControl;
use self::release_asset_attestation::ReleaseAssetAttestationControl;
use self::release_traceability::ReleaseTraceabilityControl;
use self::repository_permissions_audit::RepositoryPermissionsAuditControl;
use self::required_status_checks::RequiredStatusChecksControl;
use self::review_independence::ReviewIndependenceControl;
use self::sbom_attestation::SbomAttestationControl;
use self::scoped_change::ScopedChangeControl;
use self::secret_scanning::SecretScanningControl;
use self::secret_scanning_push_protection::SecretScanningPushProtectionControl;
use self::security_file_change::SecurityFileChangeControl;
use self::security_policy::SecurityPolicyControl;
use self::security_test_in_ci::SecurityTestInCiControl;
use self::source_authenticity::SourceAuthenticityControl;
use self::stale_review::StaleReviewControl;
use self::test_coverage::TestCoverageControl;
use self::two_party_review::TwoPartyReviewControl;
use self::vulnerability_scanning::VulnerabilityScanningControl;
use self::workflow_permissions_restricted::WorkflowPermissionsRestrictedControl;

/// Instantiates a control by its string ID.
fn instantiate(id: &str) -> Option<Box<dyn Control>> {
    match id {
        builtin::SOURCE_AUTHENTICITY => Some(Box::new(SourceAuthenticityControl)),
        builtin::REVIEW_INDEPENDENCE => Some(Box::new(ReviewIndependenceControl)),
        builtin::BRANCH_HISTORY_INTEGRITY => Some(Box::new(BranchHistoryIntegrityControl)),
        builtin::BRANCH_PROTECTION_ENFORCEMENT => {
            Some(Box::new(BranchProtectionEnforcementControl))
        }
        builtin::TWO_PARTY_REVIEW => Some(Box::new(TwoPartyReviewControl)),
        builtin::BUILD_PROVENANCE => Some(Box::new(BuildProvenanceControl)),
        builtin::REQUIRED_STATUS_CHECKS => Some(Box::new(RequiredStatusChecksControl)),
        builtin::HOSTED_BUILD_PLATFORM => Some(Box::new(HostedBuildPlatformControl)),
        builtin::PROVENANCE_AUTHENTICITY => Some(Box::new(ProvenanceAuthenticityControl)),
        builtin::BUILD_ISOLATION => Some(Box::new(BuildIsolationControl)),
        builtin::DEPENDENCY_SIGNATURE => Some(Box::new(DependencySignatureControl)),
        builtin::DEPENDENCY_PROVENANCE_CHECK => Some(Box::new(DependencyProvenanceControl)),
        builtin::DEPENDENCY_SIGNER_VERIFIED => Some(Box::new(DependencySignerVerifiedControl)),
        builtin::DEPENDENCY_COMPLETENESS => Some(Box::new(DependencyCompletenessControl)),
        builtin::CHANGE_REQUEST_SIZE => Some(Box::new(ChangeRequestSizeControl)),
        builtin::TEST_COVERAGE => Some(Box::new(TestCoverageControl)),
        builtin::SCOPED_CHANGE => Some(Box::new(ScopedChangeControl)),
        builtin::ISSUE_LINKAGE => Some(Box::new(IssueLinkageControl)),
        builtin::STALE_REVIEW => Some(Box::new(StaleReviewControl)),
        builtin::DESCRIPTION_QUALITY => Some(Box::new(DescriptionQualityControl)),
        builtin::MERGE_COMMIT_POLICY => Some(Box::new(MergeCommitPolicyControl)),
        builtin::CONVENTIONAL_TITLE => Some(Box::new(ConventionalTitleControl)),
        builtin::SECURITY_FILE_CHANGE => Some(Box::new(SecurityFileChangeControl)),
        builtin::RELEASE_TRACEABILITY => Some(Box::new(ReleaseTraceabilityControl)),
        builtin::CODEOWNERS_COVERAGE => Some(Box::new(CodeownersCoverageControl)),
        builtin::SECRET_SCANNING => Some(Box::new(SecretScanningControl)),
        builtin::VULNERABILITY_SCANNING => Some(Box::new(VulnerabilityScanningControl)),
        builtin::SECURITY_POLICY => Some(Box::new(SecurityPolicyControl)),
        builtin::SECRET_SCANNING_PUSH_PROTECTION => {
            Some(Box::new(SecretScanningPushProtectionControl))
        }
        builtin::BRANCH_PROTECTION_ADMIN_ENFORCEMENT => {
            Some(Box::new(BranchProtectionAdminEnforcementControl))
        }
        builtin::DISMISS_STALE_REVIEWS_ON_PUSH => Some(Box::new(DismissStaleReviewsOnPushControl)),
        builtin::ACTIONS_PINNED_DEPENDENCIES => Some(Box::new(ActionsPinnedDependenciesControl)),
        builtin::ENVIRONMENT_PROTECTION_RULES => Some(Box::new(EnvironmentProtectionRulesControl)),
        builtin::CODE_SCANNING_ALERTS_RESOLVED => Some(Box::new(CodeScanningAlertsResolvedControl)),
        builtin::DEPENDENCY_LICENSE_COMPLIANCE => {
            Some(Box::new(DependencyLicenseComplianceControl))
        }
        builtin::SBOM_ATTESTATION => Some(Box::new(SbomAttestationControl)),
        builtin::RELEASE_ASSET_ATTESTATION => Some(Box::new(ReleaseAssetAttestationControl)),
        builtin::PRIVILEGED_WORKFLOW_DETECTION => {
            Some(Box::new(PrivilegedWorkflowDetectionControl))
        }
        builtin::WORKFLOW_PERMISSIONS_RESTRICTED => {
            Some(Box::new(WorkflowPermissionsRestrictedControl))
        }
        builtin::DEPENDENCY_UPDATE_TOOL => Some(Box::new(DependencyUpdateToolControl)),
        builtin::REPOSITORY_PERMISSIONS_AUDIT => Some(Box::new(RepositoryPermissionsAuditControl)),
        builtin::DEFAULT_BRANCH_SETTINGS_BASELINE => {
            Some(Box::new(DefaultBranchSettingsBaselineControl))
        }
        builtin::SECURITY_TEST_IN_CI => Some(Box::new(SecurityTestInCiControl)),
        builtin::PROTECTED_TAGS => Some(Box::new(ProtectedTagsControl)),
        builtin::AGENT_SPEC_CONFORMANCE => Some(Box::new(AgentSpecConformanceControl)),
        builtin::PRIVILEGED_OPERATION_AUDIT => Some(Box::new(PrivilegedOperationAuditControl)),
        _ => None,
    }
}

/// Returns the SARIF-friendly description for a built-in control ID.
/// Falls back to "Custom control" for unknown IDs.
pub fn control_description(id: &str) -> &'static str {
    match instantiate(id) {
        Some(c) => c.description(),
        None => "Custom control",
    }
}

/// Returns all SLSA controls required for the given track up to the given level.
pub fn slsa_controls_for_level(track: SlsaTrack, level: SlsaLevel) -> Vec<Box<dyn Control>> {
    crate::slsa::controls_for_level(track, level)
        .into_iter()
        .filter_map(|id| instantiate(id.as_str()))
        .collect()
}

/// Returns all SLSA controls across both tracks up to the given levels.
pub fn slsa_controls(source_level: SlsaLevel, build_level: SlsaLevel) -> Vec<Box<dyn Control>> {
    let mut controls = slsa_controls_for_level(SlsaTrack::Source, source_level);
    controls.extend(slsa_controls_for_level(SlsaTrack::Build, build_level));
    controls
}

/// Returns all SLSA controls (Source L4 + Build L3 + Dependencies L4).
pub fn all_slsa_controls() -> Vec<Box<dyn Control>> {
    let mut controls = slsa_controls(SlsaLevel::L4, SlsaLevel::L3);
    controls.extend(slsa_controls_for_level(
        SlsaTrack::Dependencies,
        SlsaLevel::L4,
    ));
    controls
}

/// Returns compliance controls (non-SLSA, SOC2/ASPM mapped).
pub fn compliance_controls() -> Vec<Box<dyn Control>> {
    vec![
        Box::new(ChangeRequestSizeControl),
        Box::new(TestCoverageControl),
        Box::new(ScopedChangeControl),
        Box::new(IssueLinkageControl),
        Box::new(StaleReviewControl),
        Box::new(DescriptionQualityControl),
        Box::new(MergeCommitPolicyControl),
        Box::new(ConventionalTitleControl),
        Box::new(SecurityFileChangeControl),
        Box::new(ReleaseTraceabilityControl),
        Box::new(CodeownersCoverageControl),
        Box::new(SecretScanningControl),
        Box::new(VulnerabilityScanningControl),
        Box::new(SecurityPolicyControl),
        Box::new(SecretScanningPushProtectionControl),
        Box::new(BranchProtectionAdminEnforcementControl),
        Box::new(DismissStaleReviewsOnPushControl),
        Box::new(ActionsPinnedDependenciesControl),
        Box::new(EnvironmentProtectionRulesControl),
        Box::new(CodeScanningAlertsResolvedControl),
        Box::new(DependencyLicenseComplianceControl),
        Box::new(SbomAttestationControl),
        Box::new(ReleaseAssetAttestationControl),
        Box::new(PrivilegedWorkflowDetectionControl),
        Box::new(WorkflowPermissionsRestrictedControl),
        Box::new(DependencyUpdateToolControl),
        Box::new(RepositoryPermissionsAuditControl),
        Box::new(DefaultBranchSettingsBaselineControl),
        Box::new(SecurityTestInCiControl),
        Box::new(ProtectedTagsControl),
    ]
}

/// Returns repository-posture controls only (no PR-scoped compliance controls).
///
/// These evaluate repository-level security configuration:
/// CODEOWNERS, secret scanning, vulnerability scanning, and security policy.
pub fn posture_controls() -> Vec<Box<dyn Control>> {
    vec![
        Box::new(CodeownersCoverageControl),
        Box::new(SecretScanningControl),
        Box::new(VulnerabilityScanningControl),
        Box::new(SecurityPolicyControl),
        Box::new(SecretScanningPushProtectionControl),
        Box::new(BranchProtectionAdminEnforcementControl),
        Box::new(DismissStaleReviewsOnPushControl),
        Box::new(ActionsPinnedDependenciesControl),
        Box::new(EnvironmentProtectionRulesControl),
        Box::new(CodeScanningAlertsResolvedControl),
        Box::new(DependencyLicenseComplianceControl),
        Box::new(SbomAttestationControl),
        Box::new(ReleaseAssetAttestationControl),
        Box::new(PrivilegedWorkflowDetectionControl),
        Box::new(WorkflowPermissionsRestrictedControl),
        Box::new(DependencyUpdateToolControl),
        Box::new(RepositoryPermissionsAuditControl),
        Box::new(DefaultBranchSettingsBaselineControl),
        Box::new(SecurityTestInCiControl),
        Box::new(ProtectedTagsControl),
    ]
}

/// Returns AI-ops agent safety controls (Layers 1, 2, 4).
pub fn aiops_controls() -> Vec<Box<dyn Control>> {
    vec![
        Box::new(AgentSpecConformanceControl),
        Box::new(PrivilegedOperationAuditControl),
    ]
}

/// Returns all controls (all SLSA + compliance + aiops).
pub fn all_controls() -> Vec<Box<dyn Control>> {
    let mut controls = all_slsa_controls();
    controls.extend(compliance_controls());
    controls.extend(aiops_controls());
    controls
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::control::builtin;
    use crate::slsa::control_slsa_mapping;

    #[test]
    fn slsa_l1_returns_l1_controls_only() {
        let controls = slsa_controls(SlsaLevel::L1, SlsaLevel::L1);
        for c in &controls {
            let mapping = control_slsa_mapping(&c.id()).expect("should be SLSA-mapped");
            assert!(
                mapping.level <= SlsaLevel::L1,
                "{:?} is L{:?} but should be L1 or below",
                c.id(),
                mapping.level
            );
        }
    }

    #[test]
    fn all_slsa_includes_l3_build_and_l4_source() {
        let controls = all_slsa_controls();
        let ids: Vec<_> = controls.iter().map(|c| c.id()).collect();
        assert!(
            ids.iter()
                .any(|id| id.as_str() == builtin::TWO_PARTY_REVIEW)
        );
        assert!(ids.iter().any(|id| id.as_str() == builtin::BUILD_ISOLATION));
    }

    #[test]
    fn all_controls_includes_compliance() {
        let controls = all_controls();
        let ids: Vec<_> = controls.iter().map(|c| c.id()).collect();
        assert!(
            ids.iter()
                .any(|id| id.as_str() == builtin::CHANGE_REQUEST_SIZE)
        );
        assert!(ids.iter().any(|id| id.as_str() == builtin::ISSUE_LINKAGE));
    }

    #[test]
    fn compliance_plus_slsa_plus_aiops_equals_all() {
        use crate::control::builtin;
        let compliance = compliance_controls();
        let slsa = all_slsa_controls();
        let aiops = aiops_controls();
        assert_eq!(
            compliance.len() + slsa.len() + aiops.len(),
            builtin::ALL.len(),
            "compliance + SLSA + aiops controls must cover all built-in controls"
        );
    }

    #[test]
    fn compliance_controls_are_not_slsa_mapped() {
        use crate::slsa::control_slsa_mapping;
        let controls = compliance_controls();
        for c in &controls {
            assert!(
                control_slsa_mapping(&c.id()).is_none(),
                "{:?} should not be SLSA-mapped",
                c.id()
            );
        }
    }

    #[test]
    fn compliance_controls_have_unique_ids() {
        let controls = compliance_controls();
        let mut ids: Vec<_> = controls.iter().map(|c| c.id()).collect();
        let original_len = ids.len();
        ids.sort_by_key(|id| id.as_str().to_string());
        ids.dedup();
        assert_eq!(
            ids.len(),
            original_len,
            "all compliance control IDs must be unique"
        );
    }

    #[test]
    fn all_controls_count() {
        let slsa = all_slsa_controls();
        let compliance = compliance_controls();
        let aiops = aiops_controls();
        let all = all_controls();
        assert_eq!(
            all.len(),
            slsa.len() + compliance.len() + aiops.len(),
            "all_controls = SLSA + compliance + aiops"
        );
    }

    #[test]
    fn slsa_controls_for_level_source_l2() {
        let controls = slsa_controls_for_level(SlsaTrack::Source, SlsaLevel::L2);
        let ids: Vec<_> = controls.iter().map(|c| c.id()).collect();
        assert!(
            ids.iter()
                .any(|id| id.as_str() == builtin::BRANCH_HISTORY_INTEGRITY)
        );
        assert!(
            !ids.iter()
                .any(|id| id.as_str() == builtin::BRANCH_PROTECTION_ENFORCEMENT)
        );
    }

    #[test]
    fn slsa_controls_for_level_build_l2() {
        let controls = slsa_controls_for_level(SlsaTrack::Build, SlsaLevel::L2);
        let ids: Vec<_> = controls.iter().map(|c| c.id()).collect();
        assert!(
            ids.iter()
                .any(|id| id.as_str() == builtin::HOSTED_BUILD_PLATFORM)
        );
        assert!(
            ids.iter()
                .any(|id| id.as_str() == builtin::PROVENANCE_AUTHENTICITY)
        );
        assert!(!ids.iter().any(|id| id.as_str() == builtin::BUILD_ISOLATION));
    }

    #[test]
    fn all_controls_have_meaningful_description() {
        let controls = all_controls();
        for c in &controls {
            let desc = c.description();
            assert!(
                !desc.is_empty() && desc.len() > 10,
                "control {} has too short description: '{}'",
                c.id(),
                desc,
            );
            // description must contain a keyword related to the control's purpose
            let id = c.id();
            let id_str = id.as_str();
            let has_relevant_keyword = desc.to_lowercase().contains("must")
                || desc.to_lowercase().contains("should")
                || desc.to_lowercase().contains("agent")
                || desc.to_lowercase().contains("ci")
                || desc.to_lowercase().contains("review")
                || desc.to_lowercase().contains("sign")
                || desc.to_lowercase().contains("branch")
                || desc.to_lowercase().contains("build")
                || desc.to_lowercase().contains("depend")
                || desc.to_lowercase().contains("secur")
                || desc.to_lowercase().contains("test")
                || desc.to_lowercase().contains("change")
                || desc.to_lowercase().contains("scan")
                || desc.to_lowercase().contains("release")
                || desc.to_lowercase().contains("code")
                || desc.to_lowercase().contains("permission")
                || desc.to_lowercase().contains("privileged")
                || desc.to_lowercase().contains("action")
                || desc.to_lowercase().contains("harness")
                || desc.to_lowercase().contains("environment")
                || desc.to_lowercase().contains("workflow")
                || desc.to_lowercase().contains("tag")
                || desc.to_lowercase().contains("license")
                || desc.to_lowercase().contains("sbom")
                || desc.to_lowercase().contains("attest")
                || desc.to_lowercase().contains("owner")
                || desc.to_lowercase().contains("provenance");
            assert!(
                has_relevant_keyword,
                "control {} description '{}' lacks a relevant keyword",
                id_str, desc,
            );
        }
    }
}
