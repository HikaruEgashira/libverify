# ISMAP (Information system Security Management and Assessment Program) policy preset.
# Japanese government cloud security assessment based on ISO/IEC 27001/27002/27017.
# Required for cloud services used by Japanese government agencies.
#
# Note: ISMAP management standards map to ISO 27001:2013 Annex A.
# ISO 27001:2022 renumbered controls (e.g. A.14 → A.8.25-A.8.31),
# but ISMAP still references the 2013 structure as of 2025.
# framework_ref values use control-specific ISMAP chapter references.
#
# Controls are tiered:
#   - Mandatory controls (ISO 27001 Annex A mapped) -> hard fail on violated
#   - Recommended controls (development quality) -> review on violated
#   - Build/dependency-track indeterminate -> review (infra may be absent)
#   - All other indeterminate -> fail (strict government posture)
#
# Input (set per finding):
#   input.control_id  - kebab-case control identifier (e.g. "review-independence")
#   input.status      - "satisfied" | "violated" | "indeterminate" | "not_applicable"
#   input.rationale   - human-readable explanation
#   input.subjects    - list of affected artifact URIs
#
# Output (data.verify.profile.map):
#   severity    - "info" | "warning" | "error"
#   decision    - "pass" | "review" | "fail"
#   annotations - (non-pass only) {"framework_ref": "ISMAP <clause>"}

package verify.profile

import rego.v1

default map := {"severity": "error", "decision": "fail"}

map := {"severity": "info", "decision": "pass"} if {
	input.status == "satisfied"
}

map := {"severity": "info", "decision": "pass"} if {
	input.status == "not_applicable"
}

# --- Mandatory controls (violated -> fail) ---
# ISMAP Ch.14.2.1 (Secure development policy): review-independence, branch-protection
# ISMAP Ch.14.2.5 (Secure system engineering): source-authenticity, required-status-checks
# ISMAP Ch.14.2.8 (System security testing): vulnerability-scanning, secret-scanning
# ISMAP Ch.14.2.9 (System acceptance testing): test-coverage
ismap_mandatory_controls := {
	"review-independence",
	"two-party-review",
	"branch-protection-enforcement",
	"branch-history-integrity",
	"source-authenticity",
	"required-status-checks",
	"vulnerability-scanning",
	"secret-scanning",
	"test-coverage",
	"secret-scanning-push-protection",
	"branch-protection-admin-enforcement",
	"dismiss-stale-reviews-on-push",
	"environment-protection-rules",
	"code-scanning-alerts-resolved",
	"privileged-workflow-detection",
	"repository-permissions-audit",
	"workflow-permissions-restricted",
	"default-branch-settings-baseline",
	"security-test-in-ci",
}

# --- Recommended controls (violated -> review) ---
# ISMAP Ch.14.2.2 (System change control): development quality
ismap_recommended_controls := {
	"change-request-size",
	"scoped-change",
	"description-quality",
	"merge-commit-policy",
	"conventional-title",
	"issue-linkage",
	"stale-review",
	"codeowners-coverage",
	"release-traceability",
	"security-file-change",
	"security-policy",
	"actions-pinned-dependencies",
	"dependency-license-compliance",
	"sbom-attestation",
	"release-asset-attestation",
	"dependency-update-tool",
}

# --- Build/dependency-track controls ---
# ISMAP Ch.14.2.6 (Secure development environment)
ismap_build_controls := {
	"build-provenance",
	"hosted-build-platform",
	"provenance-authenticity",
	"build-isolation",
}

# ISMAP Ch.15.1.1 (Information security in supplier relationships)
ismap_dependency_controls := {
	"dependency-signature",
	"dependency-provenance",
	"dependency-signer-verified",
	"dependency-completeness",
}

# --- Recommended controls: violated -> review ---
map := {"severity": "warning", "decision": "review", "annotations": {"framework_ref": "ISMAP Ch.14.2.2"}} if {
	input.status == "violated"
	input.control_id in ismap_recommended_controls
}

# --- Recommended controls: indeterminate -> review ---
map := {"severity": "warning", "decision": "review", "annotations": {"framework_ref": "ISMAP Ch.14.2.2"}} if {
	input.status == "indeterminate"
	input.control_id in ismap_recommended_controls
}

# --- Build/dependency indeterminate -> review (infra may be absent) ---
map := {"severity": "warning", "decision": "review", "annotations": {"framework_ref": "ISMAP Ch.14.2.6"}} if {
	input.status == "indeterminate"
	input.control_id in ismap_build_controls
}

map := {"severity": "warning", "decision": "review", "annotations": {"framework_ref": "ISMAP Ch.15.1.1"}} if {
	input.status == "indeterminate"
	input.control_id in ismap_dependency_controls
}

# --- All other indeterminate -> fail (strict) ---
map := {"severity": "error", "decision": "fail", "annotations": {"framework_ref": "ISMAP Ch.14.2.1"}} if {
	input.status == "indeterminate"
	not input.control_id in ismap_build_controls
	not input.control_id in ismap_dependency_controls
	not input.control_id in ismap_recommended_controls
}

# --- All other violated -> fail (mandatory controls) ---
map := {"severity": "error", "decision": "fail", "annotations": {"framework_ref": "ISMAP Ch.14.2.1"}} if {
	input.status == "violated"
	not input.control_id in ismap_recommended_controls
}
