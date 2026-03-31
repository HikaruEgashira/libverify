# ISMAP (Information system Security Management and Assessment Program) policy preset.
# Japanese government cloud security assessment based on ISO/IEC 27001/27002/27017.
# Required for cloud services used by Japanese government agencies.
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
ismap_mandatory_controls := {
	"review-independence",
	"branch-protection-enforcement",
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
}

# --- Recommended controls (violated -> review) ---
ismap_recommended_controls := {
	"change-request-size",
	"scoped-change",
	"description-quality",
	"merge-commit-policy",
	"conventional-title",
	"issue-linkage",
	"actions-pinned-dependencies",
	"dependency-license-compliance",
	"sbom-attestation",
	"release-asset-attestation",
}

# --- Build/dependency-track controls ---
ismap_build_controls := {
	"build-provenance",
	"hosted-build-platform",
	"provenance-authenticity",
	"build-isolation",
}

ismap_dependency_controls := {
	"dependency-signature",
	"dependency-provenance",
	"dependency-signer-verified",
	"dependency-completeness",
}

# --- Recommended controls: violated -> review ---
map := {"severity": "warning", "decision": "review", "annotations": {"framework_ref": "ISMAP A.14.2.2"}} if {
	input.status == "violated"
	input.control_id in ismap_recommended_controls
}

# --- Build/dependency indeterminate -> review (infra may be absent) ---
map := {"severity": "warning", "decision": "review", "annotations": {"framework_ref": "ISMAP A.14.2.6"}} if {
	input.status == "indeterminate"
	input.control_id in ismap_build_controls
}

map := {"severity": "warning", "decision": "review", "annotations": {"framework_ref": "ISMAP A.15.1.1"}} if {
	input.status == "indeterminate"
	input.control_id in ismap_dependency_controls
}

# --- All other indeterminate -> fail (strict) ---
map := {"severity": "error", "decision": "fail", "annotations": {"framework_ref": "ISMAP A.14.2.1"}} if {
	input.status == "indeterminate"
	not input.control_id in ismap_build_controls
	not input.control_id in ismap_dependency_controls
}

# --- All other violated -> fail (mandatory controls) ---
map := {"severity": "error", "decision": "fail", "annotations": {"framework_ref": "ISMAP A.14.2.1"}} if {
	input.status == "violated"
	not input.control_id in ismap_recommended_controls
}
