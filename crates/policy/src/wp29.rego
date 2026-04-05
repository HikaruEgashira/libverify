# UNECE WP.29 / UN-R155 (Cyber Security Management System) policy preset.
# Applicable to automotive OEMs and suppliers for vehicle type approval.
#
# Controls are mapped to UN-R155 clauses:
#   CSMS (Clause 7.2):
#     vulnerability-scanning, security-file-change, review-independence,
#     required-status-checks, test-coverage
#   Supply Chain (Clause 7.2.2.3):
#     dependency-signature, dependency-provenance,
#     dependency-signer-verified, dependency-completeness
#   Software Security (Clause 7.3):
#     source-authenticity, build-provenance, provenance-authenticity,
#     release-traceability
#   Development Environment:
#     branch-protection-enforcement, build-isolation
#   Recommended (development quality):
#     change-request-size, description-quality, scoped-change,
#     issue-linkage, stale-review, conventional-title,
#     merge-commit-policy, two-party-review, codeowners-coverage,
#     secret-scanning
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
#   annotations - optional object with framework_ref string

package verify.profile

import rego.v1

default map := {"severity": "error", "decision": "fail"}

map := {"severity": "info", "decision": "pass"} if {
	input.status == "satisfied"
}

map := {"severity": "info", "decision": "pass"} if {
	input.status == "not_applicable"
}

# --- CSMS mandatory controls (Clause 7.2) ---
wp29_csms_controls := {
	"vulnerability-scanning",
	"security-file-change",
	"review-independence",
	"required-status-checks",
	"test-coverage",
	"code-scanning-alerts-resolved",
	"privileged-workflow-detection",
	"security-test-in-ci",
}

# --- Supply chain mandatory (Clause 7.2.2.3) ---
wp29_supplychain_controls := {
	"dependency-signature",
	"dependency-provenance",
	"dependency-signer-verified",
	"dependency-completeness",
}

# --- Software security mandatory (Clause 7.3) ---
wp29_software_controls := {
	"source-authenticity",
	"build-provenance",
	"provenance-authenticity",
	"release-traceability",
	"release-asset-attestation",
}

# --- Development environment (violated -> fail, indeterminate -> review) ---
wp29_devenv_controls := {
	"branch-protection-enforcement",
	"build-isolation",
	"hosted-build-platform",
}

# --- Recommended controls (violated -> review) ---
wp29_recommended_controls := {
	"change-request-size",
	"description-quality",
	"scoped-change",
	"issue-linkage",
	"stale-review",
	"conventional-title",
	"merge-commit-policy",
	"two-party-review",
	"codeowners-coverage",
	"secret-scanning",
	"security-policy",
	"branch-history-integrity",
}

# --- Recommended: violated -> review ---
map := {"severity": "warning", "decision": "review", "annotations": {"framework_ref": "UN-R155 7.2"}} if {
	input.status == "violated"
	input.control_id in wp29_recommended_controls
}

# --- Development environment: indeterminate -> review ---
map := {"severity": "warning", "decision": "review", "annotations": {"framework_ref": "UN-R155 7.3"}} if {
	input.status == "indeterminate"
	input.control_id in wp29_devenv_controls
}

# --- All other indeterminate -> fail ---
map := {"severity": "error", "decision": "fail", "annotations": {"framework_ref": "UN-R155 7.2.2.3"}} if {
	input.status == "indeterminate"
	not input.control_id in wp29_devenv_controls
}

# --- All other violated -> fail ---
map := {"severity": "error", "decision": "fail", "annotations": {"framework_ref": "UN-R155 7.2"}} if {
	input.status == "violated"
	not input.control_id in wp29_recommended_controls
}
