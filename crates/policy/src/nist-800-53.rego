# NIST SP 800-53 Rev. 5 policy preset.
# Applicable to federal information systems (FedRAMP, FISMA).
#
# Controls are mapped to NIST 800-53 control families:
#   CM (Configuration Management):
#     branch-protection-enforcement, codeowners-coverage,
#     source-authenticity, dependency-signature
#   SA (System and Services Acquisition / Development Process):
#     review-independence, two-party-review, test-coverage,
#     required-status-checks
#   SI (System and Information Integrity):
#     build-provenance, provenance-authenticity,
#     vulnerability-scanning, secret-scanning
#   SR (Supply Chain Risk Management):
#     dependency-signature, dependency-provenance,
#     dependency-signer-verified, dependency-completeness
#   AU (Audit and Accountability, recommended):
#     issue-linkage, release-traceability
#   Development Quality (recommended):
#     change-request-size, scoped-change, description-quality,
#     merge-commit-policy, conventional-title
#
# Input (set per finding):
#   input.control_id  - kebab-case control identifier (e.g. "review-independence")
#   input.status      - "satisfied" | "violated" | "indeterminate" | "not_applicable"
#   input.rationale   - human-readable explanation
#   input.subjects    - list of affected artifact URIs
#
# Output (data.verify.profile.map):
#   severity - "info" | "warning" | "error"
#   decision - "pass" | "review" | "fail"

package verify.profile

import rego.v1

default map := {"severity": "error", "decision": "fail"}

map := {"severity": "info", "decision": "pass"} if {
	input.status == "satisfied"
}

map := {"severity": "info", "decision": "pass"} if {
	input.status == "not_applicable"
}

# --- CM + SA + SI + SR mandatory controls (violated -> fail) ---
nist_mandatory_controls := {
	"branch-protection-enforcement",
	"codeowners-coverage",
	"source-authenticity",
	"dependency-signature",
	"review-independence",
	"two-party-review",
	"test-coverage",
	"required-status-checks",
	"build-provenance",
	"provenance-authenticity",
	"vulnerability-scanning",
	"secret-scanning",
	"dependency-provenance",
	"dependency-signer-verified",
	"dependency-completeness",
	"secret-scanning-push-protection",
	"branch-protection-admin-enforcement",
	"actions-pinned-dependencies",
	"environment-protection-rules",
	"code-scanning-alerts-resolved",
	"privileged-workflow-detection",
}

# --- AU (Audit) recommended controls (violated -> review) ---
nist_audit_controls := {
	"issue-linkage",
	"release-traceability",
}

# --- Development quality recommended controls (violated -> review) ---
nist_devquality_controls := {
	"change-request-size",
	"scoped-change",
	"description-quality",
	"merge-commit-policy",
	"conventional-title",
	"dismiss-stale-reviews-on-push",
	"dependency-license-compliance",
	"sbom-attestation",
	"release-asset-attestation",
}

# --- Build/dependency-track controls (indeterminate -> review) ---
nist_build_controls := {
	"build-provenance",
	"hosted-build-platform",
	"provenance-authenticity",
	"build-isolation",
}

nist_dependency_controls := {
	"dependency-signature",
	"dependency-provenance",
	"dependency-signer-verified",
	"dependency-completeness",
}

# --- Audit recommended: violated -> review ---
map := {"severity": "warning", "decision": "review"} if {
	input.status == "violated"
	input.control_id in nist_audit_controls
}

# --- Development quality recommended: violated -> review ---
map := {"severity": "warning", "decision": "review"} if {
	input.status == "violated"
	input.control_id in nist_devquality_controls
}

# --- Build/dependency indeterminate -> review ---
map := {"severity": "warning", "decision": "review"} if {
	input.status == "indeterminate"
	input.control_id in nist_build_controls
}

map := {"severity": "warning", "decision": "review"} if {
	input.status == "indeterminate"
	input.control_id in nist_dependency_controls
}

# --- All other indeterminate -> fail ---
map := {"severity": "error", "decision": "fail"} if {
	input.status == "indeterminate"
	not input.control_id in nist_build_controls
	not input.control_id in nist_dependency_controls
}

# --- All other violated -> fail (mandatory controls) ---
map := {"severity": "error", "decision": "fail"} if {
	input.status == "violated"
	not input.control_id in nist_audit_controls
	not input.control_id in nist_devquality_controls
}
