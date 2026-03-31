# NIST SP 800-53 Rev. 5 policy preset.
# Applicable to federal information systems (FedRAMP, FISMA).
# This preset targets the Moderate baseline (287 controls).
# For Low-impact systems, consider a custom policy with fewer mandatory controls.
#
# Controls are mapped to NIST 800-53 control families:
#   CM (Configuration Management):
#     branch-protection-enforcement, codeowners-coverage,
#     source-authenticity
#   SA (System and Services Acquisition / Development Process):
#     review-independence, two-party-review, test-coverage,
#     required-status-checks
#   SI (System and Information Integrity):
#     vulnerability-scanning, secret-scanning,
#     code-scanning-alerts-resolved
#   SR (Supply Chain Risk Management):
#     dependency-signature, dependency-provenance,
#     dependency-signer-verified, dependency-completeness
#   AU (Audit and Accountability, recommended):
#     issue-linkage, release-traceability, security-file-change
#   PL (Planning, recommended):
#     security-policy
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

# --- CM + SA + SI mandatory controls (violated -> fail) ---
nist_mandatory_controls := {
	"branch-protection-enforcement",
	"branch-history-integrity",
	"codeowners-coverage",
	"source-authenticity",
	"review-independence",
	"two-party-review",
	"test-coverage",
	"required-status-checks",
	"vulnerability-scanning",
	"secret-scanning",
	"secret-scanning-push-protection",
	"branch-protection-admin-enforcement",
	"actions-pinned-dependencies",
	"environment-protection-rules",
	"code-scanning-alerts-resolved",
	"privileged-workflow-detection",
}

# --- SR (Supply Chain Risk Management) controls ---
# violated -> fail, indeterminate -> review (provenance infra may be absent)
nist_supply_chain_controls := {
	"dependency-signature",
	"dependency-provenance",
	"dependency-signer-verified",
	"dependency-completeness",
}

# --- Build controls (indeterminate -> review, violated -> fail) ---
# Build attestation infra may not be deployed; indeterminate is expected.
nist_build_controls := {
	"build-provenance",
	"hosted-build-platform",
	"provenance-authenticity",
	"build-isolation",
}

# --- AU (Audit) + PL (Planning) recommended controls (violated -> review) ---
nist_audit_controls := {
	"issue-linkage",
	"release-traceability",
	"security-file-change",
	"security-policy",
}

# --- Development quality recommended controls (violated -> review) ---
nist_devquality_controls := {
	"change-request-size",
	"scoped-change",
	"description-quality",
	"merge-commit-policy",
	"conventional-title",
	"stale-review",
	"dismiss-stale-reviews-on-push",
	"dependency-license-compliance",
	"sbom-attestation",
	"release-asset-attestation",
}

# --- Audit recommended: violated -> review ---
map := {"severity": "warning", "decision": "review", "annotations": {"framework_ref": "NIST 800-53 AU-6"}} if {
	input.status == "violated"
	input.control_id in nist_audit_controls
}

# --- Audit recommended: indeterminate -> review ---
map := {"severity": "warning", "decision": "review", "annotations": {"framework_ref": "NIST 800-53 AU-6"}} if {
	input.status == "indeterminate"
	input.control_id in nist_audit_controls
}

# --- Development quality recommended: violated -> review ---
map := {"severity": "warning", "decision": "review", "annotations": {"framework_ref": "NIST 800-53 SA-11"}} if {
	input.status == "violated"
	input.control_id in nist_devquality_controls
}

# --- Development quality recommended: indeterminate -> review ---
map := {"severity": "warning", "decision": "review", "annotations": {"framework_ref": "NIST 800-53 SA-11"}} if {
	input.status == "indeterminate"
	input.control_id in nist_devquality_controls
}

# --- Build controls: indeterminate -> review ---
map := {"severity": "warning", "decision": "review", "annotations": {"framework_ref": "NIST 800-53 SA-15"}} if {
	input.status == "indeterminate"
	input.control_id in nist_build_controls
}

# --- Build controls: violated -> fail ---
map := {"severity": "error", "decision": "fail", "annotations": {"framework_ref": "NIST 800-53 SA-15"}} if {
	input.status == "violated"
	input.control_id in nist_build_controls
}

# --- Supply chain controls: indeterminate -> review ---
map := {"severity": "warning", "decision": "review", "annotations": {"framework_ref": "NIST 800-53 SR-4"}} if {
	input.status == "indeterminate"
	input.control_id in nist_supply_chain_controls
}

# --- Supply chain controls: violated -> fail ---
map := {"severity": "error", "decision": "fail", "annotations": {"framework_ref": "NIST 800-53 SR-4"}} if {
	input.status == "violated"
	input.control_id in nist_supply_chain_controls
}

# --- All other indeterminate -> fail ---
map := {"severity": "error", "decision": "fail", "annotations": {"framework_ref": "NIST 800-53 CM-3"}} if {
	input.status == "indeterminate"
	not input.control_id in nist_build_controls
	not input.control_id in nist_supply_chain_controls
	not input.control_id in nist_audit_controls
	not input.control_id in nist_devquality_controls
}

# --- All other violated -> fail (mandatory controls) ---
map := {"severity": "error", "decision": "fail", "annotations": {"framework_ref": "NIST 800-53 CM-3"}} if {
	input.status == "violated"
	not input.control_id in nist_audit_controls
	not input.control_id in nist_devquality_controls
	not input.control_id in nist_build_controls
	not input.control_id in nist_supply_chain_controls
}
