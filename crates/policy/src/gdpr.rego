# GDPR (General Data Protection Regulation) policy preset.
# Maps SDLC controls to Articles 25 and 32.
# Focused on data protection by design and security of processing.
# Less strict than SOC2 on SDLC ceremony; strict on integrity and access.
#
# Controls are mapped to GDPR articles:
#   Art. 25 Data Protection by Design and by Default:
#     security-policy, security-file-change, scoped-change,
#     vulnerability-scanning, secret-scanning
#   Art. 32 Security of Processing:
#     branch-protection-enforcement, codeowners-coverage,
#     review-independence, two-party-review,
#     code-scanning-alerts-resolved, security-test-in-ci
#   Art. 5(1)(f) Integrity and Confidentiality:
#     source-authenticity, build-provenance, provenance-authenticity,
#     dependency controls
#   Art. 33/34 Breach Notification (supporting controls):
#     release-traceability, issue-linkage, privileged-operation-audit
#   Recommended (not directly mapped):
#     change-request-size, description-quality, conventional-title,
#     merge-commit-policy, stale-review, release-asset-attestation
#
# Input (set per finding):
#   input.control_id  - kebab-case control identifier
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

# --- Build/provenance controls ---
# Attestation infra may be absent; indeterminate -> review
gdpr_build_controls := {
	"build-provenance",
	"hosted-build-platform",
	"build-isolation",
	"provenance-authenticity",
}

map := {"severity": "warning", "decision": "review", "annotations": {"framework_ref": "GDPR Art. 5(1)(f)"}} if {
	input.status == "indeterminate"
	input.control_id in gdpr_build_controls
}

# --- Dependency/supply chain controls ---
# Provenance infra may be absent; indeterminate -> review
gdpr_dependency_controls := {
	"dependency-signature",
	"dependency-provenance",
	"dependency-signer-verified",
	"dependency-completeness",
}

map := {"severity": "warning", "decision": "review", "annotations": {"framework_ref": "GDPR Art. 5(1)(f)"}} if {
	input.status == "indeterminate"
	input.control_id in gdpr_dependency_controls
}

# --- Breach notification supporting controls ---
# Important but not hard-fail for GDPR; violated -> review
gdpr_breach_controls := {
	"release-traceability",
	"issue-linkage",
	"security-file-change",
}

map := {"severity": "warning", "decision": "review", "annotations": {"framework_ref": "GDPR Art. 33"}} if {
	input.status == "violated"
	input.control_id in gdpr_breach_controls
}

map := {"severity": "warning", "decision": "review", "annotations": {"framework_ref": "GDPR Art. 33"}} if {
	input.status == "indeterminate"
	input.control_id in gdpr_breach_controls
}

# --- Development quality recommended controls ---
# violated -> review, indeterminate -> review
gdpr_recommended_controls := {
	"change-request-size",
	"description-quality",
	"conventional-title",
	"merge-commit-policy",
	"stale-review",
	"release-asset-attestation",
	"source-authenticity",
}

map := {"severity": "warning", "decision": "review", "annotations": {"framework_ref": "GDPR Art. 25"}} if {
	input.status == "violated"
	input.control_id in gdpr_recommended_controls
}

map := {"severity": "warning", "decision": "review", "annotations": {"framework_ref": "GDPR Art. 25"}} if {
	input.status == "indeterminate"
	input.control_id in gdpr_recommended_controls
}

# --- All other indeterminate -> fail ---
map := {"severity": "error", "decision": "fail", "annotations": {"framework_ref": "GDPR Art. 32"}} if {
	input.status == "indeterminate"
	not input.control_id in gdpr_build_controls
	not input.control_id in gdpr_dependency_controls
	not input.control_id in gdpr_breach_controls
	not input.control_id in gdpr_recommended_controls
}

# --- All other violated -> fail ---
map := {"severity": "error", "decision": "fail", "annotations": {"framework_ref": "GDPR Art. 32"}} if {
	input.status == "violated"
	not input.control_id in gdpr_breach_controls
	not input.control_id in gdpr_recommended_controls
}
