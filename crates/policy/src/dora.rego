# DORA (EU Digital Operational Resilience Act) policy preset.
# Regulation (EU) 2022/2554 for financial entities.
# Strict on ICT risk management, change management, and resilience testing.
#
# Controls are mapped to DORA chapters:
#   Art. 7 ICT Risk Management Framework:
#     vulnerability-scanning, code-scanning-alerts-resolved,
#     security-test-in-ci, security-policy
#   Art. 8 Identification:
#     dependency-signature, dependency-provenance,
#     dependency-signer-verified, dependency-completeness,
#     release-traceability
#   Art. 9 Protection and Prevention:
#     branch-protection-enforcement, secret-scanning,
#     codeowners-coverage, privileged-workflow-detection
#   Art. 10 Detection:
#     security-file-change, privileged-operation-audit
#   Art. 12 ICT Change Management:
#     review-independence, two-party-review, change-request-size,
#     test-coverage, required-status-checks, stale-review,
#     issue-linkage
#   Art. 25 Digital Operational Resilience Testing:
#     build-provenance, provenance-authenticity,
#     build-isolation, hosted-build-platform
#   Recommended (not directly mapped):
#     description-quality, conventional-title, merge-commit-policy,
#     release-asset-attestation
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

# --- Art. 25 Build/resilience testing controls ---
# Attestation infra may be absent; indeterminate -> review
dora_build_controls := {
	"build-provenance",
	"provenance-authenticity",
	"build-isolation",
	"hosted-build-platform",
}

map := {"severity": "warning", "decision": "review", "annotations": {"framework_ref": "DORA Art. 25"}} if {
	input.status == "indeterminate"
	input.control_id in dora_build_controls
}

# --- Art. 8 Dependency/supply chain controls ---
# Provenance infra may be absent; indeterminate -> review
dora_dependency_controls := {
	"dependency-signature",
	"dependency-provenance",
	"dependency-signer-verified",
	"dependency-completeness",
}

map := {"severity": "warning", "decision": "review", "annotations": {"framework_ref": "DORA Art. 8"}} if {
	input.status == "indeterminate"
	input.control_id in dora_dependency_controls
}

# --- Recommended controls (not directly in DORA scope) ---
# violated -> review, indeterminate -> review
dora_recommended_controls := {
	"description-quality",
	"conventional-title",
	"merge-commit-policy",
	"release-asset-attestation",
	"scoped-change",
	"source-authenticity",
}

map := {"severity": "warning", "decision": "review", "annotations": {"framework_ref": "DORA Art. 12"}} if {
	input.status == "violated"
	input.control_id in dora_recommended_controls
}

map := {"severity": "warning", "decision": "review", "annotations": {"framework_ref": "DORA Art. 12"}} if {
	input.status == "indeterminate"
	input.control_id in dora_recommended_controls
}

# --- All other indeterminate -> fail ---
map := {"severity": "error", "decision": "fail", "annotations": {"framework_ref": "DORA Art. 7"}} if {
	input.status == "indeterminate"
	not input.control_id in dora_build_controls
	not input.control_id in dora_dependency_controls
	not input.control_id in dora_recommended_controls
}

# --- All other violated -> fail ---
map := {"severity": "error", "decision": "fail", "annotations": {"framework_ref": "DORA Art. 7"}} if {
	input.status == "violated"
	not input.control_id in dora_recommended_controls
}
