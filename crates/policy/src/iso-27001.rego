# ISO/IEC 27001:2022 Annex A policy preset.
# Maps SDLC controls to relevant Annex A controls for information security.
#
# Controls are mapped to ISO 27001 Annex A clauses:
#   A.8.25 (Secure Development Lifecycle):
#     review-independence, two-party-review, test-coverage,
#     required-status-checks, stale-review
#   A.8.26 (Application Security Requirements):
#     security-policy, security-file-change
#   A.8.27 (Secure System Architecture):
#     scoped-change, branch-protection-enforcement, codeowners-coverage
#   A.8.28 (Secure Coding):
#     code-scanning-alerts-resolved, vulnerability-scanning,
#     secret-scanning, security-test-in-ci
#   A.8.31 (Separation of Environments):
#     build-isolation, hosted-build-platform
#   A.8.32 (Change Management):
#     change-request-size, description-quality, issue-linkage,
#     release-traceability
#   A.8.33 (Test Information):
#     test-coverage
#   A.5.23 (Cloud Services):
#     dependency-signature, dependency-provenance,
#     dependency-signer-verified, dependency-completeness
#   Recommended (not directly mapped):
#     conventional-title, merge-commit-policy, release-asset-attestation
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

# --- A.8.31 Separation of Environments ---
# Build infra may be absent; indeterminate -> review
iso27001_environment_controls := {
	"build-isolation",
	"hosted-build-platform",
}

map := {"severity": "warning", "decision": "review", "annotations": {"framework_ref": "ISO 27001 A.8.31"}} if {
	input.status == "indeterminate"
	input.control_id in iso27001_environment_controls
}

# --- A.5.23 Supply chain / dependency controls ---
# Provenance infra may be absent; indeterminate -> review
iso27001_supply_chain_controls := {
	"dependency-signature",
	"dependency-provenance",
	"dependency-signer-verified",
	"dependency-completeness",
}

map := {"severity": "warning", "decision": "review", "annotations": {"framework_ref": "ISO 27001 A.5.23"}} if {
	input.status == "indeterminate"
	input.control_id in iso27001_supply_chain_controls
}

# --- Build provenance controls ---
# Attestation infra may be absent; indeterminate -> review
iso27001_build_controls := {
	"build-provenance",
	"provenance-authenticity",
}

map := {"severity": "warning", "decision": "review", "annotations": {"framework_ref": "ISO 27001 A.8.25"}} if {
	input.status == "indeterminate"
	input.control_id in iso27001_build_controls
}

# --- Recommended controls (not directly in Annex A scope) ---
# violated -> review, indeterminate -> review
# security-policy: enterprises maintain security disclosure via org-level
# SECURITY.md or internal portals; repo-level absence is not conclusive.
iso27001_recommended_controls := {
	"conventional-title",
	"merge-commit-policy",
	"release-asset-attestation",
	"source-authenticity",
	"security-policy",
}

map := {"severity": "warning", "decision": "review", "annotations": {"framework_ref": "ISO 27001 A.8.32"}} if {
	input.status == "violated"
	input.control_id in iso27001_recommended_controls
}

map := {"severity": "warning", "decision": "review", "annotations": {"framework_ref": "ISO 27001 A.8.32"}} if {
	input.status == "indeterminate"
	input.control_id in iso27001_recommended_controls
}

# --- All other indeterminate -> fail ---
map := {"severity": "error", "decision": "fail", "annotations": {"framework_ref": "ISO 27001 A.8.25"}} if {
	input.status == "indeterminate"
	not input.control_id in iso27001_environment_controls
	not input.control_id in iso27001_supply_chain_controls
	not input.control_id in iso27001_build_controls
	not input.control_id in iso27001_recommended_controls
}

# --- All other violated -> fail ---
map := {"severity": "error", "decision": "fail", "annotations": {"framework_ref": "ISO 27001 A.8.25"}} if {
	input.status == "violated"
	not input.control_id in iso27001_recommended_controls
}
