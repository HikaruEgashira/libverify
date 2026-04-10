# HIPAA Security Rule policy preset.
# Maps SDLC controls to Technical Safeguards (45 CFR 164.312).
# Strict on access control, audit, and integrity controls.
#
# Controls are mapped to HIPAA Technical Safeguards:
#   164.312(a) Access Control:
#     branch-protection-enforcement, codeowners-coverage,
#     secret-scanning, privileged-workflow-detection
#   164.312(b) Audit Controls:
#     issue-linkage, release-traceability, security-file-change,
#     privileged-operation-audit
#   164.312(c) Integrity:
#     source-authenticity, build-provenance, provenance-authenticity,
#     dependency-signature, dependency-provenance,
#     dependency-signer-verified, dependency-completeness
#   164.312(d) Person or Entity Authentication:
#     review-independence, two-party-review
#   164.312(e) Transmission Security:
#     provenance-authenticity
#   Administrative Safeguards 164.308:
#     vulnerability-scanning, code-scanning-alerts-resolved,
#     security-policy, security-test-in-ci
#   Recommended (not directly mapped):
#     change-request-size, scoped-change, description-quality,
#     conventional-title, merge-commit-policy
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
hipaa_build_controls := {
	"build-provenance",
	"hosted-build-platform",
	"build-isolation",
	"provenance-authenticity",
}

map := {"severity": "warning", "decision": "review", "annotations": {"framework_ref": "HIPAA 164.312(c)"}} if {
	input.status == "indeterminate"
	input.control_id in hipaa_build_controls
}

# --- Dependency/supply chain controls ---
# Provenance infra may be absent; indeterminate -> review
hipaa_dependency_controls := {
	"dependency-signature",
	"dependency-provenance",
	"dependency-signer-verified",
	"dependency-completeness",
}

map := {"severity": "warning", "decision": "review", "annotations": {"framework_ref": "HIPAA 164.312(c)"}} if {
	input.status == "indeterminate"
	input.control_id in hipaa_dependency_controls
}

# --- Development quality recommended controls ---
# violated -> review, indeterminate -> review
# security-policy: enterprises maintain security disclosure via org-level
# SECURITY.md or internal portals; repo-level absence is not conclusive.
hipaa_recommended_controls := {
	"change-request-size",
	"scoped-change",
	"description-quality",
	"conventional-title",
	"merge-commit-policy",
	"release-asset-attestation",
	"stale-review",
	"security-policy",
}

map := {"severity": "warning", "decision": "review", "annotations": {"framework_ref": "HIPAA 164.308(a)(8)"}} if {
	input.status == "violated"
	input.control_id in hipaa_recommended_controls
}

map := {"severity": "warning", "decision": "review", "annotations": {"framework_ref": "HIPAA 164.308(a)(8)"}} if {
	input.status == "indeterminate"
	input.control_id in hipaa_recommended_controls
}

# --- All other indeterminate -> fail ---
map := {"severity": "error", "decision": "fail", "annotations": {"framework_ref": "HIPAA 164.312"}} if {
	input.status == "indeterminate"
	not input.control_id in hipaa_build_controls
	not input.control_id in hipaa_dependency_controls
	not input.control_id in hipaa_recommended_controls
}

# --- All other violated -> fail ---
map := {"severity": "error", "decision": "fail", "annotations": {"framework_ref": "HIPAA 164.312"}} if {
	input.status == "violated"
	not input.control_id in hipaa_recommended_controls
}
