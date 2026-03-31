# SOC1 (SSAE 18 / ISAE 3402) policy preset.
# Focused on Internal Controls over Financial Reporting (ICFR).
# Enforces processing integrity and change traceability controls strictly.
# Controls outside ICFR scope are advisory (review, not fail).
#
# Key SOC1 control objectives mapped:
#   CC-PI  (Processing Integrity): build provenance, required status checks,
#          hosted build platform, provenance authenticity
#   CC-CM  (Change Management): review independence, branch protection,
#          two-party review, stale review
#   CC-TR  (Traceability): issue linkage, release traceability
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

# --- Advisory controls (dev quality, not ICFR-relevant) ---
# Change-request size, scoped change, description quality, merge commit policy,
# conventional title, test coverage: violations are warnings, not gates.
soc1_advisory_controls := {
	"change-request-size",
	"scoped-change",
	"description-quality",
	"merge-commit-policy",
	"conventional-title",
	"test-coverage",
}

map := {"severity": "warning", "decision": "review"} if {
	input.status == "violated"
	input.control_id in soc1_advisory_controls
}

map := {"severity": "warning", "decision": "review"} if {
	input.status == "indeterminate"
	input.control_id in soc1_advisory_controls
}

# --- Non-ICFR controls (outside SOC1 scope → review, not fail) ---
# These controls relate to security posture, not financial reporting.
# SOC1 auditors do not issue exceptions for these.
soc1_out_of_scope := {
	"source-authenticity",
	"security-policy",
	"security-file-change",
	"vulnerability-scanning",
	"secret-scanning",
	"codeowners-coverage",
	"branch-history-integrity",
	"secret-scanning-push-protection",
	"branch-protection-admin-enforcement",
	"dismiss-stale-reviews-on-push",
	"actions-pinned-dependencies",
	"environment-protection-rules",
	"code-scanning-alerts-resolved",
	"dependency-license-compliance",
	"sbom-attestation",
	"release-asset-attestation",
	"privileged-workflow-detection",
	"repository-permissions-audit",
	"workflow-permissions-restricted",
	"dependency-update-tool",
}

map := {"severity": "warning", "decision": "review"} if {
	input.status == "violated"
	input.control_id in soc1_out_of_scope
}

map := {"severity": "warning", "decision": "review"} if {
	input.status == "indeterminate"
	input.control_id in soc1_out_of_scope
}

# --- Strict controls (ICFR-critical): violated or indeterminate → fail ---
map := {"severity": "error", "decision": "fail"} if {
	input.status == "violated"
	not input.control_id in soc1_advisory_controls
	not input.control_id in soc1_out_of_scope
}

map := {"severity": "error", "decision": "fail"} if {
	input.status == "indeterminate"
	not input.control_id in soc1_advisory_controls
	not input.control_id in soc1_out_of_scope
}
