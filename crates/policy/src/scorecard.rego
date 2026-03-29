# OpenSSF Scorecard-compatible preset.
#
# Maps libverify controls to their OSSF Scorecard equivalents, using
# Scorecard risk levels (Critical / High / Medium) to drive gate severity.
#
# Only controls that libverify can actually verify are included.
# Scorecard checks with no libverify equivalent (License, Maintained,
# Contributors, Fuzzing, Packaging, CII-Best-Practices, Binary-Artifacts,
# Dangerous-Workflow, Dependency-Update-Tool, Token-Permissions) are
# intentionally omitted — those are static repository posture checks
# outside libverify's verification scope and should be assessed by
# Scorecard itself.
#
# Scorecard mapping:
#   Critical  → Vulnerabilities       → vulnerability-scanning
#   High      → Branch-Protection     → branch-protection-enforcement
#   High      → Code-Review           → review-independence
#   High      → Signed-Releases       → build-provenance, provenance-authenticity
#   Medium    → CI-Tests              → required-status-checks
#   Medium    → Security-Policy       → security-policy
#   Medium    → Pinned-Dependencies   → dependency-signature
#   Medium    → SAST                  → vulnerability-scanning (code_scanning)
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

default map := {"severity": "warning", "decision": "review"}

map := {"severity": "info", "decision": "pass"} if {
	input.status == "satisfied"
}

map := {"severity": "info", "decision": "pass"} if {
	input.status == "not_applicable"
}

# --- Critical / High: violated or indeterminate → fail ---

map := {"severity": "error", "decision": "fail"} if {
	input.status == "violated"
	input.control_id in scorecard_critical_high
}

map := {"severity": "error", "decision": "fail"} if {
	input.status == "indeterminate"
	input.control_id in scorecard_critical_high
}

# --- Medium: violated → fail, indeterminate → review ---

map := {"severity": "error", "decision": "fail"} if {
	input.status == "violated"
	input.control_id in scorecard_medium
}

map := {"severity": "warning", "decision": "review"} if {
	input.status == "indeterminate"
	input.control_id in scorecard_medium
}

# --- Controls not mapped to Scorecard: advisory only ---

map := {"severity": "warning", "decision": "review"} if {
	input.status == "violated"
	not input.control_id in scorecard_critical_high
	not input.control_id in scorecard_medium
}

map := {"severity": "warning", "decision": "review"} if {
	input.status == "indeterminate"
	not input.control_id in scorecard_critical_high
	not input.control_id in scorecard_medium
}

# Scorecard Critical + High risk checks
# Critical: Vulnerabilities
# High: Branch-Protection, Code-Review, Signed-Releases
scorecard_critical_high := {
	"vulnerability-scanning",
	"branch-protection-enforcement",
	"review-independence",
	"build-provenance",
	"provenance-authenticity",
}

# Scorecard Medium risk checks
# CI-Tests, Security-Policy, Pinned-Dependencies, SAST
scorecard_medium := {
	"required-status-checks",
	"security-policy",
	"dependency-signature",
}
