# SOC2 (Trust Services Criteria) policy preset.
# Enforces all five Trust Services Categories relevant to SDLC:
#   Security, Availability, Processing Integrity, Confidentiality, Privacy.
#
# All controls are strict by default. SOC2 CC7 (System Operations) and
# CC8 (Change Management) controls are treated as hard gates.
# Indeterminate findings on build-track controls are escalated to review
# (evidence may require attestation infrastructure not yet in place).
#
# SOC2 criteria mapping:
#   CC6 (Logical Access):     source-authenticity, branch-protection-enforcement
#   CC7 (System Operations):  issue-linkage, stale-review, security-file-change,
#                             release-traceability, required-status-checks
#   CC8 (Change Management):  review-independence, two-party-review, pr-size,
#                             test-coverage, scoped-change, description-quality,
#                             merge-commit-policy, conventional-title,
#                             branch-history-integrity
#   PI  (Processing Integrity): build-provenance, hosted-build-platform,
#                               provenance-authenticity, build-isolation
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

# --- Build-track indeterminate → review (attestation infra may be absent) ---
soc2_build_controls := {
	"build-provenance",
	"hosted-build-platform",
	"provenance-authenticity",
	"build-isolation",
}

map := {"severity": "warning", "decision": "review"} if {
	input.status == "indeterminate"
	input.control_id in soc2_build_controls
}

# --- All other indeterminate → fail (strict SOC2 posture) ---
map := {"severity": "error", "decision": "fail"} if {
	input.status == "indeterminate"
	not input.control_id in soc2_build_controls
}

# --- All violated → fail (no exceptions in SOC2) ---
map := {"severity": "error", "decision": "fail"} if {
	input.status == "violated"
}
