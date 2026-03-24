# OSS project / solo developer preset.
# Tolerates unsigned commits, self-reviewed merges, and dev-quality conventions
# that are common in open-source and personal projects.
#
# Relaxations:
#   - source-authenticity: unsigned commits → review (common in OSS)
#   - review-independence: solo self-merge → review (indeterminate)
#   - two-party-review: single reviewer → review (OSS norm is 1 approver)
#   - required-status-checks: CI may not exist → review (indeterminate)
#   - issue-linkage: trivial fixes/docs skip issues → review
#   - conventional-title: most OSS don't use conventional commits → review
#   - ASPM posture: codeowners, secret-scanning, vuln-scanning → review
#   - security-policy: strict (SECURITY.md is primary disclosure channel for OSS)
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

# --- Controls relaxed for OSS (violated → review) ---
# These are common in open-source workflows and should not block CI.
# Controls that commonly produce false positives in OSS due to platform
# limitations (Gerrit mirrors, bot workflows, no GHAS, etc.)
oss_review_on_violated := {
	"source-authenticity",
	"two-party-review",
	"branch-protection-enforcement",
	"issue-linkage",
	"conventional-title",
	"codeowners-coverage",
	"vulnerability-scanning",
	"secret-scanning",
	"dependency-provenance",
	"dependency-signer-verified",
	"dependency-completeness",
}

map := {"severity": "warning", "decision": "review"} if {
	input.status == "violated"
	input.control_id in oss_review_on_violated
}

# --- Controls relaxed for OSS (indeterminate → review) ---
# Evidence may be incomplete for OSS (Gerrit mirrors, external CI, etc.)
# Indeterminate = "cannot prove from available evidence" → review, not fail.
oss_review_on_indeterminate := {
	"review-independence",
	"required-status-checks",
	"branch-history-integrity",
	"branch-protection-enforcement",
	"two-party-review",
	"codeowners-coverage",
	"vulnerability-scanning",
	"secret-scanning",
	"dependency-provenance",
	"dependency-signer-verified",
	"dependency-completeness",
}

map := {"severity": "warning", "decision": "review"} if {
	input.status == "indeterminate"
	input.control_id in oss_review_on_indeterminate
}

# --- Generic fallbacks ---

map := {"severity": "error", "decision": "fail"} if {
	input.status == "indeterminate"
	not input.control_id in oss_review_on_indeterminate
}

map := {"severity": "error", "decision": "fail"} if {
	input.status == "violated"
	not input.control_id in oss_review_on_violated
}
