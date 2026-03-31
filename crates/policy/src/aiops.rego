# AI-driven SDLC audit preset.
# Designed for workflows where AI generates code, commits, and PRs.
#
# Key design decisions:
#   - All indeterminate → review (insufficient evidence → human escalation)
#   - Dev-quality controls (titles, descriptions, PR size) → review on violated
#     because AI-generated content may not follow human conventions
#   - Security-critical controls remain strict (violated → fail)
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

# All indeterminate -> review (escalate to human, don't auto-fail)
map := {"severity": "warning", "decision": "review"} if {
	input.status == "indeterminate"
}

# --- Dev-quality controls: violated → review ---
# AI-generated PRs commonly produce non-conventional titles, descriptions,
# and commit messages. These are style violations, not security issues.
aiops_devquality_controls := {
	"conventional-title",
	"description-quality",
	"change-request-size",
	"scoped-change",
	"merge-commit-policy",
	"issue-linkage",
	"workflow-permissions-restricted",
	"dependency-update-tool",
}

map := {"severity": "warning", "decision": "review"} if {
	input.status == "violated"
	input.control_id in aiops_devquality_controls
}

# --- Security-critical: violated → fail ---
map := {"severity": "error", "decision": "fail"} if {
	input.status == "violated"
	not input.control_id in aiops_devquality_controls
}
