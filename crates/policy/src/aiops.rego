# AI-driven SDLC audit preset.
# Designed for workflows where AI agents autonomously write code, run tests,
# and merge changes — with or without human-initiated pull requests.
#
# Key design decisions:
#   - Agent safety controls (harness, permissions, spec, privileged ops)
#     are strict: violated → fail
#   - PR-ceremony controls (titles, descriptions, PR size, review) → review
#     on violated, because agents may not create PRs or follow human conventions
#   - All indeterminate → review (insufficient evidence → human escalation)
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

# --- Agent safety controls (strict on violated) ---
# These are the core agent safety controls that must never be bypassed.
aiops_agent_safety := {
	"harness-result",
	"destructive-action-detection",
	"agent-permission-boundary",
	"agent-spec-conformance",
	"privileged-operation-audit",
}

map := {"severity": "error", "decision": "fail"} if {
	input.status == "violated"
	input.control_id in aiops_agent_safety
}

# --- PR-ceremony + dev-quality controls (advisory on violated) ---
# AI-generated PRs commonly produce non-conventional titles, descriptions,
# and commit messages. In agentless workflows, PRs may not exist.
# Violations are advisory (review), not blocking.
aiops_advisory_controls := {
	"conventional-title",
	"description-quality",
	"change-request-size",
	"scoped-change",
	"merge-commit-policy",
	"issue-linkage",
	"review-independence",
	"two-party-review",
	"stale-review",
	"branch-history-integrity",
	"branch-protection-enforcement",
	"branch-protection-admin-enforcement",
	"dismiss-stale-reviews-on-push",
	"source-authenticity",
	"workflow-permissions-restricted",
	"dependency-update-tool",
}

map := {"severity": "warning", "decision": "review"} if {
	input.status == "violated"
	input.control_id in aiops_advisory_controls
}

# --- All other controls: violated → fail (security-critical stays strict) ---
map := {"severity": "error", "decision": "fail"} if {
	input.status == "violated"
	not input.control_id in aiops_agent_safety
	not input.control_id in aiops_advisory_controls
}
