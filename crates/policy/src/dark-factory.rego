# Dark Factory preset for AI-agent-driven development.
# PR-based controls are advisory; agent safety controls are strict.
#
# In a "dark factory" workflow, AI agents autonomously write code, run tests,
# and merge changes without human-initiated pull requests. This preset:
#   - Enforces agent safety controls strictly (harness, permissions, spec)
#   - Treats PR-ceremony controls as advisory (PRs may not exist)
#   - Keeps all other security-critical controls strict
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

# All indeterminate -> review (escalate to human)
map := {"severity": "warning", "decision": "review"} if {
	input.status == "indeterminate"
}

# --- Dark factory core controls (strict on violated) ---
# These are the agent safety controls that must never be bypassed.
dark_factory_required := {
	"harness-result",
	"destructive-action-detection",
	"agent-permission-boundary",
	"agent-spec-conformance",
	"privileged-operation-audit",
}

map := {"severity": "error", "decision": "fail"} if {
	input.status == "violated"
	input.control_id in dark_factory_required
}

# --- PR-ceremony controls (advisory on violated) ---
# In dark factory workflows, PRs may not exist or may be auto-generated.
# Violations are advisory (review), not blocking.
pr_ceremony_controls := {
	"review-independence",
	"two-party-review",
	"stale-review",
	"change-request-size",
	"description-quality",
	"conventional-title",
	"merge-commit-policy",
	"issue-linkage",
	"scoped-change",
	"branch-history-integrity",
	"branch-protection-enforcement",
	"branch-protection-admin-enforcement",
	"dismiss-stale-reviews-on-push",
	"source-authenticity",
}

map := {"severity": "warning", "decision": "review"} if {
	input.status == "violated"
	input.control_id in pr_ceremony_controls
}

# --- All other controls: violated -> fail (security-critical stays strict) ---
map := {"severity": "error", "decision": "fail"} if {
	input.status == "violated"
	not input.control_id in dark_factory_required
	not input.control_id in pr_ceremony_controls
}
