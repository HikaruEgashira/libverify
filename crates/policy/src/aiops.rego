# AI-driven SDLC audit preset.
# Maps all indeterminate findings to review instead of fail, so that
# insufficient evidence is escalated to a human reviewer rather than
# causing an automatic gate failure. Violated controls still fail.
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

map := {"severity": "error", "decision": "fail"} if {
	input.status == "violated"
}
