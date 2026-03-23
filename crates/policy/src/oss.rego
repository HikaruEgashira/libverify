# OSS project / solo developer preset.
# Tolerates unsigned commits and self-reviewed merges that are common
# in open-source and personal projects, while keeping all other
# controls strict.
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

# source-authenticity violated -> review (unsigned commits are acceptable in OSS)
map := {"severity": "warning", "decision": "review"} if {
	input.control_id == "source-authenticity"
	input.status == "violated"
}

# review-independence indeterminate -> review (solo maintainer self-merge)
map := {"severity": "warning", "decision": "review"} if {
	input.control_id == "review-independence"
	input.status == "indeterminate"
}

# required-status-checks indeterminate -> review (CI may not be configured in personal repos)
map := {"severity": "warning", "decision": "review"} if {
	input.control_id == "required-status-checks"
	input.status == "indeterminate"
}

# Generic indeterminate -> fail (except those handled above)
map := {"severity": "error", "decision": "fail"} if {
	input.status == "indeterminate"
	input.control_id != "review-independence"
	input.control_id != "required-status-checks"
}

# Generic violated -> fail (except source-authenticity, handled above)
map := {"severity": "error", "decision": "fail"} if {
	input.status == "violated"
	input.control_id != "source-authenticity"
}
