# SLSA Level 1 preset (Source L1, Build L1, Dependencies L1).
# Required: source-authenticity, review-independence, build-provenance,
#           required-status-checks, dependency-signature.
# All other controls are advisory (indeterminate → review).
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

map := {"severity": "error", "decision": "fail"} if {
	input.status == "indeterminate"
	input.control_id in required
}

map := {"severity": "warning", "decision": "review"} if {
	input.status == "indeterminate"
	not input.control_id in required
}

map := {"severity": "error", "decision": "fail"} if {
	input.status == "violated"
}

required := {
	"source-authenticity",
	"review-independence",
	"build-provenance",
	"required-status-checks",
	"dependency-signature",
}
