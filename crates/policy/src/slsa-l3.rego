# SLSA Level 3 preset (Source L3, Build L3, Dependencies L3).
# Adds: branch-protection-enforcement, build-isolation,
#        dependency-signature, dependency-provenance, dependency-signer-verified.
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
	"branch-history-integrity",
	"branch-protection-enforcement",
	"build-provenance",
	"required-status-checks",
	"hosted-build-platform",
	"provenance-authenticity",
	"build-isolation",
	"dependency-signature",
	"dependency-provenance",
	"dependency-signer-verified",
}
