# SLSA Level 1 preset (Source L1, Build L1, Dependencies L1).
#
# SLSA v1.2 Level 1 requirements per track:
#   Source L1:  Version controlled (prerequisite; no libverify control)
#   Build L1:   Provenance exists → build-provenance
#   Dep L1:     Dependency inventory exists → dependency-signature (proxy)
#
# Only controls that directly map to SLSA v1.2 L1 requirements are required.
# All other controls are advisory (violated/indeterminate → review).
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

# --- Required controls: violated or indeterminate → fail ---
map := {"severity": "error", "decision": "fail"} if {
	input.status == "violated"
	input.control_id in required
}

map := {"severity": "error", "decision": "fail"} if {
	input.status == "indeterminate"
	input.control_id in required
}

# --- Non-required controls: violated or indeterminate → review ---
map := {"severity": "warning", "decision": "review"} if {
	input.status == "violated"
	not input.control_id in required
}

map := {"severity": "warning", "decision": "review"} if {
	input.status == "indeterminate"
	not input.control_id in required
}

# SLSA v1.2 Level 1 required controls:
#   Build L1:  build-provenance (provenance must exist)
#   Dep L1:    dependency-signature (proxy for dependency inventory)
required := {
	"build-provenance",
	"dependency-signature",
}
