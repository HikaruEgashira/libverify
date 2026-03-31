# SLSA Level 2 preset (Source L2, Build L2, Dependencies L2).
#
# SLSA v1.2 Level 2 requirements per track:
#   Source L2:  History & provenance → branch-history-integrity
#   Build L2:   Hosted build platform → hosted-build-platform, provenance-authenticity
#   Dep L2:     Known vulnerabilities triaged → vulnerability-scanning
#
# Inherits all L1 required controls.
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

# SLSA v1.2 Level 2 = L1 + per-track L2 additions:
#   Source L2:  branch-history-integrity (reliable history)
#   Build L1:   build-provenance
#   Build L2:   hosted-build-platform, provenance-authenticity
#   Dep L1:     dependency-signature
#   Dep L2:     vulnerability-scanning (known vulns triaged)
required := {
	"build-provenance",
	"dependency-signature",
	"branch-history-integrity",
	"hosted-build-platform",
	"provenance-authenticity",
	"vulnerability-scanning",
}
