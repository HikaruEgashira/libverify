# SLSA Level 4 preset (Source L4, Build L3, Dependencies L4 — maximum).
#
# SLSA v1.2 Level 4 requirements per track:
#   Source L4:  Two-party review → two-party-review, review-independence
#   Build L3:   (maximum; no Build L4 in SLSA v1.2)
#   Dep L4:     Proactive defense against upstream attack →
#               dependency-completeness
#
# Inherits all L1+L2+L3 required controls.
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

# SLSA v1.2 Level 4 = L1 + L2 + L3 + per-track L4 additions:
#   Source L2:  branch-history-integrity
#   Source L3:  branch-protection-enforcement, source-authenticity,
#              required-status-checks
#   Source L4:  two-party-review, review-independence
#   Build L1:   build-provenance
#   Build L2:   hosted-build-platform, provenance-authenticity
#   Build L3:   build-isolation
#   Dep L1:     dependency-signature
#   Dep L2:     vulnerability-scanning
#   Dep L3:     dependency-provenance, dependency-signer-verified
#   Dep L4:     dependency-completeness
required := {
	"build-provenance",
	"dependency-signature",
	"branch-history-integrity",
	"hosted-build-platform",
	"provenance-authenticity",
	"vulnerability-scanning",
	"branch-protection-enforcement",
	"source-authenticity",
	"required-status-checks",
	"build-isolation",
	"dependency-provenance",
	"dependency-signer-verified",
	"two-party-review",
	"review-independence",
	"dependency-completeness",
}
