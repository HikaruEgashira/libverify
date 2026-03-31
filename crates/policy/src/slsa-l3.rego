# SLSA Level 3 preset (Source L3, Build L3, Dependencies L3).
#
# SLSA v1.2 Level 3 requirements per track:
#   Source L3:  Continuous technical controls → branch-protection-enforcement,
#               source-authenticity, required-status-checks
#   Build L3:   Hardened builds → build-isolation
#   Dep L3:     Dependencies from producer-controlled locations →
#               dependency-provenance, dependency-signer-verified
#
# Inherits all L1+L2 required controls.
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

# SLSA v1.2 Level 3 = L1 + L2 + per-track L3 additions:
#   Source L2:  branch-history-integrity
#   Source L3:  branch-protection-enforcement, source-authenticity,
#              required-status-checks (continuous enforcement)
#   Build L1:   build-provenance
#   Build L2:   hosted-build-platform, provenance-authenticity
#   Build L3:   build-isolation (hardened builds)
#   Dep L1:     dependency-signature
#   Dep L2:     vulnerability-scanning
#   Dep L3:     dependency-provenance, dependency-signer-verified
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
}
