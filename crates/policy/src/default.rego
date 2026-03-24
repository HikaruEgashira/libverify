# Default OPA policy: all controls are strict (Indeterminate → Fail).
# Copy and modify this file to customize gate decisions per organization.
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

# --- Dependency-track L2+ controls → advisory ---
# Most package registries (crates.io, npm, PyPI) do not yet provide
# cryptographic signatures, signer identity, or transparency logs.
# These controls will fail for virtually all dependencies today,
# producing noise rather than signal. Relax to review until ecosystem
# adoption matures. dependency-signature (L1, checksum-based) remains strict.
default_dependency_advisory := {
	"dependency-provenance",
	"dependency-signer-verified",
	"dependency-completeness",
}

map := {"severity": "warning", "decision": "review"} if {
	input.status == "violated"
	input.control_id in default_dependency_advisory
}

map := {"severity": "warning", "decision": "review"} if {
	input.status == "indeterminate"
	input.control_id in default_dependency_advisory
}

# --- Generic fallbacks (strict) ---
map := {"severity": "error", "decision": "fail"} if {
	input.status == "indeterminate"
	not input.control_id in default_dependency_advisory
}

map := {"severity": "error", "decision": "fail"} if {
	input.status == "violated"
	not input.control_id in default_dependency_advisory
}
