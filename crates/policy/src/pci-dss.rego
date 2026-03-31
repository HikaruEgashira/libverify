# PCI DSS v4.0 Requirement 6.x (Secure Development) policy preset.
# Applicable to payment card processing systems and supporting infrastructure.
#
# Controls are mapped to PCI DSS v4.0 requirements:
#   Req 6.2.3 (Code Review):      review-independence, two-party-review, stale-review
#   Req 6.3.1 (Vulnerability Mgmt): vulnerability-scanning, secret-scanning
#   Req 6.5.1 (Change Management): change-request-size, description-quality, issue-linkage
#   Req 6.5.4 (Separation of Duties): review-independence, two-party-review
#   Build Integrity:               build-provenance, source-authenticity
#   Development Quality (advisory): test-coverage, scoped-change, conventional-title,
#                                    merge-commit-policy
#   Dependency Controls:           dependency-signature, dependency-provenance
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

# --- Req 6.2.3 / 6.5.4: Code review and separation of duties (violated -> fail) ---
# --- Req 6.3.1: Vulnerability management (violated -> fail) ---
# --- Req 6.5.1: Change management (violated -> fail) ---
# --- Build integrity (violated -> fail) ---
pcidss_mandatory_controls := {
	"review-independence",
	"two-party-review",
	"stale-review",
	"vulnerability-scanning",
	"secret-scanning",
	"change-request-size",
	"description-quality",
	"issue-linkage",
	"build-provenance",
	"source-authenticity",
	"secret-scanning-push-protection",
	"branch-protection-admin-enforcement",
	"actions-pinned-dependencies",
	"environment-protection-rules",
	"code-scanning-alerts-resolved",
	"dependency-license-compliance",
	"privileged-workflow-detection",
}

# --- Development quality (advisory, violated -> review) ---
pcidss_advisory_controls := {
	"test-coverage",
	"scoped-change",
	"conventional-title",
	"merge-commit-policy",
	"dismiss-stale-reviews-on-push",
	"sbom-attestation",
	"release-asset-attestation",
}

# --- Dependency controls (violated -> fail, indeterminate -> review) ---
pcidss_dependency_controls := {
	"dependency-signature",
	"dependency-provenance",
}

# --- Advisory controls: violated -> review ---
map := {"severity": "warning", "decision": "review"} if {
	input.status == "violated"
	input.control_id in pcidss_advisory_controls
}

# --- Dependency controls: indeterminate -> review ---
map := {"severity": "warning", "decision": "review"} if {
	input.status == "indeterminate"
	input.control_id in pcidss_dependency_controls
}

# --- All other indeterminate -> fail (strict PCI DSS posture) ---
map := {"severity": "error", "decision": "fail"} if {
	input.status == "indeterminate"
	not input.control_id in pcidss_dependency_controls
}

# --- All other violated -> fail (PCI DSS-critical controls) ---
map := {"severity": "error", "decision": "fail"} if {
	input.status == "violated"
	not input.control_id in pcidss_advisory_controls
}
