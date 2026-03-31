# PCI DSS v4.0 Requirement 6.x (Secure Development) policy preset.
# Applicable to payment card processing systems and supporting infrastructure.
#
# Controls are mapped to PCI DSS v4.0 requirements:
#   Req 6.2.3 (Code Review):      review-independence, two-party-review
#   Req 6.3.1 (Vulnerability Mgmt): vulnerability-scanning, secret-scanning,
#                                    code-scanning-alerts-resolved
#   Req 6.5.1 (Change Management): issue-linkage, stale-review
#   Req 6.5.4 (Separation of Duties): review-independence
#   Build Integrity:               build-provenance, source-authenticity,
#                                  provenance-authenticity
#   Development Quality (advisory): test-coverage, scoped-change,
#                                   conventional-title, merge-commit-policy,
#                                   change-request-size, description-quality
#   Dependency Controls:           dependency-signature, dependency-provenance
#
# Note: change-request-size and description-quality are advisory because
# PCI DSS Req 6.5.1 requires change management processes, not PR size limits
# or description formatting.
#
# Input (set per finding):
#   input.control_id  - kebab-case control identifier (e.g. "review-independence")
#   input.status      - "satisfied" | "violated" | "indeterminate" | "not_applicable"
#   input.rationale   - human-readable explanation
#   input.subjects    - list of affected artifact URIs
#
# Output (data.verify.profile.map):
#   severity    - "info" | "warning" | "error"
#   decision    - "pass" | "review" | "fail"
#   annotations - optional map with "framework_ref" linking to the PCI DSS requirement

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
	"issue-linkage",
	"build-provenance",
	"source-authenticity",
	"provenance-authenticity",
	"branch-protection-enforcement",
	"branch-history-integrity",
	"secret-scanning-push-protection",
	"branch-protection-admin-enforcement",
	"actions-pinned-dependencies",
	"environment-protection-rules",
	"code-scanning-alerts-resolved",
	"dependency-license-compliance",
	"privileged-workflow-detection",
	"default-branch-settings-baseline",
	"security-test-in-ci",
}

# --- Development quality (advisory, violated/indeterminate -> review) ---
# PCI DSS does not prescribe PR size, description format, or commit conventions.
pcidss_advisory_controls := {
	"test-coverage",
	"scoped-change",
	"conventional-title",
	"merge-commit-policy",
	"change-request-size",
	"description-quality",
	"dismiss-stale-reviews-on-push",
	"sbom-attestation",
	"release-asset-attestation",
	"codeowners-coverage",
	"release-traceability",
	"security-policy",
	"security-file-change",
	"repository-permissions-audit",
	"workflow-permissions-restricted",
	"dependency-update-tool",
}

# --- Dependency controls (violated -> fail, indeterminate -> review) ---
pcidss_dependency_controls := {
	"dependency-signature",
	"dependency-provenance",
	"dependency-signer-verified",
	"dependency-completeness",
}

# --- Build controls (violated -> fail, indeterminate -> review) ---
pcidss_build_controls := {
	"hosted-build-platform",
	"build-isolation",
}

# --- Advisory controls: violated -> review ---
map := {"severity": "warning", "decision": "review", "annotations": {"framework_ref": "PCI DSS v4.0 Req 6.5.1"}} if {
	input.status == "violated"
	input.control_id in pcidss_advisory_controls
}

# --- Advisory controls: indeterminate -> review ---
map := {"severity": "warning", "decision": "review", "annotations": {"framework_ref": "PCI DSS v4.0 Req 6.5.1"}} if {
	input.status == "indeterminate"
	input.control_id in pcidss_advisory_controls
}

# --- Dependency controls: indeterminate -> review ---
map := {"severity": "warning", "decision": "review", "annotations": {"framework_ref": "PCI DSS v4.0 Req 6.3.2"}} if {
	input.status == "indeterminate"
	input.control_id in pcidss_dependency_controls
}

# --- Build controls: indeterminate -> review ---
map := {"severity": "warning", "decision": "review", "annotations": {"framework_ref": "PCI DSS v4.0 Req 6.5.1"}} if {
	input.status == "indeterminate"
	input.control_id in pcidss_build_controls
}

# --- All other indeterminate -> fail (strict PCI DSS posture) ---
map := {"severity": "error", "decision": "fail", "annotations": {"framework_ref": "PCI DSS v4.0 Req 6.2.3"}} if {
	input.status == "indeterminate"
	not input.control_id in pcidss_dependency_controls
	not input.control_id in pcidss_build_controls
	not input.control_id in pcidss_advisory_controls
}

# --- All other violated -> fail (PCI DSS-critical controls) ---
map := {"severity": "error", "decision": "fail", "annotations": {"framework_ref": "PCI DSS v4.0 Req 6.2.3"}} if {
	input.status == "violated"
	not input.control_id in pcidss_advisory_controls
}
