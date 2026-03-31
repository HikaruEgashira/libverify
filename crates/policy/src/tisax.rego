# TISAX (Trusted Information Security Assessment Exchange) policy preset.
# Based on VDA ISA (Information Security Assessment) catalog.
# Designed for AL3 (highest assessment level) for automotive industry.
#
# Controls are mapped to VDA ISA domains:
#   VDA ISA 1.3.1 (Change Management): change-request-size, review-independence,
#                                       description-quality
#   VDA ISA 1.3.2 (Separation of Duties): review-independence, two-party-review,
#                                          codeowners-coverage
#   VDA ISA 1.6.1 (Cryptography):      source-authenticity, dependency-signature
#   VDA ISA 3.1.2 (Development Env):   build-isolation, hosted-build-platform
#   VDA ISA 3.1.3 (Source Code Mgmt):  branch-protection-enforcement,
#                                       branch-history-integrity
#   VDA ISA 4.1  (Supply Chain):       dependency-signature, dependency-provenance,
#                                       dependency-signer-verified,
#                                       dependency-completeness, vulnerability-scanning
#   Recommended (dev quality):          test-coverage, scoped-change, conventional-title,
#                                       merge-commit-policy, issue-linkage
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
#   annotations - optional object with "framework_ref" citing VDA ISA clause

package verify.profile

import rego.v1

default map := {"severity": "error", "decision": "fail"}

map := {"severity": "info", "decision": "pass"} if {
	input.status == "satisfied"
}

map := {"severity": "info", "decision": "pass"} if {
	input.status == "not_applicable"
}

# --- AL3 mandatory controls (violated -> fail) ---
# Combines VDA ISA 1.3.1, 1.3.2, 1.6.1, 3.1.3, 4.1
tisax_mandatory_controls := {
	"review-independence",
	"two-party-review",
	"codeowners-coverage",
	"source-authenticity",
	"dependency-signature",
	"branch-protection-enforcement",
	"branch-history-integrity",
	"dependency-provenance",
	"dependency-signer-verified",
	"dependency-completeness",
	"vulnerability-scanning",
	"secret-scanning",
	"required-status-checks",
	"build-provenance",
	"provenance-authenticity",
	"secret-scanning-push-protection",
	"branch-protection-admin-enforcement",
	"actions-pinned-dependencies",
	"environment-protection-rules",
	"code-scanning-alerts-resolved",
	"privileged-workflow-detection",
	"repository-permissions-audit",
	"workflow-permissions-restricted",
}

# --- Development environment (VDA ISA 3.1.2) ---
# violated -> fail, indeterminate -> review (infra may be absent)
tisax_devenv_controls := {
	"build-isolation",
	"hosted-build-platform",
}

# --- Recommended controls (violated -> review) ---
# These improve development quality but are not explicitly required by VDA ISA.
# sbom-attestation, release-asset-attestation, dependency-license-compliance:
#   Useful for VDA ISA 4.1 supply chain visibility but not mandatory controls.
#   Moved to recommended until VDA ISA explicitly mandates SBOM attestation.
tisax_recommended_controls := {
	"test-coverage",
	"scoped-change",
	"conventional-title",
	"merge-commit-policy",
	"issue-linkage",
	"change-request-size",
	"description-quality",
	"stale-review",
	"release-traceability",
	"security-file-change",
	"security-policy",
	"dismiss-stale-reviews-on-push",
	"dependency-license-compliance",
	"sbom-attestation",
	"release-asset-attestation",
	"dependency-update-tool",
}

# --- Recommended: violated -> review ---
map := {"severity": "warning", "decision": "review", "annotations": {"framework_ref": "TISAX VDA ISA 1.3.1"}} if {
	input.status == "violated"
	input.control_id in tisax_recommended_controls
}

# --- Development environment: indeterminate -> review ---
map := {"severity": "warning", "decision": "review", "annotations": {"framework_ref": "TISAX VDA ISA 3.1.2"}} if {
	input.status == "indeterminate"
	input.control_id in tisax_devenv_controls
}

# --- All other indeterminate -> fail (strict AL3 posture) ---
map := {"severity": "error", "decision": "fail", "annotations": {"framework_ref": "TISAX VDA ISA 4.1"}} if {
	input.status == "indeterminate"
	not input.control_id in tisax_devenv_controls
}

# --- All other violated -> fail ---
map := {"severity": "error", "decision": "fail", "annotations": {"framework_ref": "TISAX VDA ISA 4.1"}} if {
	input.status == "violated"
	not input.control_id in tisax_recommended_controls
}
