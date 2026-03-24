# SOC2 (Trust Services Criteria) policy preset.
# Enforces all five Trust Services Categories relevant to SDLC:
#   Security, Availability, Processing Integrity, Confidentiality, Privacy.
#
# Controls are tiered:
#   - Security-critical controls (CC6/CC7/CC8/PI core) → hard fail on violated
#   - Advisory controls (dev-quality, style) → review on violated
#   - OSS-origin controls → review on violated (enterprises use alternative evidence)
#   - Build/dependency-track indeterminate → review (infra may be absent)
#
# SOC2 criteria mapping:
#   CC6 (Logical Access):     source-authenticity, branch-protection-enforcement,
#                             codeowners-coverage, secret-scanning
#   CC7 (System Operations):  issue-linkage, stale-review, security-file-change,
#                             release-traceability, required-status-checks,
#                             vulnerability-scanning, security-policy
#   CC8 (Change Management):  review-independence, two-party-review, change-request-size,
#                             test-coverage, scoped-change, description-quality,
#                             merge-commit-policy, conventional-title,
#                             branch-history-integrity
#   PI  (Processing Integrity): build-provenance, hosted-build-platform,
#                               provenance-authenticity, build-isolation
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

# --- Build-track indeterminate → review (attestation infra may be absent) ---
soc2_build_controls := {
	"build-provenance",
	"hosted-build-platform",
	"provenance-authenticity",
	"build-isolation",
}

map := {"severity": "warning", "decision": "review"} if {
	input.status == "indeterminate"
	input.control_id in soc2_build_controls
}

# --- Dependency-track indeterminate → review (provenance infra may be absent) ---
soc2_dependency_controls := {
	"dependency-signature",
	"dependency-provenance",
	"dependency-signer-verified",
	"dependency-completeness",
}

map := {"severity": "warning", "decision": "review"} if {
	input.status == "indeterminate"
	input.control_id in soc2_dependency_controls
}

# --- Advisory controls (dev quality / style, not SOC2-critical) ---
# These improve hygiene but no SOC2 auditor will issue an exception for
# non-conventional commit titles or large PRs.
soc2_advisory_controls := {
	"change-request-size",
	"scoped-change",
	"description-quality",
	"merge-commit-policy",
	"conventional-title",
}

map := {"severity": "warning", "decision": "review"} if {
	input.status == "violated"
	input.control_id in soc2_advisory_controls
}

map := {"severity": "warning", "decision": "review"} if {
	input.status == "indeterminate"
	input.control_id in soc2_advisory_controls
}

# --- OSS-origin controls → review in enterprise (alternative evidence accepted) ---
# security-policy checks for SECURITY.md which is an OSS convention.
# Enterprises typically maintain disclosure processes in internal portals,
# so a missing repo-level file is not a hard failure for SOC2.
soc2_oss_origin_controls := {
	"security-policy",
}

map := {"severity": "warning", "decision": "review"} if {
	input.status == "violated"
	input.control_id in soc2_oss_origin_controls
}

map := {"severity": "warning", "decision": "review"} if {
	input.status == "indeterminate"
	input.control_id in soc2_oss_origin_controls
}

# --- All other indeterminate → fail (strict SOC2 posture) ---
map := {"severity": "error", "decision": "fail"} if {
	input.status == "indeterminate"
	not input.control_id in soc2_build_controls
	not input.control_id in soc2_dependency_controls
	not input.control_id in soc2_advisory_controls
	not input.control_id in soc2_oss_origin_controls
}

# --- All other violated → fail (SOC2-critical controls) ---
map := {"severity": "error", "decision": "fail"} if {
	input.status == "violated"
	not input.control_id in soc2_advisory_controls
	not input.control_id in soc2_oss_origin_controls
}
