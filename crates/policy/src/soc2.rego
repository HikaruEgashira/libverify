# SOC2 (Trust Services Criteria) policy preset.
# Enforces all five Trust Services Categories relevant to SDLC:
#   Security, Availability, Processing Integrity, Confidentiality, Privacy.
#
# Controls are tiered:
#   - Security-critical controls (CC6/CC7/CC8/PI core) → hard fail on violated
#   - Advisory controls (dev-quality, style) → review on violated
#   - Build/dependency-track indeterminate → review (infra may be absent)
#   - Source-authenticity → review (commit signing is not a CC6 requirement;
#     CC6 covers authentication/authorization, not Git signatures)
#
# SOC2 criteria mapping:
#   CC6 (Logical Access):     branch-protection-enforcement,
#                             codeowners-coverage, secret-scanning
#   CC7 (System Operations):  stale-review, security-file-change,
#                             release-traceability, required-status-checks,
#                             vulnerability-scanning, security-policy
#   CC8 (Change Management):  review-independence, two-party-review,
#                             branch-history-integrity, test-coverage
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
# --- Enterprise posture controls not directly TSC-critical → advisory ---
# These are good security practices but SOC2 auditors assess them via
# alternative evidence (GRC platforms, security tooling dashboards).
soc2_enterprise_advisory_controls := {
	"release-asset-attestation",
}

map := {"severity": "warning", "decision": "review"} if {
	input.status == "violated"
	input.control_id in soc2_enterprise_advisory_controls
}

map := {"severity": "warning", "decision": "review"} if {
	input.status == "indeterminate"
	input.control_id in soc2_enterprise_advisory_controls
}

soc2_advisory_controls := {
	"change-request-size",
	"scoped-change",
	"description-quality",
	"merge-commit-policy",
	"conventional-title",
	"issue-linkage",
}

map := {"severity": "warning", "decision": "review"} if {
	input.status == "violated"
	input.control_id in soc2_advisory_controls
}

map := {"severity": "warning", "decision": "review"} if {
	input.status == "indeterminate"
	input.control_id in soc2_advisory_controls
}

# --- Controls not directly required by SOC2 TSC → review ---
# source-authenticity: commit signing is not a CC6 authentication requirement.
# security-policy: enterprises maintain disclosure in internal portals.
# security-file-change: no direct TSC mapping.
# stale-review: CC7 operational concern but not a hard gate.
soc2_non_tsc_controls := {
	"source-authenticity",
	"security-policy",
	"security-file-change",
	"stale-review",
}

map := {"severity": "warning", "decision": "review"} if {
	input.status == "violated"
	input.control_id in soc2_non_tsc_controls
}

map := {"severity": "warning", "decision": "review"} if {
	input.status == "indeterminate"
	input.control_id in soc2_non_tsc_controls
}

# --- All other indeterminate → fail (strict SOC2 posture) ---
map := {"severity": "error", "decision": "fail"} if {
	input.status == "indeterminate"
	not input.control_id in soc2_build_controls
	not input.control_id in soc2_dependency_controls
	not input.control_id in soc2_advisory_controls
	not input.control_id in soc2_non_tsc_controls
	not input.control_id in soc2_enterprise_advisory_controls
}

# --- All other violated → fail (SOC2-critical controls) ---
map := {"severity": "error", "decision": "fail"} if {
	input.status == "violated"
	not input.control_id in soc2_advisory_controls
	not input.control_id in soc2_non_tsc_controls
	not input.control_id in soc2_enterprise_advisory_controls
}
