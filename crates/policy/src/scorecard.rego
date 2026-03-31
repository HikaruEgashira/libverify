# OpenSSF Scorecard-compatible preset.
#
# Maps libverify controls to their OSSF Scorecard equivalents, using
# Scorecard risk levels (Critical / High / Medium / Low) to drive gate severity.
#
# Only controls that libverify can actually verify are included.
# Scorecard checks with no libverify equivalent (License, Maintained,
# Contributors, Fuzzing, Packaging, CII-Best-Practices, Binary-Artifacts,
# Dependency-Update-Tool, Webhooks) are intentionally omitted — those are
# static repository posture checks outside libverify's verification scope
# and should be assessed by Scorecard itself.
#
# Scorecard mapping (risk level → libverify controls):
#   Critical  → Dangerous-Workflow      → privileged-workflow-detection
#   High      → Branch-Protection       → branch-protection-enforcement,
#                                          branch-protection-admin-enforcement
#   High      → Code-Review             → review-independence, two-party-review
#   High      → Signed-Releases         → build-provenance, provenance-authenticity
#   High      → Token-Permissions       → actions-pinned-dependencies (proxy)
#   Medium    → CI-Tests                → required-status-checks
#   Medium    → Security-Policy         → security-policy
#   Medium    → Pinned-Dependencies     → dependency-signature
#   Medium    → SAST                    → vulnerability-scanning, code-scanning-alerts-resolved
#   Medium    → SBOM                    → sbom-attestation
#   Low       → (no libverify mapping for CII-Best-Practices, License, etc.)
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

# --- Critical / High: violated or indeterminate → fail ---

map := {"severity": "error", "decision": "fail"} if {
	input.status == "violated"
	input.control_id in scorecard_critical_high
}

map := {"severity": "error", "decision": "fail"} if {
	input.status == "indeterminate"
	input.control_id in scorecard_critical_high
}

# --- Medium: violated → fail, indeterminate → review ---

map := {"severity": "error", "decision": "fail"} if {
	input.status == "violated"
	input.control_id in scorecard_medium
}

map := {"severity": "warning", "decision": "review"} if {
	input.status == "indeterminate"
	input.control_id in scorecard_medium
}

# --- Controls not mapped to Scorecard: advisory only ---

map := {"severity": "warning", "decision": "review"} if {
	input.status == "violated"
	not input.control_id in scorecard_critical_high
	not input.control_id in scorecard_medium
}

map := {"severity": "warning", "decision": "review"} if {
	input.status == "indeterminate"
	not input.control_id in scorecard_critical_high
	not input.control_id in scorecard_medium
}

# Scorecard Critical risk checks
# Critical: Dangerous-Workflow → privileged-workflow-detection
#
# Scorecard High risk checks
# High: Branch-Protection → branch-protection-enforcement,
#                           branch-protection-admin-enforcement
# High: Code-Review → review-independence, two-party-review
# High: Signed-Releases → build-provenance, provenance-authenticity
# High: Token-Permissions → actions-pinned-dependencies (closest proxy)
scorecard_critical_high := {
	"privileged-workflow-detection",
	"vulnerability-scanning",
	"branch-protection-enforcement",
	"branch-protection-admin-enforcement",
	"review-independence",
	"two-party-review",
	"build-provenance",
	"provenance-authenticity",
	"actions-pinned-dependencies",
	"secret-scanning",
	"repository-permissions-audit",
	"workflow-permissions-restricted",
	"default-branch-settings-baseline",
	"protected-tags",
}

# Scorecard Medium risk checks
# Medium: CI-Tests → required-status-checks
# Medium: Security-Policy → security-policy
# Medium: Pinned-Dependencies → dependency-signature
# Medium: SAST → code-scanning-alerts-resolved
# Medium: SBOM → sbom-attestation
scorecard_medium := {
	"required-status-checks",
	"security-policy",
	"dependency-signature",
	"code-scanning-alerts-resolved",
	"sbom-attestation",
	"dependency-update-tool",
	"security-test-in-ci",
}
