# OSS project / solo developer preset.
# Tolerates unsigned commits, self-reviewed merges, and dev-quality conventions
# that are common in open-source and personal projects.
#
# Relaxations (violated/indeterminate → review instead of fail):
#   Source:     unsigned commits, self-merge, solo review, stale review
#   CI/CD:      missing CI, no status checks
#   Posture:    codeowners, secret/vuln scanning, security-policy
#   Dev-quality: PR size, scoped change, descriptions, conventional titles
#   Enterprise: GHAS features (push protection, admin enforcement, code scanning, etc.)
#   Build/Dep:  attestation infra (provenance, signatures) typically absent in OSS
#
# Only controls that are strict (violated → fail):
#   - test-coverage: basic code hygiene even for OSS
#   - source-authenticity: violated (distinct from indeterminate) still reviewed
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

# --- Controls relaxed for OSS (violated → review) ---
# These are common in open-source workflows and should not block CI.
# Controls that commonly produce false positives in OSS due to platform
# limitations (Gerrit mirrors, bot workflows, no GHAS, etc.)
oss_review_on_violated := {
	"source-authenticity",
	"two-party-review",
	"branch-protection-enforcement",
	"issue-linkage",
	"conventional-title",
	"codeowners-coverage",
	"vulnerability-scanning",
	"secret-scanning",
	"security-policy",
	"stale-review",
	"security-file-change",
	# Dev-quality controls (style, not security)
	"change-request-size",
	"scoped-change",
	"description-quality",
	"merge-commit-policy",
	"release-traceability",
	# Enterprise posture controls (require GHAS/Enterprise, not available in most OSS)
	"secret-scanning-push-protection",
	"branch-protection-admin-enforcement",
	"dismiss-stale-reviews-on-push",
	"actions-pinned-dependencies",
	"environment-protection-rules",
	"code-scanning-alerts-resolved",
	"dependency-license-compliance",
	"sbom-attestation",
	"release-asset-attestation",
	"privileged-workflow-detection",
	"repository-permissions-audit",
	"workflow-permissions-restricted",
	"dependency-update-tool",
	"default-branch-settings-baseline",
	"security-test-in-ci",
}

map := {"severity": "warning", "decision": "review"} if {
	input.status == "violated"
	input.control_id in oss_review_on_violated
}

# --- Controls relaxed for OSS (indeterminate → review) ---
# Evidence may be incomplete for OSS (Gerrit mirrors, external CI, etc.)
# Indeterminate = "cannot prove from available evidence" → review, not fail.
oss_review_on_indeterminate := {
	"review-independence",
	"required-status-checks",
	"branch-history-integrity",
	"branch-protection-enforcement",
	"two-party-review",
	"codeowners-coverage",
	"vulnerability-scanning",
	"secret-scanning",
	"security-policy",
	"stale-review",
	"security-file-change",
	# Dev-quality controls
	"change-request-size",
	"scoped-change",
	"description-quality",
	"merge-commit-policy",
	"release-traceability",
	# Build/dependency controls (attestation infra typically absent in OSS)
	"build-provenance",
	"hosted-build-platform",
	"provenance-authenticity",
	"build-isolation",
	"dependency-signature",
	"dependency-provenance",
	"dependency-signer-verified",
	"dependency-completeness",
	# Enterprise posture controls
	"secret-scanning-push-protection",
	"branch-protection-admin-enforcement",
	"dismiss-stale-reviews-on-push",
	"actions-pinned-dependencies",
	"environment-protection-rules",
	"code-scanning-alerts-resolved",
	"dependency-license-compliance",
	"sbom-attestation",
	"release-asset-attestation",
	"privileged-workflow-detection",
	"repository-permissions-audit",
	"workflow-permissions-restricted",
	"dependency-update-tool",
	"default-branch-settings-baseline",
	"security-test-in-ci",
}

map := {"severity": "warning", "decision": "review"} if {
	input.status == "indeterminate"
	input.control_id in oss_review_on_indeterminate
}

# --- Generic fallbacks ---

map := {"severity": "error", "decision": "fail"} if {
	input.status == "indeterminate"
	not input.control_id in oss_review_on_indeterminate
}

map := {"severity": "error", "decision": "fail"} if {
	input.status == "violated"
	not input.control_id in oss_review_on_violated
}
