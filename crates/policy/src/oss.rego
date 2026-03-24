# OSS project / solo developer preset.
# Tolerates unsigned commits and self-reviewed merges that are common
# in open-source and personal projects, while keeping all other
# controls strict.
#
# ASPM posture controls are relaxed for OSS:
#   - codeowners-coverage: many small projects don't use CODEOWNERS
#   - secret-scanning: not available on all GitHub plans
#   - vulnerability-scanning: projects may use external scanners (Snyk, Trivy)
#   - security-policy: strict — SECURITY.md is the primary disclosure channel for OSS
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

# source-authenticity violated -> review (unsigned commits are acceptable in OSS)
map := {"severity": "warning", "decision": "review"} if {
	input.control_id == "source-authenticity"
	input.status == "violated"
}

# review-independence indeterminate -> review (solo maintainer self-merge)
map := {"severity": "warning", "decision": "review"} if {
	input.control_id == "review-independence"
	input.status == "indeterminate"
}

# required-status-checks indeterminate -> review (CI may not be configured in personal repos)
map := {"severity": "warning", "decision": "review"} if {
	input.control_id == "required-status-checks"
	input.status == "indeterminate"
}

# --- ASPM posture controls relaxed for OSS ---

# codeowners-coverage: many OSS projects don't use CODEOWNERS
oss_posture_review_controls := {
	"codeowners-coverage",
	"vulnerability-scanning",
}

map := {"severity": "warning", "decision": "review"} if {
	input.control_id in oss_posture_review_controls
	input.status == "violated"
}

map := {"severity": "warning", "decision": "review"} if {
	input.control_id in oss_posture_review_controls
	input.status == "indeterminate"
}

# secret-scanning indeterminate -> review (not available on GitHub Free)
map := {"severity": "warning", "decision": "review"} if {
	input.control_id == "secret-scanning"
	input.status == "indeterminate"
}

# Generic indeterminate -> fail (except those handled above)
map := {"severity": "error", "decision": "fail"} if {
	input.status == "indeterminate"
	input.control_id != "review-independence"
	input.control_id != "required-status-checks"
	input.control_id != "secret-scanning"
	not input.control_id in oss_posture_review_controls
}

# Generic violated -> fail (except those handled above)
map := {"severity": "error", "decision": "fail"} if {
	input.status == "violated"
	input.control_id != "source-authenticity"
	not input.control_id in oss_posture_review_controls
}
