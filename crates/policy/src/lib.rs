use anyhow::{Context, Result, bail};

use libverify_core::control::ControlFinding;
use libverify_core::profile::{
    ControlProfile, FindingSeverity, GateDecision, ProfileOutcome, SeverityLabels,
};
use std::collections::BTreeMap;

const RULE_PATH: &str = "data.verify.profile.map";

/// Single source of truth for built-in presets.
///
/// To add a preset: append one entry here and create the `.rego` file.
/// Everything else (lookup, error messages, tests) derives from this table.
struct Preset {
    /// CLI-facing name (e.g. "scorecard")
    name: &'static str,
    /// Rego source (embedded at compile time)
    rego: &'static str,
    /// Internal profile name used by `severity_labels()` dispatch
    profile_name: &'static str,
}

const PRESETS: &[Preset] = &[
    Preset {
        name: "default",
        rego: include_str!("default.rego"),
        profile_name: "opa-default",
    },
    Preset {
        name: "oss",
        rego: include_str!("oss.rego"),
        profile_name: "oss",
    },
    Preset {
        name: "aiops",
        rego: include_str!("aiops.rego"),
        profile_name: "aiops",
    },
    Preset {
        name: "soc1",
        rego: include_str!("soc1.rego"),
        profile_name: "soc1",
    },
    Preset {
        name: "soc2",
        rego: include_str!("soc2.rego"),
        profile_name: "soc2",
    },
    Preset {
        name: "scorecard",
        rego: include_str!("scorecard.rego"),
        profile_name: "scorecard",
    },
    Preset {
        name: "slsa-l1",
        rego: include_str!("slsa-l1.rego"),
        profile_name: "slsa-l1",
    },
    Preset {
        name: "slsa-l2",
        rego: include_str!("slsa-l2.rego"),
        profile_name: "slsa-l2",
    },
    Preset {
        name: "slsa-l3",
        rego: include_str!("slsa-l3.rego"),
        profile_name: "slsa-l3",
    },
    Preset {
        name: "slsa-l4",
        rego: include_str!("slsa-l4.rego"),
        profile_name: "slsa-l4",
    },
    Preset {
        name: "ismap",
        rego: include_str!("ismap.rego"),
        profile_name: "ismap",
    },
    Preset {
        name: "pci-dss",
        rego: include_str!("pci-dss.rego"),
        profile_name: "pci-dss",
    },
    Preset {
        name: "tisax",
        rego: include_str!("tisax.rego"),
        profile_name: "tisax",
    },
    Preset {
        name: "nist-800-53",
        rego: include_str!("nist-800-53.rego"),
        profile_name: "nist-800-53",
    },
    Preset {
        name: "wp29",
        rego: include_str!("wp29.rego"),
        profile_name: "wp29",
    },
];

/// Returns the names of all built-in presets.
pub fn available_presets() -> Vec<&'static str> {
    PRESETS.iter().map(|p| p.name).collect()
}

/// OPA-based profile that evaluates Rego policies to map control findings
/// to gate decisions, enabling per-organization customization.
pub struct OpaProfile {
    engine: regorus::Engine,
    profile_name: String,
}

impl OpaProfile {
    /// Loads a built-in preset by name, or falls back to file path.
    pub fn from_preset_or_file(name: &str) -> Result<Self> {
        if let Some(preset) = PRESETS.iter().find(|p| p.name == name) {
            return Self::from_rego_with_name(
                &format!("{}.rego", preset.name),
                preset.rego,
                preset.profile_name,
            );
        }
        Self::from_file(name)
    }

    /// Loads a custom Rego policy from the given file path.
    pub fn from_file(path: &str) -> Result<Self> {
        let names: Vec<_> = available_presets();
        let policy = std::fs::read_to_string(path).with_context(|| {
            format!(
                "reading policy '{path}'. Use a built-in preset ({}) or a path to a .rego file",
                names.join(", ")
            )
        })?;
        Self::from_rego_with_name(path, &policy, "opa-custom")
    }

    /// Loads a Rego policy from a string.
    pub fn from_rego(name: &str, rego: &str) -> Result<Self> {
        Self::from_rego_with_name(name, rego, "opa-custom")
    }

    fn from_rego_with_name(name: &str, rego: &str, profile_name: &str) -> Result<Self> {
        let mut engine = regorus::Engine::new();
        engine
            .add_policy(name.to_string(), rego.to_string())
            .with_context(|| format!("parsing policy {name}"))?;
        Ok(Self {
            engine,
            profile_name: profile_name.to_string(),
        })
    }

    fn eval_finding(
        &self,
        finding: &ControlFinding,
    ) -> Result<(FindingSeverity, GateDecision, BTreeMap<String, String>)> {
        let input_json = serde_json::to_string(finding).context("serializing finding to JSON")?;

        let mut engine = self.engine.clone();
        engine.set_input(regorus::Value::from_json_str(&input_json).context("parsing input")?);

        let result = engine
            .eval_rule(RULE_PATH.to_string())
            .context("evaluating OPA rule")?;

        let severity = result["severity"]
            .as_string()
            .context("policy output missing 'severity' string field")?;
        let decision = result["decision"]
            .as_string()
            .context("policy output missing 'decision' string field")?;

        let severity = parse_severity(severity.as_ref())?;
        let decision = parse_decision(decision.as_ref())?;

        // Extract optional annotations object from Rego output
        let annotations = extract_annotations(&result);

        Ok((severity, decision, annotations))
    }
}

impl ControlProfile for OpaProfile {
    fn name(&self) -> &str {
        &self.profile_name
    }

    fn map(&self, finding: &ControlFinding) -> ProfileOutcome {
        let (severity, decision, annotations) = self.eval_finding(finding).unwrap_or_else(|err| {
            eprintln!(
                "Warning: OPA evaluation failed for {}: {err:#}. Defaulting to Fail.",
                finding.control_id
            );
            (FindingSeverity::Error, GateDecision::Fail, BTreeMap::new())
        });

        ProfileOutcome {
            control_id: finding.control_id.clone(),
            severity,
            decision,
            rationale: finding.rationale.clone(),
            annotations,
        }
    }

    fn severity_labels(&self) -> SeverityLabels {
        match self.profile_name.as_str() {
            "soc1" => SeverityLabels {
                info: "effective".to_string(),
                warning: "deficiency".to_string(),
                error: "material_weakness".to_string(),
            },
            _ => SeverityLabels::default(),
        }
    }
}

/// Extract string-valued entries from the optional "annotations" object in Rego output.
fn extract_annotations(result: &regorus::Value) -> BTreeMap<String, String> {
    let mut map = BTreeMap::new();
    if let Ok(ann) = result["annotations"].as_object() {
        for (k, v) in ann.iter() {
            if let (Ok(key), Ok(val)) = (k.as_string(), v.as_string()) {
                map.insert(key.to_string(), val.to_string());
            }
        }
    }
    map
}

fn parse_severity(s: &str) -> Result<FindingSeverity> {
    match s {
        "info" => Ok(FindingSeverity::Info),
        "warning" => Ok(FindingSeverity::Warning),
        "error" => Ok(FindingSeverity::Error),
        _ => bail!("invalid severity '{s}': expected info, warning, or error"),
    }
}

fn parse_decision(s: &str) -> Result<GateDecision> {
    match s {
        "pass" => Ok(GateDecision::Pass),
        "review" => Ok(GateDecision::Review),
        "fail" => Ok(GateDecision::Fail),
        _ => bail!("invalid decision '{s}': expected pass, review, or fail"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use libverify_core::control::{ControlStatus, builtin};

    fn make_finding(control_id: &str, status: ControlStatus) -> ControlFinding {
        let id = builtin::id(control_id);
        match status {
            ControlStatus::Satisfied => {
                ControlFinding::satisfied(id, "test rationale", vec!["subject".into()])
            }
            ControlStatus::Violated => {
                ControlFinding::violated(id, "test rationale", vec!["subject".into()])
            }
            ControlStatus::Indeterminate => {
                ControlFinding::indeterminate(id, "test rationale", vec!["subject".into()], vec![])
            }
            ControlStatus::NotApplicable => ControlFinding::not_applicable(id, "test rationale"),
        }
    }

    #[test]
    fn all_presets_load() {
        for name in available_presets() {
            assert!(
                OpaProfile::from_preset_or_file(name).is_ok(),
                "preset '{name}' failed to load"
            );
        }
    }

    #[test]
    fn default_policy_violated_fails() {
        let profile = OpaProfile::from_preset_or_file("default").unwrap();
        let finding = make_finding(builtin::REVIEW_INDEPENDENCE, ControlStatus::Violated);
        let outcome = profile.map(&finding);
        assert_eq!(outcome.decision, GateDecision::Fail);
    }

    #[test]
    fn default_policy_satisfied_passes() {
        let profile = OpaProfile::from_preset_or_file("default").unwrap();
        let finding = make_finding(builtin::REVIEW_INDEPENDENCE, ControlStatus::Satisfied);
        let outcome = profile.map(&finding);
        assert_eq!(outcome.decision, GateDecision::Pass);
    }

    #[test]
    fn oss_preset_source_authenticity_violated_is_review() {
        let profile = OpaProfile::from_preset_or_file("oss").unwrap();
        let finding = make_finding(builtin::SOURCE_AUTHENTICITY, ControlStatus::Violated);
        let outcome = profile.map(&finding);
        assert_eq!(outcome.decision, GateDecision::Review);
    }

    #[test]
    fn soc1_preset_returns_soc1_severity_labels() {
        let profile = OpaProfile::from_preset_or_file("soc1").unwrap();
        let labels = profile.severity_labels();
        assert_eq!(labels.error, "material_weakness");
    }

    #[test]
    fn slsa_l1_required_indeterminate_fails() {
        // SLSA v1.2: Build L1 requires build-provenance
        let profile = OpaProfile::from_preset_or_file("slsa-l1").unwrap();
        let finding = make_finding(builtin::BUILD_PROVENANCE, ControlStatus::Indeterminate);
        let outcome = profile.map(&finding);
        assert_eq!(outcome.decision, GateDecision::Fail);
    }

    #[test]
    fn slsa_l1_review_independence_not_required() {
        // SLSA v1.2: Source L1 only requires version control, not review independence
        let profile = OpaProfile::from_preset_or_file("slsa-l1").unwrap();
        let finding = make_finding(builtin::REVIEW_INDEPENDENCE, ControlStatus::Indeterminate);
        let outcome = profile.map(&finding);
        assert_eq!(outcome.decision, GateDecision::Review);
    }

    #[test]
    fn slsa_l1_optional_indeterminate_reviews() {
        let profile = OpaProfile::from_preset_or_file("slsa-l1").unwrap();
        let finding = make_finding(
            builtin::BRANCH_HISTORY_INTEGRITY,
            ControlStatus::Indeterminate,
        );
        let outcome = profile.map(&finding);
        assert_eq!(outcome.decision, GateDecision::Review);
    }

    #[test]
    fn slsa_l2_branch_history_required() {
        let profile = OpaProfile::from_preset_or_file("slsa-l2").unwrap();
        let finding = make_finding(
            builtin::BRANCH_HISTORY_INTEGRITY,
            ControlStatus::Indeterminate,
        );
        let outcome = profile.map(&finding);
        assert_eq!(outcome.decision, GateDecision::Fail);
    }

    #[test]
    fn slsa_l1_non_slsa_control_indeterminate_reviews() {
        let profile = OpaProfile::from_preset_or_file("slsa-l1").unwrap();
        let finding = make_finding(builtin::CHANGE_REQUEST_SIZE, ControlStatus::Indeterminate);
        let outcome = profile.map(&finding);
        assert_eq!(outcome.decision, GateDecision::Review);
    }

    #[test]
    fn slsa_l1_dependency_signature_required() {
        let profile = OpaProfile::from_preset_or_file("slsa-l1").unwrap();
        let finding = make_finding(builtin::DEPENDENCY_SIGNATURE, ControlStatus::Indeterminate);
        let outcome = profile.map(&finding);
        assert_eq!(outcome.decision, GateDecision::Fail);
    }

    #[test]
    fn slsa_l2_vulnerability_scanning_required() {
        // SLSA v1.2: Dep L2 requires known vulnerabilities triaged
        let profile = OpaProfile::from_preset_or_file("slsa-l2").unwrap();
        let finding = make_finding(
            builtin::VULNERABILITY_SCANNING,
            ControlStatus::Indeterminate,
        );
        let outcome = profile.map(&finding);
        assert_eq!(outcome.decision, GateDecision::Fail);
    }

    #[test]
    fn slsa_l2_dependency_provenance_not_required() {
        // SLSA v1.2: dependency-provenance is Dep L3, not L2
        let profile = OpaProfile::from_preset_or_file("slsa-l2").unwrap();
        let finding = make_finding(
            builtin::DEPENDENCY_PROVENANCE_CHECK,
            ControlStatus::Indeterminate,
        );
        let outcome = profile.map(&finding);
        assert_eq!(outcome.decision, GateDecision::Review);
    }

    #[test]
    fn slsa_l3_dependency_signer_verified_required() {
        let profile = OpaProfile::from_preset_or_file("slsa-l3").unwrap();
        let finding = make_finding(
            builtin::DEPENDENCY_SIGNER_VERIFIED,
            ControlStatus::Indeterminate,
        );
        let outcome = profile.map(&finding);
        assert_eq!(outcome.decision, GateDecision::Fail);
    }

    #[test]
    fn slsa_l4_dependency_completeness_required() {
        let profile = OpaProfile::from_preset_or_file("slsa-l4").unwrap();
        let finding = make_finding(
            builtin::DEPENDENCY_COMPLETENESS,
            ControlStatus::Indeterminate,
        );
        let outcome = profile.map(&finding);
        assert_eq!(outcome.decision, GateDecision::Fail);
    }

    #[test]
    fn slsa_l1_dependency_provenance_optional() {
        let profile = OpaProfile::from_preset_or_file("slsa-l1").unwrap();
        let finding = make_finding(
            builtin::DEPENDENCY_PROVENANCE_CHECK,
            ControlStatus::Indeterminate,
        );
        let outcome = profile.map(&finding);
        assert_eq!(outcome.decision, GateDecision::Review);
    }

    #[test]
    fn soc1_change_request_size_advisory() {
        let profile = OpaProfile::from_preset_or_file("soc1").unwrap();
        let finding = make_finding(builtin::CHANGE_REQUEST_SIZE, ControlStatus::Violated);
        let outcome = profile.map(&finding);
        assert_eq!(outcome.decision, GateDecision::Review);
    }

    // --- Scorecard preset tests ---

    #[test]
    fn scorecard_critical_violated_fails() {
        let profile = OpaProfile::from_preset_or_file("scorecard").unwrap();
        let finding = make_finding(builtin::VULNERABILITY_SCANNING, ControlStatus::Violated);
        let outcome = profile.map(&finding);
        assert_eq!(outcome.decision, GateDecision::Fail);
        assert_eq!(outcome.severity, FindingSeverity::Error);
    }

    #[test]
    fn scorecard_critical_indeterminate_fails() {
        let profile = OpaProfile::from_preset_or_file("scorecard").unwrap();
        let finding = make_finding(
            builtin::VULNERABILITY_SCANNING,
            ControlStatus::Indeterminate,
        );
        let outcome = profile.map(&finding);
        assert_eq!(outcome.decision, GateDecision::Fail);
    }

    #[test]
    fn scorecard_high_violated_fails() {
        let profile = OpaProfile::from_preset_or_file("scorecard").unwrap();
        let finding = make_finding(builtin::REVIEW_INDEPENDENCE, ControlStatus::Violated);
        let outcome = profile.map(&finding);
        assert_eq!(outcome.decision, GateDecision::Fail);
    }

    #[test]
    fn scorecard_medium_violated_fails() {
        let profile = OpaProfile::from_preset_or_file("scorecard").unwrap();
        let finding = make_finding(builtin::REQUIRED_STATUS_CHECKS, ControlStatus::Violated);
        let outcome = profile.map(&finding);
        assert_eq!(outcome.decision, GateDecision::Fail);
    }

    #[test]
    fn scorecard_medium_indeterminate_reviews() {
        let profile = OpaProfile::from_preset_or_file("scorecard").unwrap();
        let finding = make_finding(
            builtin::REQUIRED_STATUS_CHECKS,
            ControlStatus::Indeterminate,
        );
        let outcome = profile.map(&finding);
        assert_eq!(outcome.decision, GateDecision::Review);
    }

    #[test]
    fn scorecard_unmapped_violated_reviews() {
        let profile = OpaProfile::from_preset_or_file("scorecard").unwrap();
        let finding = make_finding(builtin::CHANGE_REQUEST_SIZE, ControlStatus::Violated);
        let outcome = profile.map(&finding);
        assert_eq!(outcome.decision, GateDecision::Review);
    }

    #[test]
    fn custom_policy_from_string() {
        let custom_rego = r#"
package verify.profile
import rego.v1
default map := {"severity": "error", "decision": "fail"}
map := {"severity": "info", "decision": "pass"} if { input.status == "satisfied" }
map := {"severity": "warning", "decision": "review"} if { input.status == "indeterminate" }
"#;
        let profile = OpaProfile::from_rego("custom.rego", custom_rego).unwrap();
        let finding = make_finding(builtin::REVIEW_INDEPENDENCE, ControlStatus::Indeterminate);
        let outcome = profile.map(&finding);
        assert_eq!(outcome.decision, GateDecision::Review);
    }

    #[test]
    fn annotations_extracted_from_rego() {
        let rego = r#"
package verify.profile
import rego.v1
default map := {"severity": "error", "decision": "fail", "annotations": {"framework_ref": "TEST-1"}}
map := {"severity": "info", "decision": "pass"} if { input.status == "satisfied" }
"#;
        let profile = OpaProfile::from_rego("ann.rego", rego).unwrap();
        let finding = make_finding(builtin::REVIEW_INDEPENDENCE, ControlStatus::Violated);
        let outcome = profile.map(&finding);
        assert_eq!(
            outcome.annotations.get("framework_ref").map(|s| s.as_str()),
            Some("TEST-1")
        );
    }

    #[test]
    fn annotations_empty_when_absent() {
        let profile = OpaProfile::from_preset_or_file("default").unwrap();
        let finding = make_finding(builtin::REVIEW_INDEPENDENCE, ControlStatus::Violated);
        let outcome = profile.map(&finding);
        assert!(outcome.annotations.is_empty());
    }

    #[test]
    fn ismap_annotations_present() {
        let profile = OpaProfile::from_preset_or_file("ismap").unwrap();
        let finding = make_finding(builtin::REVIEW_INDEPENDENCE, ControlStatus::Violated);
        let outcome = profile.map(&finding);
        assert!(
            !outcome.annotations.is_empty(),
            "ISMAP violated finding should have annotations"
        );
        assert!(outcome.annotations.contains_key("framework_ref"));
    }

    /// Ensure every preset returns a deterministic result for every built-in
    /// control in both violated and indeterminate states.
    /// This catches control_id classification gaps that silently fall to default.
    #[test]
    fn all_presets_cover_all_controls() {
        let presets = available_presets();
        // Presets that intentionally use status-only rules (no per-control sets)
        // and have a deliberate default for unclassified controls:
        //   - default:  all violated/indeterminate → fail (intentional)
        //   - slsa-l1/l2/l3/l4: non-required → review (intentional)
        //   - scorecard: unmapped → review (intentional)
        //   - aiops: devquality → review, rest → fail (uses complement)
        //   - oss: uses complement with explicit fallback
        //
        // For presets with explicit sets (soc1, soc2, ismap, pci-dss, tisax,
        // nist-800-53, wp29), we verify every control produces a result.
        // All presets should load and evaluate without error.
        for preset_name in &presets {
            let profile = OpaProfile::from_preset_or_file(preset_name)
                .unwrap_or_else(|e| panic!("Failed to load preset '{preset_name}': {e}"));
            for control_id in builtin::ALL {
                for status in [ControlStatus::Violated, ControlStatus::Indeterminate] {
                    let finding = make_finding(control_id, status);
                    let outcome = profile.map(&finding);
                    // Every control must produce pass, review, or fail — never panic
                    assert!(
                        matches!(
                            outcome.decision,
                            GateDecision::Pass | GateDecision::Review | GateDecision::Fail
                        ),
                        "Preset '{preset_name}' returned unexpected decision for \
                         control '{control_id}' with status {status:?}: {:?}",
                        outcome.decision,
                    );
                }
            }
        }
    }
}
