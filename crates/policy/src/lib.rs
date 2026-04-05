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
    /// CLI-facing name (e.g. "soc2")
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

    // ── Preset registry ─────────────────────────────────────────────

    #[test]
    fn available_presets_returns_exact_list() {
        assert_eq!(
            available_presets(),
            vec![
                "default",
                "oss",
                "aiops",
                "soc1",
                "soc2",
                "slsa-l1",
                "slsa-l2",
                "slsa-l3",
                "slsa-l4",
                "ismap",
                "pci-dss",
                "tisax",
                "nist-800-53",
                "wp29",
            ]
        );
    }

    #[test]
    fn all_presets_load_valid_rego() {
        for name in available_presets() {
            OpaProfile::from_preset_or_file(name)
                .unwrap_or_else(|e| panic!("preset '{name}' failed to load: {e}"));
        }
    }

    // ── Profile identity ────────────────────────────────────────────

    #[test]
    fn profile_name_matches_preset_for_all_presets() {
        let expected: &[(&str, &str)] = &[
            ("default", "opa-default"),
            ("oss", "oss"),
            ("aiops", "aiops"),
            ("soc1", "soc1"),
            ("soc2", "soc2"),
            ("slsa-l1", "slsa-l1"),
            ("slsa-l2", "slsa-l2"),
            ("slsa-l3", "slsa-l3"),
            ("slsa-l4", "slsa-l4"),
            ("ismap", "ismap"),
            ("pci-dss", "pci-dss"),
            ("tisax", "tisax"),
            ("nist-800-53", "nist-800-53"),
            ("wp29", "wp29"),
        ];
        for &(preset, expected_name) in expected {
            let profile = OpaProfile::from_preset_or_file(preset).unwrap();
            assert_eq!(profile.name(), expected_name, "preset '{preset}'");
        }
    }

    #[test]
    fn custom_rego_profile_name_is_opa_custom() {
        let rego = r#"
package verify.profile
import rego.v1
default map := {"severity": "error", "decision": "fail"}
"#;
        let profile = OpaProfile::from_rego("test.rego", rego).unwrap();
        assert_eq!(profile.name(), "opa-custom");
    }

    // ── Severity labels ─────────────────────────────────────────────

    #[test]
    fn severity_labels_soc1_returns_all_custom_labels() {
        let profile = OpaProfile::from_preset_or_file("soc1").unwrap();
        let labels = profile.severity_labels();
        assert_eq!(labels.info, "effective");
        assert_eq!(labels.warning, "deficiency");
        assert_eq!(labels.error, "material_weakness");
    }

    #[test]
    fn severity_labels_non_soc1_presets_return_default() {
        let defaults = SeverityLabels::default();
        for name in available_presets().into_iter().filter(|n| *n != "soc1") {
            let profile = OpaProfile::from_preset_or_file(name).unwrap();
            assert_eq!(
                profile.severity_labels(),
                defaults,
                "preset '{name}' should use default severity labels"
            );
        }
    }

    // ── Policy decision matrix ──────────────────────────────────────
    // Each row: (preset, control, status, expected_decision, expected_severity)

    #[test]
    fn preset_control_decision_matrix() {
        use ControlStatus::*;
        use FindingSeverity as S;
        use GateDecision as D;

        let cases: &[(&str, &str, ControlStatus, D, S)] = &[
            // default: advisory-only — violated → review, satisfied → pass
            (
                "default",
                builtin::REVIEW_INDEPENDENCE,
                Violated,
                D::Review,
                S::Warning,
            ),
            (
                "default",
                builtin::REVIEW_INDEPENDENCE,
                Satisfied,
                D::Pass,
                S::Info,
            ),
            // oss: complement-based — source-authenticity violated → review
            (
                "oss",
                builtin::SOURCE_AUTHENTICITY,
                Violated,
                D::Review,
                S::Warning,
            ),
            // slsa-l1: build-provenance required, review-independence optional
            (
                "slsa-l1",
                builtin::BUILD_PROVENANCE,
                Indeterminate,
                D::Fail,
                S::Error,
            ),
            (
                "slsa-l1",
                builtin::REVIEW_INDEPENDENCE,
                Indeterminate,
                D::Review,
                S::Warning,
            ),
            (
                "slsa-l1",
                builtin::BRANCH_HISTORY_INTEGRITY,
                Indeterminate,
                D::Review,
                S::Warning,
            ),
            (
                "slsa-l1",
                builtin::DEPENDENCY_SIGNATURE,
                Indeterminate,
                D::Fail,
                S::Error,
            ),
            (
                "slsa-l1",
                builtin::DEPENDENCY_PROVENANCE_CHECK,
                Indeterminate,
                D::Review,
                S::Warning,
            ),
            (
                "slsa-l1",
                builtin::CHANGE_REQUEST_SIZE,
                Indeterminate,
                D::Review,
                S::Warning,
            ),
            // slsa-l2: branch-history + vuln-scanning required, dep-provenance not yet
            (
                "slsa-l2",
                builtin::BRANCH_HISTORY_INTEGRITY,
                Indeterminate,
                D::Fail,
                S::Error,
            ),
            (
                "slsa-l2",
                builtin::VULNERABILITY_SCANNING,
                Indeterminate,
                D::Fail,
                S::Error,
            ),
            (
                "slsa-l2",
                builtin::DEPENDENCY_PROVENANCE_CHECK,
                Indeterminate,
                D::Review,
                S::Warning,
            ),
            // slsa-l3: dep-signer-verified required
            (
                "slsa-l3",
                builtin::DEPENDENCY_SIGNER_VERIFIED,
                Indeterminate,
                D::Fail,
                S::Error,
            ),
            // slsa-l4: dep-completeness required
            (
                "slsa-l4",
                builtin::DEPENDENCY_COMPLETENESS,
                Indeterminate,
                D::Fail,
                S::Error,
            ),
            // soc1: change-request-size is advisory
            (
                "soc1",
                builtin::CHANGE_REQUEST_SIZE,
                Violated,
                D::Review,
                S::Warning,
            ),
            // aiops: agent safety controls are strict
            (
                "aiops",
                builtin::AGENT_SPEC_CONFORMANCE,
                Violated,
                D::Fail,
                S::Error,
            ),
            (
                "aiops",
                builtin::PRIVILEGED_OPERATION_AUDIT,
                Violated,
                D::Fail,
                S::Error,
            ),
            // aiops: PR-ceremony controls are advisory
            (
                "aiops",
                builtin::REVIEW_INDEPENDENCE,
                Violated,
                D::Review,
                S::Warning,
            ),
            (
                "aiops",
                builtin::TWO_PARTY_REVIEW,
                Violated,
                D::Review,
                S::Warning,
            ),
            (
                "aiops",
                builtin::CHANGE_REQUEST_SIZE,
                Violated,
                D::Review,
                S::Warning,
            ),
            // aiops: indeterminate -> review
            (
                "aiops",
                builtin::AGENT_SPEC_CONFORMANCE,
                Indeterminate,
                D::Review,
                S::Warning,
            ),
            // aiops: other security controls stay strict
            (
                "aiops",
                builtin::VULNERABILITY_SCANNING,
                Violated,
                D::Fail,
                S::Error,
            ),
        ];

        for &(preset, control, status, exp_decision, exp_severity) in cases {
            let profile = OpaProfile::from_preset_or_file(preset).unwrap();
            let outcome = profile.map(&make_finding(control, status));
            assert_eq!(
                outcome.decision, exp_decision,
                "{preset}/{control}/{status:?}: expected decision {exp_decision:?}, got {:?}",
                outcome.decision,
            );
            assert_eq!(
                outcome.severity, exp_severity,
                "{preset}/{control}/{status:?}: expected severity {exp_severity:?}, got {:?}",
                outcome.severity,
            );
        }
    }

    // ── Custom Rego ─────────────────────────────────────────────────

    #[test]
    fn custom_policy_maps_all_statuses() {
        let rego = r#"
package verify.profile
import rego.v1
default map := {"severity": "error", "decision": "fail"}
map := {"severity": "info", "decision": "pass"} if { input.status == "satisfied" }
map := {"severity": "warning", "decision": "review"} if { input.status == "indeterminate" }
"#;
        let profile = OpaProfile::from_rego("custom.rego", rego).unwrap();
        let cases = [
            (
                ControlStatus::Satisfied,
                GateDecision::Pass,
                FindingSeverity::Info,
            ),
            (
                ControlStatus::Indeterminate,
                GateDecision::Review,
                FindingSeverity::Warning,
            ),
            (
                ControlStatus::Violated,
                GateDecision::Fail,
                FindingSeverity::Error,
            ),
        ];
        for (status, exp_decision, exp_severity) in cases {
            let outcome = profile.map(&make_finding(builtin::REVIEW_INDEPENDENCE, status));
            assert_eq!(outcome.decision, exp_decision, "status {status:?}");
            assert_eq!(outcome.severity, exp_severity, "status {status:?}");
        }
    }

    // ── Annotations ─────────────────────────────────────────────────

    #[test]
    fn annotations_extracted_with_correct_key_value() {
        let rego = r#"
package verify.profile
import rego.v1
default map := {"severity": "error", "decision": "fail", "annotations": {"framework_ref": "TEST-1"}}
map := {"severity": "info", "decision": "pass"} if { input.status == "satisfied" }
"#;
        let profile = OpaProfile::from_rego("ann.rego", rego).unwrap();
        let outcome = profile.map(&make_finding(
            builtin::REVIEW_INDEPENDENCE,
            ControlStatus::Violated,
        ));
        assert_eq!(outcome.annotations.len(), 1);
        assert_eq!(outcome.annotations["framework_ref"], "TEST-1");
    }

    #[test]
    fn annotations_empty_when_rego_omits_them() {
        let profile = OpaProfile::from_preset_or_file("default").unwrap();
        let outcome = profile.map(&make_finding(
            builtin::REVIEW_INDEPENDENCE,
            ControlStatus::Violated,
        ));
        assert!(outcome.annotations.is_empty());
    }

    #[test]
    fn ismap_annotations_contain_framework_ref() {
        let profile = OpaProfile::from_preset_or_file("ismap").unwrap();
        let outcome = profile.map(&make_finding(
            builtin::REVIEW_INDEPENDENCE,
            ControlStatus::Violated,
        ));
        assert!(
            outcome.annotations.contains_key("framework_ref"),
            "ISMAP annotations: {:?}",
            outcome.annotations,
        );
    }

    // ── Exhaustive coverage ─────────────────────────────────────────

    /// Every preset × every control × {violated, indeterminate} must produce
    /// a valid decision without panic. Catches Rego classification gaps.
    #[test]
    fn all_presets_cover_all_controls() {
        for preset_name in &available_presets() {
            let profile = OpaProfile::from_preset_or_file(preset_name)
                .unwrap_or_else(|e| panic!("preset '{preset_name}': {e}"));
            for control_id in builtin::ALL {
                for status in [ControlStatus::Violated, ControlStatus::Indeterminate] {
                    let outcome = profile.map(&make_finding(control_id, status));
                    assert!(
                        matches!(
                            outcome.decision,
                            GateDecision::Pass | GateDecision::Review | GateDecision::Fail
                        ),
                        "{preset_name}/{control_id}/{status:?}: {:?}",
                        outcome.decision,
                    );
                }
            }
        }
    }
}
