use anyhow::{Context, Result, bail};

use libverify_core::control::ControlFinding;
use libverify_core::profile::{
    ControlProfile, FindingSeverity, GateDecision, ProfileOutcome, SeverityLabels,
};

const DEFAULT_POLICY: &str = include_str!("default.rego");
const OSS_POLICY: &str = include_str!("oss.rego");
const AIOPS_POLICY: &str = include_str!("aiops.rego");
const SOC1_POLICY: &str = include_str!("soc1.rego");
const SOC2_POLICY: &str = include_str!("soc2.rego");
const RULE_PATH: &str = "data.verify.profile.map";

/// OPA-based profile that evaluates Rego policies to map control findings
/// to gate decisions, enabling per-organization customization.
pub struct OpaProfile {
    engine: regorus::Engine,
    profile_name: String,
}

impl OpaProfile {
    /// Loads a custom Rego policy from the given file path.
    pub fn from_file(path: &str) -> Result<Self> {
        let policy = std::fs::read_to_string(path).with_context(|| {
            format!(
                "reading policy '{path}'. Use a built-in preset (default, oss, aiops, soc1, soc2) or a path to a .rego file"
            )
        })?;
        Self::from_rego_with_name(path, &policy, "opa-custom")
    }

    /// Loads a Rego policy from a string.
    pub fn from_rego(name: &str, rego: &str) -> Result<Self> {
        Self::from_rego_with_name(name, rego, "opa-custom")
    }

    pub fn default_policy() -> Result<Self> {
        Self::from_rego_with_name("default.rego", DEFAULT_POLICY, "opa-default")
    }

    pub fn oss_preset() -> Result<Self> {
        Self::from_rego_with_name("oss.rego", OSS_POLICY, "oss")
    }

    pub fn aiops_preset() -> Result<Self> {
        Self::from_rego_with_name("aiops.rego", AIOPS_POLICY, "aiops")
    }

    pub fn soc1_preset() -> Result<Self> {
        Self::from_rego_with_name("soc1.rego", SOC1_POLICY, "soc1")
    }

    pub fn soc2_preset() -> Result<Self> {
        Self::from_rego_with_name("soc2.rego", SOC2_POLICY, "soc2")
    }

    /// Loads a built-in preset by name, or falls back to file path.
    pub fn from_preset_or_file(name: &str) -> Result<Self> {
        match name {
            "default" => Self::default_policy(),
            "oss" => Self::oss_preset(),
            "aiops" => Self::aiops_preset(),
            "soc1" => Self::soc1_preset(),
            "soc2" => Self::soc2_preset(),
            path => Self::from_file(path),
        }
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

    fn eval_finding(&self, finding: &ControlFinding) -> Result<(FindingSeverity, GateDecision)> {
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
        Ok((severity, decision))
    }
}

impl ControlProfile for OpaProfile {
    fn name(&self) -> &str {
        &self.profile_name
    }

    fn map(&self, finding: &ControlFinding) -> ProfileOutcome {
        let (severity, decision) = self.eval_finding(finding).unwrap_or_else(|err| {
            eprintln!(
                "Warning: OPA evaluation failed for {}: {err:#}. Defaulting to Fail.",
                finding.control_id
            );
            (FindingSeverity::Error, GateDecision::Fail)
        });

        ProfileOutcome {
            control_id: finding.control_id.clone(),
            severity,
            decision,
            rationale: finding.rationale.clone(),
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
            ControlStatus::Indeterminate => ControlFinding::indeterminate(
                id,
                "test rationale",
                vec!["subject".into()],
                vec![],
            ),
            ControlStatus::NotApplicable => {
                ControlFinding::not_applicable(id, "test rationale")
            }
        }
    }

    #[test]
    fn default_policy_loads() {
        assert!(OpaProfile::default_policy().is_ok());
    }

    #[test]
    fn all_presets_load() {
        assert!(OpaProfile::from_preset_or_file("default").is_ok());
        assert!(OpaProfile::from_preset_or_file("oss").is_ok());
        assert!(OpaProfile::from_preset_or_file("aiops").is_ok());
        assert!(OpaProfile::from_preset_or_file("soc1").is_ok());
        assert!(OpaProfile::from_preset_or_file("soc2").is_ok());
    }

    #[test]
    fn default_policy_violated_fails() {
        let profile = OpaProfile::default_policy().unwrap();
        let finding = make_finding(builtin::REVIEW_INDEPENDENCE, ControlStatus::Violated);
        let outcome = profile.map(&finding);
        assert_eq!(outcome.decision, GateDecision::Fail);
    }

    #[test]
    fn default_policy_satisfied_passes() {
        let profile = OpaProfile::default_policy().unwrap();
        let finding = make_finding(builtin::REVIEW_INDEPENDENCE, ControlStatus::Satisfied);
        let outcome = profile.map(&finding);
        assert_eq!(outcome.decision, GateDecision::Pass);
    }

    #[test]
    fn oss_preset_source_authenticity_violated_is_review() {
        let profile = OpaProfile::oss_preset().unwrap();
        let finding = make_finding(builtin::SOURCE_AUTHENTICITY, ControlStatus::Violated);
        let outcome = profile.map(&finding);
        assert_eq!(outcome.decision, GateDecision::Review);
    }

    #[test]
    fn soc1_preset_returns_soc1_severity_labels() {
        let profile = OpaProfile::soc1_preset().unwrap();
        let labels = profile.severity_labels();
        assert_eq!(labels.error, "material_weakness");
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
}
