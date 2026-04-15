use crate::control::{Control, ControlFinding, ControlId, builtin};
use crate::evidence::{EvidenceBundle, EvidenceState};

/// Simple binary check that deployment maintains healthy service metrics.
pub struct DeploymentHealthControl;

impl Control for DeploymentHealthControl {
    fn id(&self) -> ControlId {
        builtin::id(builtin::DEPLOYMENT_HEALTH)
    }

    fn description(&self) -> &'static str {
        "Deployment must maintain healthy service metrics"
    }

    fn evaluate(&self, evidence: &EvidenceBundle) -> Vec<ControlFinding> {
        let id = self.id();

        let diff = match &evidence.behavioral_diff {
            EvidenceState::NotApplicable => {
                return vec![ControlFinding::not_applicable(
                    id,
                    "Behavioral diff evidence is not applicable",
                )];
            }
            EvidenceState::Missing { gaps } => {
                return vec![ControlFinding::indeterminate(
                    id,
                    "Behavioral diff evidence is unavailable",
                    vec![],
                    gaps.clone(),
                )];
            }
            EvidenceState::Complete { value } | EvidenceState::Partial { value, .. } => value,
        };

        let mut violations: Vec<String> = Vec::new();

        for metric in &diff.metrics {
            let lower = metric.name.to_lowercase();

            // Error rate metrics: current > 5.0 (5%) is critical
            if (lower.contains("error_rate") || lower.contains("_5xx")) && metric.current > 5.0 {
                violations.push(format!(
                    "{}: {:.2}% (threshold: 5%)",
                    metric.name, metric.current,
                ));
            }

            // Availability/uptime metrics: current < 99.0 is critical
            if (lower.contains("availability") || lower.contains("uptime")) && metric.current < 99.0
            {
                violations.push(format!(
                    "{}: {:.2}% (threshold: 99%)",
                    metric.name, metric.current,
                ));
            }
        }

        if violations.is_empty() {
            vec![ControlFinding::satisfied(
                id,
                format!(
                    "Deployment {} is healthy — no critical thresholds breached",
                    diff.deployment_id
                ),
                vec![diff.deployment_id.clone()],
            )]
        } else {
            vec![ControlFinding::violated(
                id,
                format!("Service health degraded: {}", violations.join("; ")),
                violations,
            )]
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::control::ControlStatus;
    use crate::evidence::{BehavioralDiff, EvidenceGap, MetricObservation};

    fn metric(name: &str, baseline: f64, current: f64) -> MetricObservation {
        MetricObservation {
            name: name.to_string(),
            current,
            baseline,
            unit: None,
            window_secs: None,
        }
    }

    fn make_bundle(metrics: Vec<MetricObservation>) -> EvidenceBundle {
        EvidenceBundle {
            behavioral_diff: EvidenceState::complete(BehavioralDiff {
                deployment_id: "deploy-42".to_string(),
                environment: Some("production".to_string()),
                metrics,
                observed_at: None,
            }),
            ..Default::default()
        }
    }

    #[test]
    fn healthy_metrics_is_satisfied() {
        let findings = DeploymentHealthControl.evaluate(&make_bundle(vec![
            metric("error_rate_5xx", 0.5, 1.0),
            metric("service_availability", 99.99, 99.95),
        ]));
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].status, ControlStatus::Satisfied);
    }

    #[test]
    fn high_error_rate_is_violated() {
        let findings = DeploymentHealthControl.evaluate(&make_bundle(vec![
            metric("error_rate_5xx", 0.5, 6.0), // 6% > 5% threshold
        ]));
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].status, ControlStatus::Violated);
        assert!(findings[0].rationale.contains("error_rate_5xx"));
    }

    #[test]
    fn low_availability_is_violated() {
        let findings = DeploymentHealthControl.evaluate(&make_bundle(vec![
            metric("service_availability", 99.99, 98.5), // 98.5% < 99% threshold
        ]));
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].status, ControlStatus::Violated);
        assert!(findings[0].rationale.contains("availability"));
    }

    #[test]
    fn unrelated_metrics_are_not_checked() {
        let findings = DeploymentHealthControl.evaluate(&make_bundle(vec![
            metric("cpu_usage", 50.0, 95.0), // not an error/availability metric
            metric("requests_rps", 1000.0, 500.0), // throughput, not health
        ]));
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].status, ControlStatus::Satisfied);
    }

    #[test]
    fn missing_evidence_is_indeterminate() {
        let bundle = EvidenceBundle {
            behavioral_diff: EvidenceState::missing(vec![EvidenceGap::CollectionFailed {
                source: "datadog".to_string(),
                subject: "metrics".to_string(),
                detail: "auth failed".to_string(),
            }]),
            ..Default::default()
        };
        let findings = DeploymentHealthControl.evaluate(&bundle);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].status, ControlStatus::Indeterminate);
    }

    #[test]
    fn not_applicable_when_evidence_not_applicable() {
        let bundle = EvidenceBundle::default();
        let findings = DeploymentHealthControl.evaluate(&bundle);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].status, ControlStatus::NotApplicable);
    }

    #[test]
    fn multiple_violations_are_all_reported() {
        let findings = DeploymentHealthControl.evaluate(&make_bundle(vec![
            metric("error_rate_5xx", 0.5, 7.0),
            metric("service_availability", 99.99, 95.0),
        ]));
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].status, ControlStatus::Violated);
        assert_eq!(findings[0].subjects.len(), 2);
    }

    #[test]
    fn error_rate_at_boundary_is_satisfied() {
        // Exactly 5.0 should NOT trigger (threshold is >5.0)
        let findings = DeploymentHealthControl.evaluate(&make_bundle(vec![metric(
            "error_rate_5xx",
            0.5,
            5.0,
        )]));
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].status, ControlStatus::Satisfied);
    }

    #[test]
    fn uptime_metric_also_detected() {
        let findings = DeploymentHealthControl.evaluate(&make_bundle(vec![metric(
            "system_uptime",
            99.99,
            97.0,
        )]));
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].status, ControlStatus::Violated);
    }
}
