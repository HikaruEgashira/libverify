use crate::control::{Control, ControlFinding, ControlId, builtin};
use crate::evidence::{EvidenceBundle, EvidenceState, MetricObservation};

/// Detects behavioral regressions in post-deploy metrics.
pub struct BehavioralRegressionControl;

/// Metric category for threshold determination.
enum MetricCategory {
    /// Latency/duration metrics: regression if current > baseline * 1.1
    Latency,
    /// Error/failure metrics: regression if current > baseline * 1.05
    Error,
    /// Throughput/success metrics: regression if current < baseline * 0.9
    Throughput,
    /// Unknown category: no opinion
    Unknown,
}

fn classify_metric(name: &str) -> MetricCategory {
    let lower = name.to_lowercase();
    if lower.ends_with("_latency")
        || lower.ends_with("_duration")
        || lower.ends_with("_p50")
        || lower.ends_with("_p90")
        || lower.ends_with("_p95")
        || lower.ends_with("_p99")
    {
        MetricCategory::Latency
    } else if lower.ends_with("_error")
        || lower.ends_with("_5xx")
        || lower.ends_with("_4xx")
        || lower.ends_with("_failure")
    {
        MetricCategory::Error
    } else if lower.ends_with("_throughput")
        || lower.ends_with("_qps")
        || lower.ends_with("_rps")
        || lower.ends_with("_success")
    {
        MetricCategory::Throughput
    } else {
        MetricCategory::Unknown
    }
}

fn is_regressed(metric: &MetricObservation) -> Option<f64> {
    // Avoid division by zero; if baseline is zero, we cannot compute relative change.
    if metric.baseline == 0.0 {
        return None;
    }

    match classify_metric(&metric.name) {
        MetricCategory::Latency => {
            // Regression if current > baseline * 1.1 (10% increase is bad)
            if metric.current > metric.baseline * 1.1 {
                Some((metric.current - metric.baseline) / metric.baseline * 100.0)
            } else {
                None
            }
        }
        MetricCategory::Error => {
            // Regression if current > baseline * 1.05 (5% increase is bad)
            if metric.current > metric.baseline * 1.05 {
                Some((metric.current - metric.baseline) / metric.baseline * 100.0)
            } else {
                None
            }
        }
        MetricCategory::Throughput => {
            // Regression if current < baseline * 0.9 (10% decrease is bad)
            if metric.current < metric.baseline * 0.9 {
                Some((metric.current - metric.baseline) / metric.baseline * 100.0)
            } else {
                None
            }
        }
        MetricCategory::Unknown => None,
    }
}

impl Control for BehavioralRegressionControl {
    fn id(&self) -> ControlId {
        builtin::id(builtin::BEHAVIORAL_REGRESSION)
    }

    fn description(&self) -> &'static str {
        "Post-deployment metrics must not regress beyond acceptable thresholds"
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

        let mut regressions: Vec<String> = Vec::new();

        for metric in &diff.metrics {
            if let Some(delta_pct) = is_regressed(metric) {
                regressions.push(format!(
                    "{}: {:.1}% change (baseline={}, current={})",
                    metric.name, delta_pct, metric.baseline, metric.current,
                ));
            }
        }

        if regressions.is_empty() {
            vec![ControlFinding::satisfied(
                id,
                format!(
                    "No metric regressions detected for deployment {}",
                    diff.deployment_id
                ),
                vec![diff.deployment_id.clone()],
            )]
        } else {
            let subjects: Vec<String> = regressions.clone();
            vec![ControlFinding::violated(
                id,
                format!(
                    "{} metric regression(s) detected: {}",
                    regressions.len(),
                    regressions.join("; ")
                ),
                subjects,
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
                deployment_id: "abc123".to_string(),
                environment: Some("canary".to_string()),
                metrics,
                observed_at: None,
            }),
            ..Default::default()
        }
    }

    #[test]
    fn no_regressions_is_satisfied() {
        let findings = BehavioralRegressionControl.evaluate(&make_bundle(vec![
            metric("http_request_duration_p99", 100.0, 105.0), // +5%, under 10% threshold
            metric("error_rate_5xx", 1.0, 1.04),               // +4%, under 5% threshold
            metric("requests_rps", 1000.0, 950.0),             // -5%, under 10% threshold
        ]));
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].status, ControlStatus::Satisfied);
    }

    #[test]
    fn latency_regression_is_violated() {
        let findings = BehavioralRegressionControl.evaluate(&make_bundle(vec![
            metric("http_request_duration_p99", 100.0, 120.0), // +20%
        ]));
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].status, ControlStatus::Violated);
        assert!(findings[0].rationale.contains("duration_p99"));
    }

    #[test]
    fn error_regression_is_violated() {
        let findings = BehavioralRegressionControl.evaluate(&make_bundle(vec![
            metric("api_error", 2.0, 2.2), // +10%, over 5% threshold
        ]));
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].status, ControlStatus::Violated);
    }

    #[test]
    fn throughput_regression_is_violated() {
        let findings = BehavioralRegressionControl.evaluate(&make_bundle(vec![
            metric("requests_rps", 1000.0, 800.0), // -20%
        ]));
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].status, ControlStatus::Violated);
    }

    #[test]
    fn unknown_metric_category_is_ignored() {
        let findings = BehavioralRegressionControl.evaluate(&make_bundle(vec![
            metric("cpu_usage", 50.0, 90.0), // big change but unknown category
        ]));
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].status, ControlStatus::Satisfied);
    }

    #[test]
    fn zero_baseline_is_not_regression() {
        let findings = BehavioralRegressionControl.evaluate(&make_bundle(vec![
            metric("error_rate_5xx", 0.0, 1.0), // can't compute relative change
        ]));
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].status, ControlStatus::Satisfied);
    }

    #[test]
    fn missing_evidence_is_indeterminate() {
        let bundle = EvidenceBundle {
            behavioral_diff: EvidenceState::missing(vec![EvidenceGap::CollectionFailed {
                source: "prometheus".to_string(),
                subject: "metrics".to_string(),
                detail: "timeout".to_string(),
            }]),
            ..Default::default()
        };
        let findings = BehavioralRegressionControl.evaluate(&bundle);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].status, ControlStatus::Indeterminate);
    }

    #[test]
    fn not_applicable_when_evidence_not_applicable() {
        let bundle = EvidenceBundle::default();
        let findings = BehavioralRegressionControl.evaluate(&bundle);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].status, ControlStatus::NotApplicable);
    }

    #[test]
    fn multiple_regressions_are_all_reported() {
        let findings = BehavioralRegressionControl.evaluate(&make_bundle(vec![
            metric("http_request_duration_p99", 100.0, 150.0),
            metric("error_rate_5xx", 1.0, 2.0),
            metric("requests_rps", 1000.0, 500.0),
        ]));
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].status, ControlStatus::Violated);
        assert!(findings[0].rationale.contains("3 metric regression(s)"));
    }
}
