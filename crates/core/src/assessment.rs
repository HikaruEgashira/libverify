use std::cmp::Reverse;

use serde::{Deserialize, Serialize};

use crate::control::{Control, ControlFinding, ControlStatus, evaluate_all};
use crate::evidence::EvidenceBundle;
use crate::profile::{ControlProfile, ProfileOutcome, SeverityLabels, apply_profile};
use crate::registry::ControlRegistry;

/// Complete assessment result combining raw control findings with profile-mapped outcomes.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AssessmentReport {
    pub profile_name: String,
    pub findings: Vec<ControlFinding>,
    pub outcomes: Vec<ProfileOutcome>,
    pub severity_labels: SeverityLabels,
}

/// Assessment report with optional raw evidence bundle for audit trails.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct VerificationResult {
    #[serde(flatten)]
    pub report: AssessmentReport,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub evidence: Option<EvidenceBundle>,
}

impl VerificationResult {
    pub fn new(report: AssessmentReport, evidence: Option<EvidenceBundle>) -> Self {
        Self { report, evidence }
    }
}

/// Batch verification report for multiple change requests.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct BatchReport {
    pub reports: Vec<BatchEntry>,
    pub total_pass: usize,
    pub total_review: usize,
    pub total_fail: usize,
    pub skipped: Vec<SkippedEntry>,
}

/// A single entry in a batch report.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct BatchEntry {
    pub subject_id: String,
    #[serde(flatten)]
    pub result: VerificationResult,
}

/// A skipped entry in a batch report.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SkippedEntry {
    pub subject_id: String,
    pub reason: String,
}

/// Evaluates all controls against evidence and maps findings through a profile.
pub fn assess(
    evidence: &EvidenceBundle,
    controls: &[Box<dyn Control>],
    profile: &dyn ControlProfile,
) -> AssessmentReport {
    let findings: Vec<ControlFinding> = evaluate_all(controls, evidence)
        .into_iter()
        .filter(|f| f.status != ControlStatus::NotApplicable)
        .collect();
    let outcomes = apply_profile(profile, &findings);

    AssessmentReport {
        profile_name: profile.name().to_string(),
        findings,
        outcomes,
        severity_labels: profile.severity_labels(),
    }
}

/// Assess using a control registry and profile.
pub fn assess_with_registry(
    evidence: &EvidenceBundle,
    registry: &ControlRegistry,
    profile: &dyn ControlProfile,
) -> AssessmentReport {
    assess(evidence, registry.controls(), profile)
}

// ---------------------------------------------------------------------------
// Fleet-level aggregation
// ---------------------------------------------------------------------------

use crate::profile::GateDecision;
use std::collections::HashMap;

/// Fleet-level aggregation of verification results across multiple repositories.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FleetReport {
    /// Per-repo summaries, sorted by fail count descending (worst first).
    pub repos: Vec<RepoSummary>,
    /// Control-level statistics across the fleet.
    pub control_stats: Vec<ControlFleetStat>,
    /// Fleet-wide totals.
    pub total_pass: usize,
    pub total_review: usize,
    pub total_fail: usize,
}

/// Summary of a single repository's verification results.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RepoSummary {
    pub repo_id: String,
    pub pass: usize,
    pub review: usize,
    pub fail: usize,
    /// Failing control IDs for quick triage.
    pub failing_controls: Vec<String>,
}

/// Fleet-wide statistics for a single control.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ControlFleetStat {
    pub control_id: String,
    /// Number of repos where this control failed.
    pub fail_count: usize,
    /// Number of repos where this control was reviewed.
    pub review_count: usize,
    /// Number of repos where this control passed.
    pub pass_count: usize,
    /// SOC2 TSC criteria mapping.
    pub tsc_criteria: Vec<String>,
}

impl FleetReport {
    /// Build a fleet report from a set of (repo_id, assessment_report) pairs.
    pub fn from_assessments(entries: Vec<(String, &AssessmentReport)>) -> Self {
        let mut repos = Vec::new();
        let mut control_map: HashMap<String, (usize, usize, usize)> = HashMap::new();
        let mut total_pass = 0;
        let mut total_review = 0;
        let mut total_fail = 0;

        for (repo_id, report) in &entries {
            let mut pass = 0;
            let mut review = 0;
            let mut fail = 0;
            let mut failing_controls = Vec::new();

            for outcome in &report.outcomes {
                let key = outcome.control_id.as_str().to_string();
                let entry = control_map.entry(key.clone()).or_insert((0, 0, 0));

                match outcome.decision {
                    GateDecision::Pass => {
                        pass += 1;
                        entry.2 += 1;
                    }
                    GateDecision::Review => {
                        review += 1;
                        entry.1 += 1;
                    }
                    GateDecision::Fail => {
                        fail += 1;
                        entry.0 += 1;
                        failing_controls.push(key);
                    }
                }
            }

            total_pass += pass;
            total_review += review;
            total_fail += fail;

            repos.push(RepoSummary {
                repo_id: repo_id.clone(),
                pass,
                review,
                fail,
                failing_controls,
            });
        }

        // Sort repos by fail count descending (worst first)
        repos.sort_by_key(|r| Reverse(r.fail));

        // Build control stats sorted by fail count descending
        let mut control_stats: Vec<ControlFleetStat> = control_map
            .into_iter()
            .map(|(id, (fail, review, pass))| ControlFleetStat {
                tsc_criteria: crate::control::builtin_tsc_mapping(&id)
                    .iter()
                    .map(|s| s.to_string())
                    .collect(),
                control_id: id,
                fail_count: fail,
                review_count: review,
                pass_count: pass,
            })
            .collect();
        control_stats.sort_by_key(|s| Reverse(s.fail_count));

        FleetReport {
            repos,
            control_stats,
            total_pass,
            total_review,
            total_fail,
        }
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use crate::control::{Control, ControlFinding, ControlId, ControlStatus};
    use crate::evidence::EvidenceBundle;
    use crate::profile::{
        ControlProfile, FindingSeverity, GateDecision, ProfileOutcome, SeverityLabels,
    };

    use super::{assess, AssessmentReport, FleetReport};

    // -----------------------------------------------------------------------
    // Helpers: stub control and profile
    // -----------------------------------------------------------------------

    struct StubControl {
        id: &'static str,
        status: ControlStatus,
    }

    impl Control for StubControl {
        fn id(&self) -> ControlId {
            ControlId::new(self.id)
        }

        fn evaluate(&self, _evidence: &EvidenceBundle) -> Vec<ControlFinding> {
            vec![match self.status {
                ControlStatus::Satisfied => {
                    ControlFinding::satisfied(self.id(), "ok", vec!["s".into()])
                }
                ControlStatus::Violated => {
                    ControlFinding::violated(self.id(), "bad", vec!["s".into()])
                }
                ControlStatus::Indeterminate => {
                    ControlFinding::indeterminate(self.id(), "unknown", vec!["s".into()], vec![])
                }
                ControlStatus::NotApplicable => ControlFinding::not_applicable(self.id(), "n/a"),
            }]
        }
    }

    struct StubProfile;

    impl ControlProfile for StubProfile {
        fn name(&self) -> &str {
            "stub"
        }

        fn map(&self, finding: &ControlFinding) -> ProfileOutcome {
            let (severity, decision) = match finding.status {
                ControlStatus::Satisfied => (FindingSeverity::Info, GateDecision::Pass),
                ControlStatus::Violated => (FindingSeverity::Error, GateDecision::Fail),
                ControlStatus::Indeterminate => (FindingSeverity::Warning, GateDecision::Review),
                ControlStatus::NotApplicable => (FindingSeverity::Info, GateDecision::Pass),
            };
            ProfileOutcome {
                control_id: finding.control_id.clone(),
                severity,
                decision,
                rationale: finding.rationale.clone(),
                annotations: BTreeMap::new(),
            }
        }
    }

    fn make_report(outcomes: Vec<(ControlId, GateDecision)>) -> AssessmentReport {
        let findings: Vec<ControlFinding> = outcomes
            .iter()
            .map(|(id, decision)| match decision {
                GateDecision::Pass => {
                    ControlFinding::satisfied(id.clone(), "ok", vec!["s".into()])
                }
                GateDecision::Fail => {
                    ControlFinding::violated(id.clone(), "bad", vec!["s".into()])
                }
                GateDecision::Review => {
                    ControlFinding::indeterminate(id.clone(), "unknown", vec!["s".into()], vec![])
                }
            })
            .collect();

        let profile_outcomes: Vec<ProfileOutcome> = outcomes
            .into_iter()
            .map(|(id, decision)| {
                let severity = match decision {
                    GateDecision::Pass => FindingSeverity::Info,
                    GateDecision::Fail => FindingSeverity::Error,
                    GateDecision::Review => FindingSeverity::Warning,
                };
                ProfileOutcome {
                    control_id: id,
                    severity,
                    decision,
                    rationale: String::new(),
                    annotations: BTreeMap::new(),
                }
            })
            .collect();

        AssessmentReport {
            profile_name: "stub".into(),
            findings,
            outcomes: profile_outcomes,
            severity_labels: SeverityLabels::default(),
        }
    }

    // ===================================================================
    // 1. assess() — NotApplicable filtering (kills != mutation on line 65)
    // ===================================================================

    #[test]
    fn assess_filters_not_applicable_findings() {
        let evidence = EvidenceBundle::default();
        let controls: Vec<Box<dyn Control>> = vec![
            Box::new(StubControl {
                id: "ctrl-ok",
                status: ControlStatus::Satisfied,
            }),
            Box::new(StubControl {
                id: "ctrl-na",
                status: ControlStatus::NotApplicable,
            }),
        ];

        let report = assess(&evidence, &controls, &StubProfile);

        assert_eq!(report.findings.len(), 1);
        assert_eq!(report.findings[0].control_id.as_str(), "ctrl-ok");
        assert_eq!(report.findings[0].status, ControlStatus::Satisfied);
    }

    #[test]
    fn assess_includes_violated_finding() {
        let evidence = EvidenceBundle::default();
        let controls: Vec<Box<dyn Control>> = vec![Box::new(StubControl {
            id: "ctrl-bad",
            status: ControlStatus::Violated,
        })];

        let report = assess(&evidence, &controls, &StubProfile);

        assert_eq!(report.findings.len(), 1);
        assert_eq!(report.findings[0].status, ControlStatus::Violated);
        assert_eq!(report.outcomes.len(), 1);
        assert_eq!(report.outcomes[0].decision, GateDecision::Fail);
    }

    #[test]
    fn assess_includes_indeterminate_finding() {
        let evidence = EvidenceBundle::default();
        let controls: Vec<Box<dyn Control>> = vec![Box::new(StubControl {
            id: "ctrl-unk",
            status: ControlStatus::Indeterminate,
        })];

        let report = assess(&evidence, &controls, &StubProfile);

        assert_eq!(report.findings.len(), 1);
        assert_eq!(report.findings[0].status, ControlStatus::Indeterminate);
    }

    #[test]
    fn assess_profile_name_propagated() {
        let evidence = EvidenceBundle::default();
        let controls: Vec<Box<dyn Control>> = vec![];
        let report = assess(&evidence, &controls, &StubProfile);
        assert_eq!(report.profile_name, "stub");
    }

    // ===================================================================
    // 2. FleetReport::from_assessments — totals, sorting, per-control
    // ===================================================================

    #[test]
    fn fleet_report_totals_are_correct() {
        let id_a = ControlId::new("ctrl-a");
        let id_b = ControlId::new("ctrl-b");

        let r1 = make_report(vec![
            (id_a.clone(), GateDecision::Pass),
            (id_b.clone(), GateDecision::Fail),
        ]);
        let r2 = make_report(vec![
            (id_a.clone(), GateDecision::Pass),
            (id_b.clone(), GateDecision::Pass),
        ]);

        let fleet = FleetReport::from_assessments(vec![
            ("repo-1".into(), &r1),
            ("repo-2".into(), &r2),
        ]);

        assert_eq!(fleet.total_pass, 3);
        assert_eq!(fleet.total_review, 0);
        assert_eq!(fleet.total_fail, 1);
        assert_eq!(fleet.repos.len(), 2);
    }

    #[test]
    fn fleet_report_totals_with_review() {
        let id_a = ControlId::new("ctrl-a");
        let id_b = ControlId::new("ctrl-b");
        let id_c = ControlId::new("ctrl-c");

        let r1 = make_report(vec![
            (id_a.clone(), GateDecision::Pass),
            (id_b.clone(), GateDecision::Review),
            (id_c.clone(), GateDecision::Fail),
        ]);
        let r2 = make_report(vec![
            (id_a.clone(), GateDecision::Review),
            (id_b.clone(), GateDecision::Fail),
            (id_c.clone(), GateDecision::Fail),
        ]);

        let fleet = FleetReport::from_assessments(vec![
            ("repo-1".into(), &r1),
            ("repo-2".into(), &r2),
        ]);

        assert_eq!(fleet.total_pass, 1);
        assert_eq!(fleet.total_review, 2);
        assert_eq!(fleet.total_fail, 3);
    }

    #[test]
    fn fleet_report_repos_sorted_by_fail_descending() {
        let id = ControlId::new("ctrl-a");

        let r_good = make_report(vec![(id.clone(), GateDecision::Pass)]);
        let r_bad = make_report(vec![(id.clone(), GateDecision::Fail)]);

        let fleet = FleetReport::from_assessments(vec![
            ("repo-good".into(), &r_good),
            ("repo-bad".into(), &r_bad),
        ]);

        assert_eq!(fleet.repos[0].repo_id, "repo-bad");
        assert_eq!(fleet.repos[0].fail, 1);
        assert_eq!(fleet.repos[1].repo_id, "repo-good");
        assert_eq!(fleet.repos[1].fail, 0);
    }

    #[test]
    fn fleet_report_control_stats_sorted_by_fail_descending() {
        let id_a = ControlId::new("ctrl-a");
        let id_b = ControlId::new("ctrl-b");

        let r1 = make_report(vec![
            (id_a.clone(), GateDecision::Fail),
            (id_b.clone(), GateDecision::Pass),
        ]);
        let r2 = make_report(vec![
            (id_a.clone(), GateDecision::Fail),
            (id_b.clone(), GateDecision::Pass),
        ]);

        let fleet = FleetReport::from_assessments(vec![
            ("repo-1".into(), &r1),
            ("repo-2".into(), &r2),
        ]);

        assert_eq!(fleet.control_stats[0].control_id, "ctrl-a");
        assert_eq!(fleet.control_stats[0].fail_count, 2);
        assert_eq!(fleet.control_stats[0].pass_count, 0);

        let stat_b = fleet
            .control_stats
            .iter()
            .find(|s| s.control_id == "ctrl-b")
            .unwrap();
        assert_eq!(stat_b.fail_count, 0);
        assert_eq!(stat_b.pass_count, 2);
    }

    #[test]
    fn fleet_report_per_control_counts_are_exact() {
        let id_x = ControlId::new("ctrl-x");

        let r_pass = make_report(vec![(id_x.clone(), GateDecision::Pass)]);
        let r_review = make_report(vec![(id_x.clone(), GateDecision::Review)]);
        let r_fail = make_report(vec![(id_x.clone(), GateDecision::Fail)]);

        let fleet = FleetReport::from_assessments(vec![
            ("repo-pass".into(), &r_pass),
            ("repo-review".into(), &r_review),
            ("repo-fail".into(), &r_fail),
        ]);

        assert_eq!(fleet.control_stats.len(), 1);
        let stat = &fleet.control_stats[0];
        assert_eq!(stat.control_id, "ctrl-x");
        assert_eq!(stat.pass_count, 1);
        assert_eq!(stat.review_count, 1);
        assert_eq!(stat.fail_count, 1);
    }

    #[test]
    fn fleet_report_failing_controls_listed() {
        let id_a = ControlId::new("ctrl-a");
        let id_b = ControlId::new("ctrl-b");

        let r = make_report(vec![
            (id_a.clone(), GateDecision::Pass),
            (id_b.clone(), GateDecision::Fail),
        ]);

        let fleet = FleetReport::from_assessments(vec![("repo-1".into(), &r)]);

        let repo = &fleet.repos[0];
        assert_eq!(repo.failing_controls, vec!["ctrl-b"]);
    }

    #[test]
    fn fleet_report_empty_input() {
        let fleet = FleetReport::from_assessments(vec![]);

        assert_eq!(fleet.repos.len(), 0);
        assert_eq!(fleet.control_stats.len(), 0);
        assert_eq!(fleet.total_pass, 0);
        assert_eq!(fleet.total_review, 0);
        assert_eq!(fleet.total_fail, 0);
    }

    #[test]
    fn fleet_report_repo_summary_counts_match_totals() {
        let id_a = ControlId::new("ctrl-a");
        let id_b = ControlId::new("ctrl-b");
        let id_c = ControlId::new("ctrl-c");

        let r1 = make_report(vec![
            (id_a.clone(), GateDecision::Pass),
            (id_b.clone(), GateDecision::Review),
            (id_c.clone(), GateDecision::Fail),
        ]);
        let r2 = make_report(vec![
            (id_a.clone(), GateDecision::Fail),
            (id_b.clone(), GateDecision::Fail),
            (id_c.clone(), GateDecision::Review),
        ]);
        let r3 = make_report(vec![
            (id_a.clone(), GateDecision::Pass),
            (id_b.clone(), GateDecision::Pass),
            (id_c.clone(), GateDecision::Pass),
        ]);

        let fleet = FleetReport::from_assessments(vec![
            ("repo-1".into(), &r1),
            ("repo-2".into(), &r2),
            ("repo-3".into(), &r3),
        ]);

        // Sum individual repo counts and verify they match fleet totals
        let sum_pass: usize = fleet.repos.iter().map(|r| r.pass).sum();
        let sum_review: usize = fleet.repos.iter().map(|r| r.review).sum();
        let sum_fail: usize = fleet.repos.iter().map(|r| r.fail).sum();
        assert_eq!(sum_pass, fleet.total_pass);
        assert_eq!(sum_review, fleet.total_review);
        assert_eq!(sum_fail, fleet.total_fail);

        // Verify exact values (kills += to -= and += to *= mutations)
        assert_eq!(fleet.total_pass, 4);
        assert_eq!(fleet.total_review, 2);
        assert_eq!(fleet.total_fail, 3);

        // Sum control stats and verify they match fleet totals
        let ctrl_pass: usize = fleet.control_stats.iter().map(|s| s.pass_count).sum();
        let ctrl_review: usize = fleet.control_stats.iter().map(|s| s.review_count).sum();
        let ctrl_fail: usize = fleet.control_stats.iter().map(|s| s.fail_count).sum();
        assert_eq!(ctrl_pass, fleet.total_pass);
        assert_eq!(ctrl_review, fleet.total_review);
        assert_eq!(ctrl_fail, fleet.total_fail);
    }
}
