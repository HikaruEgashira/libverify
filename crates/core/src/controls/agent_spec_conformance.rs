use crate::control::{Control, ControlFinding, ControlId, builtin};
use crate::evidence::EvidenceBundle;

pub struct AgentSpecConformanceControl;

impl Control for AgentSpecConformanceControl {
    fn id(&self) -> ControlId {
        builtin::id(builtin::AGENT_SPEC_CONFORMANCE)
    }

    fn description(&self) -> &'static str {
        "Agent must conform to its spec (allowed paths, tools, budget)"
    }

    fn evaluate(&self, _evidence: &EvidenceBundle) -> Vec<ControlFinding> {
        vec![ControlFinding::not_applicable(
            self.id(),
            "agent-spec-conformance control not yet implemented",
        )]
    }
}
