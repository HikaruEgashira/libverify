use crate::control::{Control, ControlFinding, ControlId, builtin};
use crate::evidence::EvidenceBundle;

pub struct AgentPermissionBoundaryControl;

impl Control for AgentPermissionBoundaryControl {
    fn id(&self) -> ControlId {
        builtin::id(builtin::AGENT_PERMISSION_BOUNDARY)
    }

    fn description(&self) -> &'static str {
        "Agent must operate within granted permissions"
    }

    fn evaluate(&self, _evidence: &EvidenceBundle) -> Vec<ControlFinding> {
        vec![ControlFinding::not_applicable(
            self.id(),
            "agent-permission-boundary control not yet implemented",
        )]
    }
}
