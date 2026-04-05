use crate::control::{Control, ControlFinding, ControlId, builtin};
use crate::evidence::EvidenceBundle;

pub struct DestructiveActionDetectionControl;

impl Control for DestructiveActionDetectionControl {
    fn id(&self) -> ControlId {
        builtin::id(builtin::DESTRUCTIVE_ACTION_DETECTION)
    }

    fn description(&self) -> &'static str {
        "Agent action logs must not contain destructive operations"
    }

    fn evaluate(&self, _evidence: &EvidenceBundle) -> Vec<ControlFinding> {
        vec![ControlFinding::not_applicable(
            self.id(),
            "destructive-action-detection control not yet implemented",
        )]
    }
}
