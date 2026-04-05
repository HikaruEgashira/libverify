use crate::control::{Control, ControlFinding, ControlId, builtin};
use crate::evidence::EvidenceBundle;

pub struct HarnessResultControl;

impl Control for HarnessResultControl {
    fn id(&self) -> ControlId {
        builtin::id(builtin::HARNESS_RESULT)
    }

    fn description(&self) -> &'static str {
        "All required CI harnesses (build, test, lint, typecheck) must pass"
    }

    fn evaluate(&self, _evidence: &EvidenceBundle) -> Vec<ControlFinding> {
        vec![ControlFinding::not_applicable(
            self.id(),
            "harness-result control not yet implemented",
        )]
    }
}
