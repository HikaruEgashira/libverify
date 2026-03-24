use crate::control::{Control, ControlId};

/// Registry for dynamically collecting controls from multiple sources.
///
/// Built-in controls are pre-registered. Platform-specific verifiers
/// can register additional controls (e.g. "jira-linkage").
pub struct ControlRegistry {
    controls: Vec<Box<dyn Control>>,
}

impl ControlRegistry {
    /// Creates an empty registry.
    pub fn new() -> Self {
        Self {
            controls: Vec::new(),
        }
    }

    /// Creates a registry with all built-in controls (20 SLSA + compliance).
    pub fn builtin() -> Self {
        let mut registry = Self::new();
        registry.register_builtins();
        registry
    }

    /// Registers a single control.
    pub fn register(&mut self, control: Box<dyn Control>) {
        self.controls.push(control);
    }

    /// Registers all built-in controls.
    fn register_builtins(&mut self) {
        use crate::controls;
        self.controls.extend(controls::all_controls());
    }

    /// Returns a slice of all registered controls.
    pub fn controls(&self) -> &[Box<dyn Control>] {
        &self.controls
    }

    /// Returns the IDs of all registered controls.
    pub fn control_ids(&self) -> Vec<ControlId> {
        self.controls.iter().map(|c| c.id()).collect()
    }

    /// Returns the number of registered controls.
    pub fn len(&self) -> usize {
        self.controls.len()
    }

    /// Returns true if no controls are registered.
    pub fn is_empty(&self) -> bool {
        self.controls.is_empty()
    }
}

impl Default for ControlRegistry {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn builtin_registry_has_21_controls() {
        let registry = ControlRegistry::builtin();
        assert_eq!(registry.len(), 21);
    }

    #[test]
    fn empty_registry() {
        let registry = ControlRegistry::new();
        assert!(registry.is_empty());
    }
}
