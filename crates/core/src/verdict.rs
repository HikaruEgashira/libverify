use serde::{Deserialize, Serialize};

/// Severity levels for control outcomes.
///
/// Invariant: the ordering Pass < Warning < Error corresponds to
/// increasing severity.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    Pass,
    Warning,
    Error,
}

impl Severity {
    /// Returns true if this severity should cause a non-zero exit code.
    pub fn is_failing(&self) -> bool {
        matches!(self, Severity::Error)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn severity_ordering() {
        assert!(Severity::Pass < Severity::Warning);
        assert!(Severity::Warning < Severity::Error);
    }

    #[test]
    fn severity_is_failing() {
        assert!(!Severity::Pass.is_failing());
        assert!(!Severity::Warning.is_failing());
        assert!(Severity::Error.is_failing());
    }
}
