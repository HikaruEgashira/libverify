/// Check if a filename matches common generated-file patterns.
///
/// Matches: `*.lock`, `*-lock.json`, `*-lock.yaml`, `*-lock.yml`, `*.snap`, `*.generated.*`
pub fn is_generated_file(filename: &str) -> bool {
    let name = filename.rsplit('/').next().unwrap_or(filename);
    name.ends_with(".lock")
        || name.ends_with("-lock.json")
        || name.ends_with("-lock.yaml")
        || name.ends_with("-lock.yml")
        || name.ends_with(".snap")
        || name.contains(".generated.")
}

use crate::verdict::Severity;

/// Classify a PR's size into a severity level.
///
/// Returns `Error` when either dimension exceeds its error threshold,
/// `Warning` when either exceeds its warning threshold, `Pass` otherwise.
pub fn classify_pr_size(
    total_lines: usize,
    total_files: usize,
    warn_lines: usize,
    warn_files: usize,
    error_lines: usize,
    error_files: usize,
) -> Severity {
    if total_lines > error_lines || total_files > error_files {
        Severity::Error
    } else if total_lines > warn_lines || total_files > warn_files {
        Severity::Warning
    } else {
        Severity::Pass
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── is_generated_file ──────────────────────────────────────────

    #[test]
    fn lock_file() {
        assert!(is_generated_file("Cargo.lock"));
        assert!(is_generated_file("yarn.lock"));
        assert!(is_generated_file("deep/path/Gemfile.lock"));
    }

    #[test]
    fn lock_json() {
        assert!(is_generated_file("package-lock.json"));
        assert!(is_generated_file("node_modules/foo/package-lock.json"));
    }

    #[test]
    fn lock_yaml() {
        assert!(is_generated_file("pnpm-lock.yaml"));
        assert!(is_generated_file("some/path/pnpm-lock.yaml"));
        assert!(is_generated_file("pnpm-lock.yml"));
    }

    #[test]
    fn yarn_lock() {
        assert!(is_generated_file("yarn.lock"));
        assert!(is_generated_file("packages/app/yarn.lock"));
    }

    #[test]
    fn snap_file() {
        assert!(is_generated_file("tests/__snapshots__/foo.snap"));
    }

    #[test]
    fn generated_file() {
        assert!(is_generated_file("src/schema.generated.ts"));
        assert!(is_generated_file("proto/api.generated.go"));
    }

    #[test]
    fn normal_file() {
        assert!(!is_generated_file("src/main.rs"));
        assert!(!is_generated_file("README.md"));
        assert!(!is_generated_file("lib/lock_manager.rs"));
    }

    // ── classify_pr_size ───────────────────────────────────────────

    const WARN_LINES: usize = 500;
    const WARN_FILES: usize = 15;
    const ERROR_LINES: usize = 1000;
    const ERROR_FILES: usize = 30;

    #[test]
    fn small_pr_passes() {
        assert_eq!(
            classify_pr_size(10, 2, WARN_LINES, WARN_FILES, ERROR_LINES, ERROR_FILES),
            Severity::Pass,
        );
    }

    #[test]
    fn many_lines_warns() {
        assert_eq!(
            classify_pr_size(600, 5, WARN_LINES, WARN_FILES, ERROR_LINES, ERROR_FILES),
            Severity::Warning,
        );
    }

    #[test]
    fn many_files_warns() {
        assert_eq!(
            classify_pr_size(100, 20, WARN_LINES, WARN_FILES, ERROR_LINES, ERROR_FILES),
            Severity::Warning,
        );
    }

    #[test]
    fn huge_pr_errors() {
        assert_eq!(
            classify_pr_size(1500, 40, WARN_LINES, WARN_FILES, ERROR_LINES, ERROR_FILES),
            Severity::Error,
        );
    }

    #[test]
    fn boundary_at_threshold_passes() {
        // Exactly at the threshold is not "exceeds", so it should pass/warn respectively.
        assert_eq!(
            classify_pr_size(500, 15, WARN_LINES, WARN_FILES, ERROR_LINES, ERROR_FILES),
            Severity::Pass,
        );
        assert_eq!(
            classify_pr_size(1000, 30, WARN_LINES, WARN_FILES, ERROR_LINES, ERROR_FILES),
            Severity::Warning,
        );
    }
}
