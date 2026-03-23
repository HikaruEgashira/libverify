//! LCOV-based coverage analysis for pull request diffs.
//!
//! Pure functions that parse LCOV reports, extract changed lines from
//! unified diffs, and classify test coverage severity. No I/O — all
//! inputs are string slices provided by the CLI layer.
//!
//! `classify_coverage_severity` is formally verified by Creusot in
//! `gh-verify-verif`.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::verdict::Severity;

// --- Types ---

/// LCOV parse error. Explicit enum (no anyhow in core crate).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ParseError {
    MalformedLine { line_number: usize, content: String },
}

/// Per-file coverage data. Corresponds to one SF..end_of_record block in LCOV.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileCoverage {
    pub path: String,
    /// line_number -> execution_count
    pub lines: BTreeMap<u32, u32>,
    /// LF: lines found
    pub lines_found: u32,
    /// LH: lines hit
    pub lines_hit: u32,
}

/// Parsed coverage report, format-agnostic intermediate representation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CoverageReport {
    pub files: Vec<FileCoverage>,
}

/// Per-file coverage analysis result for PR changed lines.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileAnalysis {
    pub path: String,
    pub changed_lines: u32,
    pub covered_lines: u32,
    pub uncovered_line_numbers: Vec<u32>,
    pub coverage_pct: f64,
}

/// Aggregate coverage analysis for the entire PR.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CoverageAnalysis {
    pub files: Vec<FileAnalysis>,
    pub total_changed: u32,
    pub total_covered: u32,
    pub overall_pct: f64,
}

// --- Functions ---

/// Parse LCOV format content into a `CoverageReport`.
///
/// State machine: SF starts a record, DA adds line data, LF/LH set
/// summary counts, end_of_record finalizes. TN, FN*, BR* lines are
/// ignored (we only need line coverage).
pub fn parse_lcov(content: &str) -> Result<CoverageReport, ParseError> {
    let mut files = Vec::new();
    let mut current_path: Option<String> = None;
    let mut current_lines: BTreeMap<u32, u32> = BTreeMap::new();
    let mut lines_found: u32 = 0;
    let mut lines_hit: u32 = 0;

    for (idx, raw_line) in content.lines().enumerate() {
        let line = raw_line.trim();
        if line.is_empty() {
            continue;
        }

        if let Some(path) = line.strip_prefix("SF:") {
            // Start a new file record
            current_path = Some(path.to_string());
            current_lines.clear();
            lines_found = 0;
            lines_hit = 0;
        } else if let Some(da) = line.strip_prefix("DA:") {
            // DA:<line_number>,<execution_count>[,<checksum>]
            let parts: Vec<&str> = da.split(',').collect();
            if parts.len() < 2 {
                return Err(ParseError::MalformedLine {
                    line_number: idx + 1,
                    content: line.to_string(),
                });
            }
            let line_no: u32 = parts[0].parse().map_err(|_| ParseError::MalformedLine {
                line_number: idx + 1,
                content: line.to_string(),
            })?;
            let count: u32 = parts[1].parse().map_err(|_| ParseError::MalformedLine {
                line_number: idx + 1,
                content: line.to_string(),
            })?;
            current_lines.insert(line_no, count);
        } else if let Some(lf) = line.strip_prefix("LF:") {
            lines_found = lf.parse().unwrap_or(0);
        } else if let Some(lh) = line.strip_prefix("LH:") {
            lines_hit = lh.parse().unwrap_or(0);
        } else if line == "end_of_record" {
            if let Some(path) = current_path.take() {
                files.push(FileCoverage {
                    path,
                    lines: std::mem::take(&mut current_lines),
                    lines_found,
                    lines_hit,
                });
            }
            lines_found = 0;
            lines_hit = 0;
        }
        // TN, FN, FNDA, FNF, FNH, BRDA, BRF, BRH — silently ignored
    }

    Ok(CoverageReport { files })
}

/// Extract added line numbers from a unified diff patch.
///
/// Parses `@@ -a,b +c,d @@` hunk headers to track the new-file line
/// position, then collects lines prefixed with `+` (additions).
pub fn extract_changed_lines(patch: &str) -> Vec<u32> {
    let mut result = Vec::new();
    let mut new_line: u32 = 0;

    for line in patch.lines() {
        if line.starts_with("@@") {
            // Parse @@ -a,b +c,d @@ header
            // Find the +c,d or +c portion
            if let Some(plus_pos) = line.find('+') {
                let after_plus = &line[plus_pos + 1..];
                let end = after_plus
                    .find(|c: char| !c.is_ascii_digit() && c != ',')
                    .unwrap_or(after_plus.len());
                let range_str = &after_plus[..end];
                let start_str = range_str.split(',').next().unwrap_or("0");
                new_line = start_str.parse().unwrap_or(0);
            }
        } else if line.starts_with('+') {
            // Addition line
            result.push(new_line);
            new_line += 1;
        } else if line.starts_with('-') {
            // Deletion — does not advance new-file line counter
        } else {
            // Context line — advances new-file counter
            new_line += 1;
        }
    }

    result
}

/// Check whether an LCOV path (often absolute) matches a PR path (relative).
///
/// Returns true if `lcov_path` ends with `/<pr_path>`, or if they are
/// equal after stripping `./` prefixes.
pub fn resolve_path(lcov_path: &str, pr_path: &str) -> bool {
    let lcov_replaced = lcov_path.replace('\\', "/");
    let lcov_normalized = lcov_replaced.strip_prefix("./").unwrap_or(&lcov_replaced);
    let pr_normalized = pr_path.strip_prefix("./").unwrap_or(pr_path);

    if lcov_normalized == pr_normalized {
        return true;
    }

    // Suffix match: lcov absolute path ends with /pr_path
    let suffix = format!("/{pr_normalized}");
    lcov_normalized.ends_with(&suffix)
}

/// Analyze coverage of PR changed lines against a parsed report.
///
/// For each changed file, finds the matching LCOV entry via `resolve_path`,
/// then checks which changed lines have hit_count > 0. Files not present
/// in the report are treated as 0% covered (safe default).
pub fn analyze_coverage(
    report: &CoverageReport,
    changed_files: &[(String, Vec<u32>)],
) -> CoverageAnalysis {
    let mut file_analyses = Vec::new();
    let mut total_changed: u32 = 0;
    let mut total_covered: u32 = 0;

    for (path, changed_lines) in changed_files {
        if changed_lines.is_empty() {
            continue;
        }

        // Find matching LCOV entry
        let file_cov = report.files.iter().find(|f| resolve_path(&f.path, path));

        let mut covered: u32 = 0;
        let mut uncovered_lines = Vec::new();

        for &line_no in changed_lines {
            match file_cov {
                Some(fc) => match fc.lines.get(&line_no) {
                    Some(&count) if count > 0 => covered += 1,
                    _ => uncovered_lines.push(line_no),
                },
                None => uncovered_lines.push(line_no),
            }
        }

        let changed_count = changed_lines.len() as u32;
        let pct = if changed_count > 0 {
            (covered as f64 / changed_count as f64) * 100.0
        } else {
            100.0
        };

        total_changed += changed_count;
        total_covered += covered;

        file_analyses.push(FileAnalysis {
            path: path.clone(),
            changed_lines: changed_count,
            covered_lines: covered,
            uncovered_line_numbers: uncovered_lines,
            coverage_pct: pct,
        });
    }

    let overall_pct = if total_changed > 0 {
        (total_covered as f64 / total_changed as f64) * 100.0
    } else {
        100.0
    };

    CoverageAnalysis {
        files: file_analyses,
        total_changed,
        total_covered,
        overall_pct,
    }
}

/// Classify coverage severity using integer arithmetic (no f64).
///
/// Matches the Creusot predicate in `gh-verify-verif`:
/// - `total == 0` => Pass (no changed lines to cover)
/// - `covered * 100 > warn_pct * total` => Pass
/// - `covered * 100 > error_pct * total` => Warning
/// - otherwise => Error
pub fn classify_coverage_severity(
    covered: usize,
    total: usize,
    warn_pct: usize,
    error_pct: usize,
) -> Severity {
    if total == 0 {
        return Severity::Pass;
    }
    if covered * 100 > warn_pct * total {
        Severity::Pass
    } else if covered * 100 > error_pct * total {
        Severity::Warning
    } else {
        Severity::Error
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // --- Helpers ---

    /// Build minimal LCOV content for a single file with given line coverage.
    fn make_lcov(path: &str, lines: &[(u32, u32)]) -> String {
        let mut out = format!("SF:{path}\n");
        for &(line, count) in lines {
            out.push_str(&format!("DA:{line},{count}\n"));
        }
        out.push_str(&format!("LF:{}\n", lines.len()));
        let hit = lines.iter().filter(|(_, c)| *c > 0).count();
        out.push_str(&format!("LH:{hit}\n"));
        out.push_str("end_of_record\n");
        out
    }

    /// Build LCOV content for multiple files.
    fn make_multi_lcov(entries: &[(&str, &[(u32, u32)])]) -> String {
        entries
            .iter()
            .map(|(path, lines)| make_lcov(path, lines))
            .collect::<Vec<_>>()
            .join("")
    }

    /// Build a unified diff patch with a single hunk adding lines starting at `start`.
    fn make_patch(start: u32, added_lines: &[&str]) -> String {
        let count = added_lines.len() as u32;
        let mut out = format!("@@ -1,0 +{start},{count} @@\n");
        for line in added_lines {
            out.push_str(&format!("+{line}\n"));
        }
        out
    }

    // --- parse_lcov ---

    /// WHY: Verifies the minimal happy path — one SF/DA/LF/LH/end_of_record
    /// block parses into a single FileCoverage with correct line data.
    #[test]
    fn parse_lcov_single_file() {
        let content = make_lcov("/src/main.rs", &[(1, 5), (2, 0), (3, 1)]);
        let report = parse_lcov(&content).unwrap();
        assert_eq!(report.files.len(), 1);
        assert_eq!(report.files[0].path, "/src/main.rs");
        assert_eq!(report.files[0].lines.len(), 3);
        assert_eq!(report.files[0].lines[&1], 5);
        assert_eq!(report.files[0].lines[&2], 0);
        assert_eq!(report.files[0].lines_found, 3);
        assert_eq!(report.files[0].lines_hit, 2);
    }

    /// WHY: Multiple SF..end_of_record blocks must be parsed as separate
    /// FileCoverage entries — a real LCOV report covers many files.
    #[test]
    fn parse_lcov_multiple_files() {
        let content =
            make_multi_lcov(&[("/src/a.rs", &[(1, 1)]), ("/src/b.rs", &[(1, 0), (2, 3)])]);
        let report = parse_lcov(&content).unwrap();
        assert_eq!(report.files.len(), 2);
        assert_eq!(report.files[0].path, "/src/a.rs");
        assert_eq!(report.files[1].path, "/src/b.rs");
        assert_eq!(report.files[1].lines.len(), 2);
    }

    /// WHY: LCOV emits BRDA/BRF/BRH/FN/FNDA/FNF/FNH lines that we must
    /// silently skip — they must not corrupt the line-coverage state machine.
    #[test]
    fn parse_lcov_ignores_branch_data() {
        let content = "\
TN:test_name
SF:/src/main.rs
FN:1,main
FNDA:1,main
FNF:1
FNH:1
DA:1,1
DA:2,0
BRDA:1,0,0,1
BRF:1
BRH:1
LF:2
LH:1
end_of_record
";
        let report = parse_lcov(content).unwrap();
        assert_eq!(report.files.len(), 1);
        // Only DA lines contribute to the lines map
        assert_eq!(report.files[0].lines.len(), 2);
        assert_eq!(report.files[0].lines[&1], 1);
    }

    /// WHY: Empty input is valid — no coverage data means no files.
    /// Must not panic or error.
    #[test]
    fn parse_lcov_empty_content() {
        let report = parse_lcov("").unwrap();
        assert!(report.files.is_empty());
    }

    /// WHY: A DA line without the required comma-separated pair must produce
    /// a clear ParseError rather than silently corrupting data.
    #[test]
    fn parse_lcov_malformed_da() {
        let content = "SF:/src/main.rs\nDA:bad\nend_of_record\n";
        let err = parse_lcov(content).unwrap_err();
        match err {
            ParseError::MalformedLine {
                line_number,
                content,
            } => {
                assert_eq!(line_number, 2);
                assert!(content.contains("DA:bad"));
            }
        }
    }

    // --- extract_changed_lines ---

    /// WHY: Single-hunk patches are the common case. The line numbers must
    /// correspond to the new-file side of the diff.
    #[test]
    fn extract_changed_lines_single_hunk() {
        let patch = make_patch(10, &["line1", "line2", "line3"]);
        let lines = extract_changed_lines(&patch);
        assert_eq!(lines, vec![10, 11, 12]);
    }

    /// WHY: Multi-hunk diffs appear when edits are spread across a file.
    /// Each hunk resets the line counter to its +c start position.
    #[test]
    fn extract_changed_lines_multiple_hunks() {
        let patch = "\
@@ -1,3 +1,4 @@
 context
+added_at_2
 context
@@ -10,2 +11,3 @@
 context
+added_at_12
+added_at_13
";
        let lines = extract_changed_lines(patch);
        assert_eq!(lines, vec![2, 12, 13]);
    }

    /// WHY: Deletion-only patches have no added lines. The result must be
    /// empty — deletions cannot be "uncovered" by tests.
    #[test]
    fn extract_changed_lines_deletions_only() {
        let patch = "\
@@ -1,3 +1,1 @@
-removed1
-removed2
 kept
";
        let lines = extract_changed_lines(patch);
        assert!(lines.is_empty());
    }

    /// WHY: `++i;` is valid code (C/C++ increment). The old `stripped.starts_with("++")`
    /// check incorrectly excluded such lines. GitHub's patch field never contains
    /// `+++ b/file` headers, so the check was unnecessary and harmful.
    #[test]
    fn extract_changed_lines_increment_operator() {
        let patch = "@@ -1,2 +1,3 @@\n counter = 0;\n+    ++counter;\n other();\n";
        let lines = extract_changed_lines(patch);
        assert_eq!(lines, vec![2], "++counter line must be included");
    }

    // --- resolve_path ---

    /// WHY: LCOV typically records absolute paths. The PR uses repo-relative
    /// paths. Suffix matching bridges this gap.
    #[test]
    fn resolve_path_absolute_to_relative() {
        assert!(resolve_path(
            "/home/user/project/src/main.rs",
            "src/main.rs"
        ));
    }

    /// WHY: When LCOV path equals PR path exactly (both relative), it must match.
    #[test]
    fn resolve_path_exact() {
        assert!(resolve_path("src/main.rs", "src/main.rs"));
    }

    /// WHY: Non-matching paths must return false to avoid spurious coverage
    /// attribution across unrelated files.
    #[test]
    fn resolve_path_no_match() {
        assert!(!resolve_path("/src/other.rs", "src/main.rs"));
    }

    /// WHY: Windows LCOV paths use backslashes. Without normalization,
    /// suffix matching fails and changed files appear as 0% covered.
    #[test]
    fn resolve_path_windows_backslash() {
        assert!(resolve_path("C:\\work\\repo\\src\\foo.rs", "src/foo.rs"));
    }

    // --- analyze_coverage ---

    /// WHY: When all changed lines have hit_count > 0, the analysis must
    /// report 100% coverage with no uncovered lines.
    #[test]
    fn analyze_coverage_full() {
        let report = parse_lcov(&make_lcov("src/main.rs", &[(1, 1), (2, 3), (3, 1)])).unwrap();
        let changed = vec![("src/main.rs".to_string(), vec![1, 2, 3])];
        let analysis = analyze_coverage(&report, &changed);
        assert_eq!(analysis.total_changed, 3);
        assert_eq!(analysis.total_covered, 3);
        assert!((analysis.overall_pct - 100.0).abs() < f64::EPSILON);
        assert!(analysis.files[0].uncovered_line_numbers.is_empty());
    }

    /// WHY: Partial coverage must correctly compute the ratio and identify
    /// which specific lines are uncovered — the CLI uses this for suggestions.
    #[test]
    fn analyze_coverage_partial() {
        let report = parse_lcov(&make_lcov("src/main.rs", &[(1, 1), (2, 0), (3, 1)])).unwrap();
        let changed = vec![("src/main.rs".to_string(), vec![1, 2, 3])];
        let analysis = analyze_coverage(&report, &changed);
        assert_eq!(analysis.total_covered, 2);
        assert_eq!(analysis.total_changed, 3);
        // 2/3 ≈ 66.67%
        assert!((analysis.overall_pct - 66.666_666_666_666_6).abs() < 0.01);
        assert_eq!(analysis.files[0].uncovered_line_numbers, vec![2]);
    }

    /// WHY: Files absent from the LCOV report must be treated as 0% covered
    /// (safe default) — not silently skipped, which would inflate coverage.
    #[test]
    fn analyze_coverage_missing_file() {
        let report = parse_lcov(&make_lcov("src/other.rs", &[(1, 1)])).unwrap();
        let changed = vec![("src/missing.rs".to_string(), vec![1, 2])];
        let analysis = analyze_coverage(&report, &changed);
        assert_eq!(analysis.total_covered, 0);
        assert_eq!(analysis.total_changed, 2);
        assert!((analysis.overall_pct - 0.0).abs() < f64::EPSILON);
    }

    // --- Mutant-killing tests ---
    //
    // Each test below targets a specific surviving mutant. The test name
    // encodes the line, operator substitution, and function under test.

    /// Kills L90: `replace < with >` in parse_lcov.
    /// Original: `if parts.len() < 2` rejects DA lines with fewer than 2 fields.
    /// Mutant (`>`): would reject DA lines with MORE than 2 fields (e.g. with checksum),
    /// while accepting single-field DA lines. This test provides DA with a checksum
    /// (3 fields) which must succeed, AND single-field DA which must fail.
    #[test]
    fn parse_lcov_da_with_checksum_accepted() {
        // DA with 3 fields (checksum) must parse successfully
        let content = "SF:/src/a.rs\nDA:1,5,abc123\nLF:1\nLH:1\nend_of_record\n";
        let report = parse_lcov(content).unwrap();
        assert_eq!(report.files[0].lines[&1], 5);
    }

    #[test]
    fn parse_lcov_da_single_field_rejected() {
        // DA with only 1 field must be rejected
        let content = "SF:/src/a.rs\nDA:1\nend_of_record\n";
        assert!(parse_lcov(content).is_err());
    }

    /// Kills L97: `replace + with *` and `replace + with -` in parse_lcov.
    /// Original: error line_number is `idx + 1` (1-indexed).
    /// Mutant `*`: line_number = idx * 1 = idx (0-indexed, off by one).
    /// Mutant `-`: line_number = idx - 1 (off by two).
    /// We place the bad DA on the first line (idx=0) so `0+1=1`, `0*1=0`, `0-1` wraps.
    /// Also test at idx=2 where `2+1=3`, `2*1=2`, `2-1=1` all differ.
    #[test]
    fn parse_lcov_error_line_number_for_bad_line_no() {
        // Bad line number parse at line 3 of content (idx=2)
        let content = "SF:/src/a.rs\nDA:1,1\nDA:xyz,1\nend_of_record\n";
        let err = parse_lcov(content).unwrap_err();
        match err {
            ParseError::MalformedLine { line_number, .. } => {
                assert_eq!(line_number, 3, "error must report 1-indexed line number");
            }
        }
    }

    /// Kills L101: `replace + with *` and `replace + with -` in parse_lcov.
    /// Same as above but for the execution_count parse failure path.
    /// The line_number field parses fine, but the count field is invalid.
    #[test]
    fn parse_lcov_error_line_number_for_bad_count() {
        // Line number parses OK, but count is invalid. Error on content line 3 (idx=2).
        let content = "SF:/src/a.rs\nDA:1,1\nDA:2,xyz\nend_of_record\n";
        let err = parse_lcov(content).unwrap_err();
        match err {
            ParseError::MalformedLine { line_number, .. } => {
                assert_eq!(line_number, 3, "error must report 1-indexed line number");
            }
        }
    }

    /// Kills L142: `replace != with ==` in extract_changed_lines.
    /// Original: `.find(|c: char| !c.is_ascii_digit() && c != ',')`
    /// stops at any non-digit-non-comma (e.g., space or `@`).
    /// Mutant (`==`): `.find(|c: char| !c.is_ascii_digit() && c == ',')`
    /// only stops at comma; for a hunk header WITHOUT comma like `+5 @@`,
    /// the mutant scans past the space/@ and returns `unwrap_or(len)`,
    /// yielding `range_str = "5 @@"` which fails to parse, defaulting to 0.
    #[test]
    fn extract_changed_lines_hunk_without_comma() {
        // Hunk header `+5 @@` has no comma — single-line hunk
        let patch = "@@ -1,1 +5 @@\n+new_line\n";
        let lines = extract_changed_lines(patch);
        assert_eq!(
            lines,
            vec![5],
            "single-line hunk start must parse correctly"
        );
    }

    /// Kills L216: `replace > with ==` in analyze_coverage.
    /// Original: `if changed_count > 0 { compute pct } else { 100.0 }`
    /// Mutant (`==`): `if changed_count == 0 { compute pct } else { 100.0 }`
    /// When changed_count > 0, mutant returns 100.0 instead of real pct.
    /// When changed_count == 0, mutant tries to divide by zero (0/0 => NaN or 100.0).
    /// The existing partial-coverage test (66.67%) already checks pct but let's
    /// add a targeted test with exactly 1 changed line covered=0 for clarity.
    #[test]
    fn analyze_coverage_nonzero_changed_computes_pct() {
        // 1 changed line, 0 covered => pct must be 0.0, not 100.0
        let report = parse_lcov(&make_lcov("src/a.rs", &[(1, 0)])).unwrap();
        let changed = vec![("src/a.rs".to_string(), vec![1])];
        let analysis = analyze_coverage(&report, &changed);
        assert_eq!(analysis.files[0].changed_lines, 1);
        assert_eq!(analysis.files[0].covered_lines, 0);
        assert!(
            analysis.files[0].coverage_pct < 1.0,
            "coverage_pct must be 0.0 when no lines are covered, got {}",
            analysis.files[0].coverage_pct
        );
    }

    // --- classify_coverage_severity ---

    /// WHY: Biconditional test — verifies forward implication AND contrapositive
    /// at threshold boundaries to ensure the integer arithmetic matches the
    /// Creusot specification exactly.
    #[test]
    fn classify_severity_biconditional() {
        // total=0 => always Pass
        assert_eq!(
            classify_coverage_severity(0, 0, 80, 50),
            Severity::Pass,
            "total=0 must be Pass regardless of covered"
        );

        // warn_pct=80, error_pct=50, total=100
        // covered=81 => 81*100=8100 > 80*100=8000 => Pass
        assert_eq!(
            classify_coverage_severity(81, 100, 80, 50),
            Severity::Pass,
            "81% > 80% warn threshold => Pass"
        );
        // covered=80 => 80*100=8000 <= 80*100=8000 (not strictly greater) => NOT Pass
        assert_ne!(
            classify_coverage_severity(80, 100, 80, 50),
            Severity::Pass,
            "80% == warn threshold => NOT Pass (contrapositive)"
        );

        // covered=51 => 51*100=5100 > 50*100=5000 => Warning (not Error)
        assert_eq!(
            classify_coverage_severity(51, 100, 80, 50),
            Severity::Warning,
            "51% > 50% error threshold but <= 80% => Warning"
        );
        // covered=50 => 50*100=5000 <= 50*100=5000 => Error
        assert_eq!(
            classify_coverage_severity(50, 100, 80, 50),
            Severity::Error,
            "50% == error threshold => Error (contrapositive of Warning)"
        );

        // covered=0 => Error
        assert_eq!(
            classify_coverage_severity(0, 100, 80, 50),
            Severity::Error,
            "0% coverage => Error"
        );
    }

    /// WHY: Exhaustive test over a small domain (0..20) ensures the runtime
    /// implementation matches the Creusot spec for ALL input combinations,
    /// not just hand-picked boundary values.
    #[test]
    fn classify_severity_exhaustive_small() {
        let warn_pct = 80;
        let error_pct = 50;

        for total in 0..=20usize {
            for covered in 0..=20usize {
                let result = classify_coverage_severity(covered, total, warn_pct, error_pct);
                let spec = if total == 0 {
                    Severity::Pass
                } else if covered * 100 > warn_pct * total {
                    Severity::Pass
                } else if covered * 100 > error_pct * total {
                    Severity::Warning
                } else {
                    Severity::Error
                };
                assert_eq!(
                    result, spec,
                    "classify_coverage_severity({covered}, {total}, {warn_pct}, {error_pct}): \
                     got {result:?}, spec {spec:?}"
                );
            }
        }
    }
}
