//! JUnit XML parser for converting CI test reports into `HarnessResult` evidence.
//!
//! Parses the most common JUnit XML format: `<testsuites>` containing `<testsuite>` elements.
//! Each `<testsuite>` becomes one `HarnessResult`.
//!
//! Uses simple string scanning to avoid adding an XML parser dependency.

use crate::evidence::HarnessResult;

/// Parse JUnit XML content into `HarnessResult` entries.
///
/// Each `<testsuite>` becomes one `HarnessResult`. Supports both wrapped
/// (`<testsuites><testsuite .../>...</testsuites>`) and unwrapped
/// (`<testsuite .../>`) formats.
pub fn parse_junit_xml(xml: &str) -> Result<Vec<HarnessResult>, String> {
    let mut results = Vec::new();

    // Find all <testsuite ...> tags (self-closing or opening)
    let mut search_pos = 0;
    while let Some(start) = xml[search_pos..].find("<testsuite ") {
        let abs_start = search_pos + start;
        // Find the end of the opening tag (either /> or >)
        let tag_end = xml[abs_start..]
            .find('>')
            .ok_or_else(|| "Malformed XML: unclosed <testsuite> tag".to_string())?;
        let tag = &xml[abs_start..abs_start + tag_end + 1];

        let name = extract_attr(tag, "name").unwrap_or_default();
        let tests: u32 = extract_attr(tag, "tests")
            .and_then(|s| s.parse().ok())
            .unwrap_or(0);
        let failures: u32 = extract_attr(tag, "failures")
            .and_then(|s| s.parse().ok())
            .unwrap_or(0);
        let errors: u32 = extract_attr(tag, "errors")
            .and_then(|s| s.parse().ok())
            .unwrap_or(0);
        let skipped: u32 = extract_attr(tag, "skipped")
            .and_then(|s| s.parse().ok())
            .unwrap_or(0);
        let time: Option<f64> = extract_attr(tag, "time").and_then(|s| s.parse().ok());

        let failed_count = failures + errors;
        let passed_count = tests.saturating_sub(failed_count + skipped);
        let passed = failed_count == 0;

        results.push(HarnessResult {
            name: if name.is_empty() {
                format!("testsuite-{}", results.len())
            } else {
                name
            },
            passed,
            total: tests,
            passed_count,
            failed_count,
            skipped_count: skipped,
            duration_secs: time,
            source_format: Some("junit-xml".to_string()),
        });

        search_pos = abs_start + tag_end + 1;
    }

    if results.is_empty() {
        return Err("No <testsuite> elements found in XML".to_string());
    }

    Ok(results)
}

/// Extract an attribute value from an XML tag string.
/// Given `<testsuite name="foo" tests="10">`, `extract_attr(tag, "name")` returns `Some("foo")`.
fn extract_attr(tag: &str, attr: &str) -> Option<String> {
    let pattern = format!("{attr}=\"");
    let start = tag.find(&pattern)?;
    let value_start = start + pattern.len();
    let value_end = tag[value_start..].find('"')?;
    Some(tag[value_start..value_start + value_end].to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_single_testsuite() {
        let xml = r#"<?xml version="1.0" encoding="UTF-8"?>
<testsuites>
  <testsuite name="unit-tests" tests="42" failures="0" errors="0" skipped="2" time="1.234">
  </testsuite>
</testsuites>"#;
        let results = parse_junit_xml(xml).unwrap();
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].name, "unit-tests");
        assert!(results[0].passed);
        assert_eq!(results[0].total, 42);
        assert_eq!(results[0].passed_count, 40);
        assert_eq!(results[0].failed_count, 0);
        assert_eq!(results[0].skipped_count, 2);
        assert!((results[0].duration_secs.unwrap() - 1.234).abs() < 0.001);
        assert_eq!(results[0].source_format.as_deref(), Some("junit-xml"));
    }

    #[test]
    fn parse_multiple_testsuites() {
        let xml = r#"<testsuites>
  <testsuite name="unit" tests="10" failures="0" errors="0" time="0.5">
  </testsuite>
  <testsuite name="integration" tests="5" failures="2" errors="1" time="3.0">
  </testsuite>
</testsuites>"#;
        let results = parse_junit_xml(xml).unwrap();
        assert_eq!(results.len(), 2);
        assert!(results[0].passed);
        assert!(!results[1].passed);
        assert_eq!(results[1].failed_count, 3); // 2 failures + 1 error
        assert_eq!(results[1].passed_count, 2); // 5 - 3 = 2
    }

    #[test]
    fn parse_with_failures() {
        let xml = r#"<testsuite name="lint" tests="100" failures="3" errors="0" skipped="0">"#;
        let results = parse_junit_xml(xml).unwrap();
        assert_eq!(results.len(), 1);
        assert!(!results[0].passed);
        assert_eq!(results[0].failed_count, 3);
        assert_eq!(results[0].passed_count, 97);
    }

    #[test]
    fn parse_unwrapped_testsuite() {
        let xml = r#"<testsuite name="mytest" tests="5" failures="0" errors="0" />"#;
        let results = parse_junit_xml(xml).unwrap();
        assert_eq!(results.len(), 1);
        assert!(results[0].passed);
    }

    #[test]
    fn error_on_empty_xml() {
        let result = parse_junit_xml("<testsuites></testsuites>");
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("No <testsuite> elements"));
    }

    #[test]
    fn error_on_no_testsuite() {
        let result = parse_junit_xml("not xml at all");
        assert!(result.is_err());
    }

    #[test]
    fn unnamed_testsuite_gets_default_name() {
        let xml = r#"<testsuite tests="1" failures="0" errors="0" />"#;
        let results = parse_junit_xml(xml).unwrap();
        assert_eq!(results[0].name, "testsuite-0");
    }

    #[test]
    fn missing_optional_attrs_default_to_zero() {
        let xml = r#"<testsuite name="minimal" tests="5" failures="0" errors="0" />"#;
        let results = parse_junit_xml(xml).unwrap();
        assert_eq!(results[0].skipped_count, 0);
        assert!(results[0].duration_secs.is_none());
    }
}
