use super::*;

// --- parse_digits boundary mutations ---

#[test]
fn hash_followed_by_underscore_not_matched() {
    // Kills: removing '_' from rejection set in parse_digits
    let refs = extract_issue_references("#123_foo", &[]);
    assert!(!has_issue_linkage(&refs));
}

#[test]
fn hash_followed_by_dash_not_matched() {
    // Kills: removing '-' from rejection set in parse_digits
    let refs = extract_issue_references("#123-foo", &[]);
    assert!(!has_issue_linkage(&refs));
}

#[test]
fn hash_at_end_of_string_matched() {
    // Kills: requiring a trailing char after digits (end-of-string case)
    let refs = extract_issue_references("#999", &[]);
    assert!(has_issue_linkage(&refs));
    assert_eq!(refs[0].value, "#999");
}

#[test]
fn hash_followed_by_newline_matched() {
    let refs = extract_issue_references("#42\nnext line", &[]);
    assert!(has_issue_linkage(&refs));
    assert_eq!(refs[0].value, "#42");
}

// --- Keyword variant coverage (kills: removing individual array entries) ---

#[test]
fn keyword_fix_singular() {
    let refs = extract_issue_references("fix #10", &[]);
    assert_eq!(refs[0].value, "fix #10");
}

#[test]
fn keyword_fixed_past_tense() {
    let refs = extract_issue_references("fixed #10", &[]);
    assert_eq!(refs[0].value, "fixed #10");
}

#[test]
fn keyword_close_singular() {
    let refs = extract_issue_references("close #10", &[]);
    assert_eq!(refs[0].value, "close #10");
}

#[test]
fn keyword_closed_past_tense() {
    let refs = extract_issue_references("closed #10", &[]);
    assert_eq!(refs[0].value, "closed #10");
}

#[test]
fn keyword_resolve_singular() {
    let refs = extract_issue_references("resolve #10", &[]);
    assert_eq!(refs[0].value, "resolve #10");
}

#[test]
fn keyword_resolved_past_tense() {
    let refs = extract_issue_references("resolved #10", &[]);
    assert_eq!(refs[0].value, "resolved #10");
}

// --- Keyword word boundary ---

#[test]
fn keyword_must_be_at_word_boundary() {
    let refs = extract_issue_references("unfixes #10", &[]);
    assert!(has_issue_linkage(&refs));
    assert!(
        !refs.iter().any(|r| r.value.contains("fixes")),
        "should not extract 'fixes' from 'unfixes'"
    );
}

// --- Keyword with multiple spaces ---

#[test]
fn keyword_with_extra_spaces() {
    let refs = extract_issue_references("fixes   #10", &[]);
    assert!(has_issue_linkage(&refs));
    assert_eq!(refs[0].value, "fixes #10");
}

// --- Jira edge cases ---

#[test]
fn jira_exactly_two_letter_prefix_matches() {
    // Kills: alpha_len < 2 → alpha_len < 3
    let refs = extract_issue_references("AB-123 ticket", &[]);
    assert!(
        refs.iter()
            .any(|r| r.kind == IssueRefKind::JiraTicket && r.value == "AB-123")
    );
}

#[test]
fn jira_preceded_by_dash_not_matched() {
    let refs = extract_issue_references("X-PROJ-123", &[]);
    assert!(!refs.iter().any(|r| r.kind == IssueRefKind::JiraTicket));
}

#[test]
fn jira_followed_by_dash_not_matched() {
    let refs = extract_issue_references("PROJ-123-extra", &[]);
    assert!(!refs.iter().any(|r| r.kind == IssueRefKind::JiraTicket));
}

#[test]
fn jira_at_start_of_string() {
    let refs = extract_issue_references("PROJ-456", &[]);
    assert_eq!(refs.len(), 1);
    assert_eq!(refs[0].kind, IssueRefKind::JiraTicket);
}

#[test]
fn jira_at_end_of_string() {
    let refs = extract_issue_references("see PROJ-456", &[]);
    assert!(refs.iter().any(|r| r.value == "PROJ-456"));
}

#[test]
fn jira_no_digits_after_dash_not_matched() {
    let refs = extract_issue_references("PROJ-abc", &[]);
    assert!(!refs.iter().any(|r| r.kind == IssueRefKind::JiraTicket));
}

#[test]
fn jira_preceded_by_alphanumeric_not_matched() {
    let refs = extract_issue_references("xPROJ-123", &[]);
    assert!(!refs.iter().any(|r| r.kind == IssueRefKind::JiraTicket));
}

// --- Jira blocklist: coverage beyond inline tests ---

#[test]
fn blocklist_ssl_not_jira() {
    let refs = extract_issue_references("Uses SSL-3 protocol", &[]);
    assert!(!refs.iter().any(|r| r.kind == IssueRefKind::JiraTicket));
}

#[test]
fn blocklist_sha_not_jira() {
    let refs = extract_issue_references("SHA-256 hash", &[]);
    assert!(!refs.iter().any(|r| r.kind == IssueRefKind::JiraTicket));
}

#[test]
fn blocklist_iso_not_jira() {
    let refs = extract_issue_references("ISO-8601 date format", &[]);
    assert!(!refs.iter().any(|r| r.kind == IssueRefKind::JiraTicket));
}

#[test]
fn blocklist_tls_not_jira() {
    let refs = extract_issue_references("TLS-12 connection", &[]);
    assert!(!refs.iter().any(|r| r.kind == IssueRefKind::JiraTicket));
}

#[test]
fn blocklist_api_not_jira() {
    let refs = extract_issue_references("API-42 endpoint", &[]);
    assert!(!refs.iter().any(|r| r.kind == IssueRefKind::JiraTicket));
}

// --- URL extraction mutations ---

#[test]
fn url_without_issues_or_browse_not_matched() {
    let refs = extract_issue_references("https://github.com/owner/repo/pulls/1", &[]);
    assert!(!refs.iter().any(|r| r.kind == IssueRefKind::Url));
}

#[test]
fn url_trailing_comma_stripped() {
    let refs = extract_issue_references("See https://github.com/o/r/issues/1, for details", &[]);
    assert!(has_issue_linkage(&refs));
    assert!(!refs[0].value.ends_with(','));
}

#[test]
fn url_trailing_period_stripped() {
    let refs = extract_issue_references("See https://github.com/o/r/issues/1. Next sentence.", &[]);
    assert!(has_issue_linkage(&refs));
    assert!(!refs[0].value.ends_with('.'));
}

#[test]
fn url_http_also_matched() {
    let refs = extract_issue_references("http://github.com/o/r/issues/1", &[]);
    assert!(has_issue_linkage(&refs));
    assert_eq!(refs[0].kind, IssueRefKind::Url);
}

#[test]
fn url_in_angle_brackets() {
    let refs = extract_issue_references("Link: <https://github.com/o/r/issues/1> here", &[]);
    assert!(has_issue_linkage(&refs));
}

// --- Deduplication ---

#[test]
fn duplicate_references_deduplicated() {
    let refs = extract_issue_references("#42 and also #42", &[]);
    assert_eq!(refs.iter().filter(|r| r.value == "#42").count(), 1,);
}

// --- Custom pattern edge cases ---

#[test]
fn custom_empty_pattern_no_match() {
    let refs = extract_issue_references("anything here", &[""]);
    assert!(
        !refs
            .iter()
            .any(|r| r.kind == IssueRefKind::Url && r.value.is_empty())
    );
}

#[test]
fn custom_pattern_categorized_as_url_kind() {
    let refs = extract_issue_references("ticket: my-custom-ref-99", &["my-custom-ref-99"]);
    let custom_ref = refs.iter().find(|r| r.value == "my-custom-ref-99").unwrap();
    assert_eq!(custom_ref.kind, IssueRefKind::Url);
}

// --- Jira URL dedup ---

#[test]
fn jira_in_url_suppresses_standalone() {
    let refs = extract_issue_references("https://jira.example.com/browse/PROJ-123", &[]);
    assert!(refs.iter().any(|r| r.kind == IssueRefKind::Url));
    assert!(
        !refs
            .iter()
            .any(|r| r.kind == IssueRefKind::JiraTicket && r.value == "PROJ-123"),
        "PROJ-123 in URL should not also appear as standalone Jira ticket"
    );
}

// --- Bare # edge cases ---

#[test]
fn hash_at_start_of_string() {
    let refs = extract_issue_references("#1", &[]);
    assert!(has_issue_linkage(&refs));
    assert_eq!(refs[0].value, "#1");
}

#[test]
fn hash_preceded_by_letter_not_matched() {
    let refs = extract_issue_references("x#123", &[]);
    assert!(!has_issue_linkage(&refs));
}

#[test]
fn hash_no_digits_not_matched() {
    let refs = extract_issue_references("# text", &[]);
    assert!(!has_issue_linkage(&refs));
}
