/// SPDX license classification for compliance checking.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LicenseCategory {
    /// Permissive (MIT, Apache-2.0, BSD-2-Clause, BSD-3-Clause, ISC, Unlicense, etc.)
    Permissive,
    /// Weak copyleft (LGPL-2.1, LGPL-3.0, MPL-2.0, EPL-2.0)
    WeakCopyleft,
    /// Strong copyleft (GPL-2.0, GPL-3.0, AGPL-3.0, SSPL-1.0, EUPL-1.2)
    StrongCopyleft,
    /// Unknown/unrecognized license
    Unknown,
}

/// Classify an SPDX license identifier.
pub fn classify_license(spdx_id: &str) -> LicenseCategory {
    // Normalize: trim whitespace, compare case-insensitively
    let id = spdx_id.trim();

    // Strong copyleft
    let strong_copyleft = [
        "GPL-2.0",
        "GPL-2.0-only",
        "GPL-2.0-or-later",
        "GPL-3.0",
        "GPL-3.0-only",
        "GPL-3.0-or-later",
        "AGPL-3.0",
        "AGPL-3.0-only",
        "AGPL-3.0-or-later",
        "SSPL-1.0",
        "EUPL-1.2",
        "EUPL-1.1",
        "CECILL-2.1",
        "OSL-3.0",
        "RPL-1.5",
    ];
    for known in &strong_copyleft {
        if id.eq_ignore_ascii_case(known) {
            return LicenseCategory::StrongCopyleft;
        }
    }

    // Weak copyleft
    let weak_copyleft = [
        "LGPL-2.1",
        "LGPL-2.1-only",
        "LGPL-2.1-or-later",
        "LGPL-3.0",
        "LGPL-3.0-only",
        "LGPL-3.0-or-later",
        "MPL-2.0",
        "EPL-2.0",
        "EPL-1.0",
        "CDDL-1.0",
        "CDDL-1.1",
        "CPL-1.0",
    ];
    for known in &weak_copyleft {
        if id.eq_ignore_ascii_case(known) {
            return LicenseCategory::WeakCopyleft;
        }
    }

    // Permissive
    let permissive = [
        "MIT",
        "Apache-2.0",
        "BSD-2-Clause",
        "BSD-3-Clause",
        "ISC",
        "Unlicense",
        "0BSD",
        "CC0-1.0",
        "Zlib",
        "BSL-1.0",
        "PSF-2.0",
        "Unicode-3.0",
        "Unicode-DFS-2016",
        "BlueOak-1.0.0",
        "MIT-0",
    ];
    for known in &permissive {
        if id.eq_ignore_ascii_case(known) {
            return LicenseCategory::Permissive;
        }
    }

    LicenseCategory::Unknown
}

/// Returns true if the license is copyleft (weak or strong).
pub fn is_copyleft(spdx_id: &str) -> bool {
    matches!(
        classify_license(spdx_id),
        LicenseCategory::WeakCopyleft | LicenseCategory::StrongCopyleft
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn permissive_licenses() {
        assert_eq!(classify_license("MIT"), LicenseCategory::Permissive);
        assert_eq!(classify_license("Apache-2.0"), LicenseCategory::Permissive);
        assert_eq!(
            classify_license("BSD-3-Clause"),
            LicenseCategory::Permissive
        );
        assert_eq!(classify_license("ISC"), LicenseCategory::Permissive);
        assert_eq!(classify_license("Unlicense"), LicenseCategory::Permissive);
        assert_eq!(classify_license("0BSD"), LicenseCategory::Permissive);
    }

    #[test]
    fn weak_copyleft_licenses() {
        assert_eq!(classify_license("LGPL-2.1"), LicenseCategory::WeakCopyleft);
        assert_eq!(classify_license("MPL-2.0"), LicenseCategory::WeakCopyleft);
        assert_eq!(classify_license("EPL-2.0"), LicenseCategory::WeakCopyleft);
        assert_eq!(
            classify_license("LGPL-3.0-only"),
            LicenseCategory::WeakCopyleft
        );
    }

    #[test]
    fn strong_copyleft_licenses() {
        assert_eq!(classify_license("GPL-2.0"), LicenseCategory::StrongCopyleft);
        assert_eq!(classify_license("GPL-3.0"), LicenseCategory::StrongCopyleft);
        assert_eq!(
            classify_license("AGPL-3.0"),
            LicenseCategory::StrongCopyleft
        );
        assert_eq!(
            classify_license("SSPL-1.0"),
            LicenseCategory::StrongCopyleft
        );
        assert_eq!(
            classify_license("AGPL-3.0-or-later"),
            LicenseCategory::StrongCopyleft
        );
    }

    #[test]
    fn unknown_license() {
        assert_eq!(classify_license("PROPRIETARY"), LicenseCategory::Unknown);
        assert_eq!(classify_license(""), LicenseCategory::Unknown);
    }

    #[test]
    fn case_insensitive() {
        assert_eq!(classify_license("mit"), LicenseCategory::Permissive);
        assert_eq!(classify_license("gpl-3.0"), LicenseCategory::StrongCopyleft);
    }

    #[test]
    fn is_copyleft_checks() {
        assert!(!is_copyleft("MIT"));
        assert!(!is_copyleft("Apache-2.0"));
        assert!(is_copyleft("GPL-3.0"));
        assert!(is_copyleft("LGPL-2.1"));
        assert!(is_copyleft("AGPL-3.0"));
        assert!(!is_copyleft("UNKNOWN"));
    }

    #[test]
    fn whitespace_trimmed() {
        assert_eq!(classify_license("  MIT  "), LicenseCategory::Permissive);
    }
}
