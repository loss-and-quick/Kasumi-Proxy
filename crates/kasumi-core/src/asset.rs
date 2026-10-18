//! Asset file validation and filename safety.

use serde::{Deserialize, Serialize};

/// Reject path traversal / quoting tricks in asset filenames.
pub fn safe_filename(name: &str) -> bool {
    let name = name.trim();
    !name.is_empty()
        && !name.contains('/')
        && !name.contains("..")
        && !name.contains('"')
        && !name.contains('\\')
}

/// Check if a string is a valid http(s) URL for downloading assets.
pub fn is_valid_asset_url(url: &str) -> bool {
    let trimmed = url.trim();
    if trimmed.is_empty() || trimmed.contains(char::is_whitespace) {
        return false;
    }
    if let Ok(parsed) = url::Url::parse(trimmed) {
        (parsed.scheme() == "http" || parsed.scheme() == "https")
            && !parsed.cannot_be_a_base()
            && parsed.host().is_some()
    } else {
        false
    }
}

/// A draft asset file from the UI or an import input.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, specta::Type)]
#[serde(rename_all = "camelCase")]
pub struct AssetDraftInput {
    pub remarks: String,
    pub url: String,
}

/// The specific issue identified with an asset draft field.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, specta::Type)]
#[serde(rename_all = "camelCase")]
pub enum AssetDraftIssueKind {
    FilenameEmpty,
    FilenameUnsafe,
    FilenameTaken,
    UrlInvalid,
}

/// One field-level issue found while validating an asset draft.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, specta::Type)]
#[serde(rename_all = "camelCase")]
pub struct AssetDraftIssue {
    pub field: String,
    pub issue: AssetDraftIssueKind,
}

/// Validate an asset draft against domain safety rules and taken filenames.
pub fn validate_asset_draft(
    draft: &AssetDraftInput,
    taken_names: &[String],
) -> Vec<AssetDraftIssue> {
    let mut issues = Vec::new();
    let name = draft.remarks.trim();
    if name.is_empty() {
        issues.push(AssetDraftIssue {
            field: "remarks".into(),
            issue: AssetDraftIssueKind::FilenameEmpty,
        });
    } else if !safe_filename(name) {
        issues.push(AssetDraftIssue {
            field: "remarks".into(),
            issue: AssetDraftIssueKind::FilenameUnsafe,
        });
    } else if taken_names.iter().any(|t| t.trim() == name) {
        issues.push(AssetDraftIssue {
            field: "remarks".into(),
            issue: AssetDraftIssueKind::FilenameTaken,
        });
    }

    if !is_valid_asset_url(&draft.url) {
        issues.push(AssetDraftIssue {
            field: "url".into(),
            issue: AssetDraftIssueKind::UrlInvalid,
        });
    }

    issues
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn safe_filename_checks() {
        assert!(safe_filename("geoip.dat"));
        assert!(safe_filename("geosite-cn.dat"));
        assert!(!safe_filename(""));
        assert!(!safe_filename("   "));
        assert!(!safe_filename("../geoip.dat"));
        assert!(!safe_filename("sub/geoip.dat"));
        assert!(!safe_filename("sub\\geoip.dat"));
        assert!(!safe_filename("file\"name"));
    }

    #[test]
    fn is_valid_asset_url_checks() {
        assert!(is_valid_asset_url("https://example.com/geoip.dat"));
        assert!(is_valid_asset_url("http://localhost:8080/geosite.dat"));
        assert!(!is_valid_asset_url("ftp://example.com/file"));
        assert!(!is_valid_asset_url("not a url"));
        assert!(!is_valid_asset_url(""));
        assert!(!is_valid_asset_url("https://example .com"));
    }

    #[test]
    fn validate_asset_draft_issues() {
        let taken = vec!["geoip.dat".to_string()];

        let empty = AssetDraftInput {
            remarks: "".into(),
            url: "invalid".into(),
        };
        let issues = validate_asset_draft(&empty, &taken);
        assert_eq!(issues.len(), 2);
        assert_eq!(issues[0].issue, AssetDraftIssueKind::FilenameEmpty);
        assert_eq!(issues[1].issue, AssetDraftIssueKind::UrlInvalid);

        let unsafe_draft = AssetDraftInput {
            remarks: "../hack.dat".into(),
            url: "https://example.com/asset.dat".into(),
        };
        let issues = validate_asset_draft(&unsafe_draft, &taken);
        assert_eq!(issues.len(), 1);
        assert_eq!(issues[0].issue, AssetDraftIssueKind::FilenameUnsafe);

        let taken_draft = AssetDraftInput {
            remarks: "geoip.dat".into(),
            url: "https://example.com/asset.dat".into(),
        };
        let issues = validate_asset_draft(&taken_draft, &taken);
        assert_eq!(issues.len(), 1);
        assert_eq!(issues[0].issue, AssetDraftIssueKind::FilenameTaken);

        let valid = AssetDraftInput {
            remarks: "geosite.dat".into(),
            url: "https://example.com/asset.dat".into(),
        };
        assert!(validate_asset_draft(&valid, &taken).is_empty());
    }
}
