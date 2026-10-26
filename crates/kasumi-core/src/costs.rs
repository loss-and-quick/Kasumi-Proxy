//! Xray leastLoad balancer strategy costs evaluation and rendering.

use crate::custom_sanitize::SanitizeError;
use serde_json::Value;

pub const ALLOWED_COST_KEYS: [&str; 3] = ["match", "regexp", "value"];
pub const MAX_COST_RULES_PER_BALANCER: usize = 64;
pub const MAX_PROFILE_COST_RULES: usize = 1024;
const REGEX_SIZE_LIMIT: usize = 64 * 1024; // 64 KiB

#[derive(Debug, Clone)]
pub struct ParsedCostRule {
    pub match_str: String,
    pub is_regexp: bool,
    pub explicit_value: Option<serde_json::Number>,
}

enum CompiledMatcher {
    Substring(String),
    Regex(regex::bytes::Regex),
}

/// Normalizes Go-compatible ASCII regex pattern into Rust non-unicode regex.
///
/// Specifically:
/// - Rejects non-ASCII pattern bytes.
/// - Rejects unsupported Go/RE2 features like `\Q..\E`.
/// - Rejects Rust-only flags (x, u, R).
/// - Rejects Rust-only character class set operators (`&&`, `--`, `~~`).
/// - Normalizes `\s` to `[\t\n\f\r ]` and `\S` to `[^\t\n\f\r ]` (Go excludes vertical tab `\v` 0x0B).
pub fn validate_and_normalize_regex(
    pattern: &str,
    cost_path: &str,
) -> Result<String, SanitizeError> {
    if !pattern.is_ascii() {
        return Err(SanitizeError::Incompatible {
            path: format!("{cost_path}.match"),
            reason: "regexp costs require ASCII pattern",
        });
    }

    if pattern.contains(r"\Q") {
        return Err(SanitizeError::Incompatible {
            path: format!("{cost_path}.match"),
            reason: "unsupported regex syntax: literal quoting",
        });
    }

    let bytes = pattern.as_bytes();
    let len = bytes.len();
    let mut i = 0;
    let mut in_class = false;
    let mut normalized = String::with_capacity(len + 16);

    while i < len {
        let b = bytes[i];
        if b == b'\\' {
            if i + 1 >= len {
                normalized.push('\\');
                break;
            }
            let next = bytes[i + 1];
            if next == b's' {
                if in_class {
                    normalized.push_str("\t\n\x0c\r ");
                } else {
                    normalized.push_str("[\t\n\x0c\r ]");
                }
                i += 2;
                continue;
            } else if next == b'S' {
                normalized.push_str("[^\t\n\x0c\r ]");
                i += 2;
                continue;
            } else {
                normalized.push('\\');
                normalized.push(next as char);
                i += 2;
                continue;
            }
        }

        if !in_class {
            if b == b'[' {
                in_class = true;
                normalized.push('[');
                i += 1;
                // If first char in class is ']' or '^]', it is treated as a literal ']'
                if i < len && bytes[i] == b'^' {
                    normalized.push('^');
                    i += 1;
                }
                if i < len && bytes[i] == b']' {
                    normalized.push(']');
                    i += 1;
                }
                continue;
            } else if b == b'(' && i + 1 < len && bytes[i + 1] == b'?' {
                let mut j = i + 2;
                while j < len && bytes[j] != b')' && bytes[j] != b':' {
                    let c = bytes[j];
                    if c == b'x' || c == b'u' || c == b'R' {
                        return Err(SanitizeError::Incompatible {
                            path: format!("{cost_path}.match"),
                            reason: "unsupported regex flag",
                        });
                    }
                    j += 1;
                }
                normalized.push('(');
                i += 1;
                continue;
            }
        } else {
            if b == b']' {
                in_class = false;
                normalized.push(']');
                i += 1;
                continue;
            }
            if (b == b'&' && i + 1 < len && bytes[i + 1] == b'&')
                || (b == b'-' && i + 1 < len && bytes[i + 1] == b'-')
                || (b == b'~' && i + 1 < len && bytes[i + 1] == b'~')
            {
                return Err(SanitizeError::Incompatible {
                    path: format!("{cost_path}.match"),
                    reason: "unsupported regex character class operator",
                });
            }
        }

        normalized.push(b as char);
        i += 1;
    }

    Ok(normalized)
}

/// Extracts the first ASCII `\d+(\.\d+)?` from `s` and parses it as `f64`.
///
/// Missing number returns None. Parse errors / overflow return `Some(1.0)` matching Go's default.
pub fn first_ascii_number(s: &str) -> Option<f64> {
    let bytes = s.as_bytes();
    let len = bytes.len();
    let mut i = 0;
    while i < len {
        if bytes[i].is_ascii_digit() {
            let start = i;
            while i < len && bytes[i].is_ascii_digit() {
                i += 1;
            }
            let mut end = i;
            if i + 1 < len && bytes[i] == b'.' && bytes[i + 1].is_ascii_digit() {
                i += 2;
                while i < len && bytes[i].is_ascii_digit() {
                    i += 1;
                }
                end = i;
            }
            let num_str = &s[start..end];
            return match num_str.parse::<f64>() {
                Ok(val) if val.is_finite() => Some(val),
                _ => Some(1.0),
            };
        }
        i += 1;
    }
    None
}

/// Checks whether an f64 value is exactly representable as finite IEEE 754 single-precision (f32).
#[inline]
pub fn is_exact_f32(val: f64) -> bool {
    let as_f32 = val as f32;
    as_f32.is_finite() && (as_f32 as f64) == val
}

/// Resolves effective per-member weights for a leastLoad balancer.
///
/// Returns a list of `(member_id, resolved_weight_number)` preserving member order.
pub fn resolve_leastload_costs(
    costs_val: &Value,
    member_orig_tags: &[(&str, &str)], // (member_unique_tag, member_original_tag)
    path: &str,
    total_cost_rules: &mut usize,
) -> Result<Vec<(String, serde_json::Number)>, SanitizeError> {
    let costs_arr = costs_val
        .as_array()
        .ok_or_else(|| SanitizeError::Incompatible {
            path: format!("{path}.strategy.settings.costs"),
            reason: "balancer costs must be an array",
        })?;

    if costs_arr.len() > MAX_COST_RULES_PER_BALANCER {
        return Err(SanitizeError::Incompatible {
            path: format!("{path}.strategy.settings.costs"),
            reason: "balancer costs exceeds maximum rule limit",
        });
    }

    *total_cost_rules += costs_arr.len();
    if *total_cost_rules > MAX_PROFILE_COST_RULES {
        return Err(SanitizeError::Incompatible {
            path: format!("{path}.strategy.settings.costs"),
            reason: "profile costs exceeds total rule limit",
        });
    }

    let mut parsed_rules = Vec::with_capacity(costs_arr.len());
    let mut has_regex_rule = false;

    for (c_idx, c_val) in costs_arr.iter().enumerate() {
        let cost_path = format!("{path}.strategy.settings.costs[{c_idx}]");
        if c_val.is_null() {
            return Err(SanitizeError::Incompatible {
                path: cost_path,
                reason: "cost entry cannot be null",
            });
        }
        let c_obj = c_val
            .as_object()
            .ok_or_else(|| SanitizeError::Incompatible {
                path: cost_path.clone(),
                reason: "cost entry must be an object",
            })?;

        for k in c_obj.keys() {
            if !ALLOWED_COST_KEYS.contains(&k.as_str()) {
                return Err(SanitizeError::Incompatible {
                    path: format!("{cost_path}.{k}"),
                    reason: "unknown cost rule field",
                });
            }
        }

        let match_str = match c_obj.get("match") {
            Some(Value::String(s)) => s.clone(),
            Some(Value::Null) | None => String::new(),
            _ => {
                return Err(SanitizeError::Incompatible {
                    path: format!("{cost_path}.match"),
                    reason: "cost match must be a string",
                });
            }
        };

        let is_regexp = match c_obj.get("regexp") {
            Some(Value::Bool(b)) => *b,
            Some(Value::Null) | None => false,
            _ => {
                return Err(SanitizeError::Incompatible {
                    path: format!("{cost_path}.regexp"),
                    reason: "cost regexp must be a boolean",
                });
            }
        };
        if is_regexp {
            has_regex_rule = true;
        }

        let explicit_value = match c_obj.get("value") {
            Some(Value::Number(n)) => {
                let f = n.as_f64().ok_or_else(|| SanitizeError::Incompatible {
                    path: format!("{cost_path}.value"),
                    reason: "cost value must be a number",
                })?;
                let f32_val = f as f32;
                if !f32_val.is_finite() {
                    return Err(SanitizeError::Incompatible {
                        path: format!("{cost_path}.value"),
                        reason: "cost value exceeds float32 range",
                    });
                }
                if f32_val > 0.0 { Some(n.clone()) } else { None }
            }
            Some(Value::Null) | None => None,
            _ => {
                return Err(SanitizeError::Incompatible {
                    path: format!("{cost_path}.value"),
                    reason: "cost value must be a number",
                });
            }
        };

        parsed_rules.push(ParsedCostRule {
            match_str,
            is_regexp,
            explicit_value,
        });
    }

    if has_regex_rule {
        for (_, orig_tag) in member_orig_tags {
            if !orig_tag.is_ascii() {
                return Err(SanitizeError::Incompatible {
                    path: format!("{path}.strategy.settings.costs"),
                    reason: "regexp costs require ASCII tags",
                });
            }
        }
    }

    let mut matchers = Vec::with_capacity(parsed_rules.len());
    for (c_idx, rule) in parsed_rules.iter().enumerate() {
        let cost_path = format!("{path}.strategy.settings.costs[{c_idx}]");
        if !rule.is_regexp {
            matchers.push(CompiledMatcher::Substring(rule.match_str.clone()));
        } else {
            let normalized = validate_and_normalize_regex(&rule.match_str, &cost_path)?;
            let re = regex::bytes::RegexBuilder::new(&normalized)
                .unicode(false)
                .octal(true)
                .size_limit(REGEX_SIZE_LIMIT)
                .dfa_size_limit(REGEX_SIZE_LIMIT)
                .build()
                .map_err(|_| SanitizeError::Incompatible {
                    path: format!("{cost_path}.match"),
                    reason: "invalid regex pattern",
                })?;
            matchers.push(CompiledMatcher::Regex(re));
        }
    }

    let mut resolved = Vec::with_capacity(member_orig_tags.len());

    for (unique_tag, orig_tag) in member_orig_tags {
        let mut weight = serde_json::Number::from(1);

        for (r_idx, matcher) in matchers.iter().enumerate() {
            let matched_text = match matcher {
                CompiledMatcher::Substring(needle) => {
                    if !needle.is_empty() && orig_tag.contains(needle) {
                        Some(needle.as_str())
                    } else {
                        None
                    }
                }
                CompiledMatcher::Regex(re) => {
                    if let Some(m) = re.find(orig_tag.as_bytes()) {
                        let text = std::str::from_utf8(m.as_bytes()).unwrap_or("");
                        if !text.is_empty() { Some(text) } else { None }
                    } else {
                        None
                    }
                }
            };

            if let Some(matched) = matched_text {
                let rule = &parsed_rules[r_idx];
                if let Some(explicit) = &rule.explicit_value {
                    weight = explicit.clone();
                } else {
                    if let Some(val) = first_ascii_number(matched) {
                        if val <= 0.0 {
                            return Err(SanitizeError::Incompatible {
                                path: format!("{path}.strategy.settings.costs[{r_idx}]"),
                                reason: "auto cost value cannot be zero",
                            });
                        }
                        if !val.is_finite() || val > (f32::MAX as f64) {
                            return Err(SanitizeError::Incompatible {
                                path: format!("{path}.strategy.settings.costs[{r_idx}]"),
                                reason: "auto cost value exceeds float32 range",
                            });
                        }
                        if !is_exact_f32(val) {
                            return Err(SanitizeError::Incompatible {
                                path: format!("{path}.strategy.settings.costs[{r_idx}]"),
                                reason: "auto cost value requires exact float32 representation",
                            });
                        }
                        weight = if val.fract() == 0.0 && val <= (u64::MAX as f64) {
                            serde_json::Number::from(val as u64)
                        } else {
                            serde_json::Number::from_f64(val).unwrap()
                        };
                    } else {
                        weight = serde_json::Number::from(1);
                    }
                }
                break;
            }
        }

        resolved.push((unique_tag.to_string(), weight));
    }

    Ok(resolved)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_number_finder() {
        assert_eq!(first_ascii_number("node-99-cost-2"), Some(99.0));
        assert_eq!(first_ascii_number("cost-2"), Some(2.0));
        assert_eq!(first_ascii_number("cost-3.5"), Some(3.5));
        assert_eq!(first_ascii_number("cost-0"), Some(0.0));
        assert_eq!(first_ascii_number("cost-0.1"), Some(0.1));
        assert_eq!(first_ascii_number("cost-"), None);
        assert_eq!(first_ascii_number(".5"), Some(5.0));
        assert_eq!(first_ascii_number("1."), Some(1.0));
        assert_eq!(first_ascii_number("1.2.3"), Some(1.2));
        assert_eq!(first_ascii_number("1e5"), Some(1.0));
    }

    #[test]
    fn test_is_exact_f32() {
        assert!(is_exact_f32(1.0));
        assert!(is_exact_f32(2.0));
        assert!(is_exact_f32(3.5));
        assert!(is_exact_f32(0.5));
        assert!(is_exact_f32(0.25));
        assert!(is_exact_f32(120.0));
        assert!(is_exact_f32(99999.0));
        assert!(!is_exact_f32(0.1));
        assert!(!is_exact_f32(0.2));
        assert!(!is_exact_f32(1e40));
    }

    #[test]
    fn test_space_normalization() {
        let norm = validate_and_normalize_regex(r"node\s[0-9]", "test").unwrap();
        let re = regex::bytes::RegexBuilder::new(&norm)
            .unicode(false)
            .build()
            .unwrap();
        assert!(!re.is_match(b"node\x0b7")); // VT is NOT matched
        assert!(re.is_match(b"node\t7")); // Tab matched
        assert!(re.is_match(b"node 7")); // Space matched
    }
}
