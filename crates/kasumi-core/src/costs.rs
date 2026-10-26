//! Xray leastLoad balancer strategy costs evaluation and rendering.

use crate::custom_sanitize::SanitizeError;
use regex_syntax::ast::parse::ParserBuilder;
use regex_syntax::ast::{
    AssertionKind, Ast, ClassAsciiKind, ClassSet, ClassSetItem, Flag, FlagsItemKind, GroupKind,
    RepetitionRange,
};
use serde_json::Value;

pub const ALLOWED_COST_KEYS: [&str; 3] = ["match", "regexp", "value"];
pub const MAX_COST_RULES_PER_BALANCER: usize = 64;
pub const MAX_PROFILE_COST_RULES: usize = 1024;
pub const MAX_PROFILE_MATCHING_BYTES: usize = 64 * 1024 * 1024; // 64 MiB
pub const MAX_REGEX_SIZE_LIMIT: usize = 64 * 1024; // 64 KiB
const MAX_REGEX_AST_DEPTH: usize = 64;
const MAX_REPEAT_PRODUCT: u32 = 1000;

#[derive(Debug, Clone, Default)]
pub struct CostBudget {
    pub total_rules: usize,
    pub matching_bytes: usize,
}

#[derive(Debug, Clone)]
pub(crate) struct ParsedCostRule {
    pub(crate) match_str: String,
    pub(crate) is_regexp: bool,
    pub(crate) explicit_value: Option<serde_json::Number>,
}

enum CompiledMatcher {
    Substring(String),
    Regex(regex::bytes::Regex),
}

fn validate_escape(text: &str, cost_path: &str) -> Result<(), SanitizeError> {
    let bytes = text.as_bytes();
    if bytes.len() < 2 || bytes[0] != b'\\' {
        return Ok(());
    }
    let next = bytes[1];

    if next == b's' || next == b'S' {
        return Ok(());
    }

    if next == b'<' || next == b'>' {
        return Err(SanitizeError::Incompatible {
            path: format!("{cost_path}.match"),
            reason: "unsupported regex escape sequence",
        });
    }

    if next == b'Q' || next == b'E' {
        return Err(SanitizeError::Incompatible {
            path: format!("{cost_path}.match"),
            reason: "unsupported regex syntax: literal quoting",
        });
    }

    if next.is_ascii_digit() {
        if next == b'0' {
            if bytes.len() == 4
                && (b'0'..=b'7').contains(&bytes[2])
                && (b'0'..=b'7').contains(&bytes[3])
            {
                return Ok(());
            }
            if bytes.len() == 2 {
                return Ok(());
            }
            return Err(SanitizeError::Incompatible {
                path: format!("{cost_path}.match"),
                reason: "unsupported regex escape sequence",
            });
        } else if (b'1'..=b'3').contains(&next)
            && bytes.len() == 4
            && (b'0'..=b'7').contains(&bytes[2])
            && (b'0'..=b'7').contains(&bytes[3])
        {
            return Ok(());
        } else {
            return Err(SanitizeError::Incompatible {
                path: format!("{cost_path}.match"),
                reason: "unsupported regex escape sequence",
            });
        }
    }

    if next.is_ascii_alphabetic() {
        match next {
            b'a' | b'f' | b't' | b'n' | b'r' | b'v' | b'A' | b'z' | b'b' | b'B' | b'd' | b'D'
            | b'w' | b'W' => Ok(()),
            b'x' => {
                if bytes.len() >= 4 && bytes[2] == b'{' && bytes.ends_with(b"}") {
                    let hex = &bytes[3..bytes.len() - 1];
                    if !hex.is_empty() && hex.iter().all(u8::is_ascii_hexdigit) {
                        return Ok(());
                    }
                } else if bytes.len() == 4
                    && bytes[2].is_ascii_hexdigit()
                    && bytes[3].is_ascii_hexdigit()
                {
                    return Ok(());
                }
                Err(SanitizeError::Incompatible {
                    path: format!("{cost_path}.match"),
                    reason: "invalid regex hex escape",
                })
            }
            _ => Err(SanitizeError::Incompatible {
                path: format!("{cost_path}.match"),
                reason: "unsupported regex escape sequence",
            }),
        }
    } else {
        Ok(())
    }
}

fn validate_class_set(
    cs: &ClassSet,
    pattern: &str,
    cost_path: &str,
    depth: usize,
    class_span: Option<regex_syntax::ast::Span>,
) -> Result<(), SanitizeError> {
    if depth > MAX_REGEX_AST_DEPTH {
        return Err(SanitizeError::Incompatible {
            path: format!("{cost_path}.match"),
            reason: "regex exceeds maximum nesting depth",
        });
    }
    match cs {
        ClassSet::Item(item) => match item {
            ClassSetItem::Literal(lit) => {
                let text = &pattern[lit.span.start.offset..lit.span.end.offset];
                validate_escape(text, cost_path)?;
                if lit.c == '-'
                    && text == "-"
                    && let Some(cs) = class_span
                {
                    let is_first = lit.span.start.offset == cs.start.offset + 1
                        || (pattern.as_bytes().get(cs.start.offset + 1) == Some(&b'^')
                            && lit.span.start.offset == cs.start.offset + 2);
                    let is_last = lit.span.end.offset == cs.end.offset - 1;
                    if !is_first && !is_last {
                        return Err(SanitizeError::Incompatible {
                            path: format!("{cost_path}.match"),
                            reason: "unsupported regex character class syntax",
                        });
                    }
                    if is_first
                        && lit.span.end.offset < cs.end.offset - 1
                        && pattern.as_bytes()[lit.span.end.offset] == b'-'
                    {
                        return Err(SanitizeError::Incompatible {
                            path: format!("{cost_path}.match"),
                            reason: "unsupported regex character class syntax",
                        });
                    }
                }
                Ok(())
            }
            ClassSetItem::Range(range) => {
                let start_text =
                    &pattern[range.start.span.start.offset..range.start.span.end.offset];
                if start_text == "-" {
                    return Err(SanitizeError::Incompatible {
                        path: format!("{cost_path}.match"),
                        reason: "unsupported regex character class syntax",
                    });
                }
                validate_escape(start_text, cost_path)?;
                let end_text = &pattern[range.end.span.start.offset..range.end.span.end.offset];
                validate_escape(end_text, cost_path)
            }
            ClassSetItem::Ascii(ascii) => match ascii.kind {
                ClassAsciiKind::Alnum
                | ClassAsciiKind::Alpha
                | ClassAsciiKind::Ascii
                | ClassAsciiKind::Blank
                | ClassAsciiKind::Cntrl
                | ClassAsciiKind::Digit
                | ClassAsciiKind::Graph
                | ClassAsciiKind::Lower
                | ClassAsciiKind::Print
                | ClassAsciiKind::Punct
                | ClassAsciiKind::Space
                | ClassAsciiKind::Upper
                | ClassAsciiKind::Word
                | ClassAsciiKind::Xdigit => Ok(()),
            },
            ClassSetItem::Perl(_) | ClassSetItem::Empty(_) => Ok(()),
            ClassSetItem::Bracketed(_) => Err(SanitizeError::Incompatible {
                path: format!("{cost_path}.match"),
                reason: "unsupported regex nested character class",
            }),
            ClassSetItem::Union(union) => {
                for sub in &union.items {
                    validate_class_set(
                        &ClassSet::Item(sub.clone()),
                        pattern,
                        cost_path,
                        depth + 1,
                        class_span,
                    )?;
                }
                Ok(())
            }
            ClassSetItem::Unicode(_) => Err(SanitizeError::Incompatible {
                path: format!("{cost_path}.match"),
                reason: "unsupported regex syntax: unicode classes",
            }),
        },
        ClassSet::BinaryOp(_) => Err(SanitizeError::Incompatible {
            path: format!("{cost_path}.match"),
            reason: "unsupported regex character class operator",
        }),
    }
}

fn validate_ast(
    ast: &Ast,
    pattern: &str,
    cost_path: &str,
    depth: usize,
    repeat_product: u32,
) -> Result<(), SanitizeError> {
    if depth > MAX_REGEX_AST_DEPTH {
        return Err(SanitizeError::Incompatible {
            path: format!("{cost_path}.match"),
            reason: "regex exceeds maximum nesting depth",
        });
    }

    match ast {
        Ast::Empty(_) | Ast::Dot(_) => Ok(()),
        Ast::Literal(lit) => {
            let text = &pattern[lit.span.start.offset..lit.span.end.offset];
            validate_escape(text, cost_path)
        }
        Ast::Concat(concat) => {
            for child in &concat.asts {
                validate_ast(child, pattern, cost_path, depth + 1, repeat_product)?;
            }
            Ok(())
        }
        Ast::Alternation(alt) => {
            for child in &alt.asts {
                validate_ast(child, pattern, cost_path, depth + 1, repeat_product)?;
            }
            Ok(())
        }
        Ast::Assertion(ass) => match ass.kind {
            AssertionKind::StartLine
            | AssertionKind::EndLine
            | AssertionKind::StartText
            | AssertionKind::EndText
            | AssertionKind::WordBoundary
            | AssertionKind::NotWordBoundary => Ok(()),
            _ => Err(SanitizeError::Incompatible {
                path: format!("{cost_path}.match"),
                reason: "unsupported regex escape sequence",
            }),
        },
        Ast::ClassPerl(_) => Ok(()),
        Ast::ClassUnicode(_) => Err(SanitizeError::Incompatible {
            path: format!("{cost_path}.match"),
            reason: "unsupported regex syntax: unicode classes",
        }),
        Ast::ClassBracketed(cb) => {
            let class_slice = &pattern[cb.span.start.offset..cb.span.end.offset];
            if class_slice.starts_with("[--") || class_slice.starts_with("[^--") {
                return Err(SanitizeError::Incompatible {
                    path: format!("{cost_path}.match"),
                    reason: "unsupported regex character class syntax",
                });
            }
            validate_class_set(&cb.kind, pattern, cost_path, depth + 1, Some(cb.span))
        }
        Ast::Group(group) => {
            match &group.kind {
                GroupKind::CaptureIndex(_) => {}
                GroupKind::CaptureName { name, .. } => {
                    if name.name.is_empty()
                        || !name
                            .name
                            .chars()
                            .all(|c| c.is_ascii_alphanumeric() || c == '_')
                    {
                        return Err(SanitizeError::Incompatible {
                            path: format!("{cost_path}.match"),
                            reason: "invalid regex capture group name",
                        });
                    }
                }
                GroupKind::NonCapturing(flags) => {
                    for item in &flags.items {
                        if let FlagsItemKind::Flag(ref f) = item.kind {
                            match f {
                                Flag::CaseInsensitive
                                | Flag::MultiLine
                                | Flag::DotMatchesNewLine
                                | Flag::SwapGreed => {}
                                _ => {
                                    return Err(SanitizeError::Incompatible {
                                        path: format!("{cost_path}.match"),
                                        reason: "unsupported regex flag",
                                    });
                                }
                            }
                        }
                    }
                }
            }
            validate_ast(&group.ast, pattern, cost_path, depth + 1, repeat_product)
        }
        Ast::Flags(flags) => {
            for item in &flags.flags.items {
                if let FlagsItemKind::Flag(ref f) = item.kind {
                    match f {
                        Flag::CaseInsensitive
                        | Flag::MultiLine
                        | Flag::DotMatchesNewLine
                        | Flag::SwapGreed => {}
                        _ => {
                            return Err(SanitizeError::Incompatible {
                                path: format!("{cost_path}.match"),
                                reason: "unsupported regex flag",
                            });
                        }
                    }
                }
            }
            Ok(())
        }
        Ast::Repetition(rep) => {
            if matches!(&*rep.ast, Ast::Repetition(_)) {
                return Err(SanitizeError::Incompatible {
                    path: format!("{cost_path}.match"),
                    reason: "unsupported regex stacked quantifier",
                });
            }

            let op_span = rep.op.span;
            let op_text = &pattern[op_span.start.offset..op_span.end.offset];
            let trimmed = op_text.strip_suffix('?').unwrap_or(op_text);

            if trimmed.starts_with('{') && trimmed.ends_with('}') {
                let inner = &trimmed[1..trimmed.len() - 1];
                let parts: Vec<&str> = inner.split(',').collect();
                if parts.is_empty() || parts.len() > 2 {
                    return Err(SanitizeError::Incompatible {
                        path: format!("{cost_path}.match"),
                        reason: "unsupported regex quantifier spelling",
                    });
                }
                for (p_idx, part) in parts.iter().enumerate() {
                    if p_idx == 1 && part.is_empty() {
                        continue;
                    }
                    if part.is_empty()
                        || !part.chars().all(|c| c.is_ascii_digit())
                        || (part.len() > 1 && part.starts_with('0'))
                    {
                        return Err(SanitizeError::Incompatible {
                            path: format!("{cost_path}.match"),
                            reason: "unsupported regex quantifier spelling",
                        });
                    }
                }
            }

            let max_count: u32 = match &rep.op.kind {
                regex_syntax::ast::RepetitionKind::ZeroOrOne => 1,
                regex_syntax::ast::RepetitionKind::ZeroOrMore => 1,
                regex_syntax::ast::RepetitionKind::OneOrMore => 1,
                regex_syntax::ast::RepetitionKind::Range(range) => match range {
                    RepetitionRange::Exactly(n) => *n,
                    RepetitionRange::AtLeast(n) => *n,
                    RepetitionRange::Bounded(_, max) => *max,
                },
            };

            if max_count > MAX_REPEAT_PRODUCT {
                return Err(SanitizeError::Incompatible {
                    path: format!("{cost_path}.match"),
                    reason: "regex repetition count exceeds limit",
                });
            }

            let new_product =
                repeat_product.saturating_mul(if max_count > 1 { max_count } else { 1 });
            if new_product > MAX_REPEAT_PRODUCT {
                return Err(SanitizeError::Incompatible {
                    path: format!("{cost_path}.match"),
                    reason: "regex repetition count exceeds limit",
                });
            }

            validate_ast(&rep.ast, pattern, cost_path, depth + 1, new_product)
        }
    }
}

/// Normalizes Go-compatible ASCII regex pattern into Rust non-unicode regex.
pub(crate) fn validate_and_normalize_regex(
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

    let ast = ParserBuilder::new()
        .octal(true)
        .build()
        .parse(pattern)
        .map_err(|_| SanitizeError::Incompatible {
            path: format!("{cost_path}.match"),
            reason: "invalid regex pattern",
        })?;

    validate_ast(&ast, pattern, cost_path, 0, 1)?;

    let bytes = pattern.as_bytes();
    let len = bytes.len();
    let mut i = 0;
    let mut in_class = false;
    let mut normalized = String::with_capacity(len + 16);

    while i < len {
        let b = bytes[i];
        if b == b'\\' {
            if i + 1 < len {
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
                }
            }
            normalized.push('\\');
            if i + 1 < len {
                normalized.push(bytes[i + 1] as char);
                i += 2;
            } else {
                i += 1;
            }
            continue;
        }

        if !in_class {
            if b == b'[' {
                in_class = true;
                normalized.push('[');
                i += 1;
                if i < len && bytes[i] == b'^' {
                    normalized.push('^');
                    i += 1;
                }
                if i < len && bytes[i] == b']' {
                    normalized.push(']');
                    i += 1;
                }
                continue;
            }
        } else if b == b']' {
            in_class = false;
            normalized.push(']');
            i += 1;
            continue;
        }

        normalized.push(b as char);
        i += 1;
    }

    Ok(normalized)
}

/// Extracts the first ASCII `\d+(\.\d+)?` from `s` and parses it as `f64`.
pub(crate) fn first_ascii_number(s: &str) -> Option<f64> {
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

#[inline]
pub(crate) fn is_exact_f32(val: f64) -> bool {
    let as_f32 = val as f32;
    as_f32.is_finite() && (as_f32 as f64) == val
}

pub fn resolve_leastload_costs(
    costs_val: &Value,
    member_orig_tags: &[(&str, &str)],
    path: &str,
    budget: &mut CostBudget,
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

    budget.total_rules += costs_arr.len();
    if budget.total_rules > MAX_PROFILE_COST_RULES {
        return Err(SanitizeError::Incompatible {
            path: format!("{path}.strategy.settings.costs"),
            reason: "profile costs exceeds total rule limit",
        });
    }

    let member_tag_bytes: usize = member_orig_tags.iter().map(|(_, orig)| orig.len()).sum();
    let balancer_matching_bytes = member_tag_bytes.saturating_mul(costs_arr.len());
    budget.matching_bytes = budget
        .matching_bytes
        .saturating_add(balancer_matching_bytes);
    if budget.matching_bytes > MAX_PROFILE_MATCHING_BYTES {
        return Err(SanitizeError::Incompatible {
            path: format!("{path}.strategy.settings.costs"),
            reason: "profile costs exceeds matching text budget",
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
                .size_limit(MAX_REGEX_SIZE_LIMIT)
                .dfa_size_limit(MAX_REGEX_SIZE_LIMIT)
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
                } else if let Some(val) = first_ascii_number(matched) {
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
        assert!(!re.is_match(b"node\x0b7"));
        assert!(re.is_match(b"node\t7"));
        assert!(re.is_match(b"node 7"));
    }

    #[test]
    fn test_ast_grammar_rejections() {
        let bad_patterns = [
            (r"\u0033", "unsupported regex escape sequence"),
            (r"\U00000033", "unsupported regex escape sequence"),
            (r"\<3", "unsupported regex escape sequence"),
            (r"\1", "unsupported regex escape sequence"),
            (r"a**", "unsupported regex stacked quantifier"),
            (r"a++", "unsupported regex stacked quantifier"),
            (r"a{1001}", "regex repetition count exceeds limit"),
            (r"(a{100}){11}", "regex repetition count exceeds limit"),
            (r"a{01}", "unsupported regex quantifier spelling"),
            (r"a{ 2 }", "unsupported regex quantifier spelling"),
            (r"(?P<a.b>node)", "invalid regex capture group name"),
            (r"[a[b]]", "unsupported regex nested character class"),
            (
                r"[a-z&&[0-9]]",
                "unsupported regex character class operator",
            ),
            (r"(?x)node", "unsupported regex flag"),
            (r"(?u)node", "unsupported regex flag"),
            (r"(?R)node", "unsupported regex flag"),
        ];

        for (pat, expected_reason) in bad_patterns {
            let err = validate_and_normalize_regex(pat, "test").unwrap_err();
            assert_eq!(
                err,
                SanitizeError::Incompatible {
                    path: "test.match".into(),
                    reason: expected_reason,
                },
                "pattern '{pat}' expected error reason '{expected_reason}'"
            );
        }

        let good_patterns = [
            r"(?P<proxy>node)",
            r"(?<proxy>node)",
            r"(?:node)",
            r"(?i)node",
            r"[a-z[:digit:]]",
            r"\0",
            r"\001",
            r"\x7f",
            r"\x{7f}",
            r"node\s[0-9]",
        ];

        for pat in good_patterns {
            assert!(
                validate_and_normalize_regex(pat, "test").is_ok(),
                "pattern '{pat}' should be accepted"
            );
        }
    }
}
