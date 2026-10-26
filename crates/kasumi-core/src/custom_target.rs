//! Which outbound a provider's Xray config sends traffic to by default.
//!
//! Kasumi routes its own traffic (its `force-in` inbound, "DNS via proxy", every
//! rule that targets `proxy`, and the profile probe) to the tag `proxy`, so that
//! tag has to name what the profile itself dials by default. That is not always
//! its first outbound: a provider may keep a decoy first and route everything
//! through a balancer, or name its real exit only in a rule.

use std::collections::HashSet;

use serde_json::Value;

use crate::custom_sanitize::{SanitizedXray, is_service_outbound};

/// Where a profile's default traffic ends up.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Target {
    Outbound(String),
    Balancer { tag: String, members: Vec<String> },
}

impl Target {
    /// One line naming what a probe through this profile measures.
    pub fn describe(&self) -> String {
        match self {
            Target::Outbound(tag) => format!("outbound {tag}"),
            Target::Balancer { tag, members } => {
                format!("balancer {tag} ({})", members.join(", "))
            }
        }
    }
}

/// True if `rule` is scoped exclusively to virtual inbound tags (internal loopback transitions).
pub fn is_virtual_rule(rule: &Value, virtual_tags: &HashSet<&str>) -> bool {
    let Some(inbound) = rule.get("inboundTag") else {
        return false;
    };
    let tags: Vec<&str> = match inbound {
        Value::Array(arr) => arr.iter().filter_map(Value::as_str).collect(),
        Value::String(s) => vec![s.as_str()],
        _ => Vec::new(),
    };
    !tags.is_empty() && tags.iter().all(|t| virtual_tags.contains(t))
}

/// Pick the target of the traffic a provider config carries by default.
///
/// Conditional rules are only ever consulted by Xray for the traffic they match,
/// so following them would be following the provider's block and geo decisions;
/// the default path is what an unconditional rule, or Xray's own fallback, says.
/// If that fallback is a service rather than a proxy exit, the first usable
/// externally ruled target supplies the forced-proxy path instead.
/// Virtual-inbound rules (internal loopback fallback cascade) are excluded from the
/// external entry default search so that internal cascades do not hijack the entry target.
/// See Xray's `routing.Router.PickRoute` and `GetDefaultHandler`.
pub fn default_target(s: &SanitizedXray) -> Target {
    let routing = s.routing.as_ref();
    let rules = routing
        .and_then(|r| r.get("rules"))
        .and_then(Value::as_array);
    let balancers = routing
        .and_then(|r| r.get("balancers"))
        .and_then(Value::as_array);

    let virtual_tags: HashSet<&str> = s
        .virtual_inbound_tags
        .iter()
        .map(String::as_str)
        .chain(
            s.outbounds
                .iter()
                .filter(|o| o["protocol"] == "loopback")
                .filter_map(|o| {
                    o.get("settings")
                        .and_then(|st| st.get("inboundTag"))
                        .and_then(Value::as_str)
                }),
        )
        .collect();

    let service = |tag: &str| {
        s.outbounds
            .iter()
            .find(|o| o["tag"].as_str() == Some(tag))
            .is_some_and(is_service_outbound)
    };
    let target_for = |rule: &Value| target_of(rule, &service, balancers);

    // The first unconditional external entry rule that matches every TCP connection
    // is the one that carries the profile; virtual loopback rules are skipped.
    if let Some(rule) = rules
        .into_iter()
        .flatten()
        .find(|rule| is_unconditional_entry_rule(rule, &virtual_tags))
        && let Some(target) = target_for(rule)
    {
        return target;
    }
    // Xray's own fallback for traffic no rule matched: the first outbound.
    // If the first outbound is a loopback or normal outbound, target that directly.
    // The builder alias dispatches to it and Xray evaluates its internal ordered
    // conditional rules and cascades automatically.
    if let Some(ob) = s.outbounds.first()
        && !is_service_outbound(ob)
        && let Some(tag) = ob["tag"].as_str()
    {
        return Target::Outbound(tag.to_string());
    }
    // A service-first config has no proxied fallback. Its first usable external
    // rule identifies the exit, not the unrelated order of server declarations.
    if let Some(target) = rules
        .into_iter()
        .flatten()
        .filter(|rule| !is_virtual_rule(rule, &virtual_tags))
        .find_map(target_for)
    {
        return target;
    }
    // With no usable ruled target either, the first declared proxy is the last resort.
    s.outbounds
        .iter()
        .find(|o| !is_service_outbound(o) && o["tag"].is_string())
        .and_then(|o| o["tag"].as_str())
        .map(|tag| Target::Outbound(tag.to_string()))
        .unwrap_or(Target::Outbound("proxy".into()))
}

/// A rule's named proxy target. Direct, DNS and block services do not identify a
/// proxy exit, and a balancer made entirely of those cannot supply one either.
fn target_of(
    rule: &Value,
    service: &dyn Fn(&str) -> bool,
    balancers: Option<&Vec<Value>>,
) -> Option<Target> {
    if let Some(tag) = rule["outboundTag"].as_str() {
        return (!service(tag)).then(|| Target::Outbound(tag.to_string()));
    }
    let tag = rule["balancerTag"].as_str()?;
    let members: Vec<String> = balancers?
        .iter()
        .find(|b| b["tag"].as_str() == Some(tag))?
        .get("selector")
        .and_then(Value::as_array)?
        .iter()
        .filter_map(Value::as_str)
        .map(str::to_string)
        .collect();
    if members.is_empty() || members.iter().all(|m| service(m)) {
        return None;
    }
    Some(Target::Balancer {
        tag: tag.to_string(),
        members,
    })
}

/// Whether the rule matches every TCP connection from external entry:
/// excludes virtual-inbound scoped rules and uses the authoritative shared coverage helper.
fn is_unconditional_entry_rule(rule: &Value, virtual_tags: &HashSet<&str>) -> bool {
    let Some(obj) = rule.as_object() else {
        return false;
    };
    if is_virtual_rule(rule, virtual_tags) {
        return false;
    }
    crate::provider_graph::rule_covers_network(obj, "tcp")
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    const UUID: &str = "11111111-1111-1111-1111-111111111111";

    fn server(tag: &str) -> Value {
        json!({
            "tag": tag, "protocol": "vless",
            "settings": { "vnext": [{ "address": "srv.example", "port": 443,
                "users": [{ "id": UUID, "encryption": "none" }] }] },
        })
    }

    fn freedom(tag: &str) -> Value {
        json!({ "tag": tag, "protocol": "freedom" })
    }

    fn built(outbounds: Vec<Value>, routing: Value) -> SanitizedXray {
        SanitizedXray {
            outbounds,
            routing: (!routing.is_null()).then_some(routing),
            remarks: None,
            dropped: Vec::new(),
            observatory: None,
            burst_observatory: None,
            ingress_tags: Vec::new(),
            virtual_inbound_tags: Vec::new(),
        }
    }

    #[test]
    fn follows_the_balancer_a_catch_all_rule_names() {
        let s = built(
            vec![
                server("decoy"),
                server("main"),
                server("main-2"),
                freedom("direct"),
            ],
            json!({
                "balancers": [
                    { "tag": "lb", "selector": ["main", "main-2"] },
                    { "tag": "dead", "selector": ["direct"] },
                ],
                "rules": [{ "type": "field", "network": "tcp,udp", "balancerTag": "lb" }],
            }),
        );
        assert_eq!(
            default_target(&s),
            Target::Balancer {
                tag: "lb".into(),
                members: vec!["main".into(), "main-2".into()],
            }
        );
        assert_eq!(default_target(&s).describe(), "balancer lb (main, main-2)");
    }

    #[test]
    fn conditional_rules_are_skipped() {
        let s = built(
            vec![server("first"), server("other")],
            json!({
                "balancers": [{ "tag": "lb", "selector": ["other"] }],
                "rules": [
                    { "type": "field", "domain": ["a.example"], "balancerTag": "lb" },
                    { "type": "field", "ip": ["10.0.0.0/8"], "outboundTag": "other" },
                    { "type": "field", "protocol": ["http"], "outboundTag": "other" },
                ],
            }),
        );
        assert_eq!(default_target(&s), Target::Outbound("first".into()));
    }

    #[test]
    fn a_udp_only_rule_is_not_a_catch_all() {
        let s = built(
            vec![server("first"), server("udp-exit")],
            json!({ "rules": [
                { "type": "field", "network": "udp", "outboundTag": "udp-exit" },
            ]}),
        );
        // It carries no TCP, so the profile's TCP default is Xray's own fallback.
        assert_eq!(default_target(&s), Target::Outbound("first".into()));

        let s = built(
            vec![server("first"), server("udp-exit")],
            json!({ "rules": [
                { "type": "field", "port": "53", "outboundTag": "udp-exit" },
            ]}),
        );
        assert_eq!(default_target(&s), Target::Outbound("first".into()));
    }

    #[test]
    fn a_port_narrowed_rule_is_not_a_catch_all() {
        let s = built(
            vec![server("decoy"), server("main")],
            json!({ "rules": [
                { "type": "field", "network": "tcp", "port": "443", "outboundTag": "decoy" },
                { "type": "field", "network": "tcp,udp", "outboundTag": "main" },
            ]}),
        );
        assert_eq!(default_target(&s), Target::Outbound("main".into()));
    }

    #[test]
    fn a_full_port_range_counts_as_unconditional() {
        for list in ["1-65535", "1-100,101-65535", "65535,1-65534"] {
            let s = built(
                vec![server("decoy"), server("chosen")],
                json!({ "rules": [
                    { "type": "field", "port": list, "outboundTag": "chosen" },
                ]}),
            );
            assert_eq!(
                default_target(&s),
                Target::Outbound("chosen".into()),
                "{list}"
            );
        }
        // A single port or a gap is not everything.
        for list in ["443", "1-100,102-65535", "1-65534"] {
            let s = built(
                vec![server("decoy"), server("chosen")],
                json!({ "rules": [
                    { "type": "field", "port": list, "outboundTag": "chosen" },
                ]}),
            );
            assert_eq!(
                default_target(&s),
                Target::Outbound("decoy".into()),
                "{list}"
            );
        }
    }

    #[test]
    fn without_a_catch_all_the_first_outbound_is_the_target() {
        let s = built(vec![server("first"), server("second")], Value::Null);
        assert_eq!(default_target(&s), Target::Outbound("first".into()));
    }

    #[test]
    fn a_service_catch_all_falls_through_to_a_ruled_target() {
        // Everything the provider does not classify goes direct, and only a
        // conditional rule names a server: that server is the profile's exit.
        let s = built(
            vec![freedom("direct"), server("decoy"), server("main")],
            json!({ "rules": [
                { "type": "field", "network": "tcp,udp", "outboundTag": "direct" },
                { "type": "field", "domain": ["a.example"], "outboundTag": "main" },
            ]}),
        );
        assert_eq!(default_target(&s), Target::Outbound("main".into()));
    }

    #[test]
    fn service_first_uses_rule_order_instead_of_server_order() {
        let s = built(
            vec![freedom("direct"), server("decoy"), server("main")],
            json!({ "rules": [
                { "type": "field", "domain": ["main.example"], "outboundTag": "main" },
                { "type": "field", "domain": ["decoy.example"], "outboundTag": "decoy" }
            ] }),
        );
        assert_eq!(default_target(&s), Target::Outbound("main".into()));
    }

    #[test]
    fn service_first_rule_fallback_can_select_a_balancer() {
        let s = built(
            vec![freedom("direct"), server("decoy"), server("main")],
            json!({
                "balancers": [{ "tag": "selected", "selector": ["main"] }],
                "rules": [
                    { "type": "field", "domain": ["main.example"], "balancerTag": "selected" },
                    { "type": "field", "domain": ["decoy.example"], "outboundTag": "decoy" }
                ]
            }),
        );
        assert_eq!(
            default_target(&s),
            Target::Balancer {
                tag: "selected".into(),
                members: vec!["main".into()]
            }
        );
    }

    #[test]
    fn service_first_rule_fallback_excludes_virtual_only_rules() {
        let s = built(
            vec![
                freedom("direct"),
                server("decoy"),
                server("main"),
                json!({ "tag": "reenter", "protocol": "loopback", "settings": { "inboundTag": "inside" } }),
            ],
            json!({ "rules": [
                { "type": "field", "inboundTag": ["inside"], "outboundTag": "decoy" },
                { "type": "field", "domain": ["main.example"], "outboundTag": "main" }
            ] }),
        );
        assert_eq!(default_target(&s), Target::Outbound("main".into()));
    }

    #[test]
    fn a_balancer_of_service_outbounds_is_not_a_target() {
        let s = built(
            vec![freedom("direct"), server("main")],
            json!({
                "balancers": [{ "tag": "lb", "selector": ["direct"] }],
                "rules": [
                    { "type": "field", "network": "tcp", "balancerTag": "lb" },
                    { "type": "field", "ip": ["10.0.0.0/8"], "outboundTag": "main" },
                ],
            }),
        );
        assert_eq!(default_target(&s), Target::Outbound("main".into()));
    }

    #[test]
    fn an_untagged_outbound_is_never_the_target() {
        // Nothing but the default route can reach an untagged outbound, and the
        // sanitiser keeps those only from a config that names their tag in rules.
        let s = built(
            vec![json!({ "protocol": "vless" }), server("main")],
            Value::Null,
        );
        assert_eq!(default_target(&s), Target::Outbound("main".into()));
    }

    #[test]
    fn virtual_inbound_cascade_does_not_hijack_entry_catchall() {
        let loopback = |tag: &str, in_tag: &str| {
            json!({
                "tag": tag, "protocol": "loopback",
                "settings": { "inboundTag": in_tag }
            })
        };
        let mut s = built(
            vec![
                server("main-proxy"),
                server("fallback-proxy"),
                loopback("loopback-lte", "LTE-lte-lb-in"),
                loopback("loopback-main", "LTE-main-lb-in"),
                loopback("loopback-sticky", "LTE-sticky-lb-in"),
                freedom("direct"),
            ],
            json!({
                "balancers": [
                    { "tag": "LTE-all-balancer", "selector": ["fallback-proxy"] },
                    { "tag": "LTE-lte-balancer", "selector": ["fallback-proxy"], "fallbackTag": "loopback-lte" },
                    { "tag": "LTE-balancer", "selector": ["main-proxy"], "fallbackTag": "loopback-main" },
                    { "tag": "LTE-sticky-balancer", "selector": ["main-proxy"], "fallbackTag": "loopback-sticky" },
                ],
                "rules": [
                    { "type": "field", "inboundTag": ["LTE-lte-lb-in"], "balancerTag": "LTE-all-balancer" },
                    { "type": "field", "inboundTag": ["LTE-main-lb-in"], "balancerTag": "LTE-lte-balancer" },
                    { "type": "field", "inboundTag": ["LTE-sticky-lb-in"], "balancerTag": "LTE-balancer" },
                    { "type": "field", "domain": ["example.com"], "outboundTag": "direct" },
                    { "type": "field", "network": "tcp,udp", "balancerTag": "LTE-sticky-balancer" },
                ],
            }),
        );
        s.virtual_inbound_tags = vec![
            "LTE-lte-lb-in".into(),
            "LTE-main-lb-in".into(),
            "LTE-sticky-lb-in".into(),
        ];
        assert_eq!(
            default_target(&s),
            Target::Balancer {
                tag: "LTE-sticky-balancer".into(),
                members: vec!["main-proxy".into()],
            }
        );
    }

    #[test]
    fn domains_alias_is_treated_as_conditional() {
        let s = built(
            vec![server("decoy"), server("main"), server("conditional")],
            json!({
                "rules": [
                    { "type": "field", "domains": ["only.example"], "outboundTag": "conditional" },
                    { "type": "field", "network": "tcp,udp", "outboundTag": "main" },
                ],
            }),
        );
        assert_eq!(default_target(&s), Target::Outbound("main".into()));
    }

    #[test]
    fn first_outbound_loopback_remains_the_default_target() {
        let loopback = json!({
            "tag": "lb-out", "protocol": "loopback",
            "settings": { "inboundTag": "v" }
        });
        let mut s = built(
            vec![loopback, server("decoy"), server("actual")],
            json!({
                "rules": [
                    { "type": "field", "inboundTag": ["v"], "outboundTag": "actual" },
                ],
            }),
        );
        s.virtual_inbound_tags = vec!["v".into()];
        assert_eq!(default_target(&s), Target::Outbound("lb-out".into()));
    }

    #[test]
    fn local_virtual_first_conditional_then_unconditional() {
        let loopback = json!({
            "tag": "lb-out", "protocol": "loopback",
            "settings": { "inboundTag": "v" }
        });
        let mut s = built(
            vec![loopback, server("conditional"), server("fallback")],
            json!({
                "rules": [
                    { "type": "field", "inboundTag": ["v"], "domain": ["special.example"], "outboundTag": "conditional" },
                    { "type": "field", "inboundTag": ["v"], "network": "tcp,udp", "outboundTag": "fallback" },
                ],
            }),
        );
        s.virtual_inbound_tags = vec!["v".into()];
        // Target is the loopback entry, leaving internal conditional + fallback to Xray
        assert_eq!(default_target(&s), Target::Outbound("lb-out".into()));
    }
}
