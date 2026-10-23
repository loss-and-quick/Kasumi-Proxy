//! Which outbound a provider's Xray config sends traffic to by default.
//!
//! Kasumi routes its own traffic (its `force-in` inbound, "DNS via proxy", every
//! rule that targets `proxy`, and the profile probe) to the tag `proxy`, so that
//! tag has to name what the profile itself dials by default. That is not always
//! its first outbound: a provider may keep a decoy first and route everything
//! through a balancer, or name its real exit only in a rule.

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

/// Pick the target of the traffic a provider config carries by default.
///
/// Conditional rules are only ever consulted by Xray for the traffic they match,
/// so following them would be following the provider's block and geo decisions;
/// the default path is what an unconditional rule, or Xray's own fallback, says.
/// See Xray's `routing.Router.PickRoute` and `GetDefaultHandler`.
pub fn default_target(s: &SanitizedXray) -> Target {
    let routing = s.routing.as_ref();
    let rules = routing
        .and_then(|r| r.get("rules"))
        .and_then(Value::as_array);
    let balancers = routing
        .and_then(|r| r.get("balancers"))
        .and_then(Value::as_array);
    let service = |tag: &str| {
        s.outbounds
            .iter()
            .find(|o| o["tag"].as_str() == Some(tag))
            .is_some_and(is_service_outbound)
    };
    let target_for = |rule: &Value| target_of(rule, &service, balancers);

    // The first rule that matches every TCP connection is the one that carries
    // the profile; a later one never runs, so it is not consulted either.
    if let Some(rule) = rules
        .into_iter()
        .flatten()
        .find(|rule| is_unconditional(rule))
        && let Some(target) = target_for(rule)
    {
        return target;
    }
    // Xray's own fallback for traffic no rule matched: the first outbound.
    if let Some(ob) = s.outbounds.first()
        && !is_service_outbound(ob)
        && let Some(tag) = ob["tag"].as_str()
    {
        return Target::Outbound(tag.to_string());
    }
    // Otherwise the first rule that names something able to carry traffic.
    for rule in rules.into_iter().flatten() {
        if let Some(target) = target_for(rule) {
            return target;
        }
    }
    // A config with no reachable target: the sanitiser refuses those, so this is
    // only a last resort that keeps the caller's `proxy` tag pointing at something.
    s.outbounds
        .iter()
        .find(|o| !is_service_outbound(o) && o["tag"].is_string())
        .and_then(|o| o["tag"].as_str())
        .map(|tag| Target::Outbound(tag.to_string()))
        .unwrap_or(Target::Outbound("proxy".into()))
}

/// A rule's named target, when it can carry traffic: a service outbound only
/// drops or answers it, and a balancer made of nothing but those carries nothing.
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

/// Whether the rule matches every TCP connection: nothing but `network` or a
/// full-range `port` narrows it.
fn is_unconditional(rule: &Value) -> bool {
    const CONDITIONAL: [&str; 4] = ["domain", "ip", "protocol", "sourcePort"];
    let Some(obj) = rule.as_object() else {
        return false;
    };
    if obj.keys().any(|k| CONDITIONAL.contains(&k.as_str())) {
        return false;
    }
    // A narrowed port narrows the rule whatever its network says.
    if let Some(port) = obj.get("port")
        && !covers_every_port(port)
    {
        return false;
    }
    match obj.get("network").and_then(Value::as_str) {
        Some(network) => network.split(',').any(|n| n.trim() == "tcp"),
        None => true,
    }
}

/// Whether an Xray port list (`"53,1000-2000"`) covers 1–65535, in any order and
/// split across entries.
fn covers_every_port(port: &Value) -> bool {
    let Value::String(list) = port else {
        return false;
    };
    let mut ranges: Vec<(u32, u32)> = Vec::new();
    for part in list.split(',') {
        let part = part.trim();
        let (lo, hi) = match part.split_once('-') {
            Some((lo, hi)) => (lo.trim().parse(), hi.trim().parse()),
            None => match part.parse() {
                Ok(p) => (Ok(p), Ok(p)),
                Err(_) => return false,
            },
        };
        let (Ok(lo), Ok(hi)) = (lo, hi) else {
            return false;
        };
        ranges.push((lo, hi));
    }
    if ranges.is_empty() {
        return false;
    }
    ranges.sort_unstable();
    let mut reach = 0;
    for (lo, hi) in ranges {
        if lo > reach + 1 {
            return false;
        }
        reach = reach.max(hi);
    }
    reach >= 65535
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
            vec![freedom("direct"), server("main")],
            json!({ "rules": [
                { "type": "field", "network": "tcp,udp", "outboundTag": "direct" },
                { "type": "field", "domain": ["a.example"], "outboundTag": "main" },
            ]}),
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
}
